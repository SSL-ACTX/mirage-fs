// src/mirage_fs.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE};
#[cfg(feature = "fuse")]
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyWrite, ReplyEmpty, Request, TimeOrNow,
};
#[cfg(feature = "fuse")]
use std::ffi::OsStr;
use libc::{EIO, ENOENT, EEXIST, ENOTEMPTY, EACCES};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::Write;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use std::path::Path;
use log::{info, error, warn};

// Maximum metadata blocks (hard cap)
const METADATA_BLOCKS: u32 = 256;
const SUPERBLOCK_ID: u32 = 0;
#[allow(dead_code)]
const TTL: Duration = Duration::from_secs(1);
const METADATA_MAGIC: [u8; 8] = *b"MRGMDATA";
const METADATA_HEADER_LEN: usize = 16;

fn default_freeze_timestamps() -> bool { true }
fn default_frozen_time_secs() -> u64 { 0 }

// --- Internal Types ---

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum MirageFileType {
    Directory,
    RegularFile,
}

/// Serializable File Attribute representation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializedFileAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub kind: MirageFileType,
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_secs: u64,
}

/// The Inode structure.
#[derive(Serialize, Deserialize, Clone)]
pub struct Inode {
    pub attr: SerializedFileAttr,
    // List of physical block indices owned by this file.
    pub blocks: Vec<u32>
}

/// The Superblock contains the entire filesystem state.
#[derive(Serialize, Deserialize)]
struct Superblock {
    inodes: HashMap<u64, Inode>,
    // Directory Map: Parent Inode -> { Filename -> Child Inode }
    directory_map: HashMap<u64, HashMap<String, u64>>,
    next_inode: u64,
    // High-water mark for disk usage (append-only allocator)
    disk_size_blocks: u32,
    // Reverse map for compaction: Physical Block -> Owner Inode
    block_owner: HashMap<u32, u64>,
    #[serde(default)]
    metadata_blocks_reserved: u32,
    #[serde(default = "default_freeze_timestamps")]
    freeze_timestamps: bool,
    #[serde(default = "default_frozen_time_secs")]
    frozen_time_secs: u64,
}

// Legacy superblock for backward compatibility (pre-metadata header fields)
#[derive(Serialize, Deserialize)]
struct LegacySuperblock {
    inodes: HashMap<u64, Inode>,
    directory_map: HashMap<u64, HashMap<String, u64>>,
    next_inode: u64,
    disk_size_blocks: u32,
    block_owner: HashMap<u32, u64>,
}

// Necessary for WebDAV (Tokio runtime moves this across threads)
unsafe impl Send for MirageFS {}

pub struct MirageFS {
    disk: Box<dyn BlockDevice>,
    inodes: HashMap<u64, Inode>,
    directory_map: HashMap<u64, HashMap<String, u64>>,
    next_inode: u64,
    disk_size_blocks: u32,
    block_owner: HashMap<u32, u64>,
    uid: u32,
    gid: u32,
    read_only: bool,
    metadata_blocks_reserved: u32,
    freeze_timestamps: bool,
    frozen_time_secs: u64,
}

impl std::fmt::Debug for MirageFS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MirageFS")
        .field("inodes_count", &self.inodes.len())
        .field("disk_usage_blocks", &self.disk_size_blocks)
        .finish()
    }
}

impl MirageFS {
    fn deserialize_superblock(bytes: &[u8]) -> anyhow::Result<Superblock> {
        if let Ok(sb) = bincode::deserialize::<Superblock>(bytes) {
            return Ok(sb);
        }
        let legacy: LegacySuperblock = bincode::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;

        Ok(Superblock {
            inodes: legacy.inodes,
            directory_map: legacy.directory_map,
            next_inode: legacy.next_inode,
            disk_size_blocks: legacy.disk_size_blocks,
            block_owner: legacy.block_owner,
            metadata_blocks_reserved: 0,
            freeze_timestamps: default_freeze_timestamps(),
            frozen_time_secs: default_frozen_time_secs(),
        })
    }
    fn metadata_blocks_needed_for(data_len: usize) -> u32 {
        let total_len = METADATA_HEADER_LEN + data_len;
        ((total_len + BLOCK_SIZE - 1) / BLOCK_SIZE) as u32
    }

    fn metadata_blocks_needed_current(&self) -> anyhow::Result<u32> {
        let sb = Superblock {
            inodes: self.inodes.clone(), directory_map: self.directory_map.clone(),
            next_inode: self.next_inode,
            disk_size_blocks: self.disk_size_blocks,
            block_owner: self.block_owner.clone(),
            metadata_blocks_reserved: self.metadata_blocks_reserved,
            freeze_timestamps: self.freeze_timestamps,
            frozen_time_secs: self.frozen_time_secs,
        };

        let data = bincode::serialize(&sb)?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&data)?;
        let compressed_data = encoder.finish()?;
        Ok(Self::metadata_blocks_needed_for(compressed_data.len()))
    }

    fn expand_metadata_reserve(&mut self, new_reserved: u32) -> anyhow::Result<()> {
        if new_reserved <= self.metadata_blocks_reserved {
            return Ok(());
        }
        let delta = new_reserved - self.metadata_blocks_reserved;

        let mut blocks: Vec<u32> = self.block_owner.keys().cloned().collect();
        blocks.sort_by(|a, b| b.cmp(a));

        for old_idx in blocks {
            let data = self.disk.read_block(old_idx).map_err(|e| anyhow::anyhow!(e))?;
            let new_idx = old_idx + delta;
            self.disk.write_block(new_idx, &data).map_err(|e| anyhow::anyhow!(e))?;

            if let Some(owner_ino) = self.block_owner.remove(&old_idx) {
                self.block_owner.insert(new_idx, owner_ino);
                if let Some(inode) = self.inodes.get_mut(&owner_ino) {
                    for b in &mut inode.blocks {
                        if *b == old_idx {
                            *b = new_idx;
                        }
                    }
                }
            }
        }

        self.disk_size_blocks += delta;
        self.metadata_blocks_reserved = new_reserved;
        Ok(())
    }
    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn effective_time_secs(&self) -> u64 {
        if self.freeze_timestamps {
            self.frozen_time_secs
        } else {
            Self::now_secs()
        }
    }

    fn enforce_frozen_timestamps(&mut self) {
        if !self.freeze_timestamps {
            return;
        }
        let frozen = self.frozen_time_secs;
        for inode in self.inodes.values_mut() {
            inode.attr.mtime_secs = frozen;
        }
    }

    pub fn frozen_time_secs(&self) -> u64 {
        self.effective_time_secs()
    }

    pub fn new(disk: Box<dyn BlockDevice>, format: bool, uid: u32, gid: u32, read_only: bool) -> anyhow::Result<Self> {
        if read_only && format {
            anyhow::bail!("Read-only media cannot be formatted.");
        }
        // Attempt to load existing filesystem
        info!("Attempting to load filesystem metadata...");
        let load_result = Self::load_metadata(&disk);

        if let Ok(sb) = load_result {
            info!("Superblock Loaded! {} inodes found.", sb.inodes.len());

            if !format {
                let mut freeze_timestamps = sb.freeze_timestamps;
                let mut frozen_time_secs = sb.frozen_time_secs;
                if !freeze_timestamps || frozen_time_secs == 0 {
                    let fallback = sb.inodes.get(&1).map(|i| i.attr.mtime_secs).unwrap_or_else(Self::now_secs);
                    frozen_time_secs = fallback;
                    freeze_timestamps = true;
                }
                let mut fs = MirageFS {
                    disk,
                    inodes: sb.inodes, directory_map: sb.directory_map,
                    next_inode: sb.next_inode,
                    disk_size_blocks: sb.disk_size_blocks,
                    block_owner: sb.block_owner,
                    uid, gid,
                    read_only,
                    metadata_blocks_reserved: sb.metadata_blocks_reserved,
                    freeze_timestamps,
                    frozen_time_secs,
                };
                // Fix permissions for current user context (ownership override)
                for inode in fs.inodes.values_mut() {
                    inode.attr.uid = uid;
                    inode.attr.gid = gid;
                }
                if fs.metadata_blocks_reserved == 0 {
                    let needed = fs.metadata_blocks_needed_current().unwrap_or(1);
                    fs.metadata_blocks_reserved = needed;
                }
                if fs.disk_size_blocks < fs.metadata_blocks_reserved {
                    fs.disk_size_blocks = fs.metadata_blocks_reserved;
                }
                fs.enforce_frozen_timestamps();
                return Ok(fs);
            } else {
                warn!("Format requested. Overwriting existing filesystem.");
            }
        } else if !format {
            let err = load_result.err().unwrap();
            error!("Failed to load metadata: {}", err);
            anyhow::bail!("Could not load MirageFS metadata. Use --format if this is a new volume. Error: {}", err);
        }

        // Initialize empty filesystem
        info!("Initializing NEW filesystem...");
        let frozen_time_secs = Self::now_secs();
        let mut fs = MirageFS {
            disk,
            inodes: HashMap::new(), directory_map: HashMap::new(),
            next_inode: 2,
            disk_size_blocks: 1,
            block_owner: HashMap::new(),
            uid, gid,
            read_only,
            metadata_blocks_reserved: 1,
            freeze_timestamps: true,
            frozen_time_secs,
        };

        // Create Root Directory (Inode 1)
        let root_attr = SerializedFileAttr {
            ino: 1, size: 0, blocks: 0,
            kind: MirageFileType::Directory, perm: 0o755, nlink: 2,
            uid, gid, mtime_secs: frozen_time_secs
        };
        fs.inodes.insert(1, Inode { attr: root_attr, blocks: Vec::new() });
        fs.directory_map.insert(1, HashMap::new());

        let needed = fs.metadata_blocks_needed_current()?;
        fs.metadata_blocks_reserved = needed;
        fs.disk_size_blocks = needed;
        fs.save_metadata()?;
        fs.disk.sync()?;
        Ok(fs)
    }

    // --- Core Logic (Platform Independent) ---

    pub fn get_inode(&self, ino: u64) -> Option<&Inode> {
        self.inodes.get(&ino)
    }

    pub fn get_inode_size(&self, ino: u64) -> Option<u64> {
        self.inodes.get(&ino).map(|i| i.attr.size)
    }

    /// Resolves a full path string (e.g., "/foo/bar") to an Inode.
    pub fn resolve_path(&self, path: &Path) -> Result<u64, i32> {
        let mut current_ino = 1; // Start at Root
        for component in path.components() {
            match component {
                std::path::Component::RootDir => continue,
                std::path::Component::Normal(name) => {
                    let name_str = name.to_str().unwrap();
                    if let Some(children) = self.directory_map.get(&current_ino) {
                        if let Some(&child_ino) = children.get(name_str) {
                            current_ino = child_ino;
                        } else {
                            return Err(ENOENT);
                        }
                    } else {
                        return Err(ENOENT);
                    }
                }
                _ => continue,
            }
        }
        Ok(current_ino)
    }

    pub fn set_attr_internal(&mut self, ino: u64, size: Option<u64>, mtime: Option<u64>, mode: Option<u16>) -> Result<(), i32> {
        if self.read_only { return Err(EACCES); }
        if let Some(inode) = self.inodes.get_mut(&ino) {
            if let Some(s) = size {
                inode.attr.size = s;
            }
            if let Some(t) = mtime {
                if !self.freeze_timestamps {
                    inode.attr.mtime_secs = t;
                }
            }
            if let Some(m) = mode {
                inode.attr.perm = m;
            }
            let _ = self.sync_disk();
            Ok(())
        } else {
            Err(ENOENT)
        }
    }

    pub fn create_file_internal(&mut self, parent: u64, name: &str) -> Result<u64, i32> {
        if self.read_only { return Err(EACCES); }
        let new_ino = self.allocate_inode(MirageFileType::RegularFile, 0o644);
        self.directory_map.entry(parent).or_default().insert(name.to_string(), new_ino);
        let _ = self.sync_disk();
        Ok(new_ino)
    }

    pub fn mkdir_internal(&mut self, parent: u64, name: &str) -> Result<u64, i32> {
        if self.read_only { return Err(EACCES); }
        if let Some(children) = self.directory_map.get(&parent) {
            if children.contains_key(name) {
                return Err(EEXIST);
            }
        }
        let new_ino = self.allocate_inode(MirageFileType::Directory, 0o755);
        self.directory_map.entry(parent).or_default().insert(name.to_string(), new_ino);
        // Initialize empty children map
        self.directory_map.insert(new_ino, HashMap::new());
        let _ = self.sync_disk();
        Ok(new_ino)
    }

    pub fn unlink_internal(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        if self.read_only { return Err(EACCES); }
        let ino_to_remove = if let Some(children) = self.directory_map.get_mut(&parent) {
            children.remove(name)
        } else {
            None
        };

        if let Some(ino) = ino_to_remove {
            self.free_inode_blocks(ino);
            self.inodes.remove(&ino);
            self.directory_map.remove(&ino);
            if self.sync_disk() == 0 { Ok(()) } else { Err(EIO) }
        } else {
            Err(ENOENT)
        }
    }

    // Safe directory removal: Checks if directory is empty first.
    pub fn rmdir_internal(&mut self, parent: u64, name: &str) -> Result<(), i32> {
        if self.read_only { return Err(EACCES); }
        if let Some(children) = self.directory_map.get(&parent) {
            if let Some(&ino) = children.get(name) {
                if let Some(grandkids) = self.directory_map.get(&ino) {
                    if !grandkids.is_empty() {
                        return Err(ENOTEMPTY);
                    }
                }
            }
        }
        self.unlink_internal(parent, name)
    }

    // Atomic Rename / Move logic
    pub fn rename_internal(&mut self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
        if self.read_only { return Err(EACCES); }
        let name_str = name.to_string();
        let newname_str = newname.to_string();

        let ino_opt = self.directory_map.get(&parent)
        .and_then(|c| c.get(&name_str).cloned());

        if let Some(ino) = ino_opt {
            // Handle overwrite at destination
            let target_exists = self.directory_map.get(&newparent)
            .map(|c| c.contains_key(&newname_str)).unwrap_or(false);

            if target_exists {
                if let Some(target_ino) = self.directory_map.get(&newparent).and_then(|c| c.get(&newname_str).cloned()) {
                    if let Some(inode) = self.inodes.get(&target_ino) {
                        if matches!(inode.attr.kind, MirageFileType::Directory) {
                            if let Some(c) = self.directory_map.get(&target_ino) {
                                if !c.is_empty() {
                                    return Err(ENOTEMPTY);
                                }
                            }
                            self.directory_map.remove(&target_ino);
                            self.inodes.remove(&target_ino);
                        } else {
                            // Overwriting file: Free old blocks
                            self.free_inode_blocks(target_ino);
                            self.inodes.remove(&target_ino);
                        }
                    }
                }
            }

            // Remove from old parent
            if let Some(children) = self.directory_map.get_mut(&parent) {
                children.remove(&name_str);
            }

            // Insert into new parent
            self.directory_map.entry(newparent).or_default().insert(newname_str, ino);

            if self.sync_disk() == 0 { Ok(()) } else { Err(EIO) }
        } else {
            Err(ENOENT)
        }
    }

    pub fn readdir_internal(&self, ino: u64) -> Vec<(u64, String, MirageFileType)> {
        let mut entries = Vec::new();
        if let Some(children) = self.directory_map.get(&ino) {
            for (name, child_ino) in children {
                if let Some(child_inode) = self.inodes.get(child_ino) {
                    entries.push((*child_ino, name.clone(), child_inode.attr.kind));
                }
            }
        }
        entries
    }

    pub fn read_data_internal(&mut self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        if let Some(inode) = self.inodes.get(&ino) {
            let mut collected_data = Vec::with_capacity(size as usize);
            let mut current_offset = offset as usize;
            let mut remaining_size = size as usize;

            // Gather data from scattered blocks
            while remaining_size > 0 {
                let relative_block = current_offset / BLOCK_SIZE;
                let block_offset = current_offset % BLOCK_SIZE;

                if relative_block >= inode.blocks.len() {
                    break; // EOF
                }

                let abs_block_idx = inode.blocks[relative_block];
                match self.disk.read_block(abs_block_idx) {
                    Ok(block_data) => {
                        let available_in_block = BLOCK_SIZE - block_offset;
                        let read_len = std::cmp::min(remaining_size, available_in_block);
                        collected_data.extend_from_slice(&block_data[block_offset..block_offset + read_len]);
                        current_offset += read_len;
                        remaining_size -= read_len;
                    }
                    Err(_) => {
                        if collected_data.is_empty() { return Err(EIO); }
                        break;
                    }
                }
            }
            Ok(collected_data)
        } else {
            Err(ENOENT)
        }
    }

    pub fn write_data_internal(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, i32> {
        if self.read_only { return Err(EACCES); }
        let mut total_written: usize = 0;
        let mut current_offset = offset as usize;

        let mut blocks = if let Some(inode) = self.inodes.get(&ino) {
            inode.blocks.clone()
        } else {
            return Err(ENOENT);
        };

        while total_written < data.len() {
            let relative_block = current_offset / BLOCK_SIZE;
            let block_offset = current_offset % BLOCK_SIZE;

            // Allocate new blocks if needed
            while blocks.len() <= relative_block {
                let new_block_idx = self.disk_size_blocks;
                self.disk_size_blocks += 1;
                blocks.push(new_block_idx);
                self.block_owner.insert(new_block_idx, ino);
            }

            let abs_block_idx = blocks[relative_block];
            let remaining_data = data.len() - total_written;
            let space_in_block = BLOCK_SIZE - block_offset;
            let chunk_size = std::cmp::min(remaining_data, space_in_block);

            // Read-Modify-Write cycle for partial block writes
            let mut block_data = if block_offset == 0 && chunk_size == BLOCK_SIZE {
                [0u8; BLOCK_SIZE] // Optimization: Full block overwrite
            } else {
                match self.disk.read_block(abs_block_idx) {
                    Ok(data) => data,
                    Err(_) => [0u8; BLOCK_SIZE],
                }
            };

            let chunk_data = &data[total_written..total_written + chunk_size];
            block_data[block_offset..block_offset + chunk_size].copy_from_slice(chunk_data);

            if let Err(_) = self.disk.write_block(abs_block_idx, &block_data) {
                if total_written > 0 { break; }
                return Err(EIO);
            }

            total_written += chunk_size;
            current_offset += chunk_size;
        }

        // Update Inode metadata
        let effective_time = self.effective_time_secs();
        if let Some(inode) = self.inodes.get_mut(&ino) {
            inode.blocks = blocks;
            let end_pos = (offset as u64) + (total_written as u64);
            if end_pos > inode.attr.size { inode.attr.size = end_pos; }
            inode.attr.blocks = inode.blocks.len() as u64;
            // Update mtime
            inode.attr.mtime_secs = effective_time;
        }
        Ok(total_written)
    }

    fn load_metadata(disk: &Box<dyn BlockDevice>) -> anyhow::Result<Superblock> {
        let mut raw_data = Vec::new();
        // Check first block specifically for emptiness to fail fast
        let first = disk.read_block(SUPERBLOCK_ID).map_err(|e| anyhow::anyhow!(e))?;
        if first.iter().all(|&x| x == 0) {
            return Err(anyhow::anyhow!("Block 0 is empty (No filesystem found)"));
        }

        // New compact metadata format: [MAGIC(8)][LEN(u64)][zlib bytes]
        if &first[0..8] == METADATA_MAGIC {
            let len = u64::from_le_bytes(first[8..16].try_into().unwrap()) as usize;
            let total_len = METADATA_HEADER_LEN + len;
            let blocks_needed = (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

            raw_data.extend_from_slice(&first);
            for i in 1..blocks_needed as u32 {
                let block = disk.read_block(SUPERBLOCK_ID + i).map_err(|e| anyhow::anyhow!(e))?;
                raw_data.extend_from_slice(&block);
            }

            if raw_data.len() < total_len {
                return Err(anyhow::anyhow!("Metadata truncated"));
            }
            let compressed = &raw_data[METADATA_HEADER_LEN..METADATA_HEADER_LEN + len];
            let mut decoder = ZlibDecoder::new(compressed);
            let mut decompressed_data = Vec::new();
            if std::io::Read::read_to_end(&mut decoder, &mut decompressed_data).is_err() {
                return Err(anyhow::anyhow!("Decompression failed - Metadata Corrupt"));
            }

            return Self::deserialize_superblock(&decompressed_data);
        }

        raw_data.extend_from_slice(&first);
        for i in 1..METADATA_BLOCKS {
            let block = disk.read_block(SUPERBLOCK_ID + i).map_err(|e| anyhow::anyhow!(e))?;
            raw_data.extend_from_slice(&block);
        }

        let mut decoder = ZlibDecoder::new(&raw_data[..]);
        let mut decompressed_data = Vec::new();
        if std::io::Read::read_to_end(&mut decoder, &mut decompressed_data).is_err() {
            return Err(anyhow::anyhow!("Decompression failed - Metadata Corrupt"));
        }

        Self::deserialize_superblock(&decompressed_data)
    }

    pub fn save_metadata(&mut self) -> anyhow::Result<()> {
        let sb = Superblock {
            inodes: self.inodes.clone(), directory_map: self.directory_map.clone(),
            next_inode: self.next_inode,
            disk_size_blocks: self.disk_size_blocks,
            block_owner: self.block_owner.clone(),
            metadata_blocks_reserved: self.metadata_blocks_reserved,
            freeze_timestamps: self.freeze_timestamps,
            frozen_time_secs: self.frozen_time_secs,
        };

        let data = bincode::serialize(&sb)?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&data)?;
        let compressed_data = encoder.finish()?;

        let mut payload = Vec::with_capacity(METADATA_HEADER_LEN + compressed_data.len());
        payload.extend_from_slice(&METADATA_MAGIC);
        payload.extend_from_slice(&(compressed_data.len() as u64).to_le_bytes());
        payload.extend_from_slice(&compressed_data);

        let blocks_needed = Self::metadata_blocks_needed_for(compressed_data.len());
        if blocks_needed > METADATA_BLOCKS {
            error!("CRITICAL: Metadata size exceeds hard cap ({} blocks)", METADATA_BLOCKS);
        }
        if blocks_needed > self.metadata_blocks_reserved {
            self.expand_metadata_reserve(blocks_needed)?;
        }

        // Check if metadata fits
        if payload.len() > (METADATA_BLOCKS as usize * BLOCK_SIZE) {
            error!("CRITICAL: Metadata size ({}) exceeds reserved blocks!", payload.len());
            // In a real FS, we'd allocate dynamic metadata blocks.
            // For now, warn but try to write what we can or fail.
        }

        let chunks = payload.chunks(BLOCK_SIZE);
        for (i, chunk) in chunks.enumerate() {
            if i >= METADATA_BLOCKS as usize { break; }
            let mut block = [0u8; BLOCK_SIZE];
            block[0..chunk.len()].copy_from_slice(chunk);
            self.disk.write_block(SUPERBLOCK_ID + i as u32, &block).map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    fn allocate_inode(&mut self, kind: MirageFileType, perm: u16) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        let attr = SerializedFileAttr {
            ino, size: 0, blocks: 0,
            kind, perm, nlink: 1,
            uid: self.uid, gid: self.gid,
            mtime_secs: self.effective_time_secs()
        };
        self.inodes.insert(ino, Inode { attr, blocks: Vec::new() });
        ino
    }

    /// "Swap-and-Pop" Compaction:
    /// When blocks are freed, we move data from the END of the disk to the newly created holes.
    /// This keeps the volume contiguous and allows the container (MP4) to physically shrink.
    fn free_inode_blocks(&mut self, ino: u64) {
        let blocks_to_free = if let Some(inode) = self.inodes.get(&ino) {
            inode.blocks.clone()
        } else {
            return;
        };

        for free_block_idx in blocks_to_free {
            self.block_owner.remove(&free_block_idx);
            let last_block_idx = self.disk_size_blocks - 1;

            if free_block_idx == last_block_idx {
                self.disk_size_blocks -= 1;
            } else {
                // Relocate last block to the hole
                if let Ok(data) = self.disk.read_block(last_block_idx) {
                    if self.disk.write_block(free_block_idx, &data).is_ok() {
                        if let Some(&owner_ino) = self.block_owner.get(&last_block_idx) {
                            if let Some(owner_inode) = self.inodes.get_mut(&owner_ino) {
                                for b in &mut owner_inode.blocks {
                                    if *b == last_block_idx {
                                        *b = free_block_idx;
                                        break;
                                    }
                                }
                                self.block_owner.remove(&last_block_idx);
                                self.block_owner.insert(free_block_idx, owner_ino);
                            }
                        }
                    }
                }
                self.disk_size_blocks -= 1;
            }
        }
    }

    pub fn sync_disk(&mut self) -> i32 {
        if self.read_only {
            return 0;
        }
        if let Err(e) = self.disk.resize(self.disk_size_blocks as u64) {
            error!("Resize failed: {}", e);
            return EIO;
        }
        if let Err(e) = self.save_metadata() {
            error!("Metadata save failed: {}", e);
            return EIO;
        }
        if let Err(e) = self.disk.sync() {
            error!("Disk sync failed: {}", e);
            return EIO;
        }
        0
    }
}

// FUSE Adapter Layer (Feature Gated)
#[cfg(feature = "fuse")]
impl Filesystem for MirageFS {
    fn destroy(&mut self) { let _ = self.sync_disk(); }
    fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if self.sync_disk() == 0 { reply.ok(); } else { reply.error(EIO); }
    }
    fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        if self.sync_disk() == 0 { reply.ok(); } else { reply.error(EIO); }
    }
    fn create(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, _u: u32, _f: i32, reply: ReplyCreate) {
        let name_str = name.to_str().unwrap();
        match self.create_file_internal(parent, name_str) {
            Ok(ino) => {
                let attr: FileAttr = (&self.inodes[&ino].attr).into();
                reply.created(&TTL, &attr, 0, 0, 0)
            },
            Err(e) => reply.error(e),
        }
    }
    fn mkdir(&mut self, _req: &Request, parent: u64, name: &OsStr, _mode: u32, _u: u32, reply: ReplyEntry) {
        let name_str = name.to_str().unwrap();
        match self.mkdir_internal(parent, name_str) {
            Ok(ino) => {
                let attr: FileAttr = (&self.inodes[&ino].attr).into();
                reply.entry(&TTL, &attr, 0)
            },
            Err(e) => reply.error(e),
        }
    }
    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = name.to_str().unwrap();
        match self.rmdir_internal(parent, name_str) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.unlink_internal(parent, name.to_str().unwrap()) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn rename(&mut self, _req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
        let name_str = name.to_str().unwrap();
        let newname_str = newname.to_str().unwrap();
        match self.rename_internal(parent, name_str, newparent, newname_str) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn setattr(&mut self, _req: &Request, _ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, _size: Option<u64>, _a: Option<TimeOrNow>, _m: Option<TimeOrNow>, _c: Option<SystemTime>, _fh: Option<u64>, _cr: Option<SystemTime>, _ch: Option<SystemTime>, _bk: Option<SystemTime>, _fl: Option<u32>, reply: ReplyAttr) {
        // Simple SetAttr placeholder
        reply.error(EACCES);
    }
    fn write(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, data: &[u8], _w: u32, _f: i32, _l: Option<u64>, reply: ReplyWrite) {
        match self.write_data_internal(ino, offset as u64, data) {
            Ok(bytes) => reply.written(bytes as u32),
            Err(e) => reply.error(e),
        }
    }
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_str().unwrap();
        if let Some(children) = self.directory_map.get(&parent) {
            if let Some(&ino) = children.get(name_str) {
                if let Some(inode) = self.inodes.get(&ino) {
                    let attr: FileAttr = (&inode.attr).into();
                    reply.entry(&TTL, &attr, 0);
                    return;
                }
            }
        }
        reply.error(ENOENT);
    }
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.inodes.get(&ino) {
            Some(inode) => {
                let attr: FileAttr = (&inode.attr).into();
                reply.attr(&TTL, &attr)
            },
            None => reply.error(ENOENT),
        }
    }
    fn read(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, size: u32, _fl: i32, _l: Option<u64>, reply: ReplyData) {
        match self.read_data_internal(ino, offset as u64, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e),
        }
    }
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        if offset > 0 { reply.ok(); return; }
        let _ = reply.add(ino, 1, FileType::Directory, ".");
        let _ = reply.add(ino, 2, FileType::Directory, "..");
        let entries = self.readdir_internal(ino);
        for (i, (child_ino, name, kind)) in entries.iter().enumerate() {
            let fuse_kind = match kind {
                MirageFileType::Directory => FileType::Directory,
                MirageFileType::RegularFile => FileType::RegularFile,
            };
            let _ = reply.add(*child_ino, (i+3) as i64, fuse_kind, name);
        }
        reply.ok();
    }
}

// Helper to convert internal attrs to FUSE attrs
#[cfg(feature = "fuse")]
impl From<&SerializedFileAttr> for FileAttr {
    fn from(s: &SerializedFileAttr) -> Self {
        let kind = match s.kind {
            MirageFileType::Directory => FileType::Directory,
            MirageFileType::RegularFile => FileType::RegularFile,
        };
        FileAttr {
            ino: s.ino, size: s.size, blocks: s.blocks,
            atime: UNIX_EPOCH + Duration::from_secs(s.mtime_secs),
            mtime: UNIX_EPOCH + Duration::from_secs(s.mtime_secs),
            ctime: UNIX_EPOCH + Duration::from_secs(s.mtime_secs),
            crtime: UNIX_EPOCH + Duration::from_secs(s.mtime_secs),
            kind, perm: s.perm, nlink: s.nlink, uid: s.uid, gid: s.gid,
            rdev: 0, flags: 0, blksize: 512,
        }
    }
}

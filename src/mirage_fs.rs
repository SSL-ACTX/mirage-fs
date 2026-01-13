// src/mirage_fs.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyWrite, ReplyEmpty, Request, TimeOrNow,
};
use libc::{EIO, ENOENT};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::Write;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;

const TTL: Duration = Duration::from_secs(1);
const METADATA_BLOCKS: u32 = 2;
const SUPERBLOCK_ID: u32 = 0;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SerializedFileAttr {
    ino: u64, size: u64, blocks: u64, kind_is_dir: bool,
    perm: u16, nlink: u32, uid: u32, gid: u32, mtime_secs: u64,
}

impl From<&FileAttr> for SerializedFileAttr {
    fn from(attr: &FileAttr) -> Self {
        Self {
            ino: attr.ino, size: attr.size, blocks: attr.blocks,
            kind_is_dir: attr.kind == FileType::Directory,
            perm: attr.perm, nlink: attr.nlink, uid: attr.uid, gid: attr.gid,
            mtime_secs: attr.mtime.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        }
    }
}

impl Into<FileAttr> for SerializedFileAttr {
    fn into(self) -> FileAttr {
        FileAttr {
            ino: self.ino, size: self.size, blocks: self.blocks,
            atime: UNIX_EPOCH + Duration::from_secs(self.mtime_secs),
            mtime: UNIX_EPOCH + Duration::from_secs(self.mtime_secs),
            ctime: UNIX_EPOCH + Duration::from_secs(self.mtime_secs),
            crtime: UNIX_EPOCH + Duration::from_secs(self.mtime_secs),
            kind: if self.kind_is_dir { FileType::Directory } else { FileType::RegularFile },
            perm: self.perm, nlink: self.nlink, uid: self.uid, gid: self.gid,
            rdev: 0, flags: 0, blksize: 512,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Inode {
    attr: SerializedFileAttr,
    // Scatter-gather list of physical block indices
    blocks: Vec<u32>
}

#[derive(Serialize, Deserialize)]
struct Superblock {
    inodes: HashMap<u64, Inode>,
    directory_map: HashMap<u64, HashMap<String, u64>>,
    next_inode: u64,
    // High-water mark for disk usage
    disk_size_blocks: u32,
    // Reverse map for compaction: Physical Block -> Owner Inode
    block_owner: HashMap<u32, u64>,
}

pub struct MirageFS {
    disk: Box<dyn BlockDevice>,
    inodes: HashMap<u64, Inode>,
    directory_map: HashMap<u64, HashMap<String, u64>>,
    next_inode: u64,
    disk_size_blocks: u32,
    block_owner: HashMap<u32, u64>,
    uid: u32,
    gid: u32,
}

impl MirageFS {
    pub fn new(disk: Box<dyn BlockDevice>, format: bool, uid: u32, gid: u32) -> anyhow::Result<Self> {
        let load_result = Self::load_metadata(&disk);

        if let Ok(sb) = load_result {
            println!("Superblock Loaded! {} inodes found.", sb.inodes.len());

            if !format {
                let mut fs = MirageFS {
                    disk,
                    inodes: sb.inodes, directory_map: sb.directory_map,
                    next_inode: sb.next_inode,
                    disk_size_blocks: sb.disk_size_blocks,
                    block_owner: sb.block_owner,
                    uid, gid
                };
                // Fix permissions for current user context
                for inode in fs.inodes.values_mut() {
                    inode.attr.uid = uid;
                    inode.attr.gid = gid;
                }
                return Ok(fs);
            }
        }

        // Initialize empty filesystem
        let mut fs = MirageFS {
            disk,
            inodes: HashMap::new(), directory_map: HashMap::new(),
            next_inode: 2,
            disk_size_blocks: METADATA_BLOCKS,
            block_owner: HashMap::new(),
            uid, gid
        };

        // Create Root Directory
        let root_attr = FileAttr {
            ino: 1, size: 0, blocks: 0,
            atime: SystemTime::now(), mtime: SystemTime::now(), ctime: SystemTime::now(), crtime: SystemTime::now(),
            kind: FileType::Directory, perm: 0o755, nlink: 2,
            uid, gid,
            rdev: 0, flags: 0, blksize: 512,
        };
        fs.inodes.insert(1, Inode { attr: (&root_attr).into(), blocks: Vec::new() });
        fs.directory_map.insert(1, HashMap::new());

        fs.save_metadata()?;
        fs.disk.sync()?;
        Ok(fs)
    }

    fn load_metadata(disk: &Box<dyn BlockDevice>) -> anyhow::Result<Superblock> {
        let mut raw_data = Vec::new();
        for i in 0..METADATA_BLOCKS {
            let block = disk.read_block(SUPERBLOCK_ID + i).map_err(|e| anyhow::anyhow!(e))?;
            raw_data.extend_from_slice(&block);
        }

        if raw_data.iter().all(|&x| x == 0) { return Err(anyhow::anyhow!("Empty")); }

        let mut decoder = ZlibDecoder::new(&raw_data[..]);
        let mut decompressed_data = Vec::new();
        if std::io::Read::read_to_end(&mut decoder, &mut decompressed_data).is_err() {
            return Err(anyhow::anyhow!("Decompression failed"));
        }

        let sb: Superblock = bincode::deserialize(&decompressed_data)?;
        Ok(sb)
    }

    fn save_metadata(&mut self) -> anyhow::Result<()> {
        let sb = Superblock {
            inodes: self.inodes.clone(), directory_map: self.directory_map.clone(),
            next_inode: self.next_inode,
            disk_size_blocks: self.disk_size_blocks,
            block_owner: self.block_owner.clone(),
        };

        let data = bincode::serialize(&sb)?;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&data)?;
        let compressed_data = encoder.finish()?;

        let chunks = compressed_data.chunks(BLOCK_SIZE);
        if chunks.len() > METADATA_BLOCKS as usize {
            eprintln!("CRITICAL: Metadata overflow!");
        }

        let mut blocks_written = 0;
        for (i, chunk) in chunks.enumerate() {
            let mut block = [0u8; BLOCK_SIZE];
            block[0..chunk.len()].copy_from_slice(chunk);
            self.disk.write_block(SUPERBLOCK_ID + i as u32, &block).map_err(|e| anyhow::anyhow!(e))?;
            blocks_written += 1;
        }

        // Zero out remaining metadata blocks
        let zero_block = [0u8; BLOCK_SIZE];
        for i in blocks_written..METADATA_BLOCKS as usize {
            self.disk.write_block(SUPERBLOCK_ID + i as u32, &zero_block).map_err(|e| anyhow::anyhow!(e))?;
        }

        Ok(())
    }

    fn allocate_inode(&mut self, kind: FileType, perm: u16) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        let attr = FileAttr {
            ino, size: 0, blocks: 0, atime: SystemTime::now(), mtime: SystemTime::now(),
            ctime: SystemTime::now(), crtime: SystemTime::now(), kind, perm, nlink: 1,
            uid: self.uid, gid: self.gid,
            rdev: 0, flags: 0, blksize: 512,
        };
        self.inodes.insert(ino, Inode { attr: (&attr).into(), blocks: Vec::new() });
        ino
    }

    fn sync_disk(&mut self) -> i32 {
        if let Err(_) = self.disk.resize(self.disk_size_blocks as u64) { return EIO; }
        if let Err(_) = self.save_metadata() { return EIO; }
        if let Err(_) = self.disk.sync() { return EIO; }
        0
    }
}

impl Filesystem for MirageFS {
    fn destroy(&mut self) {
        let _ = self.sync_disk();
    }

    fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        if self.sync_disk() == 0 { reply.ok(); } else { reply.error(EIO); }
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        if self.sync_disk() == 0 { reply.ok(); } else { reply.error(EIO); }
    }

    fn create(&mut self, _req: &Request, parent: u64, name: &OsStr, mode: u32, _u: u32, _f: i32, reply: ReplyCreate) {
        let name_str = name.to_str().unwrap().to_string();
        let new_ino = self.allocate_inode(FileType::RegularFile, mode as u16);
        self.directory_map.entry(parent).or_default().insert(name_str, new_ino);

        let _ = self.sync_disk();

        if let Some(inode) = self.inodes.get(&new_ino) {
            reply.created(&TTL, &inode.attr.clone().into(), 0, 0, 0);
        } else { reply.error(EIO); }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = name.to_str().unwrap().to_string();

        let ino_to_remove = if let Some(children) = self.directory_map.get_mut(&parent) {
            children.remove(&name_str)
        } else {
            None
        };

        if let Some(ino) = ino_to_remove {
            if let Some(inode) = self.inodes.remove(&ino) {
                // COMPACTION: Swap-and-Pop to free blocks
                for &free_block_idx in &inode.blocks {
                    self.block_owner.remove(&free_block_idx);

                    let last_block_idx = self.disk_size_blocks - 1;

                    if free_block_idx == last_block_idx {
                        self.disk_size_blocks -= 1;
                    } else {
                        // Move data from end of disk to the hole we just created
                        if let Ok(data) = self.disk.read_block(last_block_idx) {
                            if self.disk.write_block(free_block_idx, &data).is_ok() {
                                // Update the owner of the moved block
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

            if self.sync_disk() == 0 { reply.ok(); } else { reply.error(EIO); }
        } else {
            reply.error(ENOENT);
        }
    }

    fn setattr(&mut self, _req: &Request, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, size: Option<u64>, _a: Option<TimeOrNow>, _m: Option<TimeOrNow>, _c: Option<SystemTime>, _fh: Option<u64>, _cr: Option<SystemTime>, _ch: Option<SystemTime>, _bk: Option<SystemTime>, _fl: Option<u32>, reply: ReplyAttr) {
        let attr_to_reply = if let Some(inode) = self.inodes.get_mut(&ino) {
            if let Some(m) = mode { inode.attr.perm = m as u16; }
            if let Some(u) = uid { inode.attr.uid = u; }
            if let Some(g) = gid { inode.attr.gid = g; }
            if let Some(s) = size { inode.attr.size = s; }

            Some(inode.attr.clone())
        } else {
            None
        };

        if let Some(attr) = attr_to_reply {
            let _ = self.sync_disk();
            reply.attr(&TTL, &attr.into());
        } else {
            reply.error(ENOENT);
        }
    }

    fn write(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, data: &[u8], _w: u32, _f: i32, _l: Option<u64>, reply: ReplyWrite) {
        if let Some(inode) = self.inodes.get_mut(&ino) {
            let mut total_written: usize = 0;
            let mut current_offset = offset as usize;

            // Loop required to handle writes spanning multiple blocks (RAID/Striping fix)
            while total_written < data.len() {
                let relative_block = current_offset / BLOCK_SIZE;
                let block_offset = current_offset % BLOCK_SIZE;

                // Dynamically allocate new blocks if writing beyond current EOF
                while inode.blocks.len() <= relative_block {
                    let new_block_idx = self.disk_size_blocks;
                    self.disk_size_blocks += 1;
                    inode.blocks.push(new_block_idx);
                    self.block_owner.insert(new_block_idx, ino);
                }

                let abs_block_idx = inode.blocks[relative_block];

                // Determine how much data fits in the current block
                let remaining_data = data.len() - total_written;
                let space_in_block = BLOCK_SIZE - block_offset;
                let chunk_size = std::cmp::min(remaining_data, space_in_block);

                // Read-Modify-Write cycle
                let mut block_data = if block_offset == 0 && chunk_size == BLOCK_SIZE {
                    [0u8; BLOCK_SIZE] // Optimization: Full block overwrite
                } else {
                    match self.disk.read_block(abs_block_idx) {
                        Ok(data) => data,
                        Err(_) => [0u8; BLOCK_SIZE],
                    }
                };

                // Copy chunk into buffer
                let chunk_data = &data[total_written..total_written + chunk_size];
                block_data[block_offset..block_offset + chunk_size].copy_from_slice(chunk_data);

                // Commit block
                if let Err(_) = self.disk.write_block(abs_block_idx, &block_data) {
                    if total_written > 0 { break; } // Return partial success if possible
                    reply.error(EIO);
                    return;
                }

                total_written += chunk_size;
                current_offset += chunk_size;
            }

            let end_pos = (offset as u64) + (total_written as u64);
            if end_pos > inode.attr.size { inode.attr.size = end_pos; }
            inode.attr.blocks = inode.blocks.len() as u64;

            reply.written(total_written as u32);
        } else { reply.error(ENOENT); }
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_str().unwrap().to_string();
        if let Some(children) = self.directory_map.get(&parent) {
            if let Some(&ino) = children.get(&name_str) {
                if let Some(inode) = self.inodes.get(&ino) {
                    reply.entry(&TTL, &inode.attr.clone().into(), 0);
                    return;
                }
            }
        }
        reply.error(ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.inodes.get(&ino) {
            Some(inode) => reply.attr(&TTL, &inode.attr.clone().into()),
            None => reply.error(ENOENT),
        }
    }

    fn read(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, size: u32, _fl: i32, _l: Option<u64>, reply: ReplyData) {
        if let Some(inode) = self.inodes.get(&ino) {
            let mut collected_data = Vec::with_capacity(size as usize);
            let mut current_offset = offset as usize;
            let mut remaining_size = size as usize;

            // Loop to aggregate data from multiple scattered blocks
            while remaining_size > 0 {
                let relative_block = current_offset / BLOCK_SIZE;
                let block_offset = current_offset % BLOCK_SIZE;

                if relative_block >= inode.blocks.len() {
                    break; // EOF reached
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
                        if collected_data.is_empty() {
                            reply.error(EIO);
                            return;
                        }
                        break;
                    }
                }
            }

            reply.data(&collected_data);
        } else { reply.error(ENOENT); }
    }

    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, mut reply: ReplyDirectory) {
        if offset > 0 { reply.ok(); return; }
        let _ = reply.add(ino, 1, FileType::Directory, ".");
        let _ = reply.add(ino, 2, FileType::Directory, "..");
        if let Some(children) = self.directory_map.get(&ino) {
            let mut i = 3;
            for (name, child_ino) in children {
                if let Some(child_inode) = self.inodes.get(child_ino) {
                    let kind = if child_inode.attr.kind_is_dir { FileType::Directory } else { FileType::RegularFile };
                    let _ = reply.add(*child_ino, i, kind, name);
                    i += 1;
                }
            }
        }
        reply.ok();
    }
}

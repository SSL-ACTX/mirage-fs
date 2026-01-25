// src/mp4_disk.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use std::io::{self, Result, Read, Write, Seek, SeekFrom};
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use filetime::{FileTime, set_file_times};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use rand::{RngCore, thread_rng};
use log::{info, debug, warn};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

// ISO BMFF Constants
const ATOM_MDAT: [u8; 4] = *b"mdat";

// H.264 NAL Unit Constants
// NAL Prefix: 00 00 00 01
const NAL_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
// NAL Header for "Filler Data" (Type 12). Ref_Idc=0.
const NAL_FILLER_TYPE: u8 = 0x0C;

// NAL Overhead: Prefix (4) + Header (1)
const NAL_OVERHEAD: usize = 5;
// Total size of one storage unit on disk
const NAL_PACKET_SIZE: usize = NAL_OVERHEAD + ENCRYPTED_BLOCK_SIZE;

const SALT_SIZE: usize = 16;
// Magic signature to identify OUR mdat vs real video mdats
const MIRAGE_MAGIC: &[u8; 8] = b"MRG_AVC1";

pub struct Mp4Disk {
    #[allow(dead_code)]
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    file: File,
    data_start_offset: u64,
    data_length: u64,
    atime: FileTime,
    mtime: FileTime,
}

impl Mp4Disk {
    pub fn new(path: PathBuf, password: &str, format: bool) -> io::Result<Self> {
        let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)?;

        let meta = file.metadata()?;
        let atime = FileTime::from_last_access_time(&meta);
        let mtime = FileTime::from_last_modification_time(&meta);

        // 1. Scan Atoms
        let (mdat_offset, mdat_size, exists) = Self::scan_for_mirage_mdat(&mut file)?;

        let (data_start, current_payload_len) = if format {
            info!("MP4: Formatting... Injecting Shadow Media Atom (H.264 NAL Camouflage)");

            let write_pos = if exists { mdat_offset } else { file.seek(SeekFrom::End(0))? };

            let mut salt = [0u8; SALT_SIZE];
            thread_rng().fill_bytes(&mut salt);

            let initial_payload_size = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
            let atom_size = 8 + initial_payload_size as u64;

            file.seek(SeekFrom::Start(write_pos))?;
            file.write_all(&u32::to_be_bytes(atom_size as u32))?;
            file.write_all(&ATOM_MDAT)?;

            Self::write_nal_unit(&mut file, NAL_FILLER_TYPE, |w: &mut File| {
                w.write_all(MIRAGE_MAGIC)?;
                w.write_all(&salt)
            })?;

            (write_pos + 8, initial_payload_size as u64)
        } else {
            if !exists {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "No MirageFS (Shadow mdat) found in MP4."));
            }
            (mdat_offset + 8, mdat_size - 8)
        };

        // 2. Read Salt
        file.seek(SeekFrom::Start(data_start))?;
        let mut first_nal = vec![0u8; NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE];
        file.read_exact(&mut first_nal)?;

        // Verify NAL structure
        if first_nal[0..4] != NAL_PREFIX || first_nal[4] != NAL_FILLER_TYPE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Corrupt NAL encapsulation."));
        }

        let payload_start = NAL_OVERHEAD;
        if &first_nal[payload_start..payload_start+8] != MIRAGE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Magic in Shadow mdat."));
        }

        let salt = &first_nal[payload_start+8..payload_start+8+SALT_SIZE];

        // 3. Crypto Setup
        debug!("MP4: Deriving keys from video stream headers...");
        let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let hash_output = password_hash.hash.ok_or(io::Error::new(io::ErrorKind::Other, "Hash failed"))?;
        let mut key_buffer = [0u8; 32];
        key_buffer.copy_from_slice(&hash_output.as_bytes()[0..32]);

        let key = Key::from_slice(&key_buffer);
        let cipher = ChaCha20Poly1305::new(key);

        let disk = Mp4Disk {
            path,
            cipher,
            file,
            data_start_offset: data_start,
            data_length: current_payload_len,
            atime,
            mtime,
        };

        disk.restore_times()?;
        Ok(disk)
    }

    fn restore_times(&self) -> io::Result<()> {
        set_file_times(&self.path, self.atime, self.mtime)
    }

    fn scan_for_mirage_mdat(file: &mut File) -> io::Result<(u64, u64, bool)> {
        let len = file.seek(SeekFrom::End(0))?;
        let mut pos = 0;

        while pos < len {
            file.seek(SeekFrom::Start(pos))?;
            let mut header = [0u8; 8];
            if file.read_exact(&mut header).is_err() { break; }

            let mut size = u32::from_be_bytes(header[0..4].try_into().unwrap()) as u64;
            let type_bytes = &header[4..8];

            if size == 1 {
                let mut ext_size = [0u8; 8];
                file.read_exact(&mut ext_size)?;
                size = u64::from_be_bytes(ext_size);
            } else if size == 0 {
                size = len - pos;
            }

            if type_bytes == &ATOM_MDAT {
                let header_len = if size > 0xFFFFFFFF { 16 } else { 8 };
                let mut peek_buf = vec![0u8; NAL_OVERHEAD + MIRAGE_MAGIC.len()];
                if file.seek(SeekFrom::Start(pos + header_len)).is_ok()
                    && file.read_exact(&mut peek_buf).is_ok()
                    {
                        if peek_buf[0..4] == NAL_PREFIX
                            && peek_buf[4] == NAL_FILLER_TYPE
                            && &peek_buf[5..5+MIRAGE_MAGIC.len()] == MIRAGE_MAGIC
                            {
                                info!("Found MirageFS Shadow mdat at offset {}", pos);
                                return Ok((pos, size, true));
                            }
                    }
            }
            pos += size;
        }
        Ok((0, 0, false))
    }

    fn write_nal_unit<F>(file: &mut File, nal_type: u8, write_payload: F) -> io::Result<()>
    where F: FnOnce(&mut File) -> io::Result<()>
    {
        file.write_all(&NAL_PREFIX)?;
        file.write_all(&[nal_type])?;
        write_payload(file)
    }

    fn update_atom_size(&mut self) -> io::Result<()> {
        let atom_pos = self.data_start_offset - 8;
        let total_size = self.data_length + 8;

        self.file.seek(SeekFrom::Start(atom_pos))?;
        if total_size > u32::MAX as u64 {
            // In the future,we would shift data to insert a 64-bit header.
            // Tho for now, we respect the limit or risk corruption. :P
            return Err(io::Error::new(io::ErrorKind::FileTooLarge, "MP4 mdat > 4GB"));
        }
        self.file.write_all(&u32::to_be_bytes(total_size as u32))?;
        Ok(())
    }
}

impl BlockDevice for Mp4Disk {
    fn is_expandable(&self) -> bool { true }

    fn block_count(&self) -> u64 {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        if self.data_length <= header_nal_len as u64 { return 0; }
        (self.data_length - header_nal_len as u64) / NAL_PACKET_SIZE as u64
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        let offset = self.data_start_offset + header_nal_len as u64 + (index as u64 * NAL_PACKET_SIZE as u64);

        if offset + NAL_PACKET_SIZE as u64 > self.data_start_offset + self.data_length {
            return Ok([0u8; BLOCK_SIZE]);
        }

        let mut packet = [0u8; NAL_PACKET_SIZE];
        let mut temp_file = self.file.try_clone()?;
        temp_file.seek(SeekFrom::Start(offset))?;
        temp_file.read_exact(&mut packet)?;

        if packet[0..4] != NAL_PREFIX || packet[4] != NAL_FILLER_TYPE {
            warn!("MP4: Bad NAL wrapper at block {}", index);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Stream Synchronization Lost"));
        }

        let encrypted_data = &packet[NAL_OVERHEAD..];
        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        let ciphertext = &encrypted_data[12..];

        match self.cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
            Ok(plaintext) => {
                let mut buffer = [0u8; BLOCK_SIZE];
                buffer.copy_from_slice(&plaintext);
                Ok(buffer)
            }
            Err(_) => {
                warn!("MP4: Decrypt failed at block {}", index);
                Err(io::Error::new(io::ErrorKind::PermissionDenied, "Auth Tag Mismatch"))
            },
        }
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        let offset = self.data_start_offset + header_nal_len as u64 + (index as u64 * NAL_PACKET_SIZE as u64);

        let end_need = offset + NAL_PACKET_SIZE as u64;
        let current_end = self.data_start_offset + self.data_length;

        if end_need > current_end {
            self.file.seek(SeekFrom::Start(current_end))?;
            let gap = end_need - current_end;
            let zeros = vec![0u8; gap as usize];
            self.file.write_all(&zeros)?;
            self.data_length = end_need - self.data_start_offset;
            self.update_atom_size()?;
        }

        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, Payload { msg: data, aad: &[] })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        self.file.seek(SeekFrom::Start(offset))?;

        Self::write_nal_unit(&mut self.file, NAL_FILLER_TYPE, |w: &mut File| {
            w.write_all(&nonce_bytes)?;
            w.write_all(&ciphertext)
        })?;

        self.restore_times()
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        let header_nal_len = NAL_OVERHEAD + MIRAGE_MAGIC.len() + SALT_SIZE;
        let new_len = header_nal_len as u64 + (block_count * NAL_PACKET_SIZE as u64);

        // Safety: Do not shrink below the header (Magic/Salt)
        if new_len < header_nal_len as u64 {
            return Ok(());
        }

        // Handles both Expansion AND Truncation (Auto-Shrink)
        if new_len != self.data_length {
            self.file.set_len(self.data_start_offset + new_len)?;
            self.data_length = new_len;
            self.update_atom_size()?;
        }
        self.restore_times()
    }

    fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        self.restore_times()
    }
}

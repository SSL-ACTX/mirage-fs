// src/mp3_disk.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use filetime::{set_file_times, FileTime};
use log::{info, warn};
use rand::{thread_rng, RngCore};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Result, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// MP3 MirageFS Carrier
///
/// Uses ID3v2 APIC frame for storage with Base128 (Sync-Safe) encoding
/// to prevent audio glitches.
pub struct Mp3Disk {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    file: File,
    atime: FileTime,
    mtime: FileTime,

    // Offset to the start of the RAW encrypted data (Base128 encoded) inside the APIC frame
    data_start_offset: u64,
    // Length of the Base128 encoded storage
    encoded_storage_len: u64,
    // Original audio size (used for quota)
    audio_size: u64,
}

const SALT_SIZE: usize = 16;
const APIC_FRAME_ID: &[u8; 4] = b"APIC";
const MAX_QUOTA_RATIO: u64 = 4;

// Fake JPEG header to camouflage entropy in APIC
const FAKE_JPEG_HEADER: &[u8] =
    b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";

impl Mp3Disk {
    pub fn new(path: PathBuf, password: &str, format: bool) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        let meta = file.metadata()?;
        let atime = FileTime::from_last_access_time(&meta);
        let mtime = FileTime::from_last_modification_time(&meta);

        let mut id3_header = [0u8; 10];
        if file.read_exact(&mut id3_header).is_err() || &id3_header[0..3] != b"ID3" {
            if !format {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "No ID3v2 tag found at start of MP3.",
                ));
            }
        }

        if format {
            info!("MP3: Formatting... Injecting APIC frame with Sync-Safe camouflage.");
            return Self::format_mp3(path, password, atime, mtime);
        }

        // Parse ID3v2 size
        let id3_size = Self::parse_syncsafe_u32(&id3_header[6..10]) as u64;
        let audio_size = meta.len().saturating_sub(10 + id3_size);

        // Scan for APIC frame
        let mut pos = 10u64;
        let mut apic_found = false;
        let mut apic_header_offset = 0u64;
        let mut apic_payload_size = 0u64;

        while pos < id3_size + 10 {
            file.seek(SeekFrom::Start(pos))?;
            let mut frame_header = [0u8; 10];
            if file.read_exact(&mut frame_header).is_err() {
                break;
            }

            let frame_id = &frame_header[0..4];
            let frame_size = u32::from_be_bytes(frame_header[4..8].try_into().unwrap()) as u64;

            if frame_id == APIC_FRAME_ID {
                apic_found = true;
                apic_header_offset = pos;
                apic_payload_size = frame_size;
                break;
            }

            if frame_id == [0, 0, 0, 0] {
                break;
            } // Padding
            pos += 10 + frame_size;
        }

        if !apic_found {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No MirageFS data found in MP3 (Missing APIC).",
            ));
        }

        // Inside APIC: MIME type (null-term), Picture type (1 byte), Description (null-term), Data
        file.seek(SeekFrom::Start(apic_header_offset + 10))?;
        let mut apic_preamble = vec![0u8; 256];
        let bytes_read = file.read(&mut apic_preamble)?;
        apic_preamble.truncate(bytes_read);

        let mut offset = 0;
        // Skip MIME (e.g. "image/jpeg\0")
        while offset < apic_preamble.len() && apic_preamble[offset] != 0 {
            offset += 1;
        }
        offset += 1; // skip null
        if offset >= apic_preamble.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid APIC preamble.",
            ));
        }
        offset += 1; // skip picture type
                     // Skip Description
        while offset < apic_preamble.len() && apic_preamble[offset] != 0 {
            offset += 1;
        }
        offset += 1; // skip null

        if offset + FAKE_JPEG_HEADER.len() > apic_preamble.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "APIC preamble too short for fake header.",
            ));
        }
        // Skip FAKE_JPEG_HEADER
        offset += FAKE_JPEG_HEADER.len();

        let data_start_offset = apic_header_offset + 10 + offset as u64;
        let encoded_storage_len = apic_payload_size - offset as u64;

        // Read Salt
        let salt_encoded_len = (SALT_SIZE * 8 + 6) / 7;
        file.seek(SeekFrom::Start(data_start_offset))?;
        let mut encoded_salt = vec![0u8; salt_encoded_len];
        file.read_exact(&mut encoded_salt)?;
        let decoded_salt = Self::concentrate_entropy(&encoded_salt);
        let salt = &decoded_salt[0..SALT_SIZE];

        // Crypto Setup
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let hash_output = password_hash
            .hash
            .ok_or(io::Error::new(io::ErrorKind::Other, "Hash failed"))?;
        let mut key_buffer = [0u8; 32];
        key_buffer.copy_from_slice(&hash_output.as_bytes()[0..32]);

        let key = Key::from_slice(&key_buffer);
        let cipher = ChaCha20Poly1305::new(key);

        Ok(Mp3Disk {
            path,
            cipher,
            file,
            atime,
            mtime,
            data_start_offset,
            encoded_storage_len,
            audio_size,
        })
    }

    fn format_mp3(
        path: PathBuf,
        password: &str,
        atime: FileTime,
        mtime: FileTime,
    ) -> io::Result<Self> {
        let original_data = std::fs::read(&path)?;
        let mut start_offset = 0;
        if original_data.starts_with(b"ID3") {
            let size = Self::parse_syncsafe_u32(&original_data[6..10]);
            start_offset = 10 + size as usize;
        }
        let audio_data = &original_data[start_offset..];

        let mut salt = [0u8; SALT_SIZE];
        thread_rng().fill_bytes(&mut salt);
        let encoded_salt = Self::dilute_entropy(&salt);

        let mut apic_payload = Vec::new();
        apic_payload.extend_from_slice(b"image/jpeg\0");
        apic_payload.push(0x03);
        apic_payload.extend_from_slice(b"Album Cover\0");
        apic_payload.extend_from_slice(FAKE_JPEG_HEADER);
        apic_payload.extend_from_slice(&encoded_salt);

        let apic_frame_size = apic_payload.len() as u32;
        let mut apic_frame = Vec::new();
        apic_frame.extend_from_slice(APIC_FRAME_ID);
        apic_frame.extend_from_slice(&apic_frame_size.to_be_bytes());
        apic_frame.extend_from_slice(&[0, 0]);
        apic_frame.extend_from_slice(&apic_payload);

        let id3_payload_size = apic_frame.len() as u32;
        let mut id3_tag = Vec::new();
        id3_tag.extend_from_slice(b"ID3\x03\x00\x00");
        id3_tag.extend_from_slice(&Self::encode_syncsafe_u32(id3_payload_size));
        id3_tag.extend_from_slice(&apic_frame);

        let mut new_file_data = Vec::new();
        new_file_data.extend_from_slice(&id3_tag);
        new_file_data.extend_from_slice(audio_data);

        // Spoof VBR Header if present to lock duration
        Self::spoof_vbr_header(&mut new_file_data, (10 + id3_payload_size) as usize);

        std::fs::write(&path, new_file_data)?;
        set_file_times(&path, atime, mtime)?;

        Self::new(path, password, false)
    }

    fn spoof_vbr_header(data: &mut [u8], audio_start: usize) {
        // Search for Xing/Info header in the first few MPEG frames
        let search_limit = std::cmp::min(data.len(), audio_start + 4096);
        for i in audio_start..search_limit.saturating_sub(10) {
            if (&data[i..i + 4] == b"Xing") || (&data[i..i + 4] == b"Info") {
                info!("MP3: Found VBR header at offset {}. Locking duration...", i);
                // Xing/Info header structure:
                // ID (4) | Flags (4) | Frames (4, optional) | Bytes (4, optional) | ...
                let flags = u32::from_be_bytes(data[i + 4..i + 8].try_into().unwrap());
                let mut offset = i + 8;
                if flags & 0x01 != 0 {
                    // Frames field present
                    offset += 4;
                }
                if flags & 0x02 != 0 {
                    // Bytes field present
                    let original_audio_size = (data.len() - audio_start) as u32;
                    data[offset..offset + 4].copy_from_slice(&original_audio_size.to_be_bytes());
                }
                break;
            }
        }
    }

    fn parse_syncsafe_u32(bytes: &[u8]) -> u32 {
        ((bytes[0] as u32) << 21)
            | ((bytes[1] as u32) << 14)
            | ((bytes[2] as u32) << 7)
            | (bytes[3] as u32)
    }

    fn encode_syncsafe_u32(size: u32) -> [u8; 4] {
        [
            ((size >> 21) & 0x7F) as u8,
            ((size >> 14) & 0x7F) as u8,
            ((size >> 7) & 0x7F) as u8,
            (size & 0x7F) as u8,
        ]
    }

    fn dilute_entropy(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity((input.len() * 8 + 6) / 7);
        let mut bit_buffer: u64 = 0;
        let mut bit_count = 0;

        for &byte in input {
            bit_buffer = (bit_buffer << 8) | (byte as u64);
            bit_count += 8;

            while bit_count >= 7 {
                bit_count -= 7;
                let val = (bit_buffer >> bit_count) & 0x7F;
                output.push(val as u8);
            }
        }

        if bit_count > 0 {
            let val = (bit_buffer << (7 - bit_count)) & 0x7F;
            output.push(val as u8);
        }
        output
    }

    fn concentrate_entropy(input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity((input.len() * 7) / 8);
        let mut bit_buffer: u64 = 0;
        let mut bit_count = 0;

        for &byte in input {
            bit_buffer = (bit_buffer << 7) | ((byte & 0x7F) as u64);
            bit_count += 7;

            while bit_count >= 8 {
                bit_count -= 8;
                let val = (bit_buffer >> bit_count) & 0xFF;
                output.push(val as u8);
            }
        }
        output
    }

    fn restore_times(&self) -> io::Result<()> {
        set_file_times(&self.path, self.atime, self.mtime)
    }
}

impl BlockDevice for Mp3Disk {
    fn is_expandable(&self) -> bool {
        true
    }

    fn block_count(&self) -> u64 {
        let encoded_block_size = (ENCRYPTED_BLOCK_SIZE * 8 + 6) / 7;
        let salt_encoded_len = (SALT_SIZE * 8 + 6) / 7;
        if self.encoded_storage_len <= salt_encoded_len as u64 {
            return 0;
        }
        (self.encoded_storage_len - salt_encoded_len as u64) / encoded_block_size as u64
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let encoded_block_size = (ENCRYPTED_BLOCK_SIZE * 8 + 6) / 7;
        let salt_encoded_len = (SALT_SIZE * 8 + 6) / 7;
        let offset = self.data_start_offset
            + salt_encoded_len as u64
            + (index as u64 * encoded_block_size as u64);

        if offset + encoded_block_size as u64 > self.data_start_offset + self.encoded_storage_len {
            return Ok([0u8; BLOCK_SIZE]);
        }

        let mut encoded_packet = vec![0u8; encoded_block_size];
        let mut temp_file = self.file.try_clone()?;
        temp_file.seek(SeekFrom::Start(offset))?;
        temp_file.read_exact(&mut encoded_packet)?;

        let packet = Self::concentrate_entropy(&encoded_packet);
        if packet.len() < ENCRYPTED_BLOCK_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Base128 decoding failed.",
            ));
        }

        let nonce = Nonce::from_slice(&packet[0..12]);
        let ciphertext = &packet[12..ENCRYPTED_BLOCK_SIZE];

        match self.cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        ) {
            Ok(plaintext) => {
                let mut buffer = [0u8; BLOCK_SIZE];
                buffer.copy_from_slice(&plaintext);
                Ok(buffer)
            }
            Err(_) => {
                warn!("MP3: Decrypt failed at block {}", index);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Auth Tag Mismatch",
                ))
            }
        }
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let encoded_block_size = (ENCRYPTED_BLOCK_SIZE * 8 + 6) / 7;
        let salt_encoded_len = (SALT_SIZE * 8 + 6) / 7;
        let offset = self.data_start_offset
            + salt_encoded_len as u64
            + (index as u64 * encoded_block_size as u64);

        if offset + encoded_block_size as u64 > self.data_start_offset + self.encoded_storage_len {
            self.resize((index + 1) as u64)?;
        }

        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &[],
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        let mut packet = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        let encoded_packet = Self::dilute_entropy(&packet);

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encoded_packet)?;
        self.restore_times()
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        let encoded_block_size = (ENCRYPTED_BLOCK_SIZE * 8 + 6) / 7;
        let salt_encoded_len = (SALT_SIZE * 8 + 6) / 7;
        let new_encoded_len = salt_encoded_len as u64 + (block_count * encoded_block_size as u64);

        if new_encoded_len == self.encoded_storage_len {
            return Ok(());
        }

        // Quota check: hidden data (concentrated) <= audio_size * MAX_QUOTA_RATIO
        let concentrated_size = (new_encoded_len * 7) / 8;
        if concentrated_size > self.audio_size * MAX_QUOTA_RATIO {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                format!(
                    "MP3 Quota Exceeded: Max hidden data is {} bytes",
                    self.audio_size * MAX_QUOTA_RATIO
                ),
            ));
        }

        let file_data = std::fs::read(&self.path)?;
        let id3_size = Self::parse_syncsafe_u32(&file_data[6..10]);
        let audio_data = file_data[10 + id3_size as usize..].to_vec();

        let mut pos = 10;
        while pos < 10 + id3_size as usize {
            let frame_id = &file_data[pos..pos + 4];
            let frame_size = u32::from_be_bytes(file_data[pos + 4..pos + 8].try_into().unwrap());
            if frame_id == APIC_FRAME_ID {
                let apic_preamble_len = (self.data_start_offset - (pos as u64 + 10)) as usize;
                let new_frame_size = apic_preamble_len as u32 + new_encoded_len as u32;

                let mut new_id3_payload = file_data[10..pos].to_vec();
                let mut apic_frame = APIC_FRAME_ID.to_vec();
                apic_frame.extend_from_slice(&new_frame_size.to_be_bytes());
                apic_frame.extend_from_slice(&file_data[pos + 8..pos + 10]);
                apic_frame.extend_from_slice(&file_data[pos + 10..pos + 10 + apic_preamble_len]);

                let mut encoded_data = vec![0u8; new_encoded_len as usize];
                let copy_len =
                    std::cmp::min(self.encoded_storage_len as usize, new_encoded_len as usize);
                encoded_data[..copy_len].copy_from_slice(
                    &file_data[self.data_start_offset as usize
                        ..self.data_start_offset as usize + copy_len],
                );
                apic_frame.extend_from_slice(&encoded_data);

                new_id3_payload.extend_from_slice(&apic_frame);
                new_id3_payload.extend_from_slice(
                    &file_data[pos + 10 + frame_size as usize..10 + id3_size as usize],
                );

                let new_id3_size = new_id3_payload.len() as u32;
                let mut new_file_data = b"ID3\x03\x00\x00".to_vec();
                new_file_data.extend_from_slice(&Self::encode_syncsafe_u32(new_id3_size));
                new_file_data.extend_from_slice(&new_id3_payload);
                new_file_data.extend_from_slice(&audio_data);

                std::fs::write(&self.path, new_file_data)?;
                self.file = OpenOptions::new().read(true).write(true).open(&self.path)?;
                self.encoded_storage_len = new_encoded_len;
                break;
            }
            pos += 10 + frame_size as usize;
        }
        self.restore_times()
    }

    fn sync(&mut self) -> Result<()> {
        self.file.sync_all()?;
        self.restore_times()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn create_mock_mp3(path: &std::path::Path) -> io::Result<()> {
        let mut file = File::create(path)?;
        // Minimal ID3v2 tag
        file.write_all(b"ID3\x03\x00\x00\x00\x00\x00\x00")?;
        // Minimal MPEG frame sync
        file.write_all(&[0xFF, 0xFB, 0x90, 0x44])?;
        // Some dummy audio data
        file.write_all(&vec![0u8; 2000])?;
        Ok(())
    }

    #[test]
    fn test_mp3_format_and_read_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.mp3");
        create_mock_mp3(&path).unwrap();

        let mut disk = Mp3Disk::new(path.clone(), "password", true).unwrap();
        assert_eq!(disk.block_count(), 0);

        let data = [0xAAu8; BLOCK_SIZE];
        disk.write_block(0, &data).unwrap();
        assert!(disk.block_count() >= 1);

        let read_data = disk.read_block(0).unwrap();
        assert_eq!(data, read_data);
    }
}

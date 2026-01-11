// src/jpeg_disk.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use std::io::{self, Result};
use std::path::PathBuf;
use std::fs::{self, OpenOptions};
use img_parts::jpeg::{Jpeg, JpegSegment};
use img_parts::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use rand::{RngCore, thread_rng};
use log::{info, debug};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

// JPEG APP1 Marker used for Exif metadata
const MIRAGE_MARKER: u8 = 0xE1;

// Adobe DNG Morphing Constants
const EXIF_HEADER: &[u8; 6] = b"Exif\0\0";
const TIFF_HEADER: &[u8; 8] = b"\x49\x49\x2A\x00\x08\x00\x00\x00"; // Little Endian TIFF
const DNG_TAG: [u8; 2] = [0x34, 0xC6];

const SALT_SIZE: usize = 16;
// Overhead: 6 (Exif) + 8 (TIFF) + 2 (Num) + 12 (Entry) + 4 (Next) = 32 bytes
const STRUCTURE_OVERHEAD: usize = 32;

pub struct JpegDisk {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    raw_storage: Vec<u8>,
    jpeg_structure: Jpeg,
}

impl JpegDisk {
    pub fn new(path: PathBuf, password: &str, format: bool) -> io::Result<Self> {
        let file_data = fs::read(&path)?;
        let mut jpeg = Jpeg::from_bytes(Bytes::from(file_data))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // 1. Scan for existing MirageFS data
        let mut encoded_storage = Vec::new();
        let mut segment_indices = Vec::new();

        for (i, segment) in jpeg.segments().iter().enumerate() {
            if segment.marker() == MIRAGE_MARKER {
                let contents = segment.contents();
                // Validate Signature: Exif Header + TIFF Header + DNG Tag
                if contents.len() > STRUCTURE_OVERHEAD
                    && &contents[0..6] == EXIF_HEADER
                    && contents[16] == DNG_TAG[0] && contents[17] == DNG_TAG[1] {
                        encoded_storage.extend_from_slice(&contents[STRUCTURE_OVERHEAD..]);
                        segment_indices.push(i);
                    }
            }
        }

        if format {
            info!("JPEG: Formatting new volume (DNG Morphing Mode)...");
            encoded_storage = Vec::new();
        }

        // 2. Initialize Storage or Format
        let raw_storage = if !format {
            if encoded_storage.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "No MirageFS (DNG) found."));
            }
            Self::concentrate_entropy(&encoded_storage)
        } else {
            let mut salt = [0u8; SALT_SIZE];
            thread_rng().fill_bytes(&mut salt);
            salt.to_vec()
        };

        if format {
            for idx in segment_indices.iter().rev() {
                jpeg.segments_mut().remove(*idx);
            }
        }

        if raw_storage.len() < SALT_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Storage too small."));
        }

        // 3. Crypto Setup (Argon2id + XChaCha20-Poly1305)
        let salt_slice = &raw_storage[0..16];
        debug!("Deriving key...");
        let salt_string = SaltString::encode_b64(salt_slice)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut key_buffer = [0u8; 32];
        let hash_output = password_hash.hash.ok_or(io::Error::new(io::ErrorKind::Other, "Hash failed"))?;
        key_buffer.copy_from_slice(&hash_output.as_bytes()[0..32]);

        let key = Key::from_slice(&key_buffer);
        let cipher = ChaCha20Poly1305::new(key);

        // 4. Verify Integrity (Block 0) if mounting
        if !format {
            let start = SALT_SIZE;
            let end = SALT_SIZE + ENCRYPTED_BLOCK_SIZE;

            if raw_storage.len() >= end {
                let packet = &raw_storage[start..end];
                let nonce = Nonce::from_slice(&packet[0..12]);
                let ciphertext = &packet[12..];

                if cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }).is_err() {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Decryption Failed."));
                }
            }
        }

        Ok(JpegDisk { path, cipher, raw_storage, jpeg_structure: jpeg })
    }

    // --- Entropy Management ---

    fn dilute_entropy(input: &[u8]) -> Vec<u8> {
        // Expands 7 bits -> 8 bytes to lower entropy density (Stealth)
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
        // Compresses 8 bytes (7 effective bits) -> original binary
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

    fn build_exif_segment(chunk: &[u8]) -> Bytes {
        let chunk_len = chunk.len() as u32;
        let mut payload = Vec::with_capacity(STRUCTURE_OVERHEAD + chunk.len());

        // Exif Header
        payload.extend_from_slice(EXIF_HEADER);
        // TIFF Header (Standard Little Endian)
        payload.extend_from_slice(TIFF_HEADER);
        // Number of Directory Entries (1)
        payload.extend_from_slice(b"\x01\x00");
        // Directory Entry (12 bytes)
        // Tag: DNGPrivateData (0xC634) -> \x34\xC6
        payload.extend_from_slice(&DNG_TAG);
        // Type: Undefined (7) -> \x07\x00
        payload.extend_from_slice(b"\x07\x00");
        // Count: Size of our data
        payload.extend_from_slice(&chunk_len.to_le_bytes());
        // Value/Offset: Data is at offset 26 (after this IFD)
        let data_offset: u32 = 26;
        payload.extend_from_slice(&data_offset.to_le_bytes());
        // Next IFD Offset (0 = None)
        payload.extend_from_slice(b"\x00\x00\x00\x00");
        // The Payload
        payload.extend_from_slice(chunk);

        Bytes::from(payload)
    }
}

impl BlockDevice for JpegDisk {
    fn block_count(&self) -> u64 { u32::MAX as u64 }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let start_offset = SALT_SIZE + (index as usize * ENCRYPTED_BLOCK_SIZE);
        let end_offset = start_offset + ENCRYPTED_BLOCK_SIZE;

        if end_offset > self.raw_storage.len() { return Ok([0u8; BLOCK_SIZE]); }

        let encrypted_packet = &self.raw_storage[start_offset..end_offset];
        let nonce = Nonce::from_slice(&encrypted_packet[0..12]);
        let ciphertext = &encrypted_packet[12..];

        match self.cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
            Ok(plaintext) => {
                let mut buffer = [0u8; BLOCK_SIZE];
                buffer.copy_from_slice(&plaintext);
                Ok(buffer)
            }
            Err(_) => Ok([0u8; BLOCK_SIZE])
        }
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, Payload { msg: data, aad: &[] })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        let mut packet = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        let start_offset = SALT_SIZE + (index as usize * ENCRYPTED_BLOCK_SIZE);
        let end_offset = start_offset + ENCRYPTED_BLOCK_SIZE;

        if end_offset > self.raw_storage.len() {
            self.raw_storage.resize(end_offset, 0);
        }

        self.raw_storage[start_offset..end_offset].copy_from_slice(&packet);
        Ok(())
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        let new_len = SALT_SIZE + (block_count as usize * ENCRYPTED_BLOCK_SIZE);
        self.raw_storage.resize(new_len, 0);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        let segments = self.jpeg_structure.segments_mut();

        // 1. Remove previous stego segments
        segments.retain(|s| {
            if s.marker() == MIRAGE_MARKER {
                let c = s.contents();
                // Check if it matches our DNG signature
                if c.len() > 16 && c[16] == DNG_TAG[0] && c[17] == DNG_TAG[1] { return false; }
            }
            true
        });

        // 2. Prepare diluted payload
        let diluted_data = Self::dilute_entropy(&self.raw_storage);
        let mut insert_idx = if segments.len() > 0 { 1 } else { 0 };
        const CHUNK_SIZE: usize = 65000;

        // 3. Inject segments
        for chunk in diluted_data.chunks(CHUNK_SIZE) {
            let bytes = Self::build_exif_segment(chunk);
            let segment = JpegSegment::new_with_contents(MIRAGE_MARKER, bytes);

            if insert_idx < segments.len() { segments.insert(insert_idx, segment); }
            else { segments.push(segment); }
            insert_idx += 1;
        }

        let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&self.path)?;

        self.jpeg_structure.clone().encoder().write_to(&mut file)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(())
    }
}

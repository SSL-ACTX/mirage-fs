// src/png_disk.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use std::io::{self, Result};
use std::path::PathBuf;
use image::RgbImage;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use log::{info, debug, warn};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

// 16 bytes (128 bits) for Salt.
// Stored in first 128 channels linearly (approx 43 pixels).
const HEADER_BITS: usize = 128;

pub struct PngDisk {
    img: RgbImage,
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    // Maps Logical Bit Index -> Physical Channel Index (Flat Index)
    bit_map: Vec<u32>,
}

impl PngDisk {
    pub fn new(path: PathBuf, password: &str, format: bool) -> io::Result<Self> {
        let mut img = image::open(&path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        .to_rgb8();

        let width = img.width();
        let height = img.height();
        let total_channels = (width as usize) * (height as usize) * 3;

        // Reserve space for Header
        if total_channels < HEADER_BITS + 4096 {
            return Err(io::Error::new(io::ErrorKind::Other, "Image too small for MirageFS"));
        }

        let mut salt = [0u8; 16];

        // 1. Handle Header (Linear Read/Write in first 128 channels)
        if format {
            info!("PNG: Formatting new volume (PRNG Scatter Mode)...");
            // Generate new Salt
            let mut rng = rand::thread_rng();
            rng.fill(&mut salt);
            info!("Generated Salt: {}", hex::encode(salt));

            // Write Salt to Image (Bits 0..128)
            let header_bits_vec = Self::bytes_to_bits(&salt);
            for (i, &bit) in header_bits_vec.iter().enumerate() {
                Self::write_channel_lsb(&mut img, i as u32, bit);
            }
        } else {
            // Read Salt from Image (Bits 0..128)
            let mut header_bits_vec = Vec::with_capacity(HEADER_BITS);
            for i in 0..HEADER_BITS {
                header_bits_vec.push(Self::read_channel_lsb(&img, i as u32));
            }
            let salt_vec = Self::bits_to_bytes(&header_bits_vec);
            salt.copy_from_slice(&salt_vec[0..16]);
            info!("Read Salt:      {}", hex::encode(salt));
        }

        // 2. Derive Key
        debug!("Deriving key...");
        let salt_string = SaltString::encode_b64(&salt)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let hash_output = password_hash.hash.ok_or(io::Error::new(io::ErrorKind::Other, "Hash failed"))?;
        let mut key_buffer = [0u8; 32];
        key_buffer.copy_from_slice(&hash_output.as_bytes()[0..32]);

        let key = Key::from_slice(&key_buffer);
        let cipher = ChaCha20Poly1305::new(key);

        // 3. Generate Coordinate Map (The "Scatter" Logic)
        // We use the derived key to seed a CSPRNG.
        // We then create a list of ALL available channel indices (skipping header)
        // and shuffle them. This creates a unique, deterministic scatter pattern.

        info!("Generating Scatter Map...");
        let _available_channels = total_channels - HEADER_BITS;
        let mut bit_map: Vec<u32> = (HEADER_BITS as u32 .. total_channels as u32).collect();

        // Seed RNG from Key (Deterministic Shuffle)
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_buffer);
        let mut shuffler = ChaCha20Rng::from_seed(seed);

        bit_map.shuffle(&mut shuffler);

        let disk = PngDisk { img, path, cipher, bit_map };

        // 4. Integrity Check (Block 0)
        if !format {
            if let Err(e) = disk.read_block(0) {
                warn!("Block 0 Verify Failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Auth Tag Mismatch"));
            }
        }

        Ok(disk)
    }

    // --- Low Level Pixel Access ---

    fn read_channel_lsb(img: &RgbImage, flat_idx: u32) -> u8 {
        let width = img.width();
        let pixel_idx = flat_idx / 3;
        let channel = (flat_idx % 3) as usize;
        let y = pixel_idx / width;
        let x = pixel_idx % width;
        let p = img.get_pixel(x, y);
        p[channel] & 1
    }

    fn write_channel_lsb(img: &mut RgbImage, flat_idx: u32, bit: u8) {
        let width = img.width();
        let pixel_idx = flat_idx / 3;
        let channel = (flat_idx % 3) as usize;
        let y = pixel_idx / width;
        let x = pixel_idx % width;
        let mut p = *img.get_pixel(x, y);
        p[channel] = (p[channel] & !1) | (bit & 1);
        img.put_pixel(x, y, p);
    }

    // --- Helper Utils ---

    fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);
        for byte in bytes {
            for i in 0..8 {
                bits.push((byte >> i) & 1);
            }
        }
        bits
    }

    fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; bits.len() / 8];
        for (i, bit) in bits.iter().enumerate() {
            if *bit == 1 {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }
        bytes
    }
}

impl BlockDevice for PngDisk {
    fn block_count(&self) -> u64 {
        let total_bits = self.bit_map.len() as u64;
        let block_bits = (ENCRYPTED_BLOCK_SIZE * 8) as u64;
        total_bits / block_bits
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let start_bit_idx = (index as usize) * ENCRYPTED_BLOCK_SIZE * 8;
        let end_bit_idx = start_bit_idx + (ENCRYPTED_BLOCK_SIZE * 8);

        if end_bit_idx > self.bit_map.len() {
            return Ok([0u8; BLOCK_SIZE]); // Uninitialized/Out of bounds
        }

        // 1. Gather scattered bits
        let mut raw_bits = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE * 8);
        for i in start_bit_idx..end_bit_idx {
            let physical_idx = self.bit_map[i];
            raw_bits.push(Self::read_channel_lsb(&self.img, physical_idx));
        }

        // 2. Reconstruct Packet
        let encrypted_packet = Self::bits_to_bytes(&raw_bits);
        if encrypted_packet.len() != ENCRYPTED_BLOCK_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "Bit/Byte Alignment Error"));
        }

        // 3. Decrypt
        let nonce = Nonce::from_slice(&encrypted_packet[0..12]);
        let ciphertext = &encrypted_packet[12..];

        match self.cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &[] }) {
            Ok(plaintext) => {
                let mut buffer = [0u8; BLOCK_SIZE];
                buffer.copy_from_slice(&plaintext);
                Ok(buffer)
            }
            Err(_) => Err(io::Error::new(io::ErrorKind::PermissionDenied, "Auth Tag Mismatch")),
        }
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let start_bit_idx = (index as usize) * ENCRYPTED_BLOCK_SIZE * 8;
        let end_bit_idx = start_bit_idx + (ENCRYPTED_BLOCK_SIZE * 8);

        if end_bit_idx > self.bit_map.len() {
            return Err(io::Error::new(io::ErrorKind::Other, "Disk Full"));
        }

        // 1. Encrypt
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, Payload { msg: data, aad: &[] })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        let mut packet = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        // 2. Scatter Bits
        let bits = Self::bytes_to_bits(&packet);
        for (i, bit) in bits.iter().enumerate() {
            let physical_idx = self.bit_map[start_bit_idx + i];
            Self::write_channel_lsb(&mut self.img, physical_idx, *bit);
        }

        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.img.save(&self.path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

// src/png_disk.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE, ENCRYPTED_BLOCK_SIZE};
use std::io::{self, Result};
use std::path::PathBuf;
use std::fs::metadata;
use filetime::{FileTime, set_file_times};
use std::collections::HashSet;
use image::RgbImage;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use log::{info, debug, warn};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2
};

// 16 bytes (128 bits) for the Header/Salt.
const SALT_BITS: usize = 128;
// Static domain separator used to derive the *location* of the salt from the password.
const LOCATION_SALT: &str = "MirageLocSalt";

// --- Dynamic Feistel Permutator ---
struct FeistelPermutator {
    rounds: u32,
    keys: [u32; 4],
    max_range: u32,
    half_bits: u32,
    mask: u32,
}

impl FeistelPermutator {
    fn new(key: &[u8; 32], max_range: u32) -> Self {
        let k0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
        let k1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
        let k2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
        let k3 = u32::from_le_bytes(key[12..16].try_into().unwrap());

        let mut bits = 32 - max_range.leading_zeros();
        if bits % 2 != 0 { bits += 1; }
        if (1 << bits) < max_range { bits += 2; }
        if bits > 32 { bits = 32; }

        let half_bits = bits / 2;
        let mask = (1 << half_bits) - 1;

        FeistelPermutator {
            rounds: 4,
            keys: [k0, k1, k2, k3],
            max_range,
            half_bits,
            mask,
        }
    }

    #[inline(always)]
    fn round_func(val: u32, key: u32) -> u32 {
        let mut x = val.wrapping_mul(0xcc9e2d51);
        x = x.rotate_left(15);
        x = x.wrapping_mul(0x1b873593);
        x ^ key
    }

    fn permute(&self, index: u32) -> u32 {
        let mut current = index;

        loop {
            let mut left = (current >> self.half_bits) & self.mask;
            let mut right = current & self.mask;

            for i in 0..self.rounds {
                let key = self.keys[i as usize];
                let f_out = Self::round_func(right, key);
                let new_right = left ^ (f_out & self.mask);
                left = right;
                right = new_right;
            }

            let result = (left << self.half_bits) | right;
            if result < self.max_range {
                return result;
            }
            current = result;
        }
    }
}

pub struct PngDisk {
    img: RgbImage,
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    permutator: FeistelPermutator,
    salt_indices: HashSet<u32>,
    sorted_salt_indices: Vec<u32>,
    atime: FileTime,
    mtime: FileTime,
}

impl PngDisk {
    pub fn new(path: PathBuf, password: &str, format: bool) -> io::Result<Self> {
        let meta = metadata(&path)?;
        let atime = FileTime::from_last_access_time(&meta);
        let mtime = FileTime::from_last_modification_time(&meta);

        let mut img = image::open(&path)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        .to_rgb8();

        let width = img.width();
        let height = img.height();
        let total_channels = (width as usize) * (height as usize) * 3;

        if total_channels < SALT_BITS + 4096 {
            return Err(io::Error::new(io::ErrorKind::Other, "Image too small for MirageFS"));
        }

        // 1. Locate Salt (Password Derived)
        debug!("Deriving salt locations...");
        let loc_seed = Self::derive_location_seed(password)?;
        let mut salt_vec = Self::generate_salt_indices(loc_seed, total_channels as u32);

        // Sort salt indices for deterministic shifting
        salt_vec.sort();
        let sorted_salt_indices = salt_vec.clone();
        let salt_indices: HashSet<u32> = salt_vec.iter().cloned().collect();

        let mut salt = [0u8; 16];

        // 2. Read or Write Salt
        if format {
            info!("PNG: Formatting (Algorithmic Scatter Mode)...");
            let mut rng = rand::thread_rng();
            rng.fill(&mut salt);
            info!("Generated Salt: {}", hex::encode(salt));

            let salt_bits = Self::bytes_to_bits(&salt);
            for (i, &bit) in salt_bits.iter().enumerate() {
                Self::write_channel_lsb(&mut img, salt_vec[i], bit);
            }
        } else {
            let mut salt_bits = Vec::with_capacity(SALT_BITS);
            for idx in &salt_vec {
                salt_bits.push(Self::read_channel_lsb(&img, *idx));
            }
            let salt_bytes = Self::bits_to_bytes(&salt_bits);
            salt.copy_from_slice(&salt_bytes[0..16]);
            info!("Read Salt:      {}", hex::encode(salt));
        }

        // 3. Derive Main Key
        debug!("Deriving main key...");
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

        // 4. Initialize Permutator
        let permutator = FeistelPermutator::new(&key_buffer, total_channels as u32);

        let disk = PngDisk { img, path, cipher, permutator, salt_indices, sorted_salt_indices, atime, mtime };

        // 5. Integrity Check
        if !format {
            if let Err(e) = disk.read_block(0) {
                warn!("Block 0 Verify Failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Decryption Failed (Auth Tag Mismatch)"));
            }
        }

        if let Err(e) = disk.restore_times() {
            warn!("PNG: Failed to restore carrier timestamps: {}", e);
        }
        Ok(disk)
    }

    fn restore_times(&self) -> io::Result<()> {
        set_file_times(&self.path, self.atime, self.mtime)
    }

    // --- Core Helpers ---

    fn derive_location_seed(password: &str) -> io::Result<[u8; 32]> {
        let salt_string = SaltString::encode_b64(LOCATION_SALT.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let output = hash.hash.ok_or(io::Error::new(io::ErrorKind::Other, "Loc Hash failed"))?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&output.as_bytes()[0..32]);
        Ok(seed)
    }

    fn generate_salt_indices(seed: [u8; 32], max_range: u32) -> Vec<u32> {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut indices = Vec::with_capacity(SALT_BITS);
        let mut used = HashSet::new();
        while indices.len() < SALT_BITS {
            let idx = rng.gen_range(0..max_range);
            if used.insert(idx) {
                indices.push(idx);
            }
        }
        indices
    }

    #[inline(always)]
    fn map_logical_to_physical(&self, logical_index: u32) -> u32 {
        // S1: Skip Salt Indices in the INPUT domain.
        // This ensures we never use a Salt Index as an input to the permutator.
        let mut adjusted_index = logical_index;
        for &salt_idx in &self.sorted_salt_indices {
            if adjusted_index >= salt_idx {
                adjusted_index += 1;
            } else {
                // Sorted, so we can stop early
                break;
            }
        }

        // S2: Permute the adjusted index.
        let mut physical = self.permutator.permute(adjusted_index);

        // S3: Handle Output Collisions (Cycle Walking).
        while self.salt_indices.contains(&physical) {
            physical = self.permutator.permute(physical);
        }

        physical
    }

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
        let total_channels = self.permutator.max_range as u64;
        let available_bits = total_channels.saturating_sub(SALT_BITS as u64);
        available_bits / (ENCRYPTED_BLOCK_SIZE as u64 * 8)
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let start_bit = (index as usize) * ENCRYPTED_BLOCK_SIZE * 8;
        let end_bit = start_bit + (ENCRYPTED_BLOCK_SIZE * 8);

        if end_bit as u64 > self.block_count() * (ENCRYPTED_BLOCK_SIZE as u64 * 8) {
            return Ok([0u8; BLOCK_SIZE]);
        }

        let mut raw_bits = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE * 8);
        for logical_idx in start_bit..end_bit {
            let physical_idx = self.map_logical_to_physical(logical_idx as u32);
            raw_bits.push(Self::read_channel_lsb(&self.img, physical_idx));
        }

        let encrypted_packet = Self::bits_to_bytes(&raw_bits);
        if encrypted_packet.len() != ENCRYPTED_BLOCK_SIZE {
            return Err(io::Error::new(io::ErrorKind::Other, "Alignment Error"));
        }

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
        let start_bit = (index as usize) * ENCRYPTED_BLOCK_SIZE * 8;
        let end_bit = start_bit + (ENCRYPTED_BLOCK_SIZE * 8);

        if end_bit as u64 > self.block_count() * (ENCRYPTED_BLOCK_SIZE as u64 * 8) {
            return Err(io::Error::new(io::ErrorKind::Other, "Disk Full"));
        }

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, Payload { msg: data, aad: &[] })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption failed"))?;

        let mut packet = Vec::with_capacity(ENCRYPTED_BLOCK_SIZE);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        let bits = Self::bytes_to_bits(&packet);
        for (i, bit) in bits.iter().enumerate() {
            let logical_idx = (start_bit + i) as u32;
            let physical_idx = self.map_logical_to_physical(logical_idx);
            Self::write_channel_lsb(&mut self.img, physical_idx, *bit);
        }

        Ok(())
    }

    fn resize(&mut self, _block_count: u64) -> Result<()> {
        // PNGs have fixed canvas size, so we can't physically shrink the container.
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        self.img.save(&self.path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.restore_times()
    }
}

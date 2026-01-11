// src/block_device.rs
use std::io::Result;

pub const BLOCK_SIZE: usize = 4096;
pub const ENCRYPTED_BLOCK_SIZE: usize = BLOCK_SIZE + 12 + 16;

pub trait BlockDevice {
    #[allow(dead_code)]
    fn block_count(&self) -> u64;
    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]>;
    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()>;
    fn sync(&mut self) -> Result<()>;
}

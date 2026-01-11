// src/raid_device.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE};
use std::io::{Result, Error, ErrorKind};
use log::{info, debug};

/// RAID 0 (Striped) Wrapper
/// Strategy: Distribute blocks across multiple images (Dilution)
/// Mapping: Device = L % N, Block = L / N
pub struct Raid0Device {
    devices: Vec<Box<dyn BlockDevice>>,
    stripe_width: u64,
}

impl Raid0Device {
    pub fn new(devices: Vec<Box<dyn BlockDevice>>) -> Result<Self> {
        if devices.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "RAID0 requires at least 1 device"));
        }
        let count = devices.len() as u64;
        info!("RAID0: Initialized with {} stripe(s).", count);
        Ok(Self { devices, stripe_width: count })
    }
}

impl BlockDevice for Raid0Device {
    fn block_count(&self) -> u64 {
        // Capacity limited by smallest member: min(cap) * N
        let min_cap = self.devices.iter()
        .map(|d| d.block_count())
        .min()
        .unwrap_or(0);

        min_cap.saturating_mul(self.stripe_width)
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let device_idx = (index as u64 % self.stripe_width) as usize;
        let local_idx = (index as u64 / self.stripe_width) as u32;

        self.devices[device_idx].read_block(local_idx)
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let device_idx = (index as u64 % self.stripe_width) as usize;
        let local_idx = (index as u64 / self.stripe_width) as u32;

        self.devices[device_idx].write_block(local_idx, data)
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        // Distribute resize across all stripes, handling remainders
        let base_count = block_count / self.stripe_width;
        let remainder = block_count % self.stripe_width;

        for (i, device) in self.devices.iter_mut().enumerate() {
            let extra = if (i as u64) < remainder { 1 } else { 0 };
            device.resize(base_count + extra)?;
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        for (i, device) in self.devices.iter_mut().enumerate() {
            debug!("RAID0: Syncing stripe {}...", i);
            device.sync()?;
        }
        Ok(())
    }
}

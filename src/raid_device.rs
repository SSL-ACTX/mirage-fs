// src/raid_device.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE};
use std::io::{Result, Error, ErrorKind};
use log::{info, debug, warn};
use serde::{Serialize, Deserialize};
use rand::{RngCore, thread_rng};

const RAID_MAGIC: &[u8; 8] = b"MIRAGEFS";

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
struct RaidMetadata {
    magic: [u8; 8],
    array_id: [u8; 16], // Unique ID for the whole array
    device_index: u32,  // Position in array (0, 1, 2...)
    device_count: u32,  // Total devices in array
}

/// RAID 0 (Striped) Wrapper
/// Strategy: Distribute blocks across multiple images (Dilution)
/// Mapping: Device = L % N, Block = (L / N) + 1 (Offset to hide metadata)
pub struct Raid0Device {
    devices: Vec<Box<dyn BlockDevice>>,
    stripe_width: u64,
}

impl Raid0Device {
    pub fn new(mut devices: Vec<Box<dyn BlockDevice>>, format: bool) -> Result<Self> {
        if devices.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "RAID0 requires at least 1 device"));
        }
        let count = devices.len() as u32;

        if format {
            info!("RAID0: Formatting - Generating new Array ID...");
            let mut array_id = [0u8; 16];
            thread_rng().fill_bytes(&mut array_id);

            for (i, device) in devices.iter_mut().enumerate() {
                let metadata = RaidMetadata {
                    magic: *RAID_MAGIC,
                    array_id,
                    device_index: i as u32,
                    device_count: count,
                };

                let encoded = bincode::serialize(&metadata)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

                // Pad to block size
                let mut block = [0u8; BLOCK_SIZE];
                if encoded.len() > BLOCK_SIZE {
                    return Err(Error::new(ErrorKind::Other, "Metadata too large for block"));
                }
                block[0..encoded.len()].copy_from_slice(&encoded);

                // Write to Physical Block 0 (Reserved)
                info!("RAID0: Writing header to device {}...", i);
                device.write_block(0, &block)?;
            }
        } else {
            info!("RAID0: Verifying array integrity...");
            let mut expected_id: Option<[u8; 16]> = None;

            for (i, device) in devices.iter().enumerate() {
                // Read Physical Block 0
                let block = device.read_block(0)?;

                // Attempt to deserialize
                let metadata: RaidMetadata = bincode::deserialize(&block)
                .map_err(|_| Error::new(ErrorKind::InvalidData, format!("Device {}: Invalid Header (Not a MirageFS volume?)", i)))?;

                // 1. Check Magic
                if &metadata.magic != RAID_MAGIC {
                    return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: Bad Magic Signature", i)));
                }

                // 2. Check Array ID consistency
                if let Some(id) = expected_id {
                    if metadata.array_id != id {
                        return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: UUID Mismatch! Does not belong to this array.", i)));
                    }
                } else {
                    expected_id = Some(metadata.array_id);
                }

                // 3. Check Count
                if metadata.device_count != count {
                    return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: Expects {} devices, but {} were provided.", i, metadata.device_count, count)));
                }

                // 4. Strict Order Check
                if metadata.device_index != i as u32 {
                    return Err(Error::new(ErrorKind::InvalidData,
                                          format!("Order Error: Device provided at position {} claims to be at position {}. Please reorder your command arguments.", i, metadata.device_index)));
                }
            }
            info!("RAID0: Integrity Check Passed. Array UUID: {}", hex::encode(expected_id.unwrap()));
        }

        info!("RAID0: Initialized with {} stripe(s).", count);
        Ok(Self { devices, stripe_width: count as u64 })
    }
}

impl BlockDevice for Raid0Device {
    fn block_count(&self) -> u64 {
        // Capacity limited by smallest member: min(cap) * N
        // We subtract 1 block from every device's capacity because Block 0 is reserved for Metadata
        let min_cap = self.devices.iter()
        .map(|d| d.block_count().saturating_sub(1))
        .min()
        .unwrap_or(0);

        min_cap.saturating_mul(self.stripe_width)
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let device_idx = (index as u64 % self.stripe_width) as usize;
        let local_idx = (index as u64 / self.stripe_width) as u32;

        // OFFSET +1: Skip the reserved Metadata Block 0
        self.devices[device_idx].read_block(local_idx + 1)
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let device_idx = (index as u64 % self.stripe_width) as usize;
        let local_idx = (index as u64 / self.stripe_width) as u32;

        // OFFSET +1: Skip the reserved Metadata Block 0
        self.devices[device_idx].write_block(local_idx + 1, data)
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        // Distribute resize across all stripes, handling remainders
        let base_count = block_count / self.stripe_width;
        let remainder = block_count % self.stripe_width;

        for (i, device) in self.devices.iter_mut().enumerate() {
            let extra = if (i as u64) < remainder { 1 } else { 0 };

            // OFFSET +1: We need to allocate space for the FS blocks PLUS our header
            device.resize(base_count + extra + 1)?;
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

// src/raid_device.rs
use crate::block_device::{BlockDevice, BLOCK_SIZE};
use std::io::{Result, Error, ErrorKind};
use log::{info, debug};
use serde::{Serialize, Deserialize};
use rand::{RngCore, thread_rng};

const RAID_MAGIC: &[u8; 8] = b"MIRAGEFS";

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy)]
struct RaidMetadata {
    magic: [u8; 8],
    array_id: [u8; 16],
    device_index: u32,
    device_count: u32,
}

/// Hybrid RAID Controller (RAID 0 + Tiered Spillover)
pub struct Raid0Device {
    devices: Vec<Box<dyn BlockDevice>>,
    total_devices: u64,
    // The block limit where Zone 1 ends (capacity of the smallest static device)
    zone1_limit_per_device: u64,
    // Indices of devices capable of Zone 2 storage
    expandable_indices: Vec<usize>,
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

                let mut block = [0u8; BLOCK_SIZE];
                if encoded.len() > BLOCK_SIZE {
                    return Err(Error::new(ErrorKind::Other, "Metadata too large for block"));
                }
                block[0..encoded.len()].copy_from_slice(&encoded);

                info!("RAID0: Writing header to device {}...", i);
                device.write_block(0, &block)?;
            }
        } else {
            info!("RAID0: Verifying array integrity...");
            let mut expected_id: Option<[u8; 16]> = None;

            for (i, device) in devices.iter().enumerate() {
                let block = device.read_block(0)?;
                let metadata: RaidMetadata = bincode::deserialize(&block)
                .map_err(|_| Error::new(ErrorKind::InvalidData, format!("Device {}: Invalid Header (Not a MirageFS volume?)", i)))?;

                if &metadata.magic != RAID_MAGIC {
                    return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: Bad Magic Signature", i)));
                }
                if let Some(id) = expected_id {
                    if metadata.array_id != id {
                        return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: UUID Mismatch!", i)));
                    }
                } else {
                    expected_id = Some(metadata.array_id);
                }
                if metadata.device_count != count {
                    return Err(Error::new(ErrorKind::InvalidData, format!("Device {}: Expects {} devices, but {} were provided.", i, metadata.device_count, count)));
                }
                if metadata.device_index != i as u32 {
                    return Err(Error::new(ErrorKind::InvalidData, format!("Order Error: Device {} at position {}.", i, metadata.device_index)));
                }
            }
            info!("RAID0: Integrity Check Passed. Array UUID: {}", hex::encode(expected_id.unwrap()));
        }

        // Calculate Zones for Hybrid RAID
        let mut min_static_cap = u64::MAX;
        let mut expandable_indices = Vec::new();
        let mut has_static = false;

        for (i, d) in devices.iter().enumerate() {
            if d.is_expandable() {
                expandable_indices.push(i);
            } else {
                has_static = true;
                // Subtract 1 because Block 0 is Header
                let cap = d.block_count().saturating_sub(1);
                if cap < min_static_cap {
                    min_static_cap = cap;
                }
            }
        }

        if !has_static {
            min_static_cap = u64::MAX;
        }

        info!("RAID0: Hybrid Tiering Active.");
        if has_static {
            info!("  -> Zone 1 (High-Stealth): Striped across {} devices (Limit: {} blocks/dev)", count, min_static_cap);
        } else {
            info!("  -> Zone 1 (High-Stealth): Unlimited Stripe (All devices dynamic).");
        }

        if !expandable_indices.is_empty() && has_static {
            info!("  -> Zone 2 (Overflow): Spilling over to {} dynamic device(s).", expandable_indices.len());
        }

        Ok(Self {
            devices,
            total_devices: count as u64,
            zone1_limit_per_device: min_static_cap,
            expandable_indices
        })
    }
}

impl BlockDevice for Raid0Device {
    fn block_count(&self) -> u64 {
        // Report virtual capacity
        let zone1_total = if self.zone1_limit_per_device == u64::MAX {
            u64::MAX / 2
        } else {
            self.zone1_limit_per_device.saturating_mul(self.total_devices)
        };

        if self.expandable_indices.is_empty() {
            zone1_total
        } else {
            1_000_000_000 // 4TB Virtual Cap
        }
    }

    fn read_block(&self, index: u32) -> Result<[u8; BLOCK_SIZE]> {
        let index_u64 = index as u64;
        let zone1_boundary = self.zone1_limit_per_device.saturating_mul(self.total_devices);

        if index_u64 < zone1_boundary {
            // Zone 1
            let device_idx = (index_u64 % self.total_devices) as usize;
            let local_idx = (index_u64 / self.total_devices) as u32;
            self.devices[device_idx].read_block(local_idx + 1)
        } else {
            // Zone 2
            if self.expandable_indices.is_empty() {
                return Ok([0u8; BLOCK_SIZE]);
            }
            let overflow_idx = index_u64 - zone1_boundary;
            let width = self.expandable_indices.len() as u64;

            let map_idx = (overflow_idx % width) as usize;
            let real_device_idx = self.expandable_indices[map_idx];

            let local_idx = self.zone1_limit_per_device
            + (overflow_idx / width)
            + 1;

            self.devices[real_device_idx].read_block(local_idx as u32)
        }
    }

    fn write_block(&mut self, index: u32, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        let index_u64 = index as u64;
        let zone1_boundary = self.zone1_limit_per_device.saturating_mul(self.total_devices);

        if index_u64 < zone1_boundary {
            let device_idx = (index_u64 % self.total_devices) as usize;
            let local_idx = (index_u64 / self.total_devices) as u32;
            self.devices[device_idx].write_block(local_idx + 1, data)
        } else {
            if self.expandable_indices.is_empty() {
                return Err(Error::new(ErrorKind::Other, "Disk Full (No expandable carriers)"));
            }
            let overflow_idx = index_u64 - zone1_boundary;
            let width = self.expandable_indices.len() as u64;

            let map_idx = (overflow_idx % width) as usize;
            let real_device_idx = self.expandable_indices[map_idx];

            let local_idx = self.zone1_limit_per_device
            + (overflow_idx / width)
            + 1;

            self.devices[real_device_idx].write_block(local_idx as u32, data)
        }
    }

    fn resize(&mut self, block_count: u64) -> Result<()> {
        let zone1_boundary = self.zone1_limit_per_device.saturating_mul(self.total_devices);

        if block_count > zone1_boundary {
            // Case A: New size is still inside Zone 2 (Overflow)
            // We resize dynamic devices to hold exactly the overflow + Zone 1 base.
            if self.expandable_indices.is_empty() {
                return Ok(());
            }

            let overflow_needed = block_count - zone1_boundary;
            let width = self.expandable_indices.len() as u64;

            // Ceiling division to ensure we cover the last partial stripe
            let rows_needed = (overflow_needed + width - 1) / width;
            let new_size = self.zone1_limit_per_device + rows_needed + 1; // +1 Header

            for &idx in &self.expandable_indices {
                self.devices[idx].resize(new_size)?;
            }

        } else {
            // Case B: New size has shrunk back into Zone 1 (Standard Stripe)
            // We must shrink dynamic devices to match the standard stripe height.
            // NOTE: Static devices (PNG) are ignored as they cannot shrink.

            // Calculate how deep into Zone 1 we are
            let base_count = block_count / self.total_devices;
            let remainder = block_count % self.total_devices;

            for (i, device) in self.devices.iter_mut().enumerate() {
                if device.is_expandable() {
                    // Check if this device is part of the partial remainder row
                    let extra = if (i as u64) < remainder { 1 } else { 0 };
                    let new_size = base_count + extra + 1; // +1 Header
                    device.resize(new_size)?;
                }
            }
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        for (i, device) in self.devices.iter_mut().enumerate() {
            debug!("RAID0: Syncing device {}...", i);
            device.sync()?;
        }
        Ok(())
    }
}

// SPDX-License-Identifier: MIT
//! Zxyphor Kernel — Device Mapper Subsystem (Rust)
//!
//! Linux-compatible device-mapper (dm) implementation:
//! - DM target types: linear, striped, mirror, zero, error, snapshot, thin
//! - Bio remapping: translate sector offsets through mapping table
//! - Mapping table: array of targets with sector ranges
//! - Suspend/resume for live table swaps
//! - Snapshot: COW exception tracking with origin + snapshot device
//! - Thin provisioning: virtual → physical block mapping
//! - Striped: I/O distribution across multiple devices
//! - Mirror: read from any leg, write to all legs
//! - Statistics per-target and per-device

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_DM_DEVICES: usize = 16;
const MAX_TARGETS: usize = 32;      // Per device
const MAX_STRIPE_LEGS: usize = 8;
const MAX_MIRROR_LEGS: usize = 4;
const MAX_SNAP_EXCEPTIONS: usize = 512;
const MAX_THIN_MAPS: usize = 1024;
const NAME_LEN: usize = 32;
const SECTOR_SIZE: u64 = 512;

// ─────────────────── Target Types ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmTargetType {
    Linear = 0,      // Simple linear mapping to destination device+offset
    Striped = 1,     // Stripe across multiple devices
    Mirror = 2,      // Mirror writes, balance reads
    Zero = 3,        // Read returns zeros, writes discarded
    Error = 4,       // Always returns I/O error
    Snapshot = 5,    // Copy-on-write snapshot
    SnapshotOrigin = 6,
    Thin = 7,        // Thin provisioning
    ThinPool = 8,
    Crypt = 9,       // Encryption (placeholder)
    Cache = 10,      // SSD caching (placeholder)
}

// ─────────────────── Device State ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DmDeviceState {
    Active = 0,
    Suspended = 1,
    Creating = 2,
    Removing = 3,
}

// ─────────────────── I/O Direction ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IoDir {
    Read = 0,
    Write = 1,
}

// ─────────────────── Bio Request ────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DmBio {
    pub sector: u64,        // Start sector on DM device
    pub count: u32,         // Number of sectors
    pub dir: IoDir,
    pub data_tag: u64,      // Opaque data handle (pointer in real kernel)
}

impl DmBio {
    pub const fn new() -> Self {
        Self {
            sector: 0,
            count: 0,
            dir: IoDir::Read,
            data_tag: 0,
        }
    }
}

// ─────────────────── Remapped Bio ───────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct RemappedBio {
    pub dev_id: u16,        // Destination underlying device
    pub sector: u64,        // Remapped sector
    pub count: u32,
    pub dir: IoDir,
    pub data_tag: u64,
    pub valid: bool,
}

impl RemappedBio {
    pub const fn empty() -> Self {
        Self {
            dev_id: 0,
            sector: 0,
            count: 0,
            dir: IoDir::Read,
            data_tag: 0,
            valid: false,
        }
    }
}

// ─────────────────── Stripe Leg ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct StripeLeg {
    pub dev_id: u16,
    pub offset: u64,        // Start sector on underlying device
    pub active: bool,
}

impl StripeLeg {
    pub const fn new() -> Self {
        Self { dev_id: 0, offset: 0, active: false }
    }
}

// ─────────────────── Mirror Leg ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct MirrorLeg {
    pub dev_id: u16,
    pub offset: u64,
    pub failed: bool,
    pub active: bool,
    pub read_count: u64,
    pub write_count: u64,
}

impl MirrorLeg {
    pub const fn new() -> Self {
        Self {
            dev_id: 0,
            offset: 0,
            failed: false,
            active: false,
            read_count: 0,
            write_count: 0,
        }
    }
}

// ─────────────────── Snapshot Exception ─────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct SnapException {
    pub old_chunk: u64,     // Origin chunk
    pub new_chunk: u64,     // COW store chunk
    pub valid: bool,
}

impl SnapException {
    pub const fn new() -> Self {
        Self { old_chunk: 0, new_chunk: 0, valid: false }
    }
}

// ─────────────────── Thin Block Map ─────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct ThinBlockMap {
    pub virtual_block: u64,
    pub physical_block: u64,
    pub allocated: bool,
}

impl ThinBlockMap {
    pub const fn new() -> Self {
        Self { virtual_block: 0, physical_block: 0, allocated: false }
    }
}

// ─────────────────── DM Target ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DmTarget {
    pub ttype: DmTargetType,
    pub start_sector: u64,    // Start in DM device space
    pub length: u64,          // Length in sectors

    // Linear: destination device + offset
    pub linear_dev: u16,
    pub linear_offset: u64,

    // Striped
    pub stripe_legs: [StripeLeg; MAX_STRIPE_LEGS],
    pub stripe_count: u8,
    pub stripe_size: u64,     // Chunk size in sectors

    // Mirror
    pub mirror_legs: [MirrorLeg; MAX_MIRROR_LEGS],
    pub mirror_count: u8,
    pub mirror_read_leg: u8,  // Round-robin read balancing index

    // Snapshot
    pub snap_origin_dev: u16,
    pub snap_cow_dev: u16,
    pub snap_chunk_size: u64, // In sectors
    pub snap_exceptions: [SnapException; MAX_SNAP_EXCEPTIONS],
    pub snap_exception_count: u32,
    pub snap_invalid: bool,   // Snapshot invalidated (overflow)

    // Thin
    pub thin_pool_idx: i16,
    pub thin_dev_id: u32,
    pub thin_maps: [ThinBlockMap; MAX_THIN_MAPS],
    pub thin_map_count: u32,
    pub thin_next_phys: u64,

    // Stats
    pub ios_read: u64,
    pub ios_write: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub errors: u64,

    pub active: bool,
}

impl DmTarget {
    pub const fn new() -> Self {
        Self {
            ttype: DmTargetType::Linear,
            start_sector: 0,
            length: 0,
            linear_dev: 0,
            linear_offset: 0,
            stripe_legs: [const { StripeLeg::new() }; MAX_STRIPE_LEGS],
            stripe_count: 0,
            stripe_size: 128, // 64KB default
            mirror_legs: [const { MirrorLeg::new() }; MAX_MIRROR_LEGS],
            mirror_count: 0,
            mirror_read_leg: 0,
            snap_origin_dev: 0,
            snap_cow_dev: 0,
            snap_chunk_size: 16, // 8KB
            snap_exceptions: [const { SnapException::new() }; MAX_SNAP_EXCEPTIONS],
            snap_exception_count: 0,
            snap_invalid: false,
            thin_pool_idx: -1,
            thin_dev_id: 0,
            thin_maps: [const { ThinBlockMap::new() }; MAX_THIN_MAPS],
            thin_map_count: 0,
            thin_next_phys: 0,
            ios_read: 0,
            ios_write: 0,
            sectors_read: 0,
            sectors_written: 0,
            errors: 0,
            active: false,
        }
    }

    /// Map a bio through this target, producing remapped bio(s)
    pub fn map_bio(&mut self, bio: &DmBio) -> MapResult {
        if !self.active { return MapResult::Error; }

        // Check if bio is within this target's range
        let offset = bio.sector.checked_sub(self.start_sector);
        let offset = match offset {
            Some(o) if o < self.length => o,
            _ => return MapResult::Error,
        };

        match self.ttype {
            DmTargetType::Linear => self.map_linear(bio, offset),
            DmTargetType::Striped => self.map_striped(bio, offset),
            DmTargetType::Mirror => self.map_mirror(bio, offset),
            DmTargetType::Zero => self.map_zero(bio),
            DmTargetType::Error => MapResult::Error,
            DmTargetType::Snapshot => self.map_snapshot(bio, offset),
            DmTargetType::SnapshotOrigin => self.map_linear(bio, offset),
            DmTargetType::Thin => self.map_thin(bio, offset),
            _ => MapResult::Error,
        }
    }

    fn map_linear(&mut self, bio: &DmBio, offset: u64) -> MapResult {
        let remapped = RemappedBio {
            dev_id: self.linear_dev,
            sector: self.linear_offset + offset,
            count: bio.count,
            dir: bio.dir,
            data_tag: bio.data_tag,
            valid: true,
        };
        self.update_stats(bio);
        MapResult::Mapped(remapped)
    }

    fn map_striped(&mut self, bio: &DmBio, offset: u64) -> MapResult {
        if self.stripe_count == 0 || self.stripe_size == 0 {
            return MapResult::Error;
        }
        let chunk = offset / self.stripe_size;
        let chunk_offset = offset % self.stripe_size;
        let leg_idx = (chunk % self.stripe_count as u64) as usize;

        if leg_idx >= self.stripe_count as usize || !self.stripe_legs[leg_idx].active {
            self.errors += 1;
            return MapResult::Error;
        }
        let leg = &self.stripe_legs[leg_idx];
        let stripe_chunk = chunk / self.stripe_count as u64;
        let dest_sector = leg.offset + stripe_chunk * self.stripe_size + chunk_offset;

        let remapped = RemappedBio {
            dev_id: leg.dev_id,
            sector: dest_sector,
            count: bio.count.min((self.stripe_size - chunk_offset) as u32),
            dir: bio.dir,
            data_tag: bio.data_tag,
            valid: true,
        };
        self.update_stats(bio);
        MapResult::Mapped(remapped)
    }

    fn map_mirror(&mut self, bio: &DmBio, offset: u64) -> MapResult {
        if self.mirror_count == 0 { return MapResult::Error; }

        match bio.dir {
            IoDir::Read => {
                // Round-robin read balancing
                let mut attempts = 0u8;
                loop {
                    let leg_idx = self.mirror_read_leg as usize;
                    self.mirror_read_leg = ((self.mirror_read_leg + 1) % self.mirror_count) as u8;
                    if leg_idx < self.mirror_count as usize
                        && self.mirror_legs[leg_idx].active
                        && !self.mirror_legs[leg_idx].failed
                    {
                        let leg = &self.mirror_legs[leg_idx];
                        let remapped = RemappedBio {
                            dev_id: leg.dev_id,
                            sector: leg.offset + offset,
                            count: bio.count,
                            dir: IoDir::Read,
                            data_tag: bio.data_tag,
                            valid: true,
                        };
                        self.update_stats(bio);
                        return MapResult::Mapped(remapped);
                    }
                    attempts += 1;
                    if attempts >= self.mirror_count { break; }
                }
                MapResult::Error
            }
            IoDir::Write => {
                // Write to first active leg (multi-write handled by caller)
                for i in 0..self.mirror_count as usize {
                    if self.mirror_legs[i].active && !self.mirror_legs[i].failed {
                        let leg = &self.mirror_legs[i];
                        let remapped = RemappedBio {
                            dev_id: leg.dev_id,
                            sector: leg.offset + offset,
                            count: bio.count,
                            dir: IoDir::Write,
                            data_tag: bio.data_tag,
                            valid: true,
                        };
                        self.update_stats(bio);
                        return MapResult::MirrorWrite(remapped, self.mirror_count);
                    }
                }
                MapResult::Error
            }
        }
    }

    fn map_zero(&mut self, bio: &DmBio) -> MapResult {
        self.update_stats(bio);
        MapResult::Zeroed
    }

    fn map_snapshot(&mut self, bio: &DmBio, offset: u64) -> MapResult {
        if self.snap_invalid { return MapResult::Error; }

        let chunk = offset / self.snap_chunk_size;

        match bio.dir {
            IoDir::Read => {
                // Check if this chunk has a COW exception
                for i in 0..self.snap_exception_count as usize {
                    if self.snap_exceptions[i].valid
                        && self.snap_exceptions[i].old_chunk == chunk
                    {
                        let cow_sector = self.snap_exceptions[i].new_chunk * self.snap_chunk_size
                            + (offset % self.snap_chunk_size);
                        let remapped = RemappedBio {
                            dev_id: self.snap_cow_dev,
                            sector: cow_sector,
                            count: bio.count,
                            dir: IoDir::Read,
                            data_tag: bio.data_tag,
                            valid: true,
                        };
                        self.update_stats(bio);
                        return MapResult::Mapped(remapped);
                    }
                }
                // No exception → read from origin
                let remapped = RemappedBio {
                    dev_id: self.snap_origin_dev,
                    sector: offset,
                    count: bio.count,
                    dir: IoDir::Read,
                    data_tag: bio.data_tag,
                    valid: true,
                };
                self.update_stats(bio);
                MapResult::Mapped(remapped)
            }
            IoDir::Write => {
                // COW: check if already remapped
                for i in 0..self.snap_exception_count as usize {
                    if self.snap_exceptions[i].valid
                        && self.snap_exceptions[i].old_chunk == chunk
                    {
                        let cow_sector = self.snap_exceptions[i].new_chunk * self.snap_chunk_size
                            + (offset % self.snap_chunk_size);
                        let remapped = RemappedBio {
                            dev_id: self.snap_cow_dev,
                            sector: cow_sector,
                            count: bio.count,
                            dir: IoDir::Write,
                            data_tag: bio.data_tag,
                            valid: true,
                        };
                        self.update_stats(bio);
                        return MapResult::Mapped(remapped);
                    }
                }
                // Allocate new COW exception
                if self.snap_exception_count as usize >= MAX_SNAP_EXCEPTIONS {
                    self.snap_invalid = true;
                    self.errors += 1;
                    return MapResult::Error; // Snapshot overflow
                }
                let new_chunk = self.snap_exception_count as u64;
                let idx = self.snap_exception_count as usize;
                self.snap_exceptions[idx] = SnapException {
                    old_chunk: chunk,
                    new_chunk,
                    valid: true,
                };
                self.snap_exception_count += 1;

                let cow_sector = new_chunk * self.snap_chunk_size
                    + (offset % self.snap_chunk_size);
                let remapped = RemappedBio {
                    dev_id: self.snap_cow_dev,
                    sector: cow_sector,
                    count: bio.count,
                    dir: IoDir::Write,
                    data_tag: bio.data_tag,
                    valid: true,
                };
                self.update_stats(bio);
                MapResult::CowWrite(remapped)
            }
        }
    }

    fn map_thin(&mut self, bio: &DmBio, offset: u64) -> MapResult {
        let block_size: u64 = 128; // 64KB blocks
        let block = offset / block_size;
        let block_offset = offset % block_size;

        // Look up virtual → physical mapping
        for i in 0..self.thin_map_count as usize {
            if self.thin_maps[i].allocated && self.thin_maps[i].virtual_block == block {
                let phys_sector = self.thin_maps[i].physical_block * block_size + block_offset;
                let remapped = RemappedBio {
                    dev_id: self.linear_dev, // Pool device
                    sector: phys_sector,
                    count: bio.count,
                    dir: bio.dir,
                    data_tag: bio.data_tag,
                    valid: true,
                };
                self.update_stats(bio);
                return MapResult::Mapped(remapped);
            }
        }

        // Not yet allocated
        match bio.dir {
            IoDir::Read => {
                // Unallocated thin read → return zeros
                self.update_stats(bio);
                MapResult::Zeroed
            }
            IoDir::Write => {
                // Allocate new block
                if self.thin_map_count as usize >= MAX_THIN_MAPS {
                    self.errors += 1;
                    return MapResult::Error;
                }
                let phys = self.thin_next_phys;
                self.thin_next_phys += 1;
                let idx = self.thin_map_count as usize;
                self.thin_maps[idx] = ThinBlockMap {
                    virtual_block: block,
                    physical_block: phys,
                    allocated: true,
                };
                self.thin_map_count += 1;

                let phys_sector = phys * block_size + block_offset;
                let remapped = RemappedBio {
                    dev_id: self.linear_dev,
                    sector: phys_sector,
                    count: bio.count,
                    dir: IoDir::Write,
                    data_tag: bio.data_tag,
                    valid: true,
                };
                self.update_stats(bio);
                MapResult::Mapped(remapped)
            }
        }
    }

    fn update_stats(&mut self, bio: &DmBio) {
        match bio.dir {
            IoDir::Read => {
                self.ios_read += 1;
                self.sectors_read += bio.count as u64;
            }
            IoDir::Write => {
                self.ios_write += 1;
                self.sectors_written += bio.count as u64;
            }
        }
    }
}

// ─────────────────── Map Result ─────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum MapResult {
    Mapped(RemappedBio),
    MirrorWrite(RemappedBio, u8),  // First leg + total count
    CowWrite(RemappedBio),
    Zeroed,
    Error,
}

// ─────────────────── DM Device ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct DmDevice {
    pub name: [u8; NAME_LEN],
    pub uuid: [u8; NAME_LEN],
    pub major: u16,
    pub minor: u16,
    pub state: DmDeviceState,

    pub targets: [DmTarget; MAX_TARGETS],
    pub target_count: u8,
    pub size_sectors: u64,

    // Pending table (for live swap)
    pub pending_targets: [DmTarget; MAX_TARGETS],
    pub pending_count: u8,
    pub has_pending: bool,

    // Global device stats
    pub total_ios: u64,
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_errors: u64,

    pub active: bool,
}

impl DmDevice {
    pub const fn new() -> Self {
        Self {
            name: [0u8; NAME_LEN],
            uuid: [0u8; NAME_LEN],
            major: 253,  // dm major
            minor: 0,
            state: DmDeviceState::Creating,
            targets: [const { DmTarget::new() }; MAX_TARGETS],
            target_count: 0,
            size_sectors: 0,
            pending_targets: [const { DmTarget::new() }; MAX_TARGETS],
            pending_count: 0,
            has_pending: false,
            total_ios: 0,
            total_reads: 0,
            total_writes: 0,
            total_errors: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(NAME_LEN - 1);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
    }

    /// Add a target to the active table
    pub fn add_target(&mut self, target: DmTarget) -> bool {
        if self.target_count as usize >= MAX_TARGETS { return false; }
        let idx = self.target_count as usize;
        self.targets[idx] = target;
        self.targets[idx].active = true;
        self.target_count += 1;
        // Update device size
        let end = target.start_sector + target.length;
        if end > self.size_sectors {
            self.size_sectors = end;
        }
        true
    }

    /// Add a target to the pending table (for live table swap)
    pub fn add_pending_target(&mut self, target: DmTarget) -> bool {
        if self.pending_count as usize >= MAX_TARGETS { return false; }
        let idx = self.pending_count as usize;
        self.pending_targets[idx] = target;
        self.pending_targets[idx].active = true;
        self.pending_count += 1;
        self.has_pending = true;
        true
    }

    /// Swap pending table to active (while suspended)
    pub fn swap_tables(&mut self) -> bool {
        if self.state != DmDeviceState::Suspended || !self.has_pending {
            return false;
        }
        // Deactivate old targets
        for i in 0..self.target_count as usize {
            self.targets[i].active = false;
        }
        // Copy pending → active
        self.targets = self.pending_targets;
        self.target_count = self.pending_count;
        self.size_sectors = 0;
        for i in 0..self.target_count as usize {
            let end = self.targets[i].start_sector + self.targets[i].length;
            if end > self.size_sectors {
                self.size_sectors = end;
            }
        }
        // Clear pending
        self.pending_count = 0;
        self.has_pending = false;
        true
    }

    pub fn suspend(&mut self) -> bool {
        if self.state != DmDeviceState::Active { return false; }
        self.state = DmDeviceState::Suspended;
        true
    }

    pub fn resume(&mut self) -> bool {
        if self.state == DmDeviceState::Suspended {
            if self.has_pending {
                self.swap_tables();
            }
            self.state = DmDeviceState::Active;
            return true;
        }
        if self.state == DmDeviceState::Creating && self.target_count > 0 {
            self.state = DmDeviceState::Active;
            return true;
        }
        false
    }

    /// Map a bio through the matching target
    pub fn map(&mut self, bio: &DmBio) -> MapResult {
        if self.state != DmDeviceState::Active {
            return MapResult::Error;
        }
        // Find target containing this sector
        for i in 0..self.target_count as usize {
            let t = &mut self.targets[i];
            if t.active
                && bio.sector >= t.start_sector
                && bio.sector < t.start_sector + t.length
            {
                let result = t.map_bio(bio);
                self.total_ios += 1;
                match bio.dir {
                    IoDir::Read => self.total_reads += 1,
                    IoDir::Write => self.total_writes += 1,
                }
                if matches!(result, MapResult::Error) {
                    self.total_errors += 1;
                }
                return result;
            }
        }
        self.total_errors += 1;
        MapResult::Error
    }
}

// ─────────────────── DM Manager ─────────────────────────────────────

pub struct DmManager {
    devices: [DmDevice; MAX_DM_DEVICES],
    device_count: u16,
    next_minor: u16,
    total_maps: u64,
    total_cow_writes: u64,
    total_thin_allocs: u64,
    initialized: bool,
}

impl DmManager {
    pub const fn new() -> Self {
        Self {
            devices: [const { DmDevice::new() }; MAX_DM_DEVICES],
            device_count: 0,
            next_minor: 0,
            total_maps: 0,
            total_cow_writes: 0,
            total_thin_allocs: 0,
            initialized: true,
        }
    }

    /// Create a new DM device
    pub fn create_device(&mut self, name: &[u8]) -> Option<u16> {
        if self.device_count as usize >= MAX_DM_DEVICES { return None; }
        for i in 0..MAX_DM_DEVICES {
            if !self.devices[i].active {
                self.devices[i] = DmDevice::new();
                self.devices[i].set_name(name);
                self.devices[i].minor = self.next_minor;
                self.devices[i].active = true;
                self.next_minor += 1;
                self.device_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    /// Remove a DM device
    pub fn remove_device(&mut self, idx: u16) -> bool {
        if (idx as usize) >= MAX_DM_DEVICES || !self.devices[idx as usize].active {
            return false;
        }
        self.devices[idx as usize].active = false;
        self.devices[idx as usize].state = DmDeviceState::Removing;
        self.device_count = self.device_count.saturating_sub(1);
        true
    }

    /// Add a linear target to a device
    pub fn add_linear_target(
        &mut self,
        dev_idx: u16,
        start: u64,
        length: u64,
        dest_dev: u16,
        dest_offset: u64,
    ) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return false;
        }
        let mut target = DmTarget::new();
        target.ttype = DmTargetType::Linear;
        target.start_sector = start;
        target.length = length;
        target.linear_dev = dest_dev;
        target.linear_offset = dest_offset;
        self.devices[dev_idx as usize].add_target(target)
    }

    /// Add a striped target
    pub fn add_stripe_target(
        &mut self,
        dev_idx: u16,
        start: u64,
        length: u64,
        stripe_size: u64,
        legs: &[(u16, u64)],  // (dev_id, offset) pairs
    ) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return false;
        }
        if legs.len() > MAX_STRIPE_LEGS || legs.is_empty() { return false; }

        let mut target = DmTarget::new();
        target.ttype = DmTargetType::Striped;
        target.start_sector = start;
        target.length = length;
        target.stripe_size = stripe_size;
        target.stripe_count = legs.len() as u8;
        for (i, &(dev, off)) in legs.iter().enumerate() {
            target.stripe_legs[i] = StripeLeg {
                dev_id: dev,
                offset: off,
                active: true,
            };
        }
        self.devices[dev_idx as usize].add_target(target)
    }

    /// Add a mirror target
    pub fn add_mirror_target(
        &mut self,
        dev_idx: u16,
        start: u64,
        length: u64,
        legs: &[(u16, u64)],
    ) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return false;
        }
        if legs.len() > MAX_MIRROR_LEGS || legs.is_empty() { return false; }

        let mut target = DmTarget::new();
        target.ttype = DmTargetType::Mirror;
        target.start_sector = start;
        target.length = length;
        target.mirror_count = legs.len() as u8;
        for (i, &(dev, off)) in legs.iter().enumerate() {
            target.mirror_legs[i] = MirrorLeg {
                dev_id: dev,
                offset: off,
                failed: false,
                active: true,
                read_count: 0,
                write_count: 0,
            };
        }
        self.devices[dev_idx as usize].add_target(target)
    }

    /// Add a snapshot target
    pub fn add_snapshot_target(
        &mut self,
        dev_idx: u16,
        start: u64,
        length: u64,
        origin_dev: u16,
        cow_dev: u16,
        chunk_size: u64,
    ) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return false;
        }
        let mut target = DmTarget::new();
        target.ttype = DmTargetType::Snapshot;
        target.start_sector = start;
        target.length = length;
        target.snap_origin_dev = origin_dev;
        target.snap_cow_dev = cow_dev;
        target.snap_chunk_size = chunk_size;
        self.devices[dev_idx as usize].add_target(target)
    }

    /// Add a thin target
    pub fn add_thin_target(
        &mut self,
        dev_idx: u16,
        start: u64,
        length: u64,
        pool_dev: u16,
        thin_id: u32,
    ) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return false;
        }
        let mut target = DmTarget::new();
        target.ttype = DmTargetType::Thin;
        target.start_sector = start;
        target.length = length;
        target.linear_dev = pool_dev;
        target.thin_dev_id = thin_id;
        self.devices[dev_idx as usize].add_target(target)
    }

    /// Suspend a device (drain in-flight I/O, prepare for table swap)
    pub fn suspend(&mut self, dev_idx: u16) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES { return false; }
        self.devices[dev_idx as usize].suspend()
    }

    /// Resume a device (activate pending table if any)
    pub fn resume(&mut self, dev_idx: u16) -> bool {
        if (dev_idx as usize) >= MAX_DM_DEVICES { return false; }
        self.devices[dev_idx as usize].resume()
    }

    /// Map a bio through a DM device
    pub fn map_bio(&mut self, dev_idx: u16, bio: &DmBio) -> MapResult {
        if (dev_idx as usize) >= MAX_DM_DEVICES || !self.devices[dev_idx as usize].active {
            return MapResult::Error;
        }
        let result = self.devices[dev_idx as usize].map(bio);
        self.total_maps += 1;
        if matches!(result, MapResult::CowWrite(_)) {
            self.total_cow_writes += 1;
        }
        result
    }

    pub fn device_count(&self) -> u16 { self.device_count }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_DM: DmManager = DmManager::new();
static mut G_DM_INIT: bool = false;

fn dm() -> &'static mut DmManager {
    unsafe { &mut G_DM }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_dm_init() {
    unsafe {
        G_DM = DmManager::new();
        G_DM_INIT = true;
    }
}

#[no_mangle]
pub extern "C" fn rust_dm_create(name_ptr: *const u8, name_len: u32) -> i16 {
    if unsafe { !G_DM_INIT } || name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match dm().create_device(name) {
        Some(idx) => idx as i16,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_dm_remove(idx: u16) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().remove_device(idx)
}

#[no_mangle]
pub extern "C" fn rust_dm_add_linear(dev: u16, start: u64, length: u64, dest_dev: u16, dest_off: u64) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().add_linear_target(dev, start, length, dest_dev, dest_off)
}

#[no_mangle]
pub extern "C" fn rust_dm_add_snapshot(dev: u16, start: u64, length: u64, origin: u16, cow: u16, chunk: u64) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().add_snapshot_target(dev, start, length, origin, cow, chunk)
}

#[no_mangle]
pub extern "C" fn rust_dm_add_thin(dev: u16, start: u64, length: u64, pool: u16, thin_id: u32) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().add_thin_target(dev, start, length, pool, thin_id)
}

#[no_mangle]
pub extern "C" fn rust_dm_suspend(dev: u16) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().suspend(dev)
}

#[no_mangle]
pub extern "C" fn rust_dm_resume(dev: u16) -> bool {
    if unsafe { !G_DM_INIT } { return false; }
    dm().resume(dev)
}

#[no_mangle]
pub extern "C" fn rust_dm_map(dev: u16, sector: u64, count: u32, is_write: bool) -> i64 {
    if unsafe { !G_DM_INIT } { return -1; }
    let bio = DmBio {
        sector,
        count,
        dir: if is_write { IoDir::Write } else { IoDir::Read },
        data_tag: 0,
    };
    match dm().map_bio(dev, &bio) {
        MapResult::Mapped(r) => r.sector as i64,
        MapResult::MirrorWrite(r, _) => r.sector as i64,
        MapResult::CowWrite(r) => r.sector as i64,
        MapResult::Zeroed => 0,
        MapResult::Error => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_dm_device_count() -> u16 {
    if unsafe { !G_DM_INIT } { return 0; }
    dm().device_count()
}

#[no_mangle]
pub extern "C" fn rust_dm_total_maps() -> u64 {
    if unsafe { !G_DM_INIT } { return 0; }
    dm().total_maps
}

#[no_mangle]
pub extern "C" fn rust_dm_total_cow() -> u64 {
    if unsafe { !G_DM_INIT } { return 0; }
    dm().total_cow_writes
}

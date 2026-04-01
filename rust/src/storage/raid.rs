// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust RAID / Device Mapper Subsystem
//
// Software RAID engine and logical volume device mapper:
// - RAID levels: 0 (stripe), 1 (mirror), 5 (distributed parity), 10 (stripe+mirror)
// - Device mapper framework for virtual block devices
// - Linear mapping, striped mapping, mirror mapping
// - Snapshot support (copy-on-write)
// - Thin provisioning
// - Integrity checking (checksums per stripe)

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_RAID_DISKS: usize = 32;
pub const MAX_DM_TARGETS: usize = 16;
pub const MAX_DM_DEVICES: usize = 32;
pub const STRIPE_SIZE: u64 = 65536; // 64 KiB default stripe
pub const SECTOR_SIZE: u64 = 512;
pub const SECTORS_PER_STRIPE: u64 = STRIPE_SIZE / SECTOR_SIZE;

// ─────────────────── Disk Component ─────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DiskState {
    Active,
    Degraded,
    Rebuilding,
    Failed,
    Spare,
    Missing,
}

#[repr(C)]
pub struct RaidDisk {
    pub id: u32,
    pub state: DiskState,
    pub total_sectors: u64,
    pub read_count: AtomicU64,
    pub write_count: AtomicU64,
    pub error_count: AtomicU32,
    /// Opaque handle identifying the underlying block device
    pub dev_handle: u64,
}

impl RaidDisk {
    pub const fn new(id: u32, total_sectors: u64, dev_handle: u64) -> Self {
        Self {
            id,
            state: DiskState::Active,
            total_sectors,
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            error_count: AtomicU32::new(0),
            dev_handle,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, DiskState::Active | DiskState::Rebuilding)
    }

    pub fn record_read(&self) {
        self.read_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_write(&self) {
        self.write_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }
}

// ─────────────────── RAID Level ─────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RaidLevel {
    Raid0,  // Striping only
    Raid1,  // Mirroring
    Raid5,  // Distributed parity
    Raid10, // Stripe of mirrors
}

impl RaidLevel {
    pub fn min_disks(&self) -> usize {
        match self {
            RaidLevel::Raid0 => 2,
            RaidLevel::Raid1 => 2,
            RaidLevel::Raid5 => 3,
            RaidLevel::Raid10 => 4,
        }
    }

    /// Number of disks that can fail without data loss
    pub fn fault_tolerance(&self, n_disks: usize) -> usize {
        match self {
            RaidLevel::Raid0 => 0,
            RaidLevel::Raid1 => n_disks.saturating_sub(1),
            RaidLevel::Raid5 => 1,
            RaidLevel::Raid10 => {
                // One per mirror group
                n_disks / 2
            }
        }
    }

    /// Usable capacity fraction
    pub fn capacity_ratio(&self, n_disks: usize) -> (usize, usize) {
        match self {
            RaidLevel::Raid0 => (n_disks, 1),       // n * disk
            RaidLevel::Raid1 => (1, 1),              // 1 * disk
            RaidLevel::Raid5 => (n_disks - 1, 1),   // (n-1) * disk
            RaidLevel::Raid10 => (n_disks / 2, 1),   // n/2 * disk
        }
    }
}

// ─────────────────── Stripe Map ─────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct StripeLocation {
    pub disk_index: usize,
    pub disk_sector: u64,
    pub parity_disk: Option<usize>,
}

/// Map a logical sector to physical stripe location for RAID 0
pub fn raid0_map(logical_sector: u64, n_disks: usize, stripe_sectors: u64) -> StripeLocation {
    let stripe = logical_sector / stripe_sectors;
    let offset_in_stripe = logical_sector % stripe_sectors;
    let disk_index = (stripe as usize) % n_disks;
    let disk_stripe = stripe / (n_disks as u64);
    let disk_sector = disk_stripe * stripe_sectors + offset_in_stripe;
    StripeLocation {
        disk_index,
        disk_sector,
        parity_disk: None,
    }
}

/// Map a logical sector for RAID 5 (left-symmetric layout)
pub fn raid5_map(logical_sector: u64, n_disks: usize, stripe_sectors: u64) -> StripeLocation {
    let data_disks = n_disks - 1;
    let stripe = logical_sector / stripe_sectors;
    let offset_in_stripe = logical_sector % stripe_sectors;
    let stripe_group = stripe / (data_disks as u64);
    let data_index_in_group = (stripe % (data_disks as u64)) as usize;

    // Left-symmetric: parity rotates
    let parity_disk = ((n_disks as u64 - 1) - (stripe_group % (n_disks as u64))) as usize;

    // Data disk index, skipping parity
    let mut disk_index = data_index_in_group;
    if disk_index >= parity_disk {
        disk_index += 1;
    }

    let disk_sector = stripe_group * stripe_sectors + offset_in_stripe;

    StripeLocation {
        disk_index,
        disk_sector,
        parity_disk: Some(parity_disk),
    }
}

/// Map a logical sector for RAID 10 (near layout)
pub fn raid10_map(logical_sector: u64, n_disks: usize, stripe_sectors: u64) -> (StripeLocation, StripeLocation) {
    let mirrors = n_disks / 2;
    let stripe = logical_sector / stripe_sectors;
    let offset_in_stripe = logical_sector % stripe_sectors;
    let mirror_group = (stripe as usize) % mirrors;
    let disk_stripe = stripe / (mirrors as u64);
    let disk_sector = disk_stripe * stripe_sectors + offset_in_stripe;

    let primary = StripeLocation {
        disk_index: mirror_group * 2,
        disk_sector,
        parity_disk: None,
    };
    let secondary = StripeLocation {
        disk_index: mirror_group * 2 + 1,
        disk_sector,
        parity_disk: None,
    };
    (primary, secondary)
}

// ─────────────────── RAID Array ─────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ArrayState {
    Active,
    Degraded,
    Rebuilding,
    Failed,
    Inactive,
}

pub struct RaidArray {
    pub id: u32,
    pub level: RaidLevel,
    pub state: ArrayState,
    pub n_disks: usize,
    pub stripe_sectors: u64,
    /// Total logical sectors available
    pub total_sectors: u64,
    /// Rebuild progress (sectors rebuilt)
    pub rebuild_progress: AtomicU64,
    pub rebuild_total: u64,
    /// Disk references (indices into a disk pool)
    pub disk_ids: [MAX_RAID_DISKS; u32],
    /// Per-stripe checksums (simplified: just xor of first bytes)
    pub checksums_enabled: bool,
    /// I/O statistics
    pub read_ios: AtomicU64,
    pub write_ios: AtomicU64,
    pub read_bytes: AtomicU64,
    pub write_bytes: AtomicU64,
}

impl RaidArray {
    pub fn new(id: u32, level: RaidLevel, n_disks: usize, disk_sectors: u64) -> Self {
        let stripe_sectors = SECTORS_PER_STRIPE;
        let (num, _den) = level.capacity_ratio(n_disks);
        let total_sectors = disk_sectors * (num as u64);

        Self {
            id,
            level,
            state: ArrayState::Active,
            n_disks,
            stripe_sectors,
            total_sectors,
            rebuild_progress: AtomicU64::new(0),
            rebuild_total: disk_sectors,
            disk_ids: [0u32; MAX_RAID_DISKS],
            checksums_enabled: true,
            read_ios: AtomicU64::new(0),
            write_ios: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
        }
    }

    /// Map a logical sector to physical location(s)
    pub fn map_sector(&self, logical_sector: u64) -> StripeLocation {
        match self.level {
            RaidLevel::Raid0 => raid0_map(logical_sector, self.n_disks, self.stripe_sectors),
            RaidLevel::Raid1 => {
                // Just read from first disk
                StripeLocation {
                    disk_index: 0,
                    disk_sector: logical_sector,
                    parity_disk: None,
                }
            }
            RaidLevel::Raid5 => raid5_map(logical_sector, self.n_disks, self.stripe_sectors),
            RaidLevel::Raid10 => {
                let (primary, _) = raid10_map(logical_sector, self.n_disks, self.stripe_sectors);
                primary
            }
        }
    }

    /// Get all targets for a write (mirrors, parity)
    pub fn write_targets(&self, logical_sector: u64) -> ([StripeLocation; MAX_RAID_DISKS], usize) {
        let mut targets: [StripeLocation; MAX_RAID_DISKS] = [StripeLocation {
            disk_index: 0,
            disk_sector: 0,
            parity_disk: None,
        }; MAX_RAID_DISKS];
        let count;

        match self.level {
            RaidLevel::Raid0 => {
                targets[0] = raid0_map(logical_sector, self.n_disks, self.stripe_sectors);
                count = 1;
            }
            RaidLevel::Raid1 => {
                // Write to all mirrors
                count = self.n_disks;
                for i in 0..self.n_disks {
                    targets[i] = StripeLocation {
                        disk_index: i,
                        disk_sector: logical_sector,
                        parity_disk: None,
                    };
                }
            }
            RaidLevel::Raid5 => {
                let loc = raid5_map(logical_sector, self.n_disks, self.stripe_sectors);
                targets[0] = loc;
                // Also update parity
                if let Some(pd) = loc.parity_disk {
                    targets[1] = StripeLocation {
                        disk_index: pd,
                        disk_sector: loc.disk_sector,
                        parity_disk: None,
                    };
                    count = 2;
                } else {
                    count = 1;
                }
            }
            RaidLevel::Raid10 => {
                let (p, s) = raid10_map(logical_sector, self.n_disks, self.stripe_sectors);
                targets[0] = p;
                targets[1] = s;
                count = 2;
            }
        }
        (targets, count)
    }

    pub fn record_read(&self, bytes: u64) {
        self.read_ios.fetch_add(1, Ordering::Relaxed);
        self.read_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_write(&self, bytes: u64) {
        self.write_ios.fetch_add(1, Ordering::Relaxed);
        self.write_bytes.fetch_add(bytes, Ordering::Relaxed);
    }
}

// ─────────────────── XOR Parity ─────────────────────────────────────
/// Compute XOR parity of multiple data buffers
pub fn xor_parity(buffers: &[&[u8]], output: &mut [u8]) {
    if buffers.is_empty() {
        return;
    }
    let len = output.len();
    // Initialize from first buffer
    for i in 0..len {
        output[i] = if i < buffers[0].len() { buffers[0][i] } else { 0 };
    }
    // XOR remaining buffers
    for buf in &buffers[1..] {
        for i in 0..len {
            if i < buf.len() {
                output[i] ^= buf[i];
            }
        }
    }
}

/// Recover a missing disk's data from other disks + parity
pub fn recover_from_parity(present: &[&[u8]], parity: &[u8], output: &mut [u8]) {
    let len = output.len();
    // Start with parity
    for i in 0..len {
        output[i] = if i < parity.len() { parity[i] } else { 0 };
    }
    // XOR each present disk
    for buf in present {
        for i in 0..len {
            if i < buf.len() {
                output[i] ^= buf[i];
            }
        }
    }
}

// ─────────────────── Device Mapper ──────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmTargetType {
    Linear,
    Striped,
    Mirror,
    Snapshot,
    Thin,
    Zero,
    Error,
    Crypt,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DmTarget {
    pub target_type: DmTargetType,
    pub start_sector: u64,
    pub length: u64,
    /// For linear: the underlying device sector offset
    pub dev_sector_offset: u64,
    /// For linear/striped: underlying device handle
    pub dev_handle: u64,
    /// For striped: stripe size in sectors
    pub stripe_size: u64,
    /// For striped: number of stripe devices
    pub stripe_count: u32,
    /// For mirror: number of mirrors
    pub mirror_count: u32,
    /// Active flag
    pub active: bool,
}

impl DmTarget {
    pub const fn linear(start: u64, len: u64, dev: u64, offset: u64) -> Self {
        Self {
            target_type: DmTargetType::Linear,
            start_sector: start,
            length: len,
            dev_sector_offset: offset,
            dev_handle: dev,
            stripe_size: 0,
            stripe_count: 0,
            mirror_count: 0,
            active: true,
        }
    }

    pub const fn zero(start: u64, len: u64) -> Self {
        Self {
            target_type: DmTargetType::Zero,
            start_sector: start,
            length: len,
            dev_sector_offset: 0,
            dev_handle: 0,
            stripe_size: 0,
            stripe_count: 0,
            mirror_count: 0,
            active: true,
        }
    }

    pub const fn error_target(start: u64, len: u64) -> Self {
        Self {
            target_type: DmTargetType::Error,
            start_sector: start,
            length: len,
            dev_sector_offset: 0,
            dev_handle: 0,
            stripe_size: 0,
            stripe_count: 0,
            mirror_count: 0,
            active: true,
        }
    }

    /// Map an I/O sector from virtual to physical
    pub fn map_sector(&self, virtual_sector: u64) -> Option<(u64, u64)> {
        if virtual_sector < self.start_sector || virtual_sector >= self.start_sector + self.length {
            return None;
        }
        let offset = virtual_sector - self.start_sector;
        match self.target_type {
            DmTargetType::Linear => {
                Some((self.dev_handle, self.dev_sector_offset + offset))
            }
            DmTargetType::Zero => {
                Some((0, 0)) // reads zero, writes discard
            }
            DmTargetType::Error => None,
            _ => {
                // Striped/mirror handled at DM device level
                Some((self.dev_handle, self.dev_sector_offset + offset))
            }
        }
    }
}

// ─────────────────── DM Device ──────────────────────────────────────
pub struct DmDevice {
    pub id: u32,
    pub name: [u8; 32],
    pub name_len: usize,
    pub targets: [DmTarget; MAX_DM_TARGETS],
    pub target_count: usize,
    pub total_sectors: u64,
    pub read_only: bool,
    pub suspended: bool,
    pub active: bool,
    pub read_ios: AtomicU64,
    pub write_ios: AtomicU64,
}

impl DmDevice {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            name: [0u8; 32],
            name_len: 0,
            targets: [DmTarget::zero(0, 0); MAX_DM_TARGETS],
            target_count: 0,
            total_sectors: 0,
            read_only: false,
            suspended: false,
            active: false,
            read_ios: AtomicU64::new(0),
            write_ios: AtomicU64::new(0),
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > 32 { 32 } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    pub fn add_target(&mut self, target: DmTarget) -> bool {
        if self.target_count >= MAX_DM_TARGETS {
            return false;
        }
        self.targets[self.target_count] = target;
        self.target_count += 1;
        // Update total sectors
        let end = target.start_sector + target.length;
        if end > self.total_sectors {
            self.total_sectors = end;
        }
        true
    }

    /// Look up which target handles a given sector
    pub fn find_target(&self, sector: u64) -> Option<&DmTarget> {
        for i in 0..self.target_count {
            let t = &self.targets[i];
            if t.active && sector >= t.start_sector && sector < t.start_sector + t.length {
                return Some(t);
            }
        }
        None
    }

    /// Map a virtual sector to (dev_handle, physical_sector)
    pub fn map_io(&self, sector: u64) -> Option<(u64, u64)> {
        if let Some(target) = self.find_target(sector) {
            return target.map_sector(sector);
        }
        None
    }

    pub fn suspend(&mut self) {
        self.suspended = true;
    }

    pub fn resume(&mut self) {
        self.suspended = false;
    }

    pub fn activate(&mut self) {
        self.active = true;
        self.suspended = false;
    }
}

// ─────────────────── Snapshot (COW) ─────────────────────────────────
pub const SNAP_CHUNK_SIZE: u64 = 8; // sectors per chunk

#[derive(Debug, Clone, Copy)]
pub struct SnapChunkMapping {
    pub origin_chunk: u64,
    pub cow_chunk: u64,
    pub valid: bool,
}

pub struct SnapshotStore {
    pub origin_dev: u64,
    pub cow_dev: u64,
    pub chunk_size: u64,
    pub chunks: [SnapChunkMapping; 4096],
    pub chunk_count: usize,
    pub cow_next_free: u64,
    pub total_origin_chunks: u64,
    pub exception_count: AtomicU64,
}

impl SnapshotStore {
    pub fn new(origin_dev: u64, cow_dev: u64, origin_sectors: u64) -> Self {
        Self {
            origin_dev,
            cow_dev,
            chunk_size: SNAP_CHUNK_SIZE,
            chunks: [SnapChunkMapping {
                origin_chunk: 0,
                cow_chunk: 0,
                valid: false,
            }; 4096],
            chunk_count: 0,
            cow_next_free: 0,
            total_origin_chunks: origin_sectors / SNAP_CHUNK_SIZE,
            exception_count: AtomicU64::new(0),
        }
    }

    /// Find an existing COW mapping for origin chunk
    pub fn find_chunk(&self, origin_chunk: u64) -> Option<u64> {
        for i in 0..self.chunk_count {
            if self.chunks[i].valid && self.chunks[i].origin_chunk == origin_chunk {
                return Some(self.chunks[i].cow_chunk);
            }
        }
        None
    }

    /// Allocate a new COW chunk for an origin chunk
    pub fn allocate_chunk(&mut self, origin_chunk: u64) -> Option<u64> {
        if self.chunk_count >= 4096 {
            return None;
        }
        let cow_chunk = self.cow_next_free;
        self.cow_next_free += 1;

        self.chunks[self.chunk_count] = SnapChunkMapping {
            origin_chunk,
            cow_chunk,
            valid: true,
        };
        self.chunk_count += 1;
        self.exception_count.fetch_add(1, Ordering::Relaxed);
        Some(cow_chunk)
    }

    /// Map read: return COW chunk if exists, else origin
    pub fn map_read(&self, sector: u64) -> (u64, u64) {
        let chunk = sector / self.chunk_size;
        let offset = sector % self.chunk_size;
        if let Some(cow) = self.find_chunk(chunk) {
            (self.cow_dev, cow * self.chunk_size + offset)
        } else {
            (self.origin_dev, sector)
        }
    }

    /// Map write: allocate COW chunk if needed, then write there
    pub fn map_write(&mut self, sector: u64) -> Option<(u64, u64)> {
        let chunk = sector / self.chunk_size;
        let offset = sector % self.chunk_size;
        let cow = if let Some(existing) = self.find_chunk(chunk) {
            existing
        } else {
            self.allocate_chunk(chunk)?
        };
        Some((self.cow_dev, cow * self.chunk_size + offset))
    }
}

// ─────────────────── Thin Provisioning ──────────────────────────────
#[derive(Debug, Clone, Copy)]
pub struct ThinBlockMapping {
    pub virtual_block: u64,
    pub physical_block: u64,
    pub allocated: bool,
}

pub struct ThinPool {
    pub pool_dev: u64,
    pub block_size: u64, // sectors per block
    pub total_blocks: u64,
    pub used_blocks: AtomicU64,
    pub mappings: [ThinBlockMapping; 8192],
    pub mapping_count: usize,
    pub overprovisioned: bool,
}

impl ThinPool {
    pub fn new(pool_dev: u64, total_sectors: u64, block_size: u64) -> Self {
        Self {
            pool_dev,
            block_size,
            total_blocks: total_sectors / block_size,
            used_blocks: AtomicU64::new(0),
            mappings: [ThinBlockMapping {
                virtual_block: 0,
                physical_block: 0,
                allocated: false,
            }; 8192],
            mapping_count: 0,
            overprovisioned: false,
        }
    }

    pub fn allocate_block(&mut self, virtual_block: u64) -> Option<u64> {
        let used = self.used_blocks.load(Ordering::Relaxed);
        if used >= self.total_blocks {
            self.overprovisioned = true;
            return None;
        }
        if self.mapping_count >= 8192 {
            return None;
        }
        let physical = used;
        self.used_blocks.fetch_add(1, Ordering::Relaxed);
        self.mappings[self.mapping_count] = ThinBlockMapping {
            virtual_block,
            physical_block: physical,
            allocated: true,
        };
        self.mapping_count += 1;
        Some(physical)
    }

    pub fn lookup(&self, virtual_block: u64) -> Option<u64> {
        for i in 0..self.mapping_count {
            if self.mappings[i].allocated && self.mappings[i].virtual_block == virtual_block {
                return Some(self.mappings[i].physical_block);
            }
        }
        None
    }

    pub fn map_io(&mut self, sector: u64) -> Option<(u64, u64)> {
        let block = sector / self.block_size;
        let offset = sector % self.block_size;
        let phys = if let Some(p) = self.lookup(block) {
            p
        } else {
            self.allocate_block(block)?
        };
        Some((self.pool_dev, phys * self.block_size + offset))
    }

    pub fn utilization_pct(&self) -> u64 {
        let used = self.used_blocks.load(Ordering::Relaxed);
        if self.total_blocks == 0 {
            return 0;
        }
        (used * 100) / self.total_blocks
    }
}

// ─────────────────── DM Registry ────────────────────────────────────
pub struct DmRegistry {
    pub devices: [Option<DmDevice>; MAX_DM_DEVICES],
    pub device_count: usize,
    pub initialized: bool,
}

impl DmRegistry {
    pub const fn new() -> Self {
        // We cannot use Option<DmDevice> in const; use a function approach
        Self {
            devices: [const { None }; MAX_DM_DEVICES],
            device_count: 0,
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    pub fn create_device(&mut self, name: &[u8]) -> Option<u32> {
        if self.device_count >= MAX_DM_DEVICES {
            return None;
        }
        for (i, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                let mut dev = DmDevice::new(i as u32);
                dev.set_name(name);
                dev.activate();
                *slot = Some(dev);
                self.device_count += 1;
                return Some(i as u32);
            }
        }
        None
    }

    pub fn get_device(&self, id: u32) -> Option<&DmDevice> {
        if (id as usize) < MAX_DM_DEVICES {
            self.devices[id as usize].as_ref()
        } else {
            None
        }
    }

    pub fn get_device_mut(&mut self, id: u32) -> Option<&mut DmDevice> {
        if (id as usize) < MAX_DM_DEVICES {
            self.devices[id as usize].as_mut()
        } else {
            None
        }
    }

    pub fn remove_device(&mut self, id: u32) -> bool {
        if (id as usize) < MAX_DM_DEVICES {
            if self.devices[id as usize].is_some() {
                self.devices[id as usize] = None;
                self.device_count = self.device_count.saturating_sub(1);
                return true;
            }
        }
        false
    }
}

// ─────────────────── Integrity Checker ──────────────────────────────
/// Simple CRC-like integrity check for stripe data
pub fn stripe_checksum(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Verify a stripe's integrity
pub fn verify_stripe(data: &[u8], expected_checksum: u32) -> bool {
    stripe_checksum(data) == expected_checksum
}

// ─────────────────── Static Globals ─────────────────────────────────
static mut DM_REGISTRY: DmRegistry = DmRegistry::new();
static DM_INIT: AtomicBool = AtomicBool::new(false);

pub fn init_dm() {
    unsafe {
        DM_REGISTRY.init();
    }
    DM_INIT.store(true, Ordering::Release);
}

pub fn dm_create(name: &[u8]) -> Option<u32> {
    unsafe { DM_REGISTRY.create_device(name) }
}

pub fn dm_add_linear(id: u32, start: u64, len: u64, dev: u64, offset: u64) -> bool {
    unsafe {
        if let Some(device) = DM_REGISTRY.get_device_mut(id) {
            return device.add_target(DmTarget::linear(start, len, dev, offset));
        }
    }
    false
}

// ─────────────────── FFI Exports ────────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_raid_xor_parity(bufs: *const *const u8, buf_lens: *const usize, count: usize, output: *mut u8, output_len: usize) {
    if bufs.is_null() || output.is_null() || count == 0 {
        return;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(output, output_len) };
    // Initialize output to zero
    for b in out.iter_mut() {
        *b = 0;
    }
    for i in 0..count {
        let ptr = unsafe { *bufs.add(i) };
        let len = unsafe { *buf_lens.add(i) };
        if !ptr.is_null() {
            let buf = unsafe { core::slice::from_raw_parts(ptr, len) };
            for j in 0..output_len {
                if j < buf.len() {
                    out[j] ^= buf[j];
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_dm_init() {
    init_dm();
}

#[no_mangle]
pub extern "C" fn rust_dm_create(name_ptr: *const u8, name_len: usize) -> i32 {
    if name_ptr.is_null() || name_len == 0 {
        return -1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    match dm_create(name) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_dm_add_linear(id: u32, start: u64, len: u64, dev: u64, offset: u64) -> bool {
    dm_add_linear(id, start, len, dev, offset)
}

#[no_mangle]
pub extern "C" fn rust_stripe_checksum(data: *const u8, len: usize) -> u32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    stripe_checksum(slice)
}

#[no_mangle]
pub extern "C" fn rust_raid5_map_disk(logical_sector: u64, n_disks: u32, stripe_sectors: u64) -> u32 {
    let loc = raid5_map(logical_sector, n_disks as usize, stripe_sectors);
    loc.disk_index as u32
}

#[no_mangle]
pub extern "C" fn rust_raid5_map_sector(logical_sector: u64, n_disks: u32, stripe_sectors: u64) -> u64 {
    let loc = raid5_map(logical_sector, n_disks as usize, stripe_sectors);
    loc.disk_sector
}

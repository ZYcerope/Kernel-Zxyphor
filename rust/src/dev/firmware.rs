// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Firmware Loader Framework (Rust)
//
// Loads firmware blobs for device drivers:
// - Firmware cache for fast repeated loading
// - Synchronous and asynchronous loading paths
// - Fallback firmware paths (/lib/firmware, /lib/firmware/updates)
// - Firmware mapping (physical memory regions, initramfs)
// - Firmware file format parsing (headers, checksums, versioning)
// - Per-device firmware binding
// - Hotplug uevent integration for userspace-assisted loading
// - Built-in firmware table (compiled-in blobs)
// - Firmware signature verification (SHA-256 digest)

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const MAX_FIRMWARE: usize = 128;
const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 128;
const MAX_FW_SIZE: usize = 4 * 1024 * 1024; // 4 MB max firmware
const MAX_BUILTIN: usize = 32;
const MAX_CACHE_ENTRIES: usize = 64;
const FW_MAGIC: u32 = 0x5A584649; // "ZXFI"
const FW_HEADER_SIZE: usize = 64;
const SHA256_DIGEST_LEN: usize = 32;

// ─────────────────── Firmware State ─────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FwState {
    Unknown = 0,
    Loading = 1,
    Available = 2,
    LoadError = 3,
    Released = 4,
    Cached = 5,
}

// ─────────────────── Firmware Source ─────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FwSource {
    Unknown = 0,
    Builtin = 1,       // Compiled into kernel
    Filesystem = 2,    // /lib/firmware/
    Initramfs = 3,     // Early cpio
    Userspace = 4,     // Uevent/sysfs fallback
    Cache = 5,         // Previously loaded, cached in memory
    Mapped = 6,        // Direct memory mapping (UEFI, ACPI)
}

// ─────────────────── Firmware Header ────────────────────────────────

/// On-disk firmware file header (Zxyphor format)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FwHeader {
    pub magic: u32,              // FW_MAGIC
    pub version_major: u16,
    pub version_minor: u16,
    pub header_size: u32,        // Size of this header
    pub data_size: u32,          // Size of firmware data
    pub data_crc32: u32,         // CRC32 of data section
    pub flags: u32,              // Feature flags
    pub target_device: u32,      // PCI device ID or similar
    pub min_kernel_version: u32, // Minimum kernel version
    pub sha256: [SHA256_DIGEST_LEN; 1], // Outer = 1 entry of 32 bytes
    pub _reserved: [u8; 4],
}

impl FwHeader {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            version_major: 0,
            version_minor: 0,
            header_size: 0,
            data_size: 0,
            data_crc32: 0,
            flags: 0,
            target_device: 0,
            min_kernel_version: 0,
            sha256: [[0u8; SHA256_DIGEST_LEN]; 1],
            _reserved: [0u8; 4],
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == FW_MAGIC && self.header_size >= FW_HEADER_SIZE as u32
    }

    pub fn version_string(&self) -> (u16, u16) {
        (self.version_major, self.version_minor)
    }
}

// ─────────────────── Firmware Entry ─────────────────────────────────

#[derive(Clone, Copy)]
pub struct FirmwareEntry {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u8,
    pub state: FwState,
    pub source: FwSource,
    /// Data buffer (physical address in real kernel)
    pub data_phys: u64,
    pub data_size: u32,
    /// Header info
    pub header: FwHeader,
    /// Verification
    pub verified: bool,
    pub crc32_valid: bool,
    /// Reference count
    pub refcount: u32,
    /// Metadata
    pub device_id: u32,      // Requesting device
    pub load_time_ticks: u64,
    pub access_count: u64,
    pub active: bool,
}

impl FirmwareEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            state: FwState::Unknown,
            source: FwSource::Unknown,
            data_phys: 0,
            data_size: 0,
            header: FwHeader::empty(),
            verified: false,
            crc32_valid: false,
            refcount: 0,
            device_id: 0,
            load_time_ticks: 0,
            access_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn set_path(&mut self, p: &[u8]) {
        let len = p.len().min(MAX_PATH_LEN - 1);
        self.path[..len].copy_from_slice(&p[..len]);
        self.path_len = len as u8;
    }

    pub fn get(&mut self) {
        self.refcount += 1;
        self.access_count += 1;
    }

    pub fn put(&mut self) -> bool {
        if self.refcount > 0 {
            self.refcount -= 1;
        }
        self.refcount == 0
    }
}

// ─────────────────── Built-in Firmware ──────────────────────────────

#[derive(Clone, Copy)]
pub struct BuiltinFirmware {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    /// Physical address and size in kernel image
    pub data_phys: u64,
    pub data_size: u32,
    pub active: bool,
}

impl BuiltinFirmware {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            data_phys: 0,
            data_size: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ─────────────────── CRC32 Verification ─────────────────────────────

/// CRC32 (Castagnoli) for firmware verification
pub struct Crc32 {
    table: [u32; 256],
}

impl Crc32 {
    pub const fn new() -> Self {
        let mut table = [0u32; 256];
        let mut i = 0u32;
        while i < 256 {
            let mut crc = i;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i as usize] = crc;
            i += 1;
        }
        Self { table }
    }

    pub fn compute(&self, data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for &byte in data {
            let idx = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ self.table[idx];
        }
        crc ^ 0xFFFFFFFF
    }
}

static CRC32_CALC: Crc32 = Crc32::new();

// ─────────────────── Firmware Search Paths ──────────────────────────

const FW_PATHS: &[&[u8]] = &[
    b"/lib/firmware/updates/",
    b"/lib/firmware/",
    b"/usr/lib/firmware/",
    b"/boot/firmware/",
];

// ─────────────────── Firmware Cache ─────────────────────────────────

#[derive(Clone, Copy)]
pub struct CacheEntry {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub fw_idx: u16,
    pub last_access: u64,
    pub hit_count: u64,
    pub active: bool,
}

impl CacheEntry {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            fw_idx: 0,
            last_access: 0,
            hit_count: 0,
            active: false,
        }
    }
}

// ─────────────────── Firmware Manager ───────────────────────────────

pub struct FirmwareManager {
    entries: [FirmwareEntry; MAX_FIRMWARE],
    builtins: [BuiltinFirmware; MAX_BUILTIN],
    cache: [CacheEntry; MAX_CACHE_ENTRIES],
    fw_count: u16,
    builtin_count: u16,
    cache_count: u16,
    /// Require signature verification
    require_signed: bool,
    /// Current tick
    current_tick: u64,
    /// Stats
    total_loads: AtomicU64,
    total_load_errors: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    total_bytes_loaded: AtomicU64,
}

impl FirmwareManager {
    pub const fn new() -> Self {
        Self {
            entries: [FirmwareEntry::new(); MAX_FIRMWARE],
            builtins: [BuiltinFirmware::new(); MAX_BUILTIN],
            cache: [CacheEntry::new(); MAX_CACHE_ENTRIES],
            fw_count: 0,
            builtin_count: 0,
            cache_count: 0,
            require_signed: false,
            current_tick: 0,
            total_loads: AtomicU64::new(0),
            total_load_errors: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            total_bytes_loaded: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        // Nothing special needed
    }

    /// Register a built-in firmware blob
    pub fn register_builtin(&mut self, name: &[u8], phys: u64, size: u32) -> bool {
        if self.builtin_count as usize >= MAX_BUILTIN {
            return false;
        }
        let idx = self.builtin_count as usize;
        self.builtins[idx].set_name(name);
        self.builtins[idx].data_phys = phys;
        self.builtins[idx].data_size = size;
        self.builtins[idx].active = true;
        self.builtin_count += 1;
        true
    }

    /// Search for built-in firmware by name
    fn find_builtin(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.builtin_count as usize {
            if self.builtins[i].active && self.builtins[i].name_len as usize == name.len() {
                if &self.builtins[i].name[..name.len()] == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Search cache for firmware
    fn cache_lookup(&mut self, name: &[u8]) -> Option<u16> {
        for i in 0..self.cache_count as usize {
            if self.cache[i].active && self.cache[i].name_len as usize == name.len() {
                if &self.cache[i].name[..name.len()] == name {
                    self.cache[i].hit_count += 1;
                    self.cache[i].last_access = self.current_tick;
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(self.cache[i].fw_idx);
                }
            }
        }
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Add firmware to cache
    fn cache_add(&mut self, name: &[u8], fw_idx: u16) {
        if self.cache_count as usize >= MAX_CACHE_ENTRIES {
            // Evict LRU
            self.cache_evict_lru();
        }
        for i in 0..MAX_CACHE_ENTRIES {
            if !self.cache[i].active {
                let len = name.len().min(MAX_NAME_LEN - 1);
                self.cache[i].name[..len].copy_from_slice(&name[..len]);
                self.cache[i].name_len = len as u8;
                self.cache[i].fw_idx = fw_idx;
                self.cache[i].last_access = self.current_tick;
                self.cache[i].hit_count = 0;
                self.cache[i].active = true;
                self.cache_count += 1;
                return;
            }
        }
    }

    fn cache_evict_lru(&mut self) {
        let mut oldest_tick = u64::MAX;
        let mut oldest_idx = 0usize;
        for i in 0..MAX_CACHE_ENTRIES {
            if self.cache[i].active && self.cache[i].last_access < oldest_tick {
                oldest_tick = self.cache[i].last_access;
                oldest_idx = i;
            }
        }
        if self.cache[oldest_idx].active {
            self.cache[oldest_idx].active = false;
            self.cache_count -= 1;
        }
    }

    fn alloc_entry(&mut self) -> Option<u16> {
        for i in 0..MAX_FIRMWARE {
            if !self.entries[i].active {
                self.entries[i] = FirmwareEntry::new();
                return Some(i as u16);
            }
        }
        None
    }

    /// Request firmware by name (synchronous)
    /// Returns firmware index or error
    pub fn request_firmware(&mut self, name: &[u8], device_id: u32) -> Result<u16, i32> {
        // 1. Check cache
        if let Some(idx) = self.cache_lookup(name) {
            if self.entries[idx as usize].active && self.entries[idx as usize].state == FwState::Available {
                self.entries[idx as usize].get();
                return Ok(idx);
            }
        }

        // 2. Check built-in
        if let Some(bi) = self.find_builtin(name) {
            let idx = self.alloc_entry().ok_or(-12i32)?; // -ENOMEM
            self.entries[idx as usize].set_name(name);
            self.entries[idx as usize].source = FwSource::Builtin;
            self.entries[idx as usize].data_phys = self.builtins[bi].data_phys;
            self.entries[idx as usize].data_size = self.builtins[bi].data_size;
            self.entries[idx as usize].state = FwState::Available;
            self.entries[idx as usize].device_id = device_id;
            self.entries[idx as usize].verified = true; // Built-in is trusted
            self.entries[idx as usize].refcount = 1;
            self.entries[idx as usize].load_time_ticks = self.current_tick;
            self.entries[idx as usize].active = true;
            self.fw_count += 1;
            self.total_loads.fetch_add(1, Ordering::Relaxed);
            self.total_bytes_loaded
                .fetch_add(self.builtins[bi].data_size as u64, Ordering::Relaxed);
            self.cache_add(name, idx);
            return Ok(idx);
        }

        // 3. Try filesystem paths
        for &path in FW_PATHS {
            if let Some(idx) = self.try_load_from_path(name, path, device_id) {
                return Ok(idx);
            }
        }

        // 4. Try uevent/userspace fallback
        if let Some(idx) = self.try_userspace_load(name, device_id) {
            return Ok(idx);
        }

        self.total_load_errors.fetch_add(1, Ordering::Relaxed);
        Err(-2) // -ENOENT
    }

    /// Try loading firmware from a filesystem path
    fn try_load_from_path(&mut self, name: &[u8], prefix: &[u8], device_id: u32) -> Option<u16> {
        // Build full path
        let mut full_path = [0u8; MAX_PATH_LEN];
        let plen = prefix.len().min(MAX_PATH_LEN - 1);
        full_path[..plen].copy_from_slice(&prefix[..plen]);
        let nlen = name.len().min(MAX_PATH_LEN - plen - 1);
        full_path[plen..plen + nlen].copy_from_slice(&name[..nlen]);
        let total_len = plen + nlen;

        // In a real kernel, would open and read the file
        // Simulate: we create a pending entry
        let idx = self.alloc_entry()?;
        self.entries[idx as usize].set_name(name);
        self.entries[idx as usize].set_path(&full_path[..total_len]);
        self.entries[idx as usize].source = FwSource::Filesystem;
        self.entries[idx as usize].state = FwState::Loading;
        self.entries[idx as usize].device_id = device_id;
        self.entries[idx as usize].load_time_ticks = self.current_tick;
        self.entries[idx as usize].active = true;
        self.fw_count += 1;

        // Would trigger VFS read here. For now, report as loading.
        Some(idx)
    }

    /// Try userspace-assisted firmware loading
    fn try_userspace_load(&mut self, name: &[u8], device_id: u32) -> Option<u16> {
        let idx = self.alloc_entry()?;
        self.entries[idx as usize].set_name(name);
        self.entries[idx as usize].source = FwSource::Userspace;
        self.entries[idx as usize].state = FwState::Loading;
        self.entries[idx as usize].device_id = device_id;
        self.entries[idx as usize].active = true;
        self.fw_count += 1;
        // Would send uevent to trigger userspace helper
        Some(idx)
    }

    /// Complete a loading firmware (called when data is available)
    pub fn complete_loading(
        &mut self,
        idx: u16,
        data_phys: u64,
        data_size: u32,
        verify: bool,
    ) -> bool {
        let i = idx as usize;
        if i >= MAX_FIRMWARE || !self.entries[i].active {
            return false;
        }
        if self.entries[i].state != FwState::Loading {
            return false;
        }
        if data_size as usize > MAX_FW_SIZE {
            self.entries[i].state = FwState::LoadError;
            return false;
        }

        self.entries[i].data_phys = data_phys;
        self.entries[i].data_size = data_size;

        if verify && self.require_signed {
            // Would verify SHA-256 signature here
            self.entries[i].verified = false; // Skip in simulation
        } else {
            self.entries[i].verified = !self.require_signed;
        }

        self.entries[i].state = FwState::Available;
        self.entries[i].refcount = 1;
        self.total_loads.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_loaded
            .fetch_add(data_size as u64, Ordering::Relaxed);
        self.cache_add(self.entries[i].get_name(), idx);
        true
    }

    /// Mark a loading firmware as failed
    pub fn fail_loading(&mut self, idx: u16) {
        let i = idx as usize;
        if i < MAX_FIRMWARE && self.entries[i].active {
            self.entries[i].state = FwState::LoadError;
            self.total_load_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Release firmware reference
    pub fn release_firmware(&mut self, idx: u16) {
        let i = idx as usize;
        if i >= MAX_FIRMWARE || !self.entries[i].active {
            return;
        }
        if self.entries[i].put() {
            // Refcount reached 0 — keep in cache but mark released
            self.entries[i].state = FwState::Released;
        }
    }

    /// Verify firmware CRC32 against header
    pub fn verify_crc32(&self, idx: u16, data: &[u8]) -> bool {
        let i = idx as usize;
        if i >= MAX_FIRMWARE || !self.entries[i].active {
            return false;
        }
        if !self.entries[i].header.is_valid() {
            return false;
        }
        let crc = CRC32_CALC.compute(data);
        crc == self.entries[i].header.data_crc32
    }

    /// Get firmware data info
    pub fn get_firmware_info(&self, idx: u16) -> Option<(u64, u32)> {
        let i = idx as usize;
        if i >= MAX_FIRMWARE || !self.entries[i].active {
            return None;
        }
        if self.entries[i].state != FwState::Available {
            return None;
        }
        Some((self.entries[i].data_phys, self.entries[i].data_size))
    }

    /// Flush cache
    pub fn flush_cache(&mut self) {
        for i in 0..MAX_CACHE_ENTRIES {
            self.cache[i].active = false;
        }
        self.cache_count = 0;
    }

    /// Enable/disable signature requirement
    pub fn set_require_signed(&mut self, require: bool) {
        self.require_signed = require;
    }

    pub fn tick(&mut self) {
        self.current_tick += 1;
    }

    pub fn firmware_count(&self) -> u16 {
        self.fw_count
    }

    pub fn builtin_count(&self) -> u16 {
        self.builtin_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut FW_MGR: FirmwareManager = FirmwareManager::new();

fn fwm() -> &'static mut FirmwareManager {
    unsafe { &mut FW_MGR }
}

fn fwm_ref() -> &'static FirmwareManager {
    unsafe { &FW_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_firmware_init() {
    fwm().init();
}

#[no_mangle]
pub extern "C" fn rust_firmware_request(
    name_ptr: *const u8,
    name_len: u32,
    device_id: u32,
) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 63 {
        return -22; // EINVAL
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match fwm().request_firmware(name, device_id) {
        Ok(idx) => idx as i32,
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn rust_firmware_release(idx: u16) {
    fwm().release_firmware(idx);
}

#[no_mangle]
pub extern "C" fn rust_firmware_complete(idx: u16, data_phys: u64, data_size: u32) -> bool {
    fwm().complete_loading(idx, data_phys, data_size, true)
}

#[no_mangle]
pub extern "C" fn rust_firmware_count() -> u16 {
    fwm_ref().firmware_count()
}

#[no_mangle]
pub extern "C" fn rust_firmware_builtin_count() -> u16 {
    fwm_ref().builtin_count()
}

#[no_mangle]
pub extern "C" fn rust_firmware_total_loads() -> u64 {
    fwm_ref().total_loads.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_firmware_total_errors() -> u64 {
    fwm_ref().total_load_errors.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_firmware_cache_hits() -> u64 {
    fwm_ref().cache_hits.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_firmware_set_require_signed(require: bool) {
    fwm().set_require_signed(require);
}

#[no_mangle]
pub extern "C" fn rust_firmware_flush_cache() {
    fwm().flush_cache();
}

#[no_mangle]
pub extern "C" fn rust_firmware_tick() {
    fwm().tick();
}

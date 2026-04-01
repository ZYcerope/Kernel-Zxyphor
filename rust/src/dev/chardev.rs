// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Character Device Framework (Rust)
//
// Provides the registration and management infrastructure for character
// devices (major/minor number allocation, file operations, cdev structs).
//
// - Major/Minor number space management (dynamic allocation)
// - CharDev trait: open, release, read, write, ioctl, poll, mmap, llseek
// - cdev registration with /dev namespace
// - Device number regions (MKDEV, MAJOR, MINOR helpers)
// - TTY, misc, mem, null, zero, random, urandom, kmsg device foundations

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ─────────────────── Device Number Encoding ─────────────────────────

/// Encode major/minor into a combined device number (32-bit)
/// Layout: [31:20] = major (12 bits), [19:8] = minor high (12 bits), [7:0] = minor low (8 bits)
pub const fn mkdev(major: u32, minor: u32) -> u32 {
    ((major & 0xFFF) << 20) | ((minor & 0xFFF00) << 0) | (minor & 0xFF)
}

pub const fn dev_major(dev: u32) -> u32 {
    (dev >> 20) & 0xFFF
}

pub const fn dev_minor(dev: u32) -> u32 {
    ((dev >> 0) & 0xFFF00) | (dev & 0xFF)
}

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CHARDEVS: usize = 256;
const MAX_DEV_REGIONS: usize = 128;
const MAX_NAME_LEN: usize = 32;
const MAX_CHRDEV_MAJOR: u32 = 512;
const DYNAMIC_MAJOR_START: u32 = 234;

// Standard major numbers
pub const MEM_MAJOR: u32 = 1;        // /dev/null, /dev/zero, /dev/mem
pub const PTY_MASTER_MAJOR: u32 = 2;
pub const PTY_SLAVE_MAJOR: u32 = 3;
pub const TTY_MAJOR: u32 = 4;
pub const TTYAUX_MAJOR: u32 = 5;     // /dev/tty, /dev/console, /dev/ptmx
pub const LP_MAJOR: u32 = 6;
pub const INPUT_MAJOR: u32 = 13;
pub const SOUND_MAJOR: u32 = 14;
pub const USB_CHAR_MAJOR: u32 = 180;
pub const MISC_MAJOR: u32 = 10;

// ─────────────────── Seek Whence ────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SeekWhence {
    Set = 0,
    Cur = 1,
    End = 2,
    Data = 3,  // seek to next data
    Hole = 4,  // seek to next hole
}

// ─────────────────── Poll Events ────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum PollEvent {
    In = 0x0001,
    Pri = 0x0002,
    Out = 0x0004,
    Err = 0x0008,
    Hup = 0x0010,
    Nval = 0x0020,
    RdNorm = 0x0040,
    RdBand = 0x0080,
    WrNorm = 0x0100,
    WrBand = 0x0200,
}

// ─────────────────── File Operations ────────────────────────────────

/// Function pointers for character device operations
#[derive(Clone, Copy)]
pub struct FileOps {
    pub open: Option<fn(dev: u32, flags: u32) -> i32>,
    pub release: Option<fn(dev: u32) -> i32>,
    pub read: Option<fn(dev: u32, buf: &mut [u8], offset: u64) -> i64>,
    pub write: Option<fn(dev: u32, buf: &[u8], offset: u64) -> i64>,
    pub ioctl: Option<fn(dev: u32, cmd: u32, arg: u64) -> i32>,
    pub poll: Option<fn(dev: u32) -> u32>,
    pub llseek: Option<fn(dev: u32, offset: i64, whence: SeekWhence) -> i64>,
    pub flush: Option<fn(dev: u32) -> i32>,
    pub fsync: Option<fn(dev: u32, datasync: bool) -> i32>,
}

impl FileOps {
    pub const fn empty() -> Self {
        Self {
            open: None,
            release: None,
            read: None,
            write: None,
            ioctl: None,
            poll: None,
            llseek: None,
            flush: None,
            fsync: None,
        }
    }
}

// ─────────────────── CharDev Registration ───────────────────────────

#[derive(Clone, Copy)]
pub struct CharDev {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub major: u32,
    pub minor_start: u32,
    pub minor_count: u32,
    pub ops: FileOps,
    pub dev_id: u32,         // Combined dev number
    pub open_count: u32,
    pub active: bool,
}

impl CharDev {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            major: 0,
            minor_start: 0,
            minor_count: 1,
            ops: FileOps::empty(),
            dev_id: 0,
            open_count: 0,
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
}

// ─────────────────── Device Number Region ───────────────────────────

/// Tracks allocated major/minor number ranges
#[derive(Clone, Copy)]
pub struct DevRegion {
    pub major: u32,
    pub minor_start: u32,
    pub minor_count: u32,
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    pub active: bool,
}

impl DevRegion {
    pub const fn new() -> Self {
        Self {
            major: 0,
            minor_start: 0,
            minor_count: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            active: false,
        }
    }

    /// Check if a (major, minor) falls within this region
    pub fn contains(&self, major: u32, minor: u32) -> bool {
        self.active
            && self.major == major
            && minor >= self.minor_start
            && minor < self.minor_start + self.minor_count
    }
}

// ─────────────────── Built-in Device Ops ────────────────────────────

/// /dev/null — absorbs all writes, reads return 0 bytes
fn null_read(_dev: u32, _buf: &mut [u8], _off: u64) -> i64 {
    0 // EOF
}

fn null_write(_dev: u32, buf: &[u8], _off: u64) -> i64 {
    buf.len() as i64
}

/// /dev/zero — reads return zero bytes
fn zero_read(_dev: u32, buf: &mut [u8], _off: u64) -> i64 {
    for b in buf.iter_mut() {
        *b = 0;
    }
    buf.len() as i64
}

fn zero_write(_dev: u32, buf: &[u8], _off: u64) -> i64 {
    buf.len() as i64
}

/// /dev/full — reads return zeros, writes return ENOSPC
fn full_read(_dev: u32, buf: &mut [u8], _off: u64) -> i64 {
    for b in buf.iter_mut() {
        *b = 0;
    }
    buf.len() as i64
}

fn full_write(_dev: u32, _buf: &[u8], _off: u64) -> i64 {
    -28 // -ENOSPC
}

/// /dev/urandom — simple PRNG (xorshift64)
static URANDOM_STATE: AtomicU64 = AtomicU64::new(0x5DEECE66D_u64);

fn urandom_read(_dev: u32, buf: &mut [u8], _off: u64) -> i64 {
    let mut state = URANDOM_STATE.load(Ordering::Relaxed);
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = (state & 0xFF) as u8;
    }
    URANDOM_STATE.store(state, Ordering::Relaxed);
    buf.len() as i64
}

fn urandom_write(_dev: u32, buf: &[u8], _off: u64) -> i64 {
    // Writes to urandom are used to seed the pool
    if !buf.is_empty() {
        let mut seed = URANDOM_STATE.load(Ordering::Relaxed);
        for &b in buf {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(b as u64);
        }
        URANDOM_STATE.store(seed, Ordering::Relaxed);
    }
    buf.len() as i64
}

/// /dev/kmsg — kernel message buffer stub
fn kmsg_read(_dev: u32, _buf: &mut [u8], _off: u64) -> i64 {
    0 // No messages available
}

fn kmsg_write(_dev: u32, buf: &[u8], _off: u64) -> i64 {
    // Would print to kernel log ring
    buf.len() as i64
}

pub const NULL_OPS: FileOps = FileOps {
    open: None,
    release: None,
    read: Some(null_read),
    write: Some(null_write),
    ioctl: None,
    poll: None,
    llseek: None,
    flush: None,
    fsync: None,
};

pub const ZERO_OPS: FileOps = FileOps {
    open: None,
    release: None,
    read: Some(zero_read),
    write: Some(zero_write),
    ioctl: None,
    poll: None,
    llseek: None,
    flush: None,
    fsync: None,
};

pub const FULL_OPS: FileOps = FileOps {
    open: None,
    release: None,
    read: Some(full_read),
    write: Some(full_write),
    ioctl: None,
    poll: None,
    llseek: None,
    flush: None,
    fsync: None,
};

pub const URANDOM_OPS: FileOps = FileOps {
    open: None,
    release: None,
    read: Some(urandom_read),
    write: Some(urandom_write),
    ioctl: None,
    poll: None,
    llseek: None,
    flush: None,
    fsync: None,
};

pub const KMSG_OPS: FileOps = FileOps {
    open: None,
    release: None,
    read: Some(kmsg_read),
    write: Some(kmsg_write),
    ioctl: None,
    poll: None,
    llseek: None,
    flush: None,
    fsync: None,
};

// ─────────────────── CharDev Manager ────────────────────────────────

pub struct CharDevManager {
    devices: [CharDev; MAX_CHARDEVS],
    regions: [DevRegion; MAX_DEV_REGIONS],
    device_count: u16,
    region_count: u16,
    /// Bitmap of allocated major numbers
    major_bitmap: [u64; 8], // 512 bits = 512 majors
    /// Dynamic major allocation counter
    next_dynamic: u32,
    /// Stats
    total_opens: AtomicU64,
    total_reads: AtomicU64,
    total_writes: AtomicU64,
    total_ioctls: AtomicU64,
}

impl CharDevManager {
    pub const fn new() -> Self {
        Self {
            devices: [CharDev::new(); MAX_CHARDEVS],
            regions: [DevRegion::new(); MAX_DEV_REGIONS],
            device_count: 0,
            region_count: 0,
            major_bitmap: [0u64; 8],
            next_dynamic: DYNAMIC_MAJOR_START,
            total_opens: AtomicU64::new(0),
            total_reads: AtomicU64::new(0),
            total_writes: AtomicU64::new(0),
            total_ioctls: AtomicU64::new(0),
        }
    }

    fn set_major_bit(&mut self, major: u32) {
        if major < MAX_CHRDEV_MAJOR {
            let idx = (major / 64) as usize;
            let bit = major % 64;
            self.major_bitmap[idx] |= 1u64 << bit;
        }
    }

    fn clear_major_bit(&mut self, major: u32) {
        if major < MAX_CHRDEV_MAJOR {
            let idx = (major / 64) as usize;
            let bit = major % 64;
            self.major_bitmap[idx] &= !(1u64 << bit);
        }
    }

    fn is_major_allocated(&self, major: u32) -> bool {
        if major >= MAX_CHRDEV_MAJOR {
            return false;
        }
        let idx = (major / 64) as usize;
        let bit = major % 64;
        (self.major_bitmap[idx] >> bit) & 1 == 1
    }

    /// Allocate a dynamic major number
    fn alloc_dynamic_major(&mut self) -> Option<u32> {
        // Search from DYNAMIC_MAJOR_START downwards
        let mut major = self.next_dynamic;
        while major > 0 {
            if !self.is_major_allocated(major) {
                self.set_major_bit(major);
                self.next_dynamic = major.wrapping_sub(1);
                return Some(major);
            }
            major = major.wrapping_sub(1);
        }
        None
    }

    /// Register a character device region (alloc_chrdev_region equivalent)
    pub fn register_region(
        &mut self,
        major: u32,
        minor_start: u32,
        count: u32,
        name: &[u8],
    ) -> Option<u32> {
        if self.region_count as usize >= MAX_DEV_REGIONS {
            return None;
        }

        let actual_major = if major == 0 {
            // Dynamic allocation
            self.alloc_dynamic_major()?
        } else {
            if self.is_major_allocated(major) {
                return None; // Already in use
            }
            self.set_major_bit(major);
            major
        };

        let idx = self.region_count as usize;
        self.regions[idx].major = actual_major;
        self.regions[idx].minor_start = minor_start;
        self.regions[idx].minor_count = count;
        let nlen = name.len().min(MAX_NAME_LEN - 1);
        self.regions[idx].name[..nlen].copy_from_slice(&name[..nlen]);
        self.regions[idx].name_len = nlen as u8;
        self.regions[idx].active = true;
        self.region_count += 1;

        Some(actual_major)
    }

    /// Unregister a device region
    pub fn unregister_region(&mut self, major: u32) -> bool {
        for i in 0..self.region_count as usize {
            if self.regions[i].active && self.regions[i].major == major {
                self.regions[i].active = false;
                self.clear_major_bit(major);
                return true;
            }
        }
        false
    }

    /// Register a character device with file operations
    pub fn register_cdev(
        &mut self,
        name: &[u8],
        major: u32,
        minor: u32,
        ops: FileOps,
    ) -> Option<u16> {
        if self.device_count as usize >= MAX_CHARDEVS {
            return None;
        }

        // Check region exists
        let mut region_ok = false;
        for i in 0..self.region_count as usize {
            if self.regions[i].contains(major, minor) {
                region_ok = true;
                break;
            }
        }
        if !region_ok && major != 0 {
            // Auto-register a region
            self.register_region(major, minor, 1, name)?;
        }

        // Find free slot
        for i in 0..MAX_CHARDEVS {
            if !self.devices[i].active {
                self.devices[i].set_name(name);
                self.devices[i].major = major;
                self.devices[i].minor_start = minor;
                self.devices[i].minor_count = 1;
                self.devices[i].ops = ops;
                self.devices[i].dev_id = mkdev(major, minor);
                self.devices[i].active = true;
                self.device_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    /// Unregister a character device
    pub fn unregister_cdev(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_CHARDEVS || !self.devices[i].active {
            return false;
        }
        if self.devices[i].open_count > 0 {
            return false; // Still in use
        }
        self.devices[i].active = false;
        self.device_count -= 1;
        true
    }

    /// Find device by major/minor
    fn find_device(&self, major: u32, minor: u32) -> Option<usize> {
        for i in 0..MAX_CHARDEVS {
            if self.devices[i].active
                && self.devices[i].major == major
                && minor >= self.devices[i].minor_start
                && minor < self.devices[i].minor_start + self.devices[i].minor_count
            {
                return Some(i);
            }
        }
        None
    }

    /// Open a character device
    pub fn open(&mut self, dev: u32, flags: u32) -> i32 {
        let major = dev_major(dev);
        let minor = dev_minor(dev);
        if let Some(idx) = self.find_device(major, minor) {
            self.total_opens.fetch_add(1, Ordering::Relaxed);
            self.devices[idx].open_count += 1;
            if let Some(open_fn) = self.devices[idx].ops.open {
                return open_fn(dev, flags);
            }
            return 0;
        }
        -19 // -ENODEV
    }

    /// Release (close) a character device
    pub fn release(&mut self, dev: u32) -> i32 {
        let major = dev_major(dev);
        let minor = dev_minor(dev);
        if let Some(idx) = self.find_device(major, minor) {
            if self.devices[idx].open_count > 0 {
                self.devices[idx].open_count -= 1;
            }
            if let Some(rel_fn) = self.devices[idx].ops.release {
                return rel_fn(dev);
            }
            return 0;
        }
        -9 // -EBADF
    }

    /// Read from a character device
    pub fn read(&self, dev: u32, buf: &mut [u8], offset: u64) -> i64 {
        let major = dev_major(dev);
        let minor = dev_minor(dev);
        if let Some(idx) = self.find_device(major, minor) {
            self.total_reads.fetch_add(1, Ordering::Relaxed);
            if let Some(read_fn) = self.devices[idx].ops.read {
                return read_fn(dev, buf, offset);
            }
            return -22; // -EINVAL
        }
        -19 // -ENODEV
    }

    /// Write to a character device
    pub fn write(&self, dev: u32, buf: &[u8], offset: u64) -> i64 {
        let major = dev_major(dev);
        let minor = dev_minor(dev);
        if let Some(idx) = self.find_device(major, minor) {
            self.total_writes.fetch_add(1, Ordering::Relaxed);
            if let Some(write_fn) = self.devices[idx].ops.write {
                return write_fn(dev, buf, offset);
            }
            return -22;
        }
        -19
    }

    /// ioctl on a character device
    pub fn ioctl(&self, dev: u32, cmd: u32, arg: u64) -> i32 {
        let major = dev_major(dev);
        let minor = dev_minor(dev);
        if let Some(idx) = self.find_device(major, minor) {
            self.total_ioctls.fetch_add(1, Ordering::Relaxed);
            if let Some(ioctl_fn) = self.devices[idx].ops.ioctl {
                return ioctl_fn(dev, cmd, arg);
            }
            return -25; // -ENOTTY
        }
        -19
    }

    /// Initialize built-in character devices
    pub fn init(&mut self) {
        // Register MEM major region (1)
        self.register_region(MEM_MAJOR, 0, 16, b"mem");
        // Register MISC major (10)
        self.register_region(MISC_MAJOR, 0, 256, b"misc");
        // Register TTY major (4)
        self.register_region(TTY_MAJOR, 0, 256, b"tty");

        // /dev/null (1, 3)
        self.register_cdev(b"null", MEM_MAJOR, 3, NULL_OPS);
        // /dev/zero (1, 5)
        self.register_cdev(b"zero", MEM_MAJOR, 5, ZERO_OPS);
        // /dev/full (1, 7)
        self.register_cdev(b"full", MEM_MAJOR, 7, FULL_OPS);
        // /dev/urandom (1, 9)
        self.register_cdev(b"urandom", MEM_MAJOR, 9, URANDOM_OPS);
        // /dev/kmsg (1, 11)
        self.register_cdev(b"kmsg", MEM_MAJOR, 11, KMSG_OPS);
    }

    pub fn device_count(&self) -> u16 {
        self.device_count
    }

    pub fn region_count(&self) -> u16 {
        self.region_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut CHARDEV_MGR: CharDevManager = CharDevManager::new();

fn mgr() -> &'static mut CharDevManager {
    unsafe { &mut CHARDEV_MGR }
}

fn mgr_ref() -> &'static CharDevManager {
    unsafe { &CHARDEV_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_chardev_init() {
    mgr().init();
}

#[no_mangle]
pub extern "C" fn rust_chardev_register(
    name_ptr: *const u8,
    name_len: u32,
    major: u32,
    minor: u32,
) -> i32 {
    if name_ptr.is_null() || name_len == 0 || name_len > 31 {
        return -1;
    }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match mgr().register_cdev(name, major, minor, FileOps::empty()) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_chardev_open(dev: u32, flags: u32) -> i32 {
    mgr().open(dev, flags)
}

#[no_mangle]
pub extern "C" fn rust_chardev_release(dev: u32) -> i32 {
    mgr().release(dev)
}

#[no_mangle]
pub extern "C" fn rust_chardev_count() -> u16 {
    mgr_ref().device_count()
}

#[no_mangle]
pub extern "C" fn rust_chardev_region_count() -> u16 {
    mgr_ref().region_count()
}

#[no_mangle]
pub extern "C" fn rust_chardev_total_opens() -> u64 {
    mgr_ref().total_opens.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_chardev_total_reads() -> u64 {
    mgr_ref().total_reads.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_chardev_total_writes() -> u64 {
    mgr_ref().total_writes.load(Ordering::Relaxed)
}

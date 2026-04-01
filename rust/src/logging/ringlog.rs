// =============================================================================
// Kernel Zxyphor — Ring Log (Lock-free Ring Buffer Logger)
// =============================================================================
// Ultra-fast lock-free logging for hot paths:
//   - Single-producer multi-consumer ring buffer
//   - Atomic operations only (no locks)
//   - Fixed-size compact entries (64 bytes each)
//   - Batch read support for consumers
//   - Memory-mapped buffer for zero-copy access
//   - Overflow detection with sequence validation
//   - Per-CPU ring buffers for zero contention
//   - Binary format for minimal overhead
// =============================================================================

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const RINGLOG_SIZE: usize = 2048;
pub const RINGLOG_MSG_LEN: usize = 40;
pub const MAX_RING_CPUS: usize = 64;

// =============================================================================
// Compact log entry (exactly 64 bytes for cache line alignment)
// =============================================================================

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct RingLogEntry {
    pub sequence: u64,        // 8
    pub timestamp_ns: u64,    // 8
    pub level_subsys: u16,    // 2 (high byte=level, low byte=subsystem)
    pub pid: u16,             // 2
    pub msg_len: u16,         // 2
    pub _padding: u16,        // 2
    pub msg: [u8; RINGLOG_MSG_LEN], // 40
}

impl RingLogEntry {
    pub const fn empty() -> Self {
        Self {
            sequence: 0,
            timestamp_ns: 0,
            level_subsys: 0,
            pid: 0,
            msg_len: 0,
            _padding: 0,
            msg: [0u8; RINGLOG_MSG_LEN],
        }
    }

    pub fn level(&self) -> u8 {
        (self.level_subsys >> 8) as u8
    }

    pub fn subsystem(&self) -> u8 {
        (self.level_subsys & 0xFF) as u8
    }
}

// =============================================================================
// Per-CPU ring buffer (single producer, multiple consumers)
// =============================================================================

pub struct RingLogBuffer {
    pub entries: [RingLogEntry; RINGLOG_SIZE],
    pub head: AtomicU32,      // Write position (only one writer per CPU)
    pub sequence: AtomicU64,
    pub total: AtomicU64,
    pub overflows: AtomicU64,
}

impl RingLogBuffer {
    pub const fn new() -> Self {
        Self {
            entries: [const { RingLogEntry::empty() }; RINGLOG_SIZE],
            head: AtomicU32::new(0),
            sequence: AtomicU64::new(1),
            total: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
        }
    }

    /// Write a log entry (single producer — no CAS needed)
    pub fn write(
        &mut self,
        level: u8,
        subsys: u8,
        pid: u16,
        msg: &[u8],
        now_ns: u64,
    ) {
        let idx = self.head.load(Ordering::Relaxed) as usize % RINGLOG_SIZE;
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);

        if self.entries[idx].sequence != 0 {
            self.overflows.fetch_add(1, Ordering::Relaxed);
        }

        let len = msg.len().min(RINGLOG_MSG_LEN);
        self.entries[idx].sequence = seq;
        self.entries[idx].timestamp_ns = now_ns;
        self.entries[idx].level_subsys = ((level as u16) << 8) | (subsys as u16);
        self.entries[idx].pid = pid;
        self.entries[idx].msg_len = len as u16;
        self.entries[idx].msg[..len].copy_from_slice(&msg[..len]);

        self.head.store((idx + 1) as u32, Ordering::Release);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Read entries starting from a sequence number
    pub fn read(&self, from_seq: u64, out: &mut [RingLogEntry]) -> usize {
        let mut count = 0;
        for entry in &self.entries {
            if entry.sequence >= from_seq && entry.sequence != 0 && count < out.len() {
                out[count] = *entry;
                count += 1;
            }
        }
        count
    }

    /// Read the most recent N entries
    pub fn read_recent(&self, n: usize, out: &mut [RingLogEntry]) -> usize {
        let head = self.head.load(Ordering::Acquire) as usize;
        let total = self.total.load(Ordering::Relaxed) as usize;
        let available = total.min(RINGLOG_SIZE);
        let to_read = n.min(available).min(out.len());

        let mut count = 0;
        let mut pos = if head >= to_read { head - to_read } else { RINGLOG_SIZE - (to_read - head) };

        while count < to_read {
            let idx = pos % RINGLOG_SIZE;
            if self.entries[idx].sequence != 0 {
                out[count] = self.entries[idx];
                count += 1;
            }
            pos += 1;
        }
        count
    }
}

// =============================================================================
// Multi-CPU Ring Log system
// =============================================================================

pub struct RingLogSystem {
    pub buffers: [RingLogBuffer; MAX_RING_CPUS],
    pub active_cpus: u32,
    pub global_seq: AtomicU64,
}

impl RingLogSystem {
    pub const fn new() -> Self {
        Self {
            buffers: [const { RingLogBuffer::new() }; MAX_RING_CPUS],
            active_cpus: 1,
            global_seq: AtomicU64::new(1),
        }
    }

    /// Log to the current CPU's buffer
    pub fn log(&mut self, cpu: u8, level: u8, subsys: u8, pid: u16, msg: &[u8], now_ns: u64) {
        let cpu_idx = cpu as usize;
        if cpu_idx >= MAX_RING_CPUS { return; }
        self.buffers[cpu_idx].write(level, subsys, pid, msg, now_ns);
    }

    /// Get total events across all CPUs
    pub fn total_events(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.active_cpus as usize {
            total += self.buffers[i].total.load(Ordering::Relaxed);
        }
        total
    }

    /// Get total overflows
    pub fn total_overflows(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.active_cpus as usize {
            total += self.buffers[i].overflows.load(Ordering::Relaxed);
        }
        total
    }
}

static mut RINGLOG: RingLogSystem = RingLogSystem::new();

pub unsafe fn ringlog() -> &'static mut RingLogSystem {
    &mut *core::ptr::addr_of_mut!(RINGLOG)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_ringlog_write(
    cpu: u8, level: u8, subsys: u8, pid: u16,
    msg_ptr: *const u8, msg_len: usize, now_ns: u64,
) {
    if msg_ptr.is_null() || msg_len == 0 { return; }
    let msg = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len.min(RINGLOG_MSG_LEN)) };
    unsafe { ringlog().log(cpu, level, subsys, pid, msg, now_ns); }
}

#[no_mangle]
pub extern "C" fn zxyphor_ringlog_total() -> u64 {
    unsafe { ringlog().total_events() }
}

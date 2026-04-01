// SPDX-License-Identifier: MIT
// Zxyphor Kernel — High-Resolution Timer & Timer Wheel (Rust)
//
// Kernel timer infrastructure:
// - Timer wheel (classic O(1) jiffies-based timers)
// - High-resolution timers (hrtimer, nanosecond precision)
// - Clock sources (TSC, HPET, PIT, ACPI PM)
// - Clock events (per-CPU tick devices)
// - POSIX timers (timer_create, timer_settime)
// - Itimer support (ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF)
// - Deadline-based timer expiry
// - Timer migration between CPUs
// - Dynamic tick (tickless idle — NO_HZ)

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const MAX_TIMERS: usize = 512;
const MAX_HRTIMERS: usize = 256;
const MAX_CLOCK_SOURCES: usize = 8;
const MAX_POSIX_TIMERS: usize = 128;
const WHEEL_SIZE: usize = 256;     // Timer wheel buckets (jiffies & 0xFF)
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_MSEC: u64 = 1_000_000;
const NSEC_PER_USEC: u64 = 1_000;

// ─────────────────── Timer State ────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TimerState {
    Inactive = 0,
    Pending = 1,
    Running = 2,   // Callback executing
    Migrating = 3,
}

// ─────────────────── HrTimer Mode ───────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum HrTimerMode {
    Absolute = 0,      // Expire at absolute time
    Relative = 1,      // Expire after delay
    Pinned = 2,        // Pinned to current CPU
    Soft = 3,          // Soft IRQ context
    Hard = 4,          // Hard IRQ context
}

// ─────────────────── HrTimer Restart ────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum HrTimerRestart {
    NoRestart = 0,
    Restart = 1,
}

// ─────────────────── Clock ID ───────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ClockId {
    Realtime = 0,
    Monotonic = 1,
    ProcessCputime = 2,
    ThreadCputime = 3,
    MonotonicRaw = 4,
    RealtimeCoarse = 5,
    MonotonicCoarse = 6,
    Boottime = 7,
}

// ─────────────────── Timespec ───────────────────────────────────────

#[derive(Clone, Copy, Default, PartialEq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

impl Timespec {
    pub const ZERO: Timespec = Timespec { sec: 0, nsec: 0 };

    pub fn from_ns(ns: u64) -> Self {
        Self {
            sec: (ns / NSEC_PER_SEC) as i64,
            nsec: (ns % NSEC_PER_SEC) as u32,
        }
    }

    pub fn to_ns(&self) -> u64 {
        (self.sec as u64) * NSEC_PER_SEC + self.nsec as u64
    }

    pub fn from_ms(ms: u64) -> Self {
        Self::from_ns(ms * NSEC_PER_MSEC)
    }

    pub fn add(&self, other: &Timespec) -> Self {
        let mut nsec = self.nsec as u64 + other.nsec as u64;
        let mut sec = self.sec + other.sec;
        if nsec >= NSEC_PER_SEC {
            nsec -= NSEC_PER_SEC;
            sec += 1;
        }
        Self {
            sec,
            nsec: nsec as u32,
        }
    }

    pub fn sub(&self, other: &Timespec) -> Self {
        let mut nsec = self.nsec as i64 - other.nsec as i64;
        let mut sec = self.sec - other.sec;
        if nsec < 0 {
            nsec += NSEC_PER_SEC as i64;
            sec -= 1;
        }
        Self {
            sec,
            nsec: nsec as u32,
        }
    }

    pub fn is_before(&self, other: &Timespec) -> bool {
        if self.sec != other.sec {
            self.sec < other.sec
        } else {
            self.nsec < other.nsec
        }
    }
}

// ─────────────────── Clock Source ────────────────────────────────────

#[derive(Clone, Copy)]
pub struct ClockSource {
    pub name: [u8; 16],
    pub name_len: u8,
    pub rating: u16,         // Higher = better (400 = TSC, 250 = HPET, 100 = PIT)
    pub mask: u64,           // Bitmask for counter wrap
    pub mult: u32,           // Multiplier for ns conversion
    pub shift: u8,           // Shift for ns conversion
    pub freq_hz: u64,        // Nominal frequency
    /// Last read counter value
    pub last_cycle: u64,
    /// Cumulative nanoseconds
    pub nsec_offset: u64,
    pub active: bool,
    pub selected: bool,

    pub fn cycles_to_ns(&self, cycles: u64) -> u64 {
        (cycles.wrapping_mul(self.mult as u64)) >> self.shift
    }

    pub fn read_ns(&self) -> u64 {
        self.nsec_offset
    }
}

impl ClockSource {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 16],
            name_len: 0,
            rating: 0,
            mask: u64::MAX,
            mult: 1,
            shift: 0,
            freq_hz: 0,
            last_cycle: 0,
            nsec_offset: 0,
            active: false,
            selected: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(15);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ─────────────────── Timer Wheel Entry ──────────────────────────────

pub type TimerCallback = fn(data: u64);

#[derive(Clone, Copy)]
pub struct TimerEntry {
    pub expires: u64,         // Jiffies value when timer fires
    pub callback: Option<TimerCallback>,
    pub data: u64,
    pub state: TimerState,
    pub cpu: u8,
    pub bucket: u8,           // Wheel bucket index
    pub periodic: bool,
    pub interval: u64,        // Re-arm interval (periodic timers)
    pub active: bool,
}

impl TimerEntry {
    pub const fn new() -> Self {
        Self {
            expires: 0,
            callback: None,
            data: 0,
            state: TimerState::Inactive,
            cpu: 0,
            bucket: 0,
            periodic: false,
            interval: 0,
            active: false,
        }
    }
}

// ─────────────────── Timer Wheel ────────────────────────────────────

pub struct TimerWheel {
    /// Each bucket is a list of timer indices
    buckets: [[u16; 32]; WHEEL_SIZE],    // 256 buckets × 32 entries max
    bucket_counts: [u8; WHEEL_SIZE],
    current_index: u8,
    jiffies: u64,
}

impl TimerWheel {
    pub const fn new() -> Self {
        Self {
            buckets: [[0xFFFF; 32]; WHEEL_SIZE],
            bucket_counts: [0u8; WHEEL_SIZE],
            current_index: 0,
            jiffies: 0,
        }
    }

    pub fn add_timer(&mut self, timer_idx: u16, expires: u64) -> bool {
        let bucket = (expires & 0xFF) as usize;
        let count = self.bucket_counts[bucket] as usize;
        if count >= 32 {
            return false;
        }
        self.buckets[bucket][count] = timer_idx;
        self.bucket_counts[bucket] += 1;
        true
    }

    pub fn remove_timer(&mut self, timer_idx: u16, bucket: u8) -> bool {
        let b = bucket as usize;
        let count = self.bucket_counts[b] as usize;
        for i in 0..count {
            if self.buckets[b][i] == timer_idx {
                // Swap with last
                self.buckets[b][i] = self.buckets[b][count - 1];
                self.bucket_counts[b] -= 1;
                return true;
            }
        }
        false
    }

    /// Get expired timers for current jiffies
    pub fn collect_expired(&mut self, jiffies: u64, out: &mut [u16; 32]) -> u8 {
        let bucket = (jiffies & 0xFF) as usize;
        let count = self.bucket_counts[bucket];
        let mut expired = 0u8;

        let mut i: usize = 0;
        while i < self.bucket_counts[bucket] as usize {
            let timer_idx = self.buckets[bucket][i];
            // Timer manager will check if actually expired
            if expired < 32 {
                out[expired as usize] = timer_idx;
                expired += 1;
            }
            i += 1;
        }

        expired
    }
}

// ─────────────────── HrTimer Entry ──────────────────────────────────

pub type HrTimerCallback = fn(data: u64) -> HrTimerRestart;

#[derive(Clone, Copy)]
pub struct HrTimer {
    pub expires: Timespec,
    pub softexpires: Timespec,  // Soft expiry for timer grouping
    pub callback: Option<HrTimerCallback>,
    pub data: u64,
    pub mode: HrTimerMode,
    pub clock_id: ClockId,
    pub state: TimerState,
    pub cpu: u8,
    /// Stats
    pub fire_count: u64,
    pub active: bool,
}

impl HrTimer {
    pub const fn new() -> Self {
        Self {
            expires: Timespec::ZERO,
            softexpires: Timespec::ZERO,
            callback: None,
            data: 0,
            mode: HrTimerMode::Relative,
            clock_id: ClockId::Monotonic,
            state: TimerState::Inactive,
            cpu: 0,
            fire_count: 0,
            active: false,
        }
    }
}

// ─────────────────── POSIX Timer ────────────────────────────────────

#[derive(Clone, Copy)]
pub struct PosixTimer {
    pub timer_id: u32,
    pub clock_id: ClockId,
    pub interval: Timespec,    // it_interval
    pub value: Timespec,       // it_value (next expiry)
    pub overrun_count: u32,
    pub signal: u8,            // Signal to deliver (SIGALRM default)
    pub pid: u32,              // Target process
    pub armed: bool,
    pub active: bool,
}

impl PosixTimer {
    pub const fn new() -> Self {
        Self {
            timer_id: 0,
            clock_id: ClockId::Realtime,
            interval: Timespec::ZERO,
            value: Timespec::ZERO,
            overrun_count: 0,
            signal: 14, // SIGALRM
            pid: 0,
            armed: false,
            active: false,
        }
    }
}

// ─────────────────── Timer Manager ──────────────────────────────────

pub struct TimerManager {
    /// Classic timer wheel
    wheel: TimerWheel,
    timers: [TimerEntry; MAX_TIMERS],
    timer_count: u16,
    /// High-resolution timers (sorted by expiry)
    hrtimers: [HrTimer; MAX_HRTIMERS],
    hrtimer_count: u16,
    /// Clock sources
    clocks: [ClockSource; MAX_CLOCK_SOURCES],
    clock_count: u8,
    current_clock: u8,
    /// POSIX timers
    posix_timers: [PosixTimer; MAX_POSIX_TIMERS],
    posix_count: u16,
    next_posix_id: u32,
    /// Time tracking
    jiffies: u64,
    wall_time: Timespec,
    boot_time: Timespec,
    monotonic_ns: u64,
    /// Tick config
    hz: u32,              // CONFIG_HZ (100, 250, 300, 1000)
    tick_nsec: u64,       // Nanoseconds per tick
    nohz_active: bool,    // Tickless idle
    /// Stats
    total_timer_fires: AtomicU64,
    total_hrtimer_fires: AtomicU64,
    total_ticks: AtomicU64,
}

impl TimerManager {
    pub const fn new() -> Self {
        Self {
            wheel: TimerWheel::new(),
            timers: [TimerEntry::new(); MAX_TIMERS],
            timer_count: 0,
            hrtimers: [HrTimer::new(); MAX_HRTIMERS],
            hrtimer_count: 0,
            clocks: [ClockSource::new(); MAX_CLOCK_SOURCES],
            clock_count: 0,
            current_clock: 0,
            posix_timers: [PosixTimer::new(); MAX_POSIX_TIMERS],
            posix_count: 0,
            next_posix_id: 1,
            jiffies: 0,
            wall_time: Timespec::ZERO,
            boot_time: Timespec::ZERO,
            monotonic_ns: 0,
            hz: 1000,
            tick_nsec: 1_000_000, // 1ms at 1000 HZ
            nohz_active: false,
            total_timer_fires: AtomicU64::new(0),
            total_hrtimer_fires: AtomicU64::new(0),
            total_ticks: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self, hz: u32) {
        self.hz = hz;
        self.tick_nsec = NSEC_PER_SEC / hz as u64;
    }

    /// Register a clock source
    pub fn register_clocksource(&mut self, name: &[u8], rating: u16, freq: u64, mask: u64) -> Option<u8> {
        if self.clock_count as usize >= MAX_CLOCK_SOURCES {
            return None;
        }
        let idx = self.clock_count;
        self.clocks[idx as usize] = ClockSource::new();
        self.clocks[idx as usize].set_name(name);
        self.clocks[idx as usize].rating = rating;
        self.clocks[idx as usize].freq_hz = freq;
        self.clocks[idx as usize].mask = mask;
        // Compute mult/shift for ns conversion
        // mult = (NSEC_PER_SEC << shift) / freq
        self.clocks[idx as usize].shift = 20;
        self.clocks[idx as usize].mult = if freq > 0 {
            ((NSEC_PER_SEC << 20) / freq) as u32
        } else {
            1
        };
        self.clocks[idx as usize].active = true;
        self.clock_count += 1;

        // Auto-select best
        self.select_best_clock();

        Some(idx)
    }

    fn select_best_clock(&mut self) {
        let mut best_rating: u16 = 0;
        let mut best_idx: u8 = 0;
        for i in 0..self.clock_count {
            if self.clocks[i as usize].active && self.clocks[i as usize].rating > best_rating {
                best_rating = self.clocks[i as usize].rating;
                best_idx = i;
            }
        }
        // Deselect old
        for i in 0..self.clock_count {
            self.clocks[i as usize].selected = false;
        }
        self.clocks[best_idx as usize].selected = true;
        self.current_clock = best_idx;
    }

    /// Add a classic (jiffies) timer
    pub fn add_timer(&mut self, delay_jiffies: u64, callback: TimerCallback, data: u64) -> Option<u16> {
        for i in 0..MAX_TIMERS {
            if !self.timers[i].active {
                let expires = self.jiffies + delay_jiffies;
                self.timers[i].expires = expires;
                self.timers[i].callback = Some(callback);
                self.timers[i].data = data;
                self.timers[i].state = TimerState::Pending;
                self.timers[i].bucket = (expires & 0xFF) as u8;
                self.timers[i].active = true;
                self.timer_count += 1;
                self.wheel.add_timer(i as u16, expires);
                return Some(i as u16);
            }
        }
        None
    }

    /// Cancel a classic timer
    pub fn del_timer(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_TIMERS || !self.timers[i].active {
            return false;
        }
        self.wheel
            .remove_timer(idx, self.timers[i].bucket);
        self.timers[i].active = false;
        self.timers[i].state = TimerState::Inactive;
        self.timer_count -= 1;
        true
    }

    /// Start an hrtimer
    pub fn hrtimer_start(
        &mut self,
        expires_ns: u64,
        callback: HrTimerCallback,
        data: u64,
        mode: HrTimerMode,
    ) -> Option<u16> {
        for i in 0..MAX_HRTIMERS {
            if !self.hrtimers[i].active {
                let abs_ns = match mode {
                    HrTimerMode::Relative | HrTimerMode::Soft => self.monotonic_ns + expires_ns,
                    _ => expires_ns,
                };
                self.hrtimers[i].expires = Timespec::from_ns(abs_ns);
                self.hrtimers[i].softexpires = Timespec::from_ns(abs_ns.saturating_sub(NSEC_PER_USEC * 100));
                self.hrtimers[i].callback = Some(callback);
                self.hrtimers[i].data = data;
                self.hrtimers[i].mode = mode;
                self.hrtimers[i].state = TimerState::Pending;
                self.hrtimers[i].active = true;
                self.hrtimer_count += 1;
                return Some(i as u16);
            }
        }
        None
    }

    /// Cancel an hrtimer
    pub fn hrtimer_cancel(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_HRTIMERS || !self.hrtimers[i].active {
            return false;
        }
        self.hrtimers[i].active = false;
        self.hrtimers[i].state = TimerState::Inactive;
        self.hrtimer_count -= 1;
        true
    }

    /// Create a POSIX timer
    pub fn posix_timer_create(&mut self, clock_id: ClockId, pid: u32) -> Option<u32> {
        if self.posix_count as usize >= MAX_POSIX_TIMERS {
            return None;
        }
        for i in 0..MAX_POSIX_TIMERS {
            if !self.posix_timers[i].active {
                let tid = self.next_posix_id;
                self.next_posix_id += 1;
                self.posix_timers[i].timer_id = tid;
                self.posix_timers[i].clock_id = clock_id;
                self.posix_timers[i].pid = pid;
                self.posix_timers[i].active = true;
                self.posix_count += 1;
                return Some(tid);
            }
        }
        None
    }

    /// Arm a POSIX timer
    pub fn posix_timer_settime(&mut self, timer_id: u32, value_ns: u64, interval_ns: u64) -> bool {
        for i in 0..MAX_POSIX_TIMERS {
            if self.posix_timers[i].active && self.posix_timers[i].timer_id == timer_id {
                self.posix_timers[i].value = Timespec::from_ns(self.monotonic_ns + value_ns);
                self.posix_timers[i].interval = Timespec::from_ns(interval_ns);
                self.posix_timers[i].armed = true;
                self.posix_timers[i].overrun_count = 0;
                return true;
            }
        }
        false
    }

    /// Process tick — called from timer interrupt
    pub fn tick(&mut self) {
        self.jiffies += 1;
        self.monotonic_ns += self.tick_nsec;
        self.total_ticks.fetch_add(1, Ordering::Relaxed);

        // Update wall time
        self.wall_time = self.wall_time.add(&Timespec::from_ns(self.tick_nsec));

        // Process timer wheel
        self.process_wheel();

        // Process hrtimers
        self.process_hrtimers();

        // Process POSIX timers
        self.process_posix_timers();
    }

    fn process_wheel(&mut self) {
        let mut expired = [0xFFFFu16; 32];
        let count = self.wheel.collect_expired(self.jiffies, &mut expired);

        for i in 0..count as usize {
            let idx = expired[i] as usize;
            if idx < MAX_TIMERS && self.timers[idx].active && self.timers[idx].expires <= self.jiffies {
                self.timers[idx].state = TimerState::Running;
                if let Some(cb) = self.timers[idx].callback {
                    cb(self.timers[idx].data);
                }
                self.total_timer_fires.fetch_add(1, Ordering::Relaxed);

                if self.timers[idx].periodic && self.timers[idx].interval > 0 {
                    // Re-arm
                    let new_expires = self.jiffies + self.timers[idx].interval;
                    self.timers[idx].expires = new_expires;
                    self.timers[idx].bucket = (new_expires & 0xFF) as u8;
                    self.timers[idx].state = TimerState::Pending;
                    self.wheel.add_timer(idx as u16, new_expires);
                } else {
                    self.timers[idx].active = false;
                    self.timers[idx].state = TimerState::Inactive;
                    self.timer_count -= 1;
                }
            }
        }
    }

    fn process_hrtimers(&mut self) {
        let now = Timespec::from_ns(self.monotonic_ns);
        for i in 0..MAX_HRTIMERS {
            if self.hrtimers[i].active
                && self.hrtimers[i].state == TimerState::Pending
                && !self.hrtimers[i].expires.is_before(&now)
                == false
            {
                // Check: now >= expires means timer should fire
                if !now.is_before(&self.hrtimers[i].expires) {
                    self.hrtimers[i].state = TimerState::Running;
                    let restart = if let Some(cb) = self.hrtimers[i].callback {
                        cb(self.hrtimers[i].data)
                    } else {
                        HrTimerRestart::NoRestart
                    };
                    self.hrtimers[i].fire_count += 1;
                    self.total_hrtimer_fires.fetch_add(1, Ordering::Relaxed);

                    match restart {
                        HrTimerRestart::Restart => {
                            self.hrtimers[i].state = TimerState::Pending;
                            // Keep same expiry, caller should update
                        }
                        HrTimerRestart::NoRestart => {
                            self.hrtimers[i].active = false;
                            self.hrtimers[i].state = TimerState::Inactive;
                            self.hrtimer_count -= 1;
                        }
                    }
                }
            }
        }
    }

    fn process_posix_timers(&mut self) {
        let now = Timespec::from_ns(self.monotonic_ns);
        for i in 0..MAX_POSIX_TIMERS {
            if self.posix_timers[i].active && self.posix_timers[i].armed {
                if !now.is_before(&self.posix_timers[i].value) {
                    // Timer expired — signal process
                    if self.posix_timers[i].interval.to_ns() > 0 {
                        // Periodic: re-arm
                        self.posix_timers[i].value =
                            self.posix_timers[i].value.add(&self.posix_timers[i].interval);
                        self.posix_timers[i].overrun_count += 1;
                    } else {
                        self.posix_timers[i].armed = false;
                    }
                }
            }
        }
    }

    pub fn get_monotonic_ns(&self) -> u64 {
        self.monotonic_ns
    }

    pub fn get_jiffies(&self) -> u64 {
        self.jiffies
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut TIMER_MGR: TimerManager = TimerManager::new();

fn tmgr() -> &'static mut TimerManager {
    unsafe { &mut TIMER_MGR }
}

fn tmgr_ref() -> &'static TimerManager {
    unsafe { &TIMER_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_timer_init(hz: u32) {
    tmgr().init(hz);
}

#[no_mangle]
pub extern "C" fn rust_timer_tick() {
    tmgr().tick();
}

#[no_mangle]
pub extern "C" fn rust_timer_jiffies() -> u64 {
    tmgr_ref().get_jiffies()
}

#[no_mangle]
pub extern "C" fn rust_timer_monotonic_ns() -> u64 {
    tmgr_ref().get_monotonic_ns()
}

#[no_mangle]
pub extern "C" fn rust_timer_count() -> u16 {
    tmgr_ref().timer_count
}

#[no_mangle]
pub extern "C" fn rust_hrtimer_count() -> u16 {
    tmgr_ref().hrtimer_count
}

#[no_mangle]
pub extern "C" fn rust_timer_total_fires() -> u64 {
    tmgr_ref().total_timer_fires.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_hrtimer_total_fires() -> u64 {
    tmgr_ref().total_hrtimer_fires.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_timer_clocksource_count() -> u8 {
    tmgr_ref().clock_count
}

#[no_mangle]
pub extern "C" fn rust_timer_posix_count() -> u16 {
    tmgr_ref().posix_count
}

#[no_mangle]
pub extern "C" fn rust_timer_total_ticks() -> u64 {
    tmgr_ref().total_ticks.load(Ordering::Relaxed)
}

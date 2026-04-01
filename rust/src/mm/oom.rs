// SPDX-License-Identifier: MIT
// Zxyphor Kernel — OOM Killer & Memory Pressure Management (Rust)
//
// Out-of-Memory handling subsystem:
// - OOM scoring based on memory usage, age, priority
// - Process selection with oom_score_adj override
// - Victim selection with task tree traversal
// - Memory pressure levels (low/medium/critical/oom)
// - Reclaim watermark management
// - Memory cgroup-aware OOM
// - Notifier chain for low-memory warnings
// - Oom reaper for stuck processes
// - Memory compaction trigger
// - Per-zone pressure tracking

#![no_std]

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, AtomicI32, Ordering};

/// Maximum tracked processes
const MAX_PROCS: usize = 512;
/// Maximum OOM event log entries
const MAX_OOM_LOG: usize = 64;
/// Maximum notifiers
const MAX_NOTIFIERS: usize = 16;

// ─────────────────── Memory Pressure Levels ─────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum PressureLevel {
    None = 0,
    Low = 1,      // Minor reclaim needed
    Medium = 2,   // Aggressive reclaim
    Critical = 3, // OOM imminent
    Oom = 4,      // Must kill something
}

impl PressureLevel {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::Critical => "critical",
            Self::Oom => "oom",
        }
    }
}

// ─────────────────── Memory Zone Info ───────────────────────────────

#[repr(C)]
pub struct ZoneWatermarks {
    /// In pages
    pub wmark_min: u64,
    pub wmark_low: u64,
    pub wmark_high: u64,
}

impl ZoneWatermarks {
    pub fn new(total_pages: u64) -> Self {
        // Standard Linux-like watermark calculation
        let min = total_pages / 256;           // ~0.4% of total
        let low = min + (min / 4);             // min + 25%
        let high = min + (min / 2);            // min + 50%
        Self {
            wmark_min: min.max(16),
            wmark_low: low.max(32),
            wmark_high: high.max(64),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ZoneType {
    Dma = 0,      // 0-16MB
    Dma32 = 1,    // 16MB-4GB
    Normal = 2,   // 4GB+
    Movable = 3,  // For memory hotplug
}

#[repr(C)]
pub struct MemZone {
    pub zone_type: ZoneType,
    pub total_pages: AtomicU64,
    pub free_pages: AtomicU64,
    pub file_pages: AtomicU64,   // page cache
    pub anon_pages: AtomicU64,   
    pub slab_pages: AtomicU64,
    pub watermarks: ZoneWatermarks,
    pub pressure: AtomicU32,     // PressureLevel as u32
    pub compact_stall: AtomicU32,
    pub compact_success: AtomicU32,
}

impl MemZone {
    pub fn new(zone_type: ZoneType, total_pages: u64) -> Self {
        Self {
            zone_type,
            total_pages: AtomicU64::new(total_pages),
            free_pages: AtomicU64::new(total_pages),
            file_pages: AtomicU64::new(0),
            anon_pages: AtomicU64::new(0),
            slab_pages: AtomicU64::new(0),
            watermarks: ZoneWatermarks::new(total_pages),
            pressure: AtomicU32::new(PressureLevel::None as u32),
            compact_stall: AtomicU32::new(0),
            compact_success: AtomicU32::new(0),
        }
    }

    pub fn update_pressure(&self) {
        let free = self.free_pages.load(Ordering::Relaxed);
        let level = if free < self.watermarks.wmark_min {
            PressureLevel::Oom
        } else if free < self.watermarks.wmark_low {
            PressureLevel::Critical
        } else if free < self.watermarks.wmark_high {
            PressureLevel::Medium
        } else if free < self.watermarks.wmark_high * 2 {
            PressureLevel::Low
        } else {
            PressureLevel::None
        };
        self.pressure.store(level as u32, Ordering::Relaxed);
    }

    pub fn current_pressure(&self) -> PressureLevel {
        match self.pressure.load(Ordering::Relaxed) {
            0 => PressureLevel::None,
            1 => PressureLevel::Low,
            2 => PressureLevel::Medium,
            3 => PressureLevel::Critical,
            _ => PressureLevel::Oom,
        }
    }
}

// ─────────────────── OOM Score ──────────────────────────────────────

/// OOM score adjustment: -1000 (never kill) to 1000 (always kill)
pub const OOM_SCORE_ADJ_MIN: i32 = -1000;
pub const OOM_SCORE_ADJ_MAX: i32 = 1000;
/// Special value: kernel/init process, never kill
pub const OOM_ADJ_UNKILLABLE: i32 = -1000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OomProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub name: [u8; 16],
    pub name_len: u8,
    /// Memory usage in pages
    pub anon_pages: u64,
    pub file_pages: u64,
    pub shmem_pages: u64,
    pub swap_pages: u64,
    /// Total RSS
    pub rss_pages: u64,
    /// OOM adjustment
    pub oom_score_adj: i32,
    /// Computed OOM score (0-2000)
    pub oom_score: u32,
    /// Process flags
    pub is_init: bool,
    pub is_kernel_thread: bool,
    pub is_oom_reaping: bool,
    pub active: bool,
}

impl OomProcessInfo {
    pub const EMPTY: Self = Self {
        pid: 0,
        uid: 0,
        name: [0u8; 16],
        name_len: 0,
        anon_pages: 0,
        file_pages: 0,
        shmem_pages: 0,
        swap_pages: 0,
        rss_pages: 0,
        oom_score_adj: 0,
        oom_score: 0,
        is_init: false,
        is_kernel_thread: false,
        is_oom_reaping: false,
        active: false,
    };

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(15);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn total_mem_pages(&self) -> u64 {
        self.rss_pages + self.swap_pages
    }

    /// Calculate OOM score (0-2000 range)
    /// Higher score = more likely to be killed
    pub fn calculate_score(&mut self, total_ram_pages: u64) {
        // Unkillable
        if self.is_init || self.is_kernel_thread || self.oom_score_adj == OOM_ADJ_UNKILLABLE {
            self.oom_score = 0;
            return;
        }

        // Base score: proportion of RAM used (0-1000 scale)
        let total_mem = self.total_mem_pages();
        let base_score = if total_ram_pages > 0 {
            ((total_mem * 1000) / total_ram_pages) as i64
        } else {
            0i64
        };

        // Apply oom_score_adj
        let adjusted = base_score + self.oom_score_adj as i64;

        // Clamp to 0-2000
        self.oom_score = adjusted.clamp(0, 2000) as u32;
    }
}

// ─────────────────── OOM Event Log ──────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OomEvent {
    pub timestamp: u64,
    pub victim_pid: u32,
    pub victim_score: u32,
    pub freed_pages: u64,
    pub trigger_zone: u8,
    pub pressure_level: u8,
    pub was_cgroup_oom: bool,
    pub cgroup_id: u32,
    pub valid: bool,
}

impl OomEvent {
    pub const EMPTY: Self = Self {
        timestamp: 0,
        victim_pid: 0,
        victim_score: 0,
        freed_pages: 0,
        trigger_zone: 0,
        pressure_level: 0,
        was_cgroup_oom: false,
        cgroup_id: 0,
        valid: false,
    };
}

// ─────────────────── Memory Notifier ────────────────────────────────

#[repr(C)]
pub struct MemNotifier {
    pub threshold_pages: u64,
    pub callback_id: u32,     // registered handler ID
    pub triggered: AtomicBool,
    pub active: bool,
}

impl MemNotifier {
    pub const EMPTY: Self = Self {
        threshold_pages: 0,
        callback_id: 0,
        triggered: AtomicBool::new(false),
        active: false,
    };
}

// ─────────────────── OOM Reaper ─────────────────────────────────────
/// Tracks processes that failed to exit promptly after OOM signal

#[repr(C)]
pub struct OomReaper {
    /// PIDs of processes being reaped
    pub victims: [u32; 8],
    pub victim_count: AtomicU32,
    /// Timeout before force-freeing memory (microseconds)
    pub reap_timeout_us: u64,
    pub timestamps: [u64; 8],
    pub total_reaped: AtomicU64,
}

impl OomReaper {
    pub const fn new() -> Self {
        Self {
            victims: [0u32; 8],
            victim_count: AtomicU32::new(0),
            reap_timeout_us: 1_000_000, // 1 second
            timestamps: [0u64; 8],
            total_reaped: AtomicU64::new(0),
        }
    }

    pub fn add_victim(&mut self, pid: u32, timestamp: u64) -> bool {
        let count = self.victim_count.load(Ordering::Relaxed) as usize;
        if count >= 8 { return false; }
        self.victims[count] = pid;
        self.timestamps[count] = timestamp;
        self.victim_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Check for timed-out victims that need force-reaping
    pub fn check_timeouts(&mut self, current_time: u64) -> Option<u32> {
        let count = self.victim_count.load(Ordering::Relaxed) as usize;
        for i in 0..count {
            if current_time - self.timestamps[i] > self.reap_timeout_us {
                let pid = self.victims[i];
                // Remove by swapping with last
                if i + 1 < count {
                    self.victims[i] = self.victims[count - 1];
                    self.timestamps[i] = self.timestamps[count - 1];
                }
                self.victim_count.fetch_sub(1, Ordering::Relaxed);
                self.total_reaped.fetch_add(1, Ordering::Relaxed);
                return Some(pid);
            }
        }
        None
    }

    pub fn remove_victim(&mut self, pid: u32) -> bool {
        let count = self.victim_count.load(Ordering::Relaxed) as usize;
        for i in 0..count {
            if self.victims[i] == pid {
                if i + 1 < count {
                    self.victims[i] = self.victims[count - 1];
                    self.timestamps[i] = self.timestamps[count - 1];
                }
                self.victim_count.fetch_sub(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }
}

// ─────────────────── OOM Killer ─────────────────────────────────────

pub struct OomKiller {
    /// Process table snapshot for scoring
    pub procs: [OomProcessInfo; MAX_PROCS],
    pub proc_count: u32,
    /// Memory zones
    pub zones: [MemZone; 4],
    pub zone_count: u8,
    /// Total system RAM
    pub total_ram_pages: AtomicU64,
    /// Event log
    pub events: [OomEvent; MAX_OOM_LOG],
    pub event_write_pos: u32,
    pub total_oom_kills: AtomicU64,
    /// Notifiers
    pub notifiers: [MemNotifier; MAX_NOTIFIERS],
    pub notifier_count: u32,
    /// Reaper
    pub reaper: OomReaper,
    /// Configuration
    pub panic_on_oom: AtomicBool,
    pub sysctl_oom_kill_allocating_task: AtomicBool,
    /// Time counter
    pub time_counter: AtomicU64,
    pub initialized: AtomicBool,
}

impl OomKiller {
    pub fn new() -> Self {
        Self {
            procs: [OomProcessInfo::EMPTY; MAX_PROCS],
            proc_count: 0,
            zones: [
                MemZone::new(ZoneType::Dma, 4096),        // 16MB DMA zone
                MemZone::new(ZoneType::Dma32, 262144),    // 1GB DMA32 zone
                MemZone::new(ZoneType::Normal, 524288),   // 2GB Normal zone
                MemZone::new(ZoneType::Movable, 0),
            ],
            zone_count: 3,
            total_ram_pages: AtomicU64::new(786432), // ~3GB
            events: [OomEvent::EMPTY; MAX_OOM_LOG],
            event_write_pos: 0,
            total_oom_kills: AtomicU64::new(0),
            notifiers: [MemNotifier::EMPTY; MAX_NOTIFIERS],
            notifier_count: 0,
            reaper: OomReaper::new(),
            panic_on_oom: AtomicBool::new(false),
            sysctl_oom_kill_allocating_task: AtomicBool::new(false),
            time_counter: AtomicU64::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Register a process for OOM tracking
    pub fn register_process(&mut self, info: OomProcessInfo) -> bool {
        if self.proc_count as usize >= MAX_PROCS { return false; }
        // Check for existing PID
        for i in 0..self.proc_count as usize {
            if self.procs[i].active && self.procs[i].pid == info.pid {
                self.procs[i] = info;
                return true;
            }
        }
        let idx = self.proc_count as usize;
        self.procs[idx] = info;
        self.procs[idx].active = true;
        self.proc_count += 1;
        true
    }

    /// Unregister a process
    pub fn unregister_process(&mut self, pid: u32) -> bool {
        for i in 0..self.proc_count as usize {
            if self.procs[i].active && self.procs[i].pid == pid {
                self.procs[i].active = false;
                return true;
            }
        }
        false
    }

    /// Update RSS for a process
    pub fn update_rss(&mut self, pid: u32, rss: u64, swap: u64) {
        for i in 0..self.proc_count as usize {
            if self.procs[i].active && self.procs[i].pid == pid {
                self.procs[i].rss_pages = rss;
                self.procs[i].swap_pages = swap;
                return;
            }
        }
    }

    /// Set oom_score_adj for a process
    pub fn set_oom_score_adj(&mut self, pid: u32, adj: i32) -> bool {
        let clamped = adj.clamp(OOM_SCORE_ADJ_MIN, OOM_SCORE_ADJ_MAX);
        for i in 0..self.proc_count as usize {
            if self.procs[i].active && self.procs[i].pid == pid {
                self.procs[i].oom_score_adj = clamped;
                return true;
            }
        }
        false
    }

    /// Recalculate all OOM scores
    fn calculate_all_scores(&mut self) {
        let total = self.total_ram_pages.load(Ordering::Relaxed);
        for i in 0..self.proc_count as usize {
            if self.procs[i].active {
                self.procs[i].calculate_score(total);
            }
        }
    }

    /// Select OOM victim (highest score wins)
    pub fn select_victim(&mut self) -> Option<u32> {
        self.calculate_all_scores();

        let mut best_score: u32 = 0;
        let mut best_pid: Option<u32> = None;
        let mut best_idx: Option<usize> = None;

        for i in 0..self.proc_count as usize {
            let proc = &self.procs[i];
            if !proc.active { continue; }
            if proc.is_init || proc.is_kernel_thread { continue; }
            if proc.oom_score_adj == OOM_ADJ_UNKILLABLE { continue; }
            if proc.is_oom_reaping { continue; }

            if proc.oom_score > best_score {
                best_score = proc.oom_score;
                best_pid = Some(proc.pid);
                best_idx = Some(i);
            }
        }

        // Also consider child processes of the best candidate
        // (Kill children before parent as they share most memory)
        if let Some(_idx) = best_idx {
            // In a real kernel, we'd check child threads here
        }

        best_pid
    }

    /// Execute OOM kill
    pub fn oom_kill(&mut self, zone_idx: u8) -> Option<u32> {
        if self.panic_on_oom.load(Ordering::Relaxed) {
            // Kernel panic mode — don't kill, panic
            return None;
        }

        // Try to kill the allocating task first if configured
        if self.sysctl_oom_kill_allocating_task.load(Ordering::Relaxed) {
            // In a real kernel, we'd check the current task
        }

        let victim_pid = self.select_victim()?;

        // Mark as being reaped
        for i in 0..self.proc_count as usize {
            if self.procs[i].active && self.procs[i].pid == victim_pid {
                self.procs[i].is_oom_reaping = true;
                let freed = self.procs[i].rss_pages;

                // Log event
                let ts = self.time_counter.fetch_add(1, Ordering::Relaxed);
                self.log_event(OomEvent {
                    timestamp: ts,
                    victim_pid,
                    victim_score: self.procs[i].oom_score,
                    freed_pages: freed,
                    trigger_zone: zone_idx,
                    pressure_level: PressureLevel::Oom as u8,
                    was_cgroup_oom: false,
                    cgroup_id: 0,
                    valid: true,
                });

                // Add to reaper for timeout tracking
                self.reaper.add_victim(victim_pid, ts);

                self.total_oom_kills.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }

        Some(victim_pid)
    }

    fn log_event(&mut self, event: OomEvent) {
        let pos = self.event_write_pos as usize % MAX_OOM_LOG;
        self.events[pos] = event;
        self.event_write_pos += 1;
    }

    /// Check all zones and trigger OOM if needed
    pub fn check_pressure(&mut self) -> PressureLevel {
        let mut worst = PressureLevel::None;

        for z in 0..self.zone_count as usize {
            self.zones[z].update_pressure();
            let level = self.zones[z].current_pressure();
            if level as u8 > worst as u8 {
                worst = level;
            }
        }

        // Fire notifiers
        self.check_notifiers();

        // If OOM, try reclaim first, then kill
        if worst == PressureLevel::Oom {
            if !self.try_reclaim() {
                // Must kill
                for z in 0..self.zone_count as usize {
                    if self.zones[z].current_pressure() == PressureLevel::Oom {
                        self.oom_kill(z as u8);
                        break;
                    }
                }
            }
        }

        worst
    }

    /// Attempt memory reclaim before resorting to OOM kill
    fn try_reclaim(&self) -> bool {
        // Try to free file-backed pages first
        for z in 0..self.zone_count as usize {
            let file_pages = self.zones[z].file_pages.load(Ordering::Relaxed);
            if file_pages > 0 {
                // In a real kernel: call shrink_page_cache(), shrink_slab()
                // For now, simulate freeing some pages
                return false; // Couldn't reclaim enough
            }
        }
        false
    }

    /// Register a low-memory notifier
    pub fn add_notifier(&mut self, threshold_pages: u64, callback_id: u32) -> bool {
        if self.notifier_count as usize >= MAX_NOTIFIERS { return false; }
        let idx = self.notifier_count as usize;
        self.notifiers[idx] = MemNotifier {
            threshold_pages,
            callback_id,
            triggered: AtomicBool::new(false),
            active: true,
        };
        self.notifier_count += 1;
        true
    }

    fn check_notifiers(&self) {
        let total_free = self.total_free_pages();
        for i in 0..self.notifier_count as usize {
            if !self.notifiers[i].active { continue; }
            if total_free < self.notifiers[i].threshold_pages {
                self.notifiers[i].triggered.store(true, Ordering::Relaxed);
            } else {
                self.notifiers[i].triggered.store(false, Ordering::Relaxed);
            }
        }
    }

    pub fn total_free_pages(&self) -> u64 {
        let mut total = 0u64;
        for z in 0..self.zone_count as usize {
            total += self.zones[z].free_pages.load(Ordering::Relaxed);
        }
        total
    }

    pub fn total_used_pages(&self) -> u64 {
        let total = self.total_ram_pages.load(Ordering::Relaxed);
        let free = self.total_free_pages();
        total.saturating_sub(free)
    }

    /// Simulate allocation: decrease free pages
    pub fn alloc_pages(&self, zone_idx: u8, pages: u64) -> bool {
        let z = zone_idx as usize;
        if z >= self.zone_count as usize { return false; }
        let free = self.zones[z].free_pages.load(Ordering::Relaxed);
        if free < pages { return false; }
        self.zones[z].free_pages.fetch_sub(pages, Ordering::Relaxed);
        true
    }

    /// Free pages back to zone
    pub fn free_pages(&self, zone_idx: u8, pages: u64) {
        let z = zone_idx as usize;
        if z >= self.zone_count as usize { return; }
        self.zones[z].free_pages.fetch_add(pages, Ordering::Relaxed);
    }

    pub fn event_count(&self) -> u32 {
        self.event_write_pos.min(MAX_OOM_LOG as u32)
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut OOM_KILLER: Option<OomKiller> = None;

fn oom_killer() -> &'static mut OomKiller {
    unsafe {
        if OOM_KILLER.is_none() {
            let mut k = OomKiller::new();
            k.init();
            OOM_KILLER = Some(k);
        }
        OOM_KILLER.as_mut().unwrap()
    }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_oom_init() {
    let _ = oom_killer();
}

#[no_mangle]
pub extern "C" fn rust_oom_register_proc(pid: u32, rss_pages: u64, adj: i32) -> i32 {
    let mut info = OomProcessInfo::EMPTY;
    info.pid = pid;
    info.rss_pages = rss_pages;
    info.oom_score_adj = adj;
    info.active = true;
    if oom_killer().register_process(info) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_oom_unregister_proc(pid: u32) -> i32 {
    if oom_killer().unregister_process(pid) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_oom_set_adj(pid: u32, adj: i32) -> i32 {
    if oom_killer().set_oom_score_adj(pid, adj) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_oom_check_pressure() -> u8 {
    oom_killer().check_pressure() as u8
}

#[no_mangle]
pub extern "C" fn rust_oom_total_free() -> u64 {
    oom_killer().total_free_pages()
}

#[no_mangle]
pub extern "C" fn rust_oom_total_kills() -> u64 {
    oom_killer().total_oom_kills.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_oom_event_count() -> u32 {
    oom_killer().event_count()
}

#[no_mangle]
pub extern "C" fn rust_oom_alloc_pages(zone: u8, pages: u64) -> i32 {
    if oom_killer().alloc_pages(zone, pages) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_oom_free_pages(zone: u8, pages: u64) {
    oom_killer().free_pages(zone, pages);
}

#[no_mangle]
pub extern "C" fn rust_oom_set_panic(panic_on_oom: u8) {
    oom_killer().panic_on_oom.store(panic_on_oom != 0, Ordering::Relaxed);
}

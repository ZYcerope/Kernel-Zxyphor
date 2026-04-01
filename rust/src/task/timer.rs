// =============================================================================
// Kernel Zxyphor — Kernel Timer Wheel (Hierarchical Hashed Timer)
// =============================================================================
// Implements a hierarchical timer wheel (inspired by Linux kernel's timer.c)
// for efficient management of kernel timers with O(1) insertion and deletion.
//
// The timer wheel has 4 levels:
//   Level 0: 256 slots, 1 tick each (0–255 ticks)
//   Level 1: 64 slots, 256 ticks each (256–16383 ticks)
//   Level 2: 64 slots, 16384 ticks each (16384–1048575 ticks)
//   Level 3: 64 slots, 1048576 ticks each (~1M–64M ticks)
//
// This allows O(1) timer insertion regardless of the timeout value.
// Timer expiry processing cascades from higher levels to lower levels.
// =============================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Timer callback type
pub type TimerCallback = extern "C" fn(context: usize);

/// Level 0: 256 slots
const LEVEL0_BITS: usize = 8;
const LEVEL0_SIZE: usize = 1 << LEVEL0_BITS; // 256
const LEVEL0_MASK: usize = LEVEL0_SIZE - 1;

/// Levels 1–3: 64 slots each
const LEVELN_BITS: usize = 6;
const LEVELN_SIZE: usize = 1 << LEVELN_BITS; // 64
const LEVELN_MASK: usize = LEVELN_SIZE - 1;

/// Maximum timers across all levels
const MAX_TIMERS: usize = 4096;

/// Timer flags
const TIMER_ACTIVE: u8 = 1 << 0;
const TIMER_PERIODIC: u8 = 1 << 1;

// =============================================================================
// Timer entry
// =============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TimerEntry {
    /// When this timer expires (absolute tick count)
    pub expires: u64,
    /// Callback function
    pub callback: Option<TimerCallback>,
    /// Opaque context for the callback
    pub context: usize,
    /// Period for periodic timers (0 = one-shot)
    pub period: u64,
    /// Timer flags
    pub flags: u8,
    /// Which level/slot this timer is currently in
    pub level: u8,
    pub slot: u16,
    /// Next timer in the same slot (linked list index, MAX_TIMERS = null)
    pub next: u16,
}

impl TimerEntry {
    pub const fn empty() -> Self {
        TimerEntry {
            expires: 0,
            callback: None,
            context: 0,
            period: 0,
            flags: 0,
            level: 0,
            slot: 0,
            next: MAX_TIMERS as u16,
        }
    }

    pub fn is_active(&self) -> bool {
        self.flags & TIMER_ACTIVE != 0
    }

    pub fn is_periodic(&self) -> bool {
        self.flags & TIMER_PERIODIC != 0
    }
}

// =============================================================================
// Timer wheel slot (head of linked list)
// =============================================================================

/// Each slot is the head of a singly-linked list of timers
#[repr(C)]
#[derive(Clone, Copy)]
struct TimerSlot {
    /// Index of the first timer in this slot (MAX_TIMERS = empty)
    head: u16,
    /// Number of timers in this slot
    count: u16,
}

impl TimerSlot {
    const fn empty() -> Self {
        TimerSlot {
            head: MAX_TIMERS as u16,
            count: 0,
        }
    }
}

// =============================================================================
// Timer wheel
// =============================================================================

/// The hierarchical timer wheel
pub struct TimerWheel {
    /// Timer pool (flat array, used as free-list)
    timers: [TimerEntry; MAX_TIMERS],
    /// Free list head
    free_head: u16,
    /// Number of active timers
    active_count: u32,

    /// Level 0 slots (256 × 1 tick)
    level0: [TimerSlot; LEVEL0_SIZE],
    /// Level 1 slots (64 × 256 ticks)
    level1: [TimerSlot; LEVELN_SIZE],
    /// Level 2 slots (64 × 16384 ticks)
    level2: [TimerSlot; LEVELN_SIZE],
    /// Level 3 slots (64 × 1048576 ticks)
    level3: [TimerSlot; LEVELN_SIZE],

    /// Current tick count
    current_tick: u64,
}

impl TimerWheel {
    pub const fn new() -> Self {
        let mut wheel = TimerWheel {
            timers: [TimerEntry::empty(); MAX_TIMERS],
            free_head: 0,
            active_count: 0,
            level0: [TimerSlot::empty(); LEVEL0_SIZE],
            level1: [TimerSlot::empty(); LEVELN_SIZE],
            level2: [TimerSlot::empty(); LEVELN_SIZE],
            level3: [TimerSlot::empty(); LEVELN_SIZE],
            current_tick: 0,
        };

        // Build free list: timer[0].next = 1, timer[1].next = 2, etc.
        let mut i = 0u16;
        while (i as usize) < MAX_TIMERS - 1 {
            wheel.timers[i as usize].next = i + 1;
            i += 1;
        }
        wheel.timers[MAX_TIMERS - 1].next = MAX_TIMERS as u16; // End of free list

        wheel
    }

    /// Allocate a timer from the free pool
    fn alloc_timer(&mut self) -> Option<u16> {
        if self.free_head as usize >= MAX_TIMERS {
            return None;
        }
        let idx = self.free_head;
        self.free_head = self.timers[idx as usize].next;
        self.timers[idx as usize].next = MAX_TIMERS as u16;
        Some(idx)
    }

    /// Return a timer to the free pool
    fn free_timer(&mut self, idx: u16) {
        self.timers[idx as usize] = TimerEntry::empty();
        self.timers[idx as usize].next = self.free_head;
        self.free_head = idx;
    }

    /// Determine which level and slot a timer should go into
    fn compute_level_slot(&self, expires: u64) -> (u8, u16) {
        let delta = expires.saturating_sub(self.current_tick);

        if delta < LEVEL0_SIZE as u64 {
            // Level 0: direct mapping
            let slot = (expires as usize) & LEVEL0_MASK;
            (0, slot as u16)
        } else if delta < (LEVEL0_SIZE * LEVELN_SIZE) as u64 {
            // Level 1
            let slot = ((expires >> LEVEL0_BITS) as usize) & LEVELN_MASK;
            (1, slot as u16)
        } else if delta < (LEVEL0_SIZE * LEVELN_SIZE * LEVELN_SIZE) as u64 {
            // Level 2
            let slot = ((expires >> (LEVEL0_BITS + LEVELN_BITS)) as usize) & LEVELN_MASK;
            (2, slot as u16)
        } else {
            // Level 3
            let slot = ((expires >> (LEVEL0_BITS + 2 * LEVELN_BITS)) as usize) & LEVELN_MASK;
            (3, slot as u16)
        }
    }

    /// Insert a timer into the appropriate wheel slot
    fn insert_into_slot(&mut self, timer_idx: u16, level: u8, slot: u16) {
        self.timers[timer_idx as usize].level = level;
        self.timers[timer_idx as usize].slot = slot;

        let slot_ref = match level {
            0 => &mut self.level0[slot as usize],
            1 => &mut self.level1[slot as usize],
            2 => &mut self.level2[slot as usize],
            _ => &mut self.level3[slot as usize],
        };

        self.timers[timer_idx as usize].next = slot_ref.head;
        slot_ref.head = timer_idx;
        slot_ref.count += 1;
    }

    /// Add a one-shot timer
    pub fn add_timer(
        &mut self,
        callback: TimerCallback,
        context: usize,
        ticks_from_now: u64,
    ) -> Option<u16> {
        let timer_idx = self.alloc_timer()?;
        let expires = self.current_tick + ticks_from_now;

        self.timers[timer_idx as usize].expires = expires;
        self.timers[timer_idx as usize].callback = Some(callback);
        self.timers[timer_idx as usize].context = context;
        self.timers[timer_idx as usize].period = 0;
        self.timers[timer_idx as usize].flags = TIMER_ACTIVE;

        let (level, slot) = self.compute_level_slot(expires);
        self.insert_into_slot(timer_idx, level, slot);
        self.active_count += 1;

        Some(timer_idx)
    }

    /// Add a periodic timer
    pub fn add_periodic_timer(
        &mut self,
        callback: TimerCallback,
        context: usize,
        period: u64,
    ) -> Option<u16> {
        let timer_idx = self.alloc_timer()?;
        let expires = self.current_tick + period;

        self.timers[timer_idx as usize].expires = expires;
        self.timers[timer_idx as usize].callback = Some(callback);
        self.timers[timer_idx as usize].context = context;
        self.timers[timer_idx as usize].period = period;
        self.timers[timer_idx as usize].flags = TIMER_ACTIVE | TIMER_PERIODIC;

        let (level, slot) = self.compute_level_slot(expires);
        self.insert_into_slot(timer_idx, level, slot);
        self.active_count += 1;

        Some(timer_idx)
    }

    /// Advance the timer wheel by one tick and fire expired timers
    pub fn tick(&mut self) -> u32 {
        self.current_tick += 1;
        let mut fired = 0u32;

        // Process level 0 slot for current tick
        let slot = (self.current_tick as usize) & LEVEL0_MASK;
        fired += self.fire_slot_level0(slot);

        // Cascade from higher levels at appropriate boundaries
        if (self.current_tick as usize) & LEVEL0_MASK == 0 {
            // Cascade level 1
            let l1_slot = ((self.current_tick >> LEVEL0_BITS) as usize) & LEVELN_MASK;
            self.cascade_level(1, l1_slot);
        }

        if (self.current_tick as usize) & ((LEVEL0_SIZE * LEVELN_SIZE) - 1) == 0 {
            // Cascade level 2
            let l2_slot = ((self.current_tick >> (LEVEL0_BITS + LEVELN_BITS)) as usize) & LEVELN_MASK;
            self.cascade_level(2, l2_slot);
        }

        if (self.current_tick as usize) & ((LEVEL0_SIZE * LEVELN_SIZE * LEVELN_SIZE) - 1) == 0 {
            // Cascade level 3
            let l3_slot = ((self.current_tick >> (LEVEL0_BITS + 2 * LEVELN_BITS)) as usize) & LEVELN_MASK;
            self.cascade_level(3, l3_slot);
        }

        fired
    }

    /// Fire all timers in a level 0 slot
    fn fire_slot_level0(&mut self, slot: usize) -> u32 {
        let mut fired = 0u32;
        let mut idx = self.level0[slot].head;

        // Detach the entire chain
        self.level0[slot].head = MAX_TIMERS as u16;
        self.level0[slot].count = 0;

        while (idx as usize) < MAX_TIMERS {
            let timer = self.timers[idx as usize];
            let next = timer.next;

            if timer.is_active() {
                if let Some(callback) = timer.callback {
                    callback(timer.context);
                    fired += 1;
                }

                if timer.is_periodic() {
                    // Re-arm periodic timer
                    let new_expires = self.current_tick + timer.period;
                    self.timers[idx as usize].expires = new_expires;
                    let (level, new_slot) = self.compute_level_slot(new_expires);
                    self.insert_into_slot(idx, level, new_slot);
                } else {
                    self.active_count -= 1;
                    self.free_timer(idx);
                }
            } else {
                self.free_timer(idx);
            }

            idx = next;
        }

        fired
    }

    /// Cascade timers from a higher level down to lower levels
    fn cascade_level(&mut self, level: u8, slot: usize) {
        let slot_ref = match level {
            1 => &mut self.level1[slot],
            2 => &mut self.level2[slot],
            _ => &mut self.level3[slot],
        };

        let mut idx = slot_ref.head;
        slot_ref.head = MAX_TIMERS as u16;
        slot_ref.count = 0;

        while (idx as usize) < MAX_TIMERS {
            let next = self.timers[idx as usize].next;
            let expires = self.timers[idx as usize].expires;

            let (new_level, new_slot) = self.compute_level_slot(expires);
            self.insert_into_slot(idx, new_level, new_slot);

            idx = next;
        }
    }
}

// =============================================================================
// Global timer wheel
// =============================================================================

static mut TIMER_WHEEL: TimerWheel = TimerWheel::new();
static TIMER_INITIALIZED: AtomicBool = AtomicBool::new(false);
static TOTAL_TICKS: AtomicU64 = AtomicU64::new(0);
static TOTAL_FIRED: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// FFI exports
// =============================================================================

/// Initialize the timer wheel
#[no_mangle]
pub extern "C" fn zxyphor_rust_timer_init() -> i32 {
    if TIMER_INITIALIZED.load(Ordering::SeqCst) {
        return crate::ffi::error::FfiError::AlreadyExists.as_i32();
    }

    TIMER_INITIALIZED.store(true, Ordering::SeqCst);
    crate::ffi::bridge::log_info("Rust hierarchical timer wheel initialized");

    crate::ffi::error::FfiError::Success.as_i32()
}

/// Add a one-shot timer
#[no_mangle]
pub extern "C" fn zxyphor_rust_timer_add(
    callback: TimerCallback,
    context: usize,
    ticks: u64,
) -> i32 {
    let wheel = unsafe { &mut TIMER_WHEEL };

    match wheel.add_timer(callback, context, ticks) {
        Some(id) => id as i32,
        None => crate::ffi::error::FfiError::NoMemory.as_i32(),
    }
}

/// Add a periodic timer
#[no_mangle]
pub extern "C" fn zxyphor_rust_timer_add_periodic(
    callback: TimerCallback,
    context: usize,
    period: u64,
) -> i32 {
    let wheel = unsafe { &mut TIMER_WHEEL };

    match wheel.add_periodic_timer(callback, context, period) {
        Some(id) => id as i32,
        None => crate::ffi::error::FfiError::NoMemory.as_i32(),
    }
}

/// Advance the timer wheel by one tick
#[no_mangle]
pub extern "C" fn zxyphor_rust_timer_tick() -> u32 {
    let wheel = unsafe { &mut TIMER_WHEEL };
    let fired = wheel.tick();

    TOTAL_TICKS.fetch_add(1, Ordering::Relaxed);
    TOTAL_FIRED.fetch_add(fired as u64, Ordering::Relaxed);

    fired
}

/// Get timer statistics
#[repr(C)]
pub struct TimerStats {
    pub total_ticks: u64,
    pub total_fired: u64,
    pub active_timers: u32,
    pub current_tick: u64,
}

#[no_mangle]
pub extern "C" fn zxyphor_rust_timer_stats(out: *mut TimerStats) -> i32 {
    if out.is_null() {
        return crate::ffi::error::FfiError::InvalidArgument.as_i32();
    }

    let wheel = unsafe { &TIMER_WHEEL };
    let stats = TimerStats {
        total_ticks: TOTAL_TICKS.load(Ordering::Relaxed),
        total_fired: TOTAL_FIRED.load(Ordering::Relaxed),
        active_timers: wheel.active_count,
        current_tick: wheel.current_tick,
    };

    unsafe { core::ptr::write(out, stats) };
    crate::ffi::error::FfiError::Success.as_i32()
}

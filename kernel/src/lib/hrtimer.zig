// ============================================================================
// Kernel Zxyphor — Advanced Timer Subsystem
//
// Comprehensive timer management including:
// - High-resolution timers (hrtimers) with nanosecond precision
// - Timer wheel for coarse-grained timeouts
// - Clock sources and clock events abstraction
// - POSIX timers (timer_create/settime/delete)
// - Interval timers (setitimer/getitimer)
// - Tickless (NO_HZ) operation support
// - Per-CPU timer management
// - Dynamic tick suppression for power saving
// - Timer migration for load balancing
// ============================================================================

const std = @import("std");

// ============================================================================
// Time Constants
// ============================================================================

pub const NSEC_PER_SEC: u64 = 1_000_000_000;
pub const NSEC_PER_MSEC: u64 = 1_000_000;
pub const NSEC_PER_USEC: u64 = 1_000;
pub const USEC_PER_SEC: u64 = 1_000_000;
pub const MSEC_PER_SEC: u64 = 1_000;
pub const HZ: u64 = 1000; // Tick rate
pub const TICK_NSEC: u64 = NSEC_PER_SEC / HZ;

// ============================================================================
// Clock IDs (POSIX)
// ============================================================================

pub const CLOCK_REALTIME = 0;
pub const CLOCK_MONOTONIC = 1;
pub const CLOCK_PROCESS_CPUTIME_ID = 2;
pub const CLOCK_THREAD_CPUTIME_ID = 3;
pub const CLOCK_MONOTONIC_RAW = 4;
pub const CLOCK_REALTIME_COARSE = 5;
pub const CLOCK_MONOTONIC_COARSE = 6;
pub const CLOCK_BOOTTIME = 7;
pub const CLOCK_REALTIME_ALARM = 8;
pub const CLOCK_BOOTTIME_ALARM = 9;
pub const CLOCK_TAI = 11;
pub const MAX_CLOCKS = 16;

// ============================================================================
// Timespec / Time types
// ============================================================================

pub const Timespec = struct {
    tv_sec: i64,
    tv_nsec: i64,

    const Self = @This();

    pub fn zero() Self {
        return .{ .tv_sec = 0, .tv_nsec = 0 };
    }

    pub fn fromNsec(nsec: u64) Self {
        return .{
            .tv_sec = @intCast(nsec / NSEC_PER_SEC),
            .tv_nsec = @intCast(nsec % NSEC_PER_SEC),
        };
    }

    pub fn toNsec(self: Self) u64 {
        return @as(u64, @intCast(self.tv_sec)) * NSEC_PER_SEC +
            @as(u64, @intCast(self.tv_nsec));
    }

    pub fn add(a: Self, b: Self) Self {
        var sec = a.tv_sec + b.tv_sec;
        var nsec = a.tv_nsec + b.tv_nsec;
        if (nsec >= @as(i64, @intCast(NSEC_PER_SEC))) {
            nsec -= @as(i64, @intCast(NSEC_PER_SEC));
            sec += 1;
        }
        return .{ .tv_sec = sec, .tv_nsec = nsec };
    }

    pub fn sub(a: Self, b: Self) Self {
        var sec = a.tv_sec - b.tv_sec;
        var nsec = a.tv_nsec - b.tv_nsec;
        if (nsec < 0) {
            nsec += @as(i64, @intCast(NSEC_PER_SEC));
            sec -= 1;
        }
        return .{ .tv_sec = sec, .tv_nsec = nsec };
    }

    pub fn cmp(a: Self, b: Self) std.math.Order {
        if (a.tv_sec < b.tv_sec) return .lt;
        if (a.tv_sec > b.tv_sec) return .gt;
        if (a.tv_nsec < b.tv_nsec) return .lt;
        if (a.tv_nsec > b.tv_nsec) return .gt;
        return .eq;
    }

    pub fn isZero(self: Self) bool {
        return self.tv_sec == 0 and self.tv_nsec == 0;
    }
};

pub const Timeval = struct {
    tv_sec: i64,
    tv_usec: i64,

    pub fn toTimespec(self: @This()) Timespec {
        return .{
            .tv_sec = self.tv_sec,
            .tv_nsec = self.tv_usec * @as(i64, @intCast(NSEC_PER_USEC)),
        };
    }

    pub fn fromTimespec(ts: Timespec) @This() {
        return .{
            .tv_sec = ts.tv_sec,
            .tv_usec = @divTrunc(ts.tv_nsec, @as(i64, @intCast(NSEC_PER_USEC))),
        };
    }
};

pub const ITimerVal = struct {
    it_interval: Timeval,
    it_value: Timeval,
};

pub const ITimerSpec = struct {
    it_interval: Timespec,
    it_value: Timespec,
};

// ============================================================================
// Ktime — Kernel time representation (nanoseconds since boot)
// ============================================================================

pub const Ktime = struct {
    nsec: i64,

    const Self = @This();

    pub fn zero() Self {
        return .{ .nsec = 0 };
    }

    pub fn fromNsec(n: i64) Self {
        return .{ .nsec = n };
    }

    pub fn fromMsec(ms: u64) Self {
        return .{ .nsec = @intCast(ms * NSEC_PER_MSEC) };
    }

    pub fn fromTimespec(ts: Timespec) Self {
        return .{ .nsec = ts.tv_sec * @as(i64, @intCast(NSEC_PER_SEC)) + ts.tv_nsec };
    }

    pub fn toTimespec(self: Self) Timespec {
        if (self.nsec >= 0) {
            return .{
                .tv_sec = @divTrunc(self.nsec, @as(i64, @intCast(NSEC_PER_SEC))),
                .tv_nsec = @mod(self.nsec, @as(i64, @intCast(NSEC_PER_SEC))),
            };
        } else {
            var sec = @divTrunc(self.nsec, @as(i64, @intCast(NSEC_PER_SEC)));
            var rem = @mod(self.nsec, @as(i64, @intCast(NSEC_PER_SEC)));
            if (rem < 0) {
                sec -= 1;
                rem += @as(i64, @intCast(NSEC_PER_SEC));
            }
            return .{ .tv_sec = sec, .tv_nsec = rem };
        }
    }

    pub fn add(a: Self, b: Self) Self {
        return .{ .nsec = a.nsec + b.nsec };
    }

    pub fn sub(a: Self, b: Self) Self {
        return .{ .nsec = a.nsec - b.nsec };
    }

    pub fn cmp(a: Self, b: Self) std.math.Order {
        if (a.nsec < b.nsec) return .lt;
        if (a.nsec > b.nsec) return .gt;
        return .eq;
    }

    pub fn isZero(self: Self) bool {
        return self.nsec == 0;
    }
};

// ============================================================================
// Clock Source — Abstraction for hardware clocks
// ============================================================================

pub const ClockSourceFlags = packed struct(u32) {
    continuous: bool = false,
    must_verify: bool = false,
    is_watchdog: bool = false,
    suspend_nonstop: bool = false,
    valid_for_hres: bool = false,
    unstable: bool = false,
    _reserved: u26 = 0,
};

pub const ClockSource = struct {
    /// Name of the clock source
    name: [32]u8,
    /// Rating (higher is better): 1-100=unfit, 100-200=mostly ok, 200-300=good, 300-400=ideal
    rating: u32,
    /// Read function: returns current cycle count
    read_fn: ?*const fn () u64,
    /// Bitmask for the counter
    mask: u64,
    /// Multiplier for cycle→nsec conversion
    mult: u32,
    /// Shift for cycle→nsec conversion
    shift: u32,
    /// Flags
    flags: ClockSourceFlags,
    /// Maximum idle time in nsec (for NO_HZ)
    max_idle_ns: u64,
    /// Maximum adjustment (ppb)
    max_adj: i32,
    /// Uncertainty margin
    uncertainty_margin: u32,
    /// Watchdog timestamp
    wd_last: u64,
    /// Last read value
    last_cycle: u64,

    const Self = @This();

    /// Convert cycles to nanoseconds.
    pub fn cyclesToNsec(self: *const Self, cycles: u64) u64 {
        return (cycles *% @as(u64, self.mult)) >> @intCast(self.shift);
    }

    /// Compute mult/shift for a given frequency.
    pub fn calcMultShift(freq: u64, target_shift: u32) struct { mult: u32, shift: u32 } {
        var shift = target_shift;
        while (shift > 0) {
            const tmp = (NSEC_PER_SEC << @intCast(shift)) / freq;
            if (tmp <= 0xFFFFFFFF) {
                return .{ .mult = @intCast(tmp), .shift = shift };
            }
            shift -= 1;
        }
        return .{ .mult = @intCast(NSEC_PER_SEC / freq), .shift = 0 };
    }

    /// Read current nanosecond timestamp.
    pub fn readNsec(self: *Self) u64 {
        if (self.read_fn) |read| {
            const cycles = read();
            const delta = (cycles - self.last_cycle) & self.mask;
            return self.cyclesToNsec(delta);
        }
        return 0;
    }
};

// ============================================================================
// Clock Event Device — Abstraction for timer interrupts
// ============================================================================

pub const ClockEventMode = enum(u8) {
    unused = 0,
    shutdown = 1,
    periodic = 2,
    oneshot = 3,
    oneshot_stopped = 4,
};

pub const ClockEventFeatures = packed struct(u32) {
    periodic: bool = false,
    oneshot: bool = false,
    oneshot_stopped: bool = false,
    c3stop: bool = false,
    _reserved: u28 = 0,
};

pub const ClockEventDevice = struct {
    /// Name
    name: [32]u8,
    /// Features
    features: ClockEventFeatures,
    /// Rating
    rating: u32,
    /// IRQ number
    irq: i32,
    /// Bound CPU
    cpu: u32,
    /// Current mode
    mode: ClockEventMode,
    /// Minimum delta (nanoseconds)
    min_delta_ns: u64,
    /// Maximum delta (nanoseconds)
    max_delta_ns: u64,
    /// Multiplier for nsec→cycles
    mult: u32,
    /// Shift
    shift: u32,
    /// Next event time
    next_event: Ktime,
    /// Event handler callback
    event_handler: ?*const fn (*ClockEventDevice) void,
    /// Set next event (hardware level)
    set_next_event: ?*const fn (u64, *ClockEventDevice) i32,
    /// Set mode
    set_mode: ?*const fn (ClockEventMode, *ClockEventDevice) void,

    const Self = @This();

    /// Program the next event.
    pub fn program(self: *Self, expires: Ktime) i32 {
        if (self.set_next_event == null) return -1;

        const now = Ktime.fromNsec(0); // Would read current time
        var delta = expires.sub(now);
        if (delta.nsec < 0) delta.nsec = 0;

        const nsec: u64 = @intCast(delta.nsec);
        if (nsec < self.min_delta_ns) {
            return self.set_next_event.?(self.min_delta_ns, self);
        }
        if (nsec > self.max_delta_ns) {
            return self.set_next_event.?(self.max_delta_ns, self);
        }
        return self.set_next_event.?(nsec, self);
    }
};

// ============================================================================
// High-Resolution Timer (hrtimer)
// ============================================================================

pub const HrtimerState = enum(u8) {
    inactive = 0,
    enqueued = 1,
    callback_running = 2,
    pending_cancel = 3,
};

pub const HrtimerRestart = enum {
    norestart,
    restart,
};

pub const HrtimerMode = enum(u8) {
    abs = 0,      // Absolute time
    rel = 1,      // Relative time
    pinned = 2,   // Pinned to CPU
    soft = 4,     // Soft IRQ context
    hard = 8,     // Hard IRQ context
    abs_pinned = 2,
    rel_pinned = 3,
    abs_soft = 4,
    rel_soft = 5,
    abs_pinned_hard = 10,
    rel_pinned_hard = 11,
};

pub const Hrtimer = struct {
    /// Expiry time
    expires: Ktime,
    /// Softexpires (allows early expiry for grouping)
    softexpires: Ktime,
    /// Callback function
    function: ?*const fn (*Hrtimer) HrtimerRestart,
    /// Clock base index
    base_idx: u8,
    /// State
    state: HrtimerState,
    /// Is this timer a soft (tasklet) or hard (IRQ) timer?
    is_soft: bool,
    /// Is this timer pinned to a CPU?
    is_pinned: bool,
    /// Is this relative mode?
    is_rel: bool,
    /// RB tree left child
    rb_left: ?*Hrtimer,
    /// RB tree right child
    rb_right: ?*Hrtimer,
    /// RB tree parent
    rb_parent: ?*Hrtimer,
    /// RB tree color (true = red)
    rb_color: bool,

    const Self = @This();

    pub fn init(clock_id: u8) Self {
        return .{
            .expires = Ktime.zero(),
            .softexpires = Ktime.zero(),
            .function = null,
            .base_idx = clock_id,
            .state = .inactive,
            .is_soft = false,
            .is_pinned = false,
            .is_rel = false,
            .rb_left = null,
            .rb_right = null,
            .rb_parent = null,
            .rb_color = false,
        };
    }
};

// ============================================================================
// Hrtimer Clock Base — Per-clock-type timer management
// ============================================================================

pub const HrtimerClockBase = struct {
    /// Clock ID
    clock_id: u8,
    /// Root of the RB tree
    rb_root: ?*Hrtimer,
    /// Leftmost node (earliest expiry)
    rb_leftmost: ?*Hrtimer,
    /// Number of timers in this base
    count: u32,
    /// Offset from monotonic
    offset: Ktime,
    /// Get the current time for this base
    get_time: *const fn () Ktime,

    const Self = @This();

    /// Insert a timer into the RB tree.
    pub fn enqueue(self: *Self, timer: *Hrtimer) void {
        var parent: ?*Hrtimer = null;
        var link: *?*Hrtimer = &self.rb_root;
        var leftmost = true;

        while (link.*) |node| {
            parent = node;
            if (timer.expires.cmp(node.expires) == .lt) {
                link = &node.rb_left;
            } else {
                link = &node.rb_right;
                leftmost = false;
            }
        }

        timer.rb_parent = parent;
        timer.rb_left = null;
        timer.rb_right = null;
        timer.rb_color = true; // New nodes are red
        link.* = timer;

        if (leftmost) {
            self.rb_leftmost = timer;
        }

        timer.state = .enqueued;
        self.count += 1;

        // Would do RB tree rebalancing here
    }

    /// Remove a timer from the RB tree.
    pub fn dequeue(self: *Self, timer: *Hrtimer) void {
        if (timer.state != .enqueued) return;

        if (self.rb_leftmost == timer) {
            // Find successor
            self.rb_leftmost = rbNext(timer);
        }

        // Simple removal (production would need full RB delete + rebalance)
        rbRemove(&self.rb_root, timer);

        timer.state = .inactive;
        timer.rb_parent = null;
        timer.rb_left = null;
        timer.rb_right = null;
        self.count -= 1;
    }

    /// Get the next expiring timer.
    pub fn nextExpiry(self: *const Self) ?Ktime {
        if (self.rb_leftmost) |leftmost| {
            return leftmost.expires;
        }
        return null;
    }

    /// Run expired timers.
    pub fn runExpired(self: *Self, now: Ktime) void {
        while (self.rb_leftmost) |timer| {
            if (timer.softexpires.cmp(now) == .gt) break;

            self.dequeue(timer);
            timer.state = .callback_running;

            if (timer.function) |func| {
                const restart = func(timer);
                if (restart == .restart and timer.state != .pending_cancel) {
                    self.enqueue(timer);
                } else {
                    timer.state = .inactive;
                }
            } else {
                timer.state = .inactive;
            }
        }
    }
};

/// Find the next node in-order.
fn rbNext(node: *Hrtimer) ?*Hrtimer {
    if (node.rb_right) |right| {
        var min = right;
        while (min.rb_left) |left| {
            min = left;
        }
        return min;
    }
    // Go up until we're a left child
    var curr = node;
    var parent = curr.rb_parent;
    while (parent) |p| {
        if (p.rb_right != curr) break;
        curr = p;
        parent = p.rb_parent;
    }
    return parent;
}

/// Simple RB tree node removal placeholder.
fn rbRemove(root: *?*Hrtimer, node: *Hrtimer) void {
    _ = root;
    // Transplant with successor if two children, etc.
    // Full RB deletion would be implemented here
    if (node.rb_parent) |parent| {
        if (parent.rb_left == node) {
            parent.rb_left = node.rb_left orelse node.rb_right;
        } else {
            parent.rb_right = node.rb_left orelse node.rb_right;
        }
    }
}

// ============================================================================
// Per-CPU Hrtimer Base
// ============================================================================

pub const HRTIMER_MAX_CLOCK_BASES = 8;

pub const HrtimerCpuBase = struct {
    /// CPU number
    cpu: u32,
    /// Active bases
    clock_base: [HRTIMER_MAX_CLOCK_BASES]HrtimerClockBase,
    /// Are hrtimers active (any timer pending)?
    hres_active: bool,
    /// Expires next (earliest across all bases)
    expires_next: Ktime,
    /// Number of hanging (expired but not yet run) timers
    nr_hangs: u32,
    /// Maximum hang time
    max_hang_time: u64,
    /// Softirq pending flag
    softirq_activated: bool,
    /// Migration flags
    migration_enabled: bool,
    /// Timer for NO_HZ
    nohz_mode: NoHzMode,
    /// Next tick time in tickless mode
    tick_next: Ktime,
    /// Number of ticks skipped
    ticks_skipped: u64,

    const Self = @This();

    pub fn init(cpu: u32) Self {
        var base: Self = undefined;
        base.cpu = cpu;
        base.hres_active = false;
        base.expires_next = Ktime.fromNsec(0x7FFFFFFFFFFFFFFF);
        base.nr_hangs = 0;
        base.max_hang_time = 0;
        base.softirq_activated = false;
        base.migration_enabled = true;
        base.nohz_mode = .inactive;
        base.tick_next = Ktime.zero();
        base.ticks_skipped = 0;

        // Initialize clock bases
        for (&base.clock_base, 0..) |*cb, i| {
            cb.* = .{
                .clock_id = @intCast(i),
                .rb_root = null,
                .rb_leftmost = null,
                .count = 0,
                .offset = Ktime.zero(),
                .get_time = defaultGetTime,
            };
        }

        return base;
    }

    /// Reprogram the next event based on all timer bases.
    pub fn reprogram(self: *Self, cev: *ClockEventDevice) void {
        var earliest = Ktime.fromNsec(0x7FFFFFFFFFFFFFFF);
        for (&self.clock_base) |*cb| {
            if (cb.nextExpiry()) |exp| {
                const adjusted = exp.add(cb.offset);
                if (adjusted.cmp(earliest) == .lt) {
                    earliest = adjusted;
                }
            }
        }
        self.expires_next = earliest;
        _ = cev.program(earliest);
    }

    /// Run all expired hrtimers.
    pub fn runExpired(self: *Self, now: Ktime) void {
        for (&self.clock_base) |*cb| {
            const adjusted_now = now.sub(cb.offset);
            cb.runExpired(adjusted_now);
        }
    }
};

fn defaultGetTime() Ktime {
    return Ktime.zero(); // Would read actual time
}

// ============================================================================
// Timer Wheel (Low-Resolution Timers)
// ============================================================================

/// Timer wheel uses a hierarchical structure:
/// Level 0: 1-63 ticks (1ms granularity at HZ=1000)
/// Level 1: 64-511 ticks (8ms granularity)
/// Level 2: 512-4095 ticks (64ms granularity)
/// Level 3: 4096-32767 ticks (512ms granularity)
/// Level 4: 32768-262143 ticks (~4s granularity)

const LVL_BITS = 6;
const LVL_SIZE = 1 << LVL_BITS; // 64
const LVL_MASK = LVL_SIZE - 1;
const LVL_DEPTH = 9;
const LVL_SHIFT = 3; // Granularity increases by 8x per level
const WHEEL_SIZE = LVL_SIZE * LVL_DEPTH; // 576 slots total

pub const TimerList = struct {
    /// Callback
    function: ?*const fn (*TimerList) void,
    /// Expiry in jiffies
    expires: u64,
    /// Flags (timer type, pinned, etc.)
    flags: u32,
    /// Bucket index in the wheel
    bucket: u16,
    /// Next timer in bucket
    next: ?*TimerList,
    /// Previous timer in bucket
    prev: ?*TimerList,
    /// Data pointer
    data: u64,

    const Self = @This();

    pub fn init() Self {
        return .{
            .function = null,
            .expires = 0,
            .flags = 0,
            .bucket = 0,
            .next = null,
            .prev = null,
            .data = 0,
        };
    }

    pub fn setup(self: *Self, function: *const fn (*TimerList) void, expires: u64) void {
        self.function = function;
        self.expires = expires;
    }

    pub fn isActive(self: *const Self) bool {
        return self.next != null;
    }
};

pub const TimerWheel = struct {
    /// Timer list heads for each bucket
    buckets: [WHEEL_SIZE]TimerBucket,
    /// Current time (jiffies)
    clk: u64,
    /// Next expiry time
    next_expiry: u64,
    /// Pending bitmap: one bit per bucket with timers
    pending: [WHEEL_SIZE / 64 + 1]u64,
    /// Per-CPU ID
    cpu: u32,
    /// Timer migration pending
    migration_pending: bool,
    /// Stats
    stats: TimerWheelStats,

    const Self = @This();

    pub fn init(cpu: u32) Self {
        var tw: Self = undefined;
        tw.clk = 0;
        tw.next_expiry = 0xFFFFFFFFFFFFFFFF;
        tw.cpu = cpu;
        tw.migration_pending = false;
        tw.stats = TimerWheelStats{};
        for (&tw.buckets) |*b| {
            b.* = TimerBucket.init();
        }
        for (&tw.pending) |*p| {
            p.* = 0;
        }
        return tw;
    }

    /// Calculate the bucket index for a given expiry.
    pub fn calcIndex(self: *const Self, expires: u64) u16 {
        const delta = expires -% self.clk;

        // Level 0: 0-63
        if (delta < LVL_SIZE) {
            return @intCast(expires & LVL_MASK);
        }

        // Higher levels with increasing granularity
        var level: u32 = 1;
        var d = delta;
        while (level < LVL_DEPTH) : (level += 1) {
            d >>= LVL_SHIFT;
            if (d < LVL_SIZE) {
                const offset = level * LVL_SIZE;
                return @intCast(offset + (expires >> @intCast(level * LVL_SHIFT) & LVL_MASK));
            }
        }

        // Cap at highest level
        return @intCast((LVL_DEPTH - 1) * LVL_SIZE + (expires >> @intCast((LVL_DEPTH - 1) * LVL_SHIFT) & LVL_MASK));
    }

    /// Add a timer to the wheel.
    pub fn addTimer(self: *Self, timer: *TimerList) void {
        const idx = self.calcIndex(timer.expires);
        timer.bucket = idx;
        self.buckets[idx].add(timer);

        // Set pending bit
        const word = idx / 64;
        const bit = @as(u6, @intCast(idx % 64));
        self.pending[word] |= @as(u64, 1) << bit;

        // Update next_expiry
        if (timer.expires < self.next_expiry) {
            self.next_expiry = timer.expires;
        }

        self.stats.add_count += 1;
    }

    /// Remove a timer from the wheel.
    pub fn removeTimer(self: *Self, timer: *TimerList) void {
        const idx = timer.bucket;
        self.buckets[idx].remove(timer);

        if (self.buckets[idx].count == 0) {
            const word = idx / 64;
            const bit = @as(u6, @intCast(idx % 64));
            self.pending[word] &= ~(@as(u64, 1) << bit);
        }

        self.stats.cancel_count += 1;
    }

    /// Modify a timer's expiry.
    pub fn modTimer(self: *Self, timer: *TimerList, new_expires: u64) void {
        if (timer.isActive()) {
            self.removeTimer(timer);
        }
        timer.expires = new_expires;
        self.addTimer(timer);
    }

    /// Process expired timers at the current tick.
    pub fn runTimers(self: *Self) void {
        if (self.clk >= self.next_expiry) {
            self.processExpired();
        }
        self.clk += 1;
    }

    fn processExpired(self: *Self) void {
        // Process level 0 buckets
        const idx = self.clk & LVL_MASK;
        self.runBucket(@intCast(idx));

        // Cascade higher levels when needed
        var level: u32 = 1;
        while (level < LVL_DEPTH) : (level += 1) {
            const shift_amount = level * LVL_SHIFT;
            if ((self.clk >> @intCast(shift_amount)) & LVL_MASK == 0) {
                // Time to cascade this level
                self.cascadeLevel(level);
            }
        }

        self.updateNextExpiry();
    }

    fn runBucket(self: *Self, idx: u16) void {
        var timer = self.buckets[idx].head;
        while (timer) |t| {
            const next = t.next;
            if (t.expires <= self.clk) {
                self.buckets[idx].remove(t);
                if (t.function) |func| {
                    func(t);
                    self.stats.fire_count += 1;
                }
            }
            timer = next;
        }
    }

    fn cascadeLevel(self: *Self, level: u32) void {
        const offset = level * LVL_SIZE;
        const shift_amount = level * LVL_SHIFT;
        const idx = @as(u16, @intCast(offset)) +
            @as(u16, @intCast((self.clk >> @intCast(shift_amount)) & LVL_MASK));

        var timer = self.buckets[idx].head;
        while (timer) |t| {
            const next = t.next;
            self.buckets[idx].remove(t);
            // Recalculate bucket for the lower level
            const new_idx = self.calcIndex(t.expires);
            t.bucket = new_idx;
            self.buckets[new_idx].add(t);
            timer = next;
        }
    }

    fn updateNextExpiry(self: *Self) void {
        self.next_expiry = 0xFFFFFFFFFFFFFFFF;
        for (self.pending, 0..) |word, i| {
            if (word != 0) {
                const bit = @ctz(word);
                const bucket_idx = i * 64 + bit;
                if (self.buckets[bucket_idx].head) |timer| {
                    if (timer.expires < self.next_expiry) {
                        self.next_expiry = timer.expires;
                    }
                }
            }
        }
    }
};

pub const TimerBucket = struct {
    head: ?*TimerList,
    tail: ?*TimerList,
    count: u32,

    pub fn init() TimerBucket {
        return .{ .head = null, .tail = null, .count = 0 };
    }

    pub fn add(self: *TimerBucket, timer: *TimerList) void {
        timer.next = null;
        timer.prev = self.tail;
        if (self.tail) |t| {
            t.next = timer;
        } else {
            self.head = timer;
        }
        self.tail = timer;
        self.count += 1;
    }

    pub fn remove(self: *TimerBucket, timer: *TimerList) void {
        if (timer.prev) |p| {
            p.next = timer.next;
        } else {
            self.head = timer.next;
        }
        if (timer.next) |n| {
            n.prev = timer.prev;
        } else {
            self.tail = timer.prev;
        }
        timer.next = null;
        timer.prev = null;
        self.count -= 1;
    }
};

pub const TimerWheelStats = struct {
    add_count: u64 = 0,
    fire_count: u64 = 0,
    cancel_count: u64 = 0,
    cascade_count: u64 = 0,
};

// ============================================================================
// NO_HZ (Tickless) Support
// ============================================================================

pub const NoHzMode = enum(u8) {
    inactive = 0,
    low_res = 1,  // Low-resolution tickless
    full = 2,      // Full dyntick
};

pub const TickSched = struct {
    /// Is this CPU in idle NO_HZ mode?
    idle_active: bool,
    /// Idle entry time
    idle_entrytime: Ktime,
    /// Total idle time
    idle_sleeptime: Ktime,
    /// IO wait time
    iowait_sleeptime: Ktime,
    /// Last jiffies value when entering idle
    idle_jiffies: u64,
    /// Last tick timestamp
    last_tick: Ktime,
    /// Next timer expiry
    next_timer: u64,
    /// Number of consecutive idle ticks
    idle_calls: u64,
    /// Number of actual idle periods
    idle_sleeps: u64,

    const Self = @This();

    pub fn init() Self {
        return .{
            .idle_active = false,
            .idle_entrytime = Ktime.zero(),
            .idle_sleeptime = Ktime.zero(),
            .iowait_sleeptime = Ktime.zero(),
            .idle_jiffies = 0,
            .last_tick = Ktime.zero(),
            .next_timer = 0,
            .idle_calls = 0,
            .idle_sleeps = 0,
        };
    }

    /// Enter idle: suppress ticks if possible.
    pub fn idleEnter(self: *Self, now: Ktime, next_event: Ktime) void {
        self.idle_active = true;
        self.idle_entrytime = now;
        self.idle_calls += 1;

        // Calculate how long we can sleep
        const sleep_ns = next_event.sub(now);
        if (sleep_ns.nsec > @as(i64, @intCast(TICK_NSEC * 2))) {
            // Worth it to go tickless
            self.idle_sleeps += 1;
        }
    }

    /// Exit idle: restart ticks if needed.
    pub fn idleExit(self: *Self, now: Ktime) void {
        if (!self.idle_active) return;
        self.idle_active = false;

        const duration = now.sub(self.idle_entrytime);
        self.idle_sleeptime = self.idle_sleeptime.add(duration);
    }
};

// ============================================================================
// POSIX Timer
// ============================================================================

pub const SIGEV_NONE = 0;
pub const SIGEV_SIGNAL = 1;
pub const SIGEV_THREAD = 2;
pub const SIGEV_THREAD_ID = 4;

pub const SigEvent = struct {
    sigev_value: u64,
    sigev_signo: i32,
    sigev_notify: i32,
    sigev_notify_thread_id: i32,
};

pub const PosixTimer = struct {
    /// Timer ID
    id: i32,
    /// Clock ID
    clock_id: i32,
    /// Signal event
    sigev: SigEvent,
    /// Interval
    interval: ITimerSpec,
    /// Owner process PID
    owner_pid: i32,
    /// Is this timer armed?
    armed: bool,
    /// Overrun count
    overrun: u32,
    /// Maximum overrun
    overrun_last: u32,
    /// Internal hrtimer
    hrtimer: Hrtimer,

    const Self = @This();

    pub fn create(id: i32, clock_id: i32, sigev: SigEvent, owner_pid: i32) Self {
        return .{
            .id = id,
            .clock_id = clock_id,
            .sigev = sigev,
            .interval = .{
                .it_interval = Timespec.zero(),
                .it_value = Timespec.zero(),
            },
            .owner_pid = owner_pid,
            .armed = false,
            .overrun = 0,
            .overrun_last = 0,
            .hrtimer = Hrtimer.init(@intCast(clock_id)),
        };
    }

    pub fn settime(self: *Self, new_value: *const ITimerSpec, old_value: ?*ITimerSpec) void {
        if (old_value) |old| {
            old.* = self.interval;
        }
        self.interval = new_value.*;
        self.armed = !new_value.it_value.isZero();
    }

    pub fn gettime(self: *const Self, curr_value: *ITimerSpec) void {
        curr_value.* = self.interval;
    }

    pub fn delete(self: *Self) void {
        self.armed = false;
        // Would dequeue hrtimer and free resources
    }

    pub fn getoverrun(self: *Self) u32 {
        const count = self.overrun;
        self.overrun = 0;
        return count;
    }
};

// ============================================================================
// Per-task Interval Timers (setitimer)
// ============================================================================

pub const ITIMER_REAL = 0;
pub const ITIMER_VIRTUAL = 1;
pub const ITIMER_PROF = 2;

pub const IntervalTimers = struct {
    /// ITIMER_REAL: wall clock timer (SIGALRM)
    real: ITimerVal,
    /// ITIMER_VIRTUAL: user CPU time (SIGVTALRM)
    virtual_timer: ITimerVal,
    /// ITIMER_PROF: user + system CPU time (SIGPROF)
    prof: ITimerVal,
    /// Active flags
    real_active: bool,
    virtual_active: bool,
    prof_active: bool,

    pub fn init() IntervalTimers {
        const zero = Timeval{ .tv_sec = 0, .tv_usec = 0 };
        const zero_it = ITimerVal{ .it_interval = zero, .it_value = zero };
        return .{
            .real = zero_it,
            .virtual_timer = zero_it,
            .prof = zero_it,
            .real_active = false,
            .virtual_active = false,
            .prof_active = false,
        };
    }

    pub fn setitimer(self: *IntervalTimers, which: u32, new: *const ITimerVal, old: ?*ITimerVal) !void {
        switch (which) {
            ITIMER_REAL => {
                if (old) |o| o.* = self.real;
                self.real = new.*;
                self.real_active = new.it_value.tv_sec != 0 or new.it_value.tv_usec != 0;
            },
            ITIMER_VIRTUAL => {
                if (old) |o| o.* = self.virtual_timer;
                self.virtual_timer = new.*;
                self.virtual_active = new.it_value.tv_sec != 0 or new.it_value.tv_usec != 0;
            },
            ITIMER_PROF => {
                if (old) |o| o.* = self.prof;
                self.prof = new.*;
                self.prof_active = new.it_value.tv_sec != 0 or new.it_value.tv_usec != 0;
            },
            else => return error.InvalidArgument,
        }
    }
};

// ============================================================================
// Global Time Keeping
// ============================================================================

pub const Timekeeper = struct {
    /// Current monotonic time (nanoseconds since boot)
    monotonic_ns: u64,
    /// Current wall clock time
    wall_time: Timespec,
    /// Boot time in wall clock
    boot_time: Timespec,
    /// Offset: monotonic → realtime
    wall_to_monotonic: Timespec,
    /// Offset: monotonic → boottime
    monotonic_to_boot: Timespec,
    /// TAI offset (leap seconds)
    tai_offset: i32,
    /// Active clock source
    clock_source: ?*ClockSource,
    /// NTP adjustment (ppb)
    ntp_adj: i64,
    /// Tick length (nsec with fractional part)
    tick_length: u64,
    /// Last update jiffies
    last_jiffies: u64,
    /// Sequence counter for lockless reads
    seq: u32,

    const Self = @This();

    /// Read current monotonic time.
    pub fn readMonotonic(self: *Self) Ktime {
        // Seqlock read side
        var seq: u32 = undefined;
        var ns: u64 = undefined;
        while (true) {
            seq = @atomicLoad(u32, &self.seq, .acquire);
            if (seq & 1 != 0) continue; // Writer active

            ns = self.monotonic_ns;
            if (self.clock_source) |cs| {
                ns += cs.readNsec();
            }

            if (@atomicLoad(u32, &self.seq, .acquire) == seq) break;
        }
        return Ktime.fromNsec(@intCast(ns));
    }

    /// Read current real (wall) time.
    pub fn readRealtime(self: *Self) Timespec {
        const mono = self.readMonotonic();
        const ts = mono.toTimespec();
        return ts.add(self.wall_to_monotonic);
    }

    /// Read boottime (monotonic + suspend time).
    pub fn readBoottime(self: *Self) Ktime {
        const mono = self.readMonotonic();
        return mono.add(Ktime.fromTimespec(self.monotonic_to_boot));
    }

    /// Update on each tick.
    pub fn update(self: *Self) void {
        // Write seqlock
        @atomicStore(u32, &self.seq, self.seq +% 1, .release);

        self.monotonic_ns += TICK_NSEC;
        self.last_jiffies += 1;

        // Apply NTP adjustment
        if (self.ntp_adj != 0) {
            const adj_ns: i64 = @divTrunc(self.ntp_adj, 1_000_000);
            if (adj_ns > 0) {
                self.monotonic_ns +%= @intCast(adj_ns);
            } else {
                self.monotonic_ns -%= @intCast(-adj_ns);
            }
        }

        self.wall_time = Timespec.fromNsec(self.monotonic_ns).add(self.wall_to_monotonic);

        @atomicStore(u32, &self.seq, self.seq +% 1, .release);
    }

    /// Set the wall clock time (e.g., from RTC on boot).
    pub fn setWallTime(self: *Self, time: Timespec) void {
        @atomicStore(u32, &self.seq, self.seq +% 1, .release);

        self.wall_time = time;
        const mono_ts = Timespec.fromNsec(self.monotonic_ns);
        self.wall_to_monotonic = time.sub(mono_ts);

        @atomicStore(u32, &self.seq, self.seq +% 1, .release);
    }

    /// Adjust TAI offset (leap seconds).
    pub fn setTaiOffset(self: *Self, offset: i32) void {
        self.tai_offset = offset;
    }
};

// ============================================================================
// Global State / Init
// ============================================================================

const MAX_CPUS = 256;

var timer_bases: [MAX_CPUS]HrtimerCpuBase = undefined;
var timer_wheels: [MAX_CPUS]TimerWheel = undefined;
var tick_sched: [MAX_CPUS]TickSched = undefined;
var timekeeper: Timekeeper = undefined;
var jiffies: u64 = 0;

/// Initialize the timer subsystem.
pub fn init() void {
    for (0..MAX_CPUS) |i| {
        timer_bases[i] = HrtimerCpuBase.init(@intCast(i));
        timer_wheels[i] = TimerWheel.init(@intCast(i));
        tick_sched[i] = TickSched.init();
    }

    timekeeper = .{
        .monotonic_ns = 0,
        .wall_time = Timespec.zero(),
        .boot_time = Timespec.zero(),
        .wall_to_monotonic = Timespec.zero(),
        .monotonic_to_boot = Timespec.zero(),
        .tai_offset = 0,
        .clock_source = null,
        .ntp_adj = 0,
        .tick_length = TICK_NSEC,
        .last_jiffies = 0,
        .seq = 0,
    };
}

/// Called on each timer tick.
pub fn tickHandler(cpu: u32) void {
    const now = timekeeper.readMonotonic();

    // Update jiffies
    jiffies += 1;
    timekeeper.update();

    // Run hrtimers
    timer_bases[cpu].runExpired(now);

    // Run timer wheel
    timer_wheels[cpu].runTimers();
}

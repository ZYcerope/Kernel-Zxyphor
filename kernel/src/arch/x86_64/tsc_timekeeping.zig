// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - TSC Calibration, Microcode Update,
// Platform Timer Sources, HPET Programming,
// PIT/APIC Timer, TSC Deadline, Clocksource Framework,
// Clock Events, Timekeeping, NTP
// More advanced than Linux 2026 timekeeping

const std = @import("std");

// ============================================================================
// TSC (Time Stamp Counter) Calibration
// ============================================================================

/// TSC calibration method
pub const TscCalibMethod = enum(u8) {
    pit = 0,            // PIT-based calibration
    hpet = 1,           // HPET-based calibration
    pmtimer = 2,        // ACPI PM Timer
    cpuid_15h = 3,      // CPUID leaf 15H (core crystal clock)
    cpuid_16h = 4,      // CPUID leaf 16H (processor frequency)
    msr = 5,            // MSR-based (model-specific)
    art = 6,            // Always Running Timer
    hypervisor = 7,     // Hypervisor provided
    // Zxyphor
    zxy_adaptive = 100, // Adaptive multi-source calibration
};

/// TSC state
pub const TscState = enum(u8) {
    unknown = 0,
    unstable = 1,
    reliable = 2,
    constant = 3,       // constant_tsc CPUID
    nonstop = 4,        // nonstop_tsc CPUID
    invariant = 5,      // invariant TSC
};

/// TSC calibration result
pub const TscCalibResult = struct {
    frequency_khz: u64 = 0,
    frequency_hz: u64 = 0,
    calibration_method: TscCalibMethod = .pit,
    state: TscState = .unknown,
    art_numerator: u32 = 0,
    art_denominator: u32 = 0,
    crystal_frequency: u64 = 0,
    adjust_factor: i64 = 0,
    is_reliable: bool = false,
    supports_deadline: bool = false,
};

/// TSC-related MSRs
pub const TscMsr = enum(u32) {
    ia32_tsc = 0x10,
    ia32_tsc_adjust = 0x3B,
    ia32_tsc_deadline = 0x6E0,
    ia32_tsc_aux = 0xC0000103,
    msr_platform_info = 0xCE,
    msr_turbo_ratio_limit = 0x1AD,
    msr_turbo_ratio_limit1 = 0x1AE,
};

// ============================================================================
// Microcode Update
// ============================================================================

/// Microcode vendor
pub const UcodeVendor = enum(u8) {
    intel = 0,
    amd = 1,
};

/// Intel microcode header
pub const IntelUcodeHeader = extern struct {
    header_version: u32,
    update_revision: u32,
    date: u32,                // BCD: MMDDYYYY
    processor_signature: u32,
    checksum: u32,
    loader_revision: u32,
    processor_flags: u32,
    data_size: u32,
    total_size: u32,
    _reserved: [3]u32,
};

/// AMD microcode header
pub const AmdUcodeHeader = extern struct {
    data_code: u32,
    patch_id: u32,
    mc_patch_data_id: u16,
    mc_patch_data_len: u16,
    init_flag: u32,
    mc_patch_data_checksum: u32,
    nb_dev_id: u32,
    sb_dev_id: u32,
    processor_revid: u16,
    nb_revid: u8,
    sb_revid: u8,
    bios_api_revid: u8,
    _reserved: [3]u8,
    match_reg: [8]u32,
};

/// Microcode update status
pub const UcodeUpdateStatus = enum(u8) {
    not_attempted = 0,
    success = 1,
    already_latest = 2,
    mismatch = 3,
    error_checksum = 4,
    error_signature = 5,
    error_apply = 6,
    not_found = 7,
};

/// Microcode info
pub const UcodeInfo = struct {
    vendor: UcodeVendor = .intel,
    cpu_signature: u32 = 0,
    pf: u32 = 0,              // platform flags (Intel)
    current_revision: u32 = 0,
    new_revision: u32 = 0,
    date: u32 = 0,
    status: UcodeUpdateStatus = .not_attempted,
    early_applied: bool = false,
    late_applied: bool = false,
};

// ============================================================================
// Platform Timer Sources
// ============================================================================

/// ACPI PM Timer
pub const PmTimer = struct {
    io_port: u16 = 0x408,    // default ACPI PM timer port
    width32: bool = false,    // 24-bit vs 32-bit
    frequency: u32 = 3579545, // 3.579545 MHz
    verified: bool = false,
};

/// PIT (Programmable Interval Timer) 8253/8254
pub const PitMode = enum(u8) {
    interrupt_on_terminal_count = 0,
    hw_retriggerable_one_shot = 1,
    rate_generator = 2,
    square_wave = 3,
    software_triggered_strobe = 4,
    hardware_triggered_strobe = 5,
};

pub const PitChannel = enum(u8) {
    channel0 = 0,    // IRQ 0
    channel1 = 1,    // DRAM refresh (legacy)
    channel2 = 2,    // PC speaker
};

pub const PitDesc = struct {
    frequency: u32 = 1193182,  // 1.193182 MHz
    mode: PitMode = .rate_generator,
    divisor: u16 = 0,
    counter_latch: u16 = 0,
};

/// I/O ports for PIT
pub const PIT_CHANNEL0 = 0x40;
pub const PIT_CHANNEL1 = 0x41;
pub const PIT_CHANNEL2 = 0x42;
pub const PIT_COMMAND = 0x43;

/// HPET (High Precision Event Timer)
pub const HpetCapabilities = packed struct(u64) {
    rev_id: u8 = 0,
    num_tim_cap: u5 = 0,
    count_size_cap: bool = false,    // 64-bit
    _reserved: bool = false,
    legacy_route_cap: bool = false,
    vendor_id: u16 = 0,
    counter_clk_period: u32 = 0,    // femtoseconds
};

pub const HpetTimerConfig = packed struct(u64) {
    _reserved0: bool = false,
    int_type_cnf: bool = false,     // 0=edge, 1=level
    int_enb_cnf: bool = false,
    type_cnf: bool = false,          // 0=non-periodic, 1=periodic
    per_int_cap: bool = false,
    size_cap: bool = false,          // 64-bit
    val_set_cnf: bool = false,
    _reserved1: bool = false,
    mode32_cnf: bool = false,        // force 32-bit
    int_route_cnf: u5 = 0,
    fsb_en_cnf: bool = false,
    fsb_int_del_cap: bool = false,
    _reserved2: u16 = 0,
    int_route_cap: u32 = 0,
};

pub const HpetRegister = struct {
    base_address: u64 = 0,
    capabilities: HpetCapabilities = .{},
    num_timers: u8 = 0,
    period_fs: u64 = 0,              // femtoseconds per tick
    frequency_hz: u64 = 0,
    is_64bit: bool = false,
    legacy_replacement: bool = false,
};

// ============================================================================
// Clocksource Framework
// ============================================================================

/// Clocksource rating
pub const ClockRating = enum(u16) {
    unavailable = 0,
    low = 100,
    normal = 200,
    good = 300,
    perfect = 400,
    // Zxyphor
    zxy_optimal = 500,
};

/// Clocksource flags
pub const ClkSrcFlags = packed struct(u32) {
    continuous: bool = false,
    must_verify: bool = false,
    watchdog: bool = false,
    unstable: bool = false,
    valid_for_hres: bool = false,
    is_continuous: bool = false,
    suspend_nonstop: bool = false,
    reselect: bool = false,
    verify_percpu: bool = false,
    // Zxyphor
    zxy_ai_compensated: bool = false,
    _padding: u22 = 0,
};

/// Clocksource descriptor
pub const ClockSourceDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    rating: u16 = 0,
    mask: u64 = 0xFFFFFFFFFFFFFFFF,
    mult: u32 = 0,
    shift: u32 = 0,
    max_idle_ns: u64 = 0,
    max_cycles: u64 = 0,
    flags: ClkSrcFlags = .{},
    uncertainty_margin: u32 = 0,
    vdso_clock_mode: u8 = 0,
    archdata: ClkSrcArchData = .{},
};

/// Architecture-specific clocksource data
pub const ClkSrcArchData = struct {
    vclock_mode: u8 = 0,
    vdso_direct: bool = false,
};

// ============================================================================
// Clock Events
// ============================================================================

/// Clock event mode
pub const ClkEvtMode = enum(u8) {
    unused = 0,
    shutdown = 1,
    periodic = 2,
    oneshot = 3,
    oneshot_stopped = 4,
    // Zxyphor
    zxy_adaptive = 100,
};

/// Clock event features
pub const ClkEvtFeatures = packed struct(u32) {
    periodic: bool = false,
    oneshot: bool = false,
    oneshot_stopped: bool = false,
    ktime: bool = false,
    hrtimer: bool = false,
    // Zxyphor
    zxy_deadline: bool = false,
    _padding: u26 = 0,
};

/// Clock event device descriptor
pub const ClkEvtDevDesc = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    features: ClkEvtFeatures = .{},
    max_delta_ns: u64 = 0,
    min_delta_ns: u64 = 0,
    max_delta_ticks: u64 = 0,
    min_delta_ticks: u64 = 0,
    mult: u32 = 0,
    shift: u32 = 0,
    rating: u16 = 0,
    mode: ClkEvtMode = .unused,
    irq: i32 = -1,
    cpumask: u64 = 0,
    next_event: i64 = 0,         // ktime
    bound_on: i32 = -1,          // CPU
};

// ============================================================================
// Timekeeping
// ============================================================================

/// Timekeeping data (core timekeeper state)
pub const TimekeeperData = struct {
    // Current clocksource
    clock_name: [32]u8 = [_]u8{0} ** 32,
    clock_name_len: u8 = 0,
    clock_mult: u32 = 0,
    clock_shift: u32 = 0,
    clock_mask: u64 = 0,
    cycle_last: u64 = 0,
    // Time values
    xtime_sec: i64 = 0,
    xtime_nsec: u64 = 0,
    wall_to_monotonic_sec: i64 = 0,
    wall_to_monotonic_nsec: i64 = 0,
    // Offsets
    offs_real: i64 = 0,         // ktime offset to realtime
    offs_boot: i64 = 0,         // ktime offset to boottime
    offs_tai: i64 = 0,          // ktime offset to TAI
    // NTP state
    ntp_tick: u64 = 0,
    ntp_error: i64 = 0,
    ntp_error_shift: u32 = 0,
    // Raw monotonic
    raw_sec: u64 = 0,
    raw_nsec: u64 = 0,
    // Suspended
    suspend_time_sec: i64 = 0,
    suspend_time_nsec: i64 = 0,
    // Zxyphor: precision tracking
    zxy_accumulated_error_ns: i64 = 0,
    zxy_correction_count: u64 = 0,
};

/// Timespec64
pub const Timespec64 = struct {
    tv_sec: i64 = 0,
    tv_nsec: i64 = 0,
};

/// Clock IDs (POSIX)
pub const ClockId = enum(u32) {
    realtime = 0,
    monotonic = 1,
    process_cputime_id = 2,
    thread_cputime_id = 3,
    monotonic_raw = 4,
    realtime_coarse = 5,
    monotonic_coarse = 6,
    boottime = 7,
    realtime_alarm = 8,
    boottime_alarm = 9,
    sgx_enclave = 10,
    tai = 11,
};

// ============================================================================
// NTP (Network Time Protocol) Kernel Interface
// ============================================================================

/// NTP status bits
pub const NtpStatus = packed struct(u32) {
    pll: bool = false,           // STA_PLL
    ppsfreq: bool = false,      // STA_PPSFREQ
    ppstime: bool = false,      // STA_PPSTIME
    fll: bool = false,          // STA_FLL
    ins: bool = false,          // STA_INS (insert leap second)
    del: bool = false,          // STA_DEL (delete leap second)
    unsync: bool = false,       // STA_UNSYNC
    freqhold: bool = false,     // STA_FREQHOLD
    ppssignal: bool = false,    // STA_PPSSIGNAL
    ppsjitter: bool = false,    // STA_PPSJITTER
    ppswander: bool = false,    // STA_PPSWANDER
    ppserror: bool = false,     // STA_PPSERROR
    clockerr: bool = false,     // STA_CLOCKERR
    nano: bool = false,         // STA_NANO (nanosecond resolution)
    mode: bool = false,         // STA_MODE (FLL/PLL)
    clk: bool = false,          // STA_CLK (clock source select)
    _padding: u16 = 0,
};

/// NTP timex (adjtimex)
pub const NtpTimex = struct {
    modes: u32 = 0,
    offset: i64 = 0,            // nanoseconds (with STA_NANO)
    freq: i64 = 0,              // frequency offset (ppm << 16)
    maxerror: i64 = 0,
    esterror: i64 = 0,
    status: NtpStatus = .{},
    constant: i64 = 0,          // PLL time constant
    precision: i64 = 0,
    tolerance: i64 = 0,
    time: Timespec64 = .{},
    tick: i64 = 0,
    ppsfreq: i64 = 0,
    jitter: i64 = 0,
    shift: i32 = 0,
    stabil: i64 = 0,
    jitcnt: i64 = 0,
    calcnt: i64 = 0,
    errcnt: i64 = 0,
    stbcnt: i64 = 0,
    tai: i32 = 0,               // TAI offset
};

/// Leap second state
pub const LeapSecondState = enum(u8) {
    normal = 0,
    insert_pending = 1,
    delete_pending = 2,
    in_progress = 3,
    done = 4,
};

// ============================================================================
// Timer Architecture Subsystem
// ============================================================================

/// APIC timer mode
pub const ApicTimerMode = enum(u8) {
    oneshot = 0,
    periodic = 1,
    tsc_deadline = 2,
};

/// APIC timer descriptor
pub const ApicTimerDesc = struct {
    mode: ApicTimerMode = .periodic,
    initial_count: u32 = 0,
    current_count: u32 = 0,
    divide_config: u8 = 0,     // divider value
    vector: u8 = 0,
    calibrated_freq: u64 = 0,
    ticks_per_us: u32 = 0,
};

/// x2APIC timer MSRs
pub const X2ApicTimerMsr = enum(u32) {
    icr = 0x838,               // Initial Count Register
    ccr = 0x839,               // Current Count Register
    dcr = 0x83E,               // Divide Configuration Register
    lvt_timer = 0x832,         // LVT Timer Register
};

// ============================================================================
// vDSO Clock support
// ============================================================================

/// vDSO data page layout
pub const VdsoData = extern struct {
    seq: u32,
    clock_mode: i32,
    cycle_last: u64,
    mask: u64,
    mult: u32,
    shift: u32,
    basetime: [12]VdsoTimestamp,  // one per CLOCK_*
    tz_minuteswest: i32,
    tz_dsttime: i32,
    hrtimer_res: u32,
    _padding: u32,
};

pub const VdsoTimestamp = extern struct {
    sec: i64,
    nsec: u64,
};

/// vDSO clock mode (x86)
pub const VdsoClockmodeX86 = enum(i32) {
    none = 0,
    tsc = 1,
    pvclock = 2,
    hvclock = 3,
};

// ============================================================================
// Timekeeping Subsystem Manager
// ============================================================================

pub const TimekeepingSubsystem = struct {
    tsc_calibration: TscCalibResult = .{},
    pm_timer: PmTimer = .{},
    pit: PitDesc = .{},
    hpet: HpetRegister = .{},
    current_clocksource: ClockSourceDesc = .{},
    clock_event: ClkEvtDevDesc = .{},
    timekeeper: TimekeeperData = .{},
    apic_timer: ApicTimerDesc = .{},
    ntp: NtpTimex = .{},
    leap_second: LeapSecondState = .normal,
    ucode_info: UcodeInfo = .{},
    fred_config: FredConfig = .{},
    initialized: bool = false,

    pub fn init() TimekeepingSubsystem {
        return TimekeepingSubsystem{
            .initialized = true,
        };
    }
};

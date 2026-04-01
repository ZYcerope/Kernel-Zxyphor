// =============================================================================
// Zxyphor Kernel — ARM64 RAS (Reliability, Availability, Serviceability)
// =============================================================================
// Implements the ARMv8.2 RAS Extension for hardware error detection, reporting,
// and recovery. RAS is critical for enterprise-grade reliability in data center
// and mission-critical workloads.
//
// RAS Architecture:
//   - ERR Record System: multiple error records per node (ERR<n>*)
//   - Error Synchronization Barrier (ESB): reliable SError delivery
//   - IESB (Implicit Error Synchronization Barrier): on exception entry
//   - Fault Injection (ERRSELR/ERXMISC): for testing error handling
//   - RAS System Error Interrupt (SEI): asynchronous error notification
//
// Error Types:
//   - Corrected Error (CE): hardware auto-corrected
//   - Deferred Error (DE): error detected but not consumed
//   - Uncorrected Error (UE): requires software handling
//   - Containable/Uncontainable: scope of error propagation
//
// Key Error Sources:
//   - L1/L2/L3 cache errors (single-bit ECC, multi-bit parity)
//   - TLB parity errors
//   - System cache/interconnect errors (GIC, SMMU)
//   - Memory controller ECC (DRAM)
//   - PCIe AER (Advanced Error Reporting) integration
//   - Processor core errors (execution pipeline, register file)
// =============================================================================

// ── RAS Error Record Registers ────────────────────────────────────────────
pub const ERR_REG = struct {
    // Error Record Select (choose which record to access)
    pub const ERRSELR_EL1: u32 = 0; // Selected via MSR/MRS

    // Error Record registers (accessed via ERX* after selecting record)
    // ERXFR_EL1: Feature register (read-only)
    // ERXCTLR_EL1: Control register
    // ERXSTATUS_EL1: Status register
    // ERXADDR_EL1: Address register
    // ERXMISC0_EL1: Misc0 register
    // ERXMISC1_EL1: Misc1 register

    // ERXSTATUS bit fields
    pub const STATUS_V: u64 = 1 << 30;      // Valid
    pub const STATUS_AV: u64 = 1 << 31;     // Address Valid
    pub const STATUS_UE: u64 = 1 << 29;     // Uncorrected Error
    pub const STATUS_UET_MASK: u64 = 0x3 << 20; // UE Type
    pub const STATUS_UET_UC: u64 = 0 << 20; // Uncorrectable
    pub const STATUS_UET_UEU: u64 = 1 << 20; // Uncontainable
    pub const STATUS_UET_UEO: u64 = 2 << 20; // Restartable
    pub const STATUS_UET_UER: u64 = 3 << 20; // Recoverable
    pub const STATUS_DE: u64 = 1 << 23;     // Deferred Error
    pub const STATUS_CE_MASK: u64 = 0x3 << 24; // Corrected Error count
    pub const STATUS_MV: u64 = 1 << 26;     // Misc Valid
    pub const STATUS_OF: u64 = 1 << 27;     // Overflow
    pub const STATUS_ER: u64 = 1 << 28;     // Error Reported
    pub const STATUS_SERR_MASK: u64 = 0xFF << 0; // Implementation-defined error code

    // ERXCTLR bits
    pub const CTLR_ED: u64 = 1 << 0;       // Error Detection enable
    pub const CTLR_UE: u64 = 1 << 1;       // Uncorrected Error reporting
    pub const CTLR_FI: u64 = 1 << 2;       // Fault Injection enable
    pub const CTLR_UI: u64 = 1 << 3;       // Uncorrected Interrupt enable
    pub const CTLR_CI: u64 = 1 << 4;       // Corrected Interrupt enable
    pub const CTLR_CFI: u64 = 1 << 8;      // CE Fault Injection
    pub const CTLR_DUI: u64 = 1 << 10;     // Deferred Use Interrupt
    pub const CTLR_WUCE: u64 = 1 << 6;     // Write-Update CE
};

// ── Error Classification ──────────────────────────────────────────────────
pub const ErrorSeverity = enum(u4) {
    corrected = 0,          // CE: automatically corrected
    corrected_overflow = 1, // CE with counter overflow
    deferred = 2,           // DE: error in non-consumed data
    uncorrected_containable = 3,   // UE: restartable
    uncorrected_recoverable = 4,   // UE: recoverable with OS action
    uncorrected_uncontainable = 5, // UE: system-wide impact
    fatal = 6,              // System must halt
};

pub const ErrorSource = enum(u8) {
    l1d_cache = 0,
    l1i_cache = 1,
    l2_cache = 2,
    l3_cache = 3,
    llc = 4,             // Last-level cache
    tlb = 5,
    bus = 6,
    memory = 7,          // DRAM ECC
    core_pipeline = 8,
    system_register = 9,
    interconnect = 10,
    gic = 11,
    smmu = 12,
    pcie = 13,
    platform = 14,
    unknown = 15,
};

pub const ErrorAction = enum {
    log_and_continue,     // CE: just log
    page_offline,         // UE on page: take page offline
    process_kill,         // UE in process: kill the process
    cpu_offline,          // UE on CPU: take CPU offline
    system_reset,         // Fatal: system reset
    system_panic,         // Fatal: panic with diagnostics
    firmware_first,       // Route to firmware (GHES/SDEI)
};

// ── Error Record ──────────────────────────────────────────────────────────
pub const ErrorRecord = struct {
    timestamp_ns: u64,       // Time of error detection
    cpu_id: u32,             // CPU that detected the error
    error_node: u32,         // Error node index
    severity: ErrorSeverity,
    source: ErrorSource,
    action: ErrorAction,
    status: u64,             // Raw ERXSTATUS value
    address: u64,            // Physical address (if available)
    misc0: u64,              // ERXMISC0 (implementation-defined)
    misc1: u64,              // ERXMISC1
    syndrome: u64,           // ESR if synchronous
    corrected_count: u32,    // Number of corrections (CE)
    is_transient: bool,      // Transient error (not sticky)
    is_precise: bool,        // Address is precise

    const Self = @This();

    pub fn init() Self {
        var rec: Self = undefined;
        @memset(@as([*]u8, @ptrCast(&rec))[0..@sizeOf(Self)], 0);
        rec.severity = .corrected;
        rec.source = .unknown;
        rec.action = .log_and_continue;
        return rec;
    }
};

// ── Error Log (Ring Buffer) ───────────────────────────────────────────────
pub const MAX_ERROR_LOG: usize = 4096;

var error_log: [MAX_ERROR_LOG]ErrorRecord = undefined;
var error_log_head: usize = 0;
var error_log_count: u64 = 0;

// Error statistics
pub const ErrorStats = struct {
    total_errors: u64 = 0,
    corrected_errors: u64 = 0,
    uncorrected_errors: u64 = 0,
    deferred_errors: u64 = 0,
    fatal_errors: u64 = 0,
    pages_offlined: u64 = 0,
    processes_killed: u64 = 0,
    cpus_offlined: u64 = 0,
    ce_threshold_exceeded: u64 = 0,
    per_source: [16]u64 = [_]u64{0} ** 16,
};

var stats: ErrorStats = .{};

// CE threshold for page offlining (too many corrected errors = failing)
pub const CE_THRESHOLD: u32 = 10;

// ── RAS Initialization ───────────────────────────────────────────────────
pub fn init() void {
    // Detect number of error records
    const num_records = detectErrorRecordCount();

    // Enable error detection on all records
    var i: u32 = 0;
    while (i < num_records) : (i += 1) {
        selectErrorRecord(i);

        // Read feature register
        const fr = readErxfr();
        _ = fr;

        // Enable error detection and reporting
        var ctlr: u64 = ERR_REG.CTLR_ED; // Enable detection
        ctlr |= ERR_REG.CTLR_UE;         // UE reporting
        ctlr |= ERR_REG.CTLR_UI;         // UE interrupt
        ctlr |= ERR_REG.CTLR_CI;         // CE interrupt
        writeErxctlr(ctlr);

        // Clear any existing status
        writeErxstatus(readErxstatus());
    }

    // Enable Error Synchronization Barrier
    enableEsb();

    // Initialize error log
    @memset(@as([*]u8, @ptrCast(&error_log))[0..@sizeOf(@TypeOf(error_log))], 0);
}

fn detectErrorRecordCount() u32 {
    // Implementation-defined: typically read from ERRIDR_EL1
    const erridr = readErridr();
    return @truncate(erridr & 0xFFFF); // NUM field
}

// ── Error Record Access ───────────────────────────────────────────────────
fn selectErrorRecord(idx: u32) void {
    asm volatile ("msr ERRSELR_EL1, %[v]; isb" : : [v] "r" (@as(u64, idx)));
}

fn readErridr() u64 {
    return asm ("mrs %[r], ERRIDR_EL1" : [r] "=r" (-> u64));
}

fn readErxfr() u64 {
    return asm ("mrs %[r], ERXFR_EL1" : [r] "=r" (-> u64));
}

fn readErxctlr() u64 {
    return asm ("mrs %[r], ERXCTLR_EL1" : [r] "=r" (-> u64));
}

fn writeErxctlr(val: u64) void {
    asm volatile ("msr ERXCTLR_EL1, %[v]" : : [v] "r" (val));
}

fn readErxstatus() u64 {
    return asm ("mrs %[r], ERXSTATUS_EL1" : [r] "=r" (-> u64));
}

fn writeErxstatus(val: u64) void {
    // Write-1-to-clear semantics
    asm volatile ("msr ERXSTATUS_EL1, %[v]" : : [v] "r" (val));
}

fn readErxaddr() u64 {
    return asm ("mrs %[r], ERXADDR_EL1" : [r] "=r" (-> u64));
}

fn readErxmisc0() u64 {
    return asm ("mrs %[r], ERXMISC0_EL1" : [r] "=r" (-> u64));
}

fn readErxmisc1() u64 {
    return asm ("mrs %[r], ERXMISC1_EL1" : [r] "=r" (-> u64));
}

fn enableEsb() void {
    // Enable IESB (Implicit Error Synchronization Barrier) in SCTLR_EL1
    var sctlr = asm ("mrs %[r], SCTLR_EL1" : [r] "=r" (-> u64));
    sctlr |= 1 << 21; // IESB bit
    asm volatile ("msr SCTLR_EL1, %[v]; isb" : : [v] "r" (sctlr));
}

// ── Error Handling ────────────────────────────────────────────────────────
pub fn handleErrorInterrupt(cpu_id: u32) void {
    const num_records = detectErrorRecordCount();

    var i: u32 = 0;
    while (i < num_records) : (i += 1) {
        selectErrorRecord(i);
        const status = readErxstatus();

        // Check if error record is valid
        if (status & ERR_REG.STATUS_V == 0) continue;

        // Build error record
        var rec = ErrorRecord.init();
        rec.timestamp_ns = getTimestamp();
        rec.cpu_id = cpu_id;
        rec.error_node = i;
        rec.status = status;

        // Read address if available
        if (status & ERR_REG.STATUS_AV != 0) {
            rec.address = readErxaddr();
            rec.is_precise = true;
        }

        // Read misc registers if valid
        if (status & ERR_REG.STATUS_MV != 0) {
            rec.misc0 = readErxmisc0();
            rec.misc1 = readErxmisc1();
        }

        // Classify severity
        if (status & ERR_REG.STATUS_UE != 0) {
            // Uncorrected error
            const uet = status & ERR_REG.STATUS_UET_MASK;
            if (uet == ERR_REG.STATUS_UET_UEU) {
                rec.severity = .uncorrected_uncontainable;
                rec.action = .system_panic;
            } else if (uet == ERR_REG.STATUS_UET_UEO) {
                rec.severity = .uncorrected_containable;
                rec.action = .process_kill;
            } else if (uet == ERR_REG.STATUS_UET_UER) {
                rec.severity = .uncorrected_recoverable;
                rec.action = if (rec.is_precise) .page_offline else .process_kill;
            } else {
                rec.severity = .fatal;
                rec.action = .system_panic;
            }
            stats.uncorrected_errors += 1;
        } else if (status & ERR_REG.STATUS_DE != 0) {
            rec.severity = .deferred;
            rec.action = .log_and_continue;
            stats.deferred_errors += 1;
        } else {
            // Corrected error
            rec.severity = .corrected;
            rec.action = .log_and_continue;
            rec.corrected_count = @truncate((status & ERR_REG.STATUS_CE_MASK) >> 24);
            stats.corrected_errors += 1;

            // CE threshold check
            if (rec.is_precise and rec.corrected_count > CE_THRESHOLD) {
                rec.action = .page_offline;
                stats.ce_threshold_exceeded += 1;
            }
        }

        // Log the error
        logError(&rec);

        // Execute recovery action
        executeAction(&rec);

        // Clear the error record
        writeErxstatus(status);
    }
}

pub fn handleSError(esr: u64, cpu_id: u32) void {
    var rec = ErrorRecord.init();
    rec.timestamp_ns = getTimestamp();
    rec.cpu_id = cpu_id;
    rec.syndrome = esr;
    rec.severity = .uncorrected_uncontainable;
    rec.source = .unknown;

    // Check if RAS extension provides more info
    const iss = esr & 0x1FFFFFF;
    const aet = (iss >> 10) & 0x7; // Asynchronous Error Type
    const dfsc = iss & 0x3F;
    _ = dfsc;

    switch (aet) {
        0b000 => { // Uncontainable
            rec.severity = .fatal;
            rec.action = .system_panic;
        },
        0b001 => { // Unrecoverable
            rec.severity = .uncorrected_uncontainable;
            rec.action = .system_reset;
        },
        0b010 => { // Restartable
            rec.severity = .uncorrected_containable;
            rec.action = .log_and_continue;
        },
        0b011 => { // Recoverable
            rec.severity = .uncorrected_recoverable;
            rec.action = .process_kill;
        },
        0b110 => { // Corrected
            rec.severity = .corrected;
            rec.action = .log_and_continue;
        },
        else => {
            rec.severity = .fatal;
            rec.action = .system_panic;
        },
    }

    logError(&rec);
    executeAction(&rec);
}

fn executeAction(rec: *const ErrorRecord) void {
    switch (rec.action) {
        .log_and_continue => {
            // Already logged, nothing more to do
        },
        .page_offline => {
            if (rec.is_precise) {
                offlinePhysicalPage(rec.address);
                stats.pages_offlined += 1;
            }
        },
        .process_kill => {
            killCurrentProcess(rec);
            stats.processes_killed += 1;
        },
        .cpu_offline => {
            offlineCpu(rec.cpu_id);
            stats.cpus_offlined += 1;
        },
        .system_reset => {
            initiateSystemReset();
        },
        .system_panic => {
            stats.fatal_errors += 1;
            kernelPanic(rec);
        },
        .firmware_first => {
            routeToFirmware(rec);
        },
    }
}

fn logError(rec: *const ErrorRecord) void {
    error_log[error_log_head % MAX_ERROR_LOG] = rec.*;
    error_log_head += 1;
    error_log_count += 1;
    stats.total_errors += 1;
    stats.per_source[@intFromEnum(rec.source)] += 1;
}

// ── Stubs for Recovery Actions ────────────────────────────────────────────
fn offlinePhysicalPage(phys_addr: u64) void {
    _ = phys_addr;
    // TODO: mark physical page as poisoned in PMM
}

fn killCurrentProcess(rec: *const ErrorRecord) void {
    _ = rec;
    // TODO: send SIGBUS to current process
}

fn offlineCpu(cpu_id: u32) void {
    _ = cpu_id;
    // TODO: migrate tasks and take CPU offline via PSCI
}

fn initiateSystemReset() void {
    // TODO: call PSCI system_reset
    while (true) asm volatile ("wfi");
}

fn kernelPanic(rec: *const ErrorRecord) void {
    _ = rec;
    while (true) asm volatile ("wfi");
}

fn routeToFirmware(rec: *const ErrorRecord) void {
    _ = rec;
    // TODO: route via SDEI (Software Delegated Exception Interface)
}

fn getTimestamp() u64 {
    return asm ("mrs %[r], CNTPCT_EL0" : [r] "=r" (-> u64));
}

// ── Public Queries ────────────────────────────────────────────────────────
pub fn getStats() ErrorStats {
    return stats;
}

pub fn getErrorCount() u64 {
    return error_log_count;
}

pub fn getLastError() ?ErrorRecord {
    if (error_log_count == 0) return null;
    return error_log[(error_log_head - 1) % MAX_ERROR_LOG];
}

pub fn getError(idx: usize) ?ErrorRecord {
    if (idx >= @min(error_log_count, MAX_ERROR_LOG)) return null;
    return error_log[idx % MAX_ERROR_LOG];
}

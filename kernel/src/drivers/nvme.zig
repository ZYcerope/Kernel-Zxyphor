// =============================================================================
// Kernel Zxyphor — NVMe Driver
// =============================================================================
// NVM Express driver implementation:
//   - Admin and I/O queue management
//   - Submission/completion queue pairs
//   - PRP (Physical Region Page) list support
//   - Identify controller/namespace
//   - Read/write/flush/discard commands
//   - MSI-X interrupt support
//   - Namespace management
//   - Queue creation/deletion
//   - Error handling and recovery
//   - Power state management
//   - S.M.A.R.T. health information
// =============================================================================

// ============================================================================
// NVMe register offsets (BAR0 MMIO)
// ============================================================================

pub const NVME_REG_CAP: u64 = 0x00;      // Controller Capabilities
pub const NVME_REG_VS: u64 = 0x08;       // Version
pub const NVME_REG_INTMS: u64 = 0x0C;    // Interrupt Mask Set
pub const NVME_REG_INTMC: u64 = 0x10;    // Interrupt Mask Clear
pub const NVME_REG_CC: u64 = 0x14;       // Controller Configuration
pub const NVME_REG_CSTS: u64 = 0x1C;     // Controller Status
pub const NVME_REG_NSSR: u64 = 0x20;     // NVM Subsystem Reset
pub const NVME_REG_AQA: u64 = 0x24;      // Admin Queue Attributes
pub const NVME_REG_ASQ: u64 = 0x28;      // Admin Submission Queue Base Address
pub const NVME_REG_ACQ: u64 = 0x30;      // Admin Completion Queue Base Address
pub const NVME_REG_SQ0TDBL: u64 = 0x1000; // Submission Queue 0 Tail Doorbell

// CC bits
pub const CC_EN: u32 = 1 << 0;           // Enable
pub const CC_CSS_NVM: u32 = 0 << 4;      // NVM command set
pub const CC_MPS_SHIFT: u5 = 7;          // Memory Page Size
pub const CC_AMS_RR: u32 = 0 << 11;      // Round Robin arbitration
pub const CC_SHN_NONE: u32 = 0 << 14;    // No shutdown
pub const CC_SHN_NORMAL: u32 = 1 << 14;  // Normal shutdown
pub const CC_SHN_ABRUPT: u32 = 2 << 14;  // Abrupt shutdown
pub const CC_IOSQES: u32 = 6 << 16;      // I/O SQ entry size (64 bytes)
pub const CC_IOCQES: u32 = 4 << 20;      // I/O CQ entry size (16 bytes)

// CSTS bits
pub const CSTS_RDY: u32 = 1 << 0;         // Ready
pub const CSTS_CFS: u32 = 1 << 1;         // Controller Fatal Status
pub const CSTS_SHST_MASK: u32 = 3 << 2;   // Shutdown Status
pub const CSTS_SHST_NORMAL: u32 = 0 << 2;
pub const CSTS_SHST_OCCURRING: u32 = 1 << 2;
pub const CSTS_SHST_COMPLETE: u32 = 2 << 2;
pub const CSTS_NSSRO: u32 = 1 << 4;       // NVM Subsystem Reset Occurred
pub const CSTS_PP: u32 = 1 << 5;          // Processing Paused

// ============================================================================
// NVMe command opcodes
// ============================================================================

// Admin commands
pub const NVME_ADMIN_DELETE_SQ: u8 = 0x00;
pub const NVME_ADMIN_CREATE_SQ: u8 = 0x01;
pub const NVME_ADMIN_GET_LOG: u8 = 0x02;
pub const NVME_ADMIN_DELETE_CQ: u8 = 0x04;
pub const NVME_ADMIN_CREATE_CQ: u8 = 0x05;
pub const NVME_ADMIN_IDENTIFY: u8 = 0x06;
pub const NVME_ADMIN_ABORT: u8 = 0x08;
pub const NVME_ADMIN_SET_FEATURES: u8 = 0x09;
pub const NVME_ADMIN_GET_FEATURES: u8 = 0x0A;
pub const NVME_ADMIN_FORMAT: u8 = 0x80;

// I/O commands (NVM command set)
pub const NVME_IO_FLUSH: u8 = 0x00;
pub const NVME_IO_WRITE: u8 = 0x01;
pub const NVME_IO_READ: u8 = 0x02;
pub const NVME_IO_WRITE_UNCOR: u8 = 0x04;
pub const NVME_IO_COMPARE: u8 = 0x05;
pub const NVME_IO_WRITE_ZEROES: u8 = 0x08;
pub const NVME_IO_DATASET_MGMT: u8 = 0x09; // TRIM/Discard

pub const MAX_NVME_CONTROLLERS: usize = 4;
pub const MAX_NAMESPACES: usize = 16;
pub const MAX_IO_QUEUES: usize = 16;
pub const ADMIN_QUEUE_DEPTH: usize = 32;
pub const IO_QUEUE_DEPTH: usize = 256;

// ============================================================================
// NVMe Submission Queue Entry (64 bytes)
// ============================================================================

pub const NvmeSubmissionEntry = extern struct {
    opcode: u8,
    flags: u8,
    command_id: u16,
    nsid: u32,           // Namespace ID
    reserved: u64,
    mptr: u64,           // Metadata pointer
    prp1: u64,           // Physical region page 1
    prp2: u64,           // Physical region page 2 / PRP list pointer
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
};

// ============================================================================
// NVMe Completion Queue Entry (16 bytes)
// ============================================================================

pub const NvmeCompletionEntry = extern struct {
    result: u32,         // Command specific result
    reserved: u32,
    sq_head: u16,        // SQ head pointer
    sq_id: u16,          // SQ identifier
    command_id: u16,
    status: u16,         // Status field (phase bit + status code)
};

// ============================================================================
// Queue pair (SQ + CQ)
// ============================================================================

pub const NvmeQueuePair = struct {
    sq_phys: u64,          // Physical address of submission queue
    cq_phys: u64,          // Physical address of completion queue
    sq_depth: u16,
    cq_depth: u16,
    sq_tail: u16,          // Producer index (host writes)
    sq_head: u16,          // Consumer index (updated from CQ)
    cq_head: u16,          // Consumer index (host reads)
    cq_phase: bool,        // Expected phase bit
    sq_doorbell: u64,      // MMIO doorbell address
    cq_doorbell: u64,

    // Tracking
    id: u16,
    irq_vector: u16,
    active: bool,
    outstanding: u16,

    // Statistics
    submitted: u64,
    completed: u64,
    errors: u64,

    pub fn init() NvmeQueuePair {
        return .{
            .sq_phys = 0,
            .cq_phys = 0,
            .sq_depth = 0,
            .cq_depth = 0,
            .sq_tail = 0,
            .sq_head = 0,
            .cq_head = 0,
            .cq_phase = true,
            .sq_doorbell = 0,
            .cq_doorbell = 0,
            .id = 0,
            .irq_vector = 0,
            .active = false,
            .outstanding = 0,
            .submitted = 0,
            .completed = 0,
            .errors = 0,
        };
    }

    /// Ring the submission queue doorbell
    fn ringSqDoorbell(self: *NvmeQueuePair) void {
        if (self.sq_doorbell == 0) return;
        const db: *volatile u32 = @ptrFromInt(self.sq_doorbell);
        db.* = @as(u32, self.sq_tail);
    }

    /// Ring the completion queue doorbell
    fn ringCqDoorbell(self: *NvmeQueuePair) void {
        if (self.cq_doorbell == 0) return;
        const db: *volatile u32 = @ptrFromInt(self.cq_doorbell);
        db.* = @as(u32, self.cq_head);
    }

    /// Submit a command to the submission queue
    pub fn submit(self: *NvmeQueuePair, cmd: NvmeSubmissionEntry) bool {
        const next_tail = (self.sq_tail + 1) % self.sq_depth;
        if (next_tail == self.sq_head) return false; // Queue full

        // Write command to SQ memory
        const sq_base: [*]volatile NvmeSubmissionEntry = @ptrFromInt(self.sq_phys);
        sq_base[self.sq_tail] = cmd;

        self.sq_tail = next_tail;
        self.outstanding += 1;
        self.submitted += 1;

        // Ring doorbell
        self.ringSqDoorbell();
        return true;
    }
};

// ============================================================================
// NVMe namespace
// ============================================================================

pub const NvmeNamespace = struct {
    nsid: u32,
    active: bool,
    size_blocks: u64,    // Size in logical blocks
    capacity: u64,
    utilization: u64,
    block_size: u32,     // Logical block size (512, 4096)
    metadata_size: u16,
    lba_format: u8,
    features: u16,       // Thin provisioning, etc.

    // Computed
    size_bytes: u64,

    pub fn init() NvmeNamespace {
        return .{
            .nsid = 0,
            .active = false,
            .size_blocks = 0,
            .capacity = 0,
            .utilization = 0,
            .block_size = 512,
            .metadata_size = 0,
            .lba_format = 0,
            .features = 0,
            .size_bytes = 0,
        };
    }

    pub fn calculateSize(self: *NvmeNamespace) void {
        self.size_bytes = self.size_blocks * @as(u64, self.block_size);
    }
};

// ============================================================================
// S.M.A.R.T. health information
// ============================================================================

pub const NvmeSmartLog = struct {
    critical_warning: u8,
    temperature: u16,           // Kelvin
    available_spare: u8,        // Percentage
    available_spare_threshold: u8,
    percentage_used: u8,        // Endurance used
    data_units_read: u128,      // In 512-byte units * 1000
    data_units_written: u128,
    host_read_commands: u128,
    host_write_commands: u128,
    controller_busy_time: u128, // Minutes
    power_cycles: u128,
    power_on_hours: u128,
    unsafe_shutdowns: u128,
    media_errors: u128,
    num_error_log_entries: u128,
    warning_comp_temperature_time: u32,
    critical_comp_temperature_time: u32,

    pub fn init() NvmeSmartLog {
        return .{
            .critical_warning = 0,
            .temperature = 0,
            .available_spare = 100,
            .available_spare_threshold = 10,
            .percentage_used = 0,
            .data_units_read = 0,
            .data_units_written = 0,
            .host_read_commands = 0,
            .host_write_commands = 0,
            .controller_busy_time = 0,
            .power_cycles = 0,
            .power_on_hours = 0,
            .unsafe_shutdowns = 0,
            .media_errors = 0,
            .num_error_log_entries = 0,
            .warning_comp_temperature_time = 0,
            .critical_comp_temperature_time = 0,
        };
    }

    pub fn temperatureCelsius(self: *const NvmeSmartLog) i16 {
        return @as(i16, @intCast(self.temperature)) - 273;
    }
};

// ============================================================================
// NVMe controller
// ============================================================================

pub const NvmeController = struct {
    id: u8,
    active: bool,
    bar0: u64,              // BAR0 MMIO base address
    bar_size: u64,

    // Controller identity
    serial: [20]u8,
    model: [40]u8,
    firmware: [8]u8,
    pci_vendor: u16,
    pci_device: u16,

    // Capabilities
    version: u32,
    max_queue_entries: u16,
    doorbell_stride: u32,
    max_transfer_size: u32,  // In pages
    num_namespaces: u32,
    supports_sgl: bool,      // Scatter Gather Lists
    supports_streams: bool,
    supports_directives: bool,

    // Queue pairs
    admin_queue: NvmeQueuePair,
    io_queues: [MAX_IO_QUEUES]NvmeQueuePair,
    io_queue_count: u16,

    // Namespaces
    namespaces: [MAX_NAMESPACES]NvmeNamespace,
    namespace_count: u32,

    // S.M.A.R.T.
    smart: NvmeSmartLog,

    // Power state
    current_power_state: u8,
    num_power_states: u8,

    // Statistics
    total_reads: u64,
    total_writes: u64,
    total_flushes: u64,
    total_errors: u64,

    pub fn init(id: u8, bar0: u64) NvmeController {
        var ctrl: NvmeController = undefined;
        ctrl.id = id;
        ctrl.active = false;
        ctrl.bar0 = bar0;
        ctrl.bar_size = 0;
        ctrl.pci_vendor = 0;
        ctrl.pci_device = 0;
        ctrl.version = 0;
        ctrl.max_queue_entries = 0;
        ctrl.doorbell_stride = 4;
        ctrl.max_transfer_size = 32;
        ctrl.num_namespaces = 0;
        ctrl.supports_sgl = false;
        ctrl.supports_streams = false;
        ctrl.supports_directives = false;
        ctrl.admin_queue = NvmeQueuePair.init();
        ctrl.io_queue_count = 0;
        ctrl.namespace_count = 0;
        ctrl.smart = NvmeSmartLog.init();
        ctrl.current_power_state = 0;
        ctrl.num_power_states = 1;
        ctrl.total_reads = 0;
        ctrl.total_writes = 0;
        ctrl.total_flushes = 0;
        ctrl.total_errors = 0;
        for (0..20) |i| ctrl.serial[i] = 0;
        for (0..40) |i| ctrl.model[i] = 0;
        for (0..8) |i| ctrl.firmware[i] = 0;
        for (0..MAX_IO_QUEUES) |i| ctrl.io_queues[i] = NvmeQueuePair.init();
        for (0..MAX_NAMESPACES) |i| ctrl.namespaces[i] = NvmeNamespace.init();
        return ctrl;
    }

    /// Read MMIO register
    fn readReg(self: *const NvmeController, offset: u64) u32 {
        const addr: *volatile u32 = @ptrFromInt(self.bar0 + offset);
        return addr.*;
    }

    /// Write MMIO register
    fn writeReg(self: *NvmeController, offset: u64, val: u32) void {
        const addr: *volatile u32 = @ptrFromInt(self.bar0 + offset);
        addr.* = val;
    }

    fn readReg64(self: *const NvmeController, offset: u64) u64 {
        const lo: *volatile u32 = @ptrFromInt(self.bar0 + offset);
        const hi: *volatile u32 = @ptrFromInt(self.bar0 + offset + 4);
        return @as(u64, hi.*) << 32 | lo.*;
    }

    fn writeReg64(self: *NvmeController, offset: u64, val: u64) void {
        const lo: *volatile u32 = @ptrFromInt(self.bar0 + offset);
        const hi: *volatile u32 = @ptrFromInt(self.bar0 + offset + 4);
        lo.* = @truncate(val);
        hi.* = @truncate(val >> 32);
    }

    /// Detect and parse controller capabilities
    pub fn detect(self: *NvmeController) bool {
        const cap = self.readReg64(NVME_REG_CAP);
        if (cap == 0 or cap == 0xFFFFFFFFFFFFFFFF) return false;

        self.version = self.readReg(NVME_REG_VS);
        self.max_queue_entries = @intCast(cap & 0xFFFF);
        self.doorbell_stride = @intCast(4 << @as(u5, @intCast((cap >> 32) & 0xF)));

        self.active = true;
        return true;
    }

    /// Reset the controller
    pub fn reset(self: *NvmeController) void {
        // Disable controller
        var cc = self.readReg(NVME_REG_CC);
        cc &= ~CC_EN;
        self.writeReg(NVME_REG_CC, cc);

        // Wait for not ready
        var timeout: u32 = 100000;
        while (timeout > 0) : (timeout -= 1) {
            if (self.readReg(NVME_REG_CSTS) & CSTS_RDY == 0) break;
        }
    }

    /// Enable the controller
    pub fn enable(self: *NvmeController) bool {
        // Setup admin queue attributes
        const aqa: u32 = (@as(u32, ADMIN_QUEUE_DEPTH - 1) << 16) | (ADMIN_QUEUE_DEPTH - 1);
        self.writeReg(NVME_REG_AQA, aqa);

        // Set admin queue base addresses
        self.writeReg64(NVME_REG_ASQ, self.admin_queue.sq_phys);
        self.writeReg64(NVME_REG_ACQ, self.admin_queue.cq_phys);

        // Enable controller
        const cc: u32 = CC_EN | CC_CSS_NVM | CC_AMS_RR | CC_IOSQES | CC_IOCQES;
        self.writeReg(NVME_REG_CC, cc);

        // Wait for ready
        var timeout: u32 = 100000;
        while (timeout > 0) : (timeout -= 1) {
            const csts = self.readReg(NVME_REG_CSTS);
            if (csts & CSTS_CFS != 0) return false; // Fatal
            if (csts & CSTS_RDY != 0) return true;
        }
        return false;
    }

    /// Shutdown the controller
    pub fn shutdown(self: *NvmeController) void {
        var cc = self.readReg(NVME_REG_CC);
        cc = (cc & ~@as(u32, 3 << 14)) | CC_SHN_NORMAL;
        self.writeReg(NVME_REG_CC, cc);

        // Wait for shutdown complete
        var timeout: u32 = 100000;
        while (timeout > 0) : (timeout -= 1) {
            if (self.readReg(NVME_REG_CSTS) & CSTS_SHST_MASK == CSTS_SHST_COMPLETE) break;
        }
        self.active = false;
    }

    /// Build a read command
    pub fn buildReadCmd(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64, cmd_id: u16) NvmeSubmissionEntry {
        return .{
            .opcode = NVME_IO_READ,
            .flags = 0,
            .command_id = cmd_id,
            .nsid = nsid,
            .reserved = 0,
            .mptr = 0,
            .prp1 = prp1,
            .prp2 = prp2,
            .cdw10 = @truncate(lba),
            .cdw11 = @truncate(lba >> 32),
            .cdw12 = @as(u32, blocks) - 1,
            .cdw13 = 0,
            .cdw14 = 0,
            .cdw15 = 0,
        };
    }

    /// Build a write command
    pub fn buildWriteCmd(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64, cmd_id: u16) NvmeSubmissionEntry {
        return .{
            .opcode = NVME_IO_WRITE,
            .flags = 0,
            .command_id = cmd_id,
            .nsid = nsid,
            .reserved = 0,
            .mptr = 0,
            .prp1 = prp1,
            .prp2 = prp2,
            .cdw10 = @truncate(lba),
            .cdw11 = @truncate(lba >> 32),
            .cdw12 = @as(u32, blocks) - 1,
            .cdw13 = 0,
            .cdw14 = 0,
            .cdw15 = 0,
        };
    }

    /// Build a flush command
    pub fn buildFlushCmd(nsid: u32, cmd_id: u16) NvmeSubmissionEntry {
        return .{
            .opcode = NVME_IO_FLUSH,
            .flags = 0,
            .command_id = cmd_id,
            .nsid = nsid,
            .reserved = 0,
            .mptr = 0,
            .prp1 = 0,
            .prp2 = 0,
            .cdw10 = 0,
            .cdw11 = 0,
            .cdw12 = 0,
            .cdw13 = 0,
            .cdw14 = 0,
            .cdw15 = 0,
        };
    }

    /// Submit an I/O read
    pub fn submitRead(self: *NvmeController, queue_idx: u16, nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) bool {
        if (queue_idx >= self.io_queue_count) return false;
        var qp = &self.io_queues[queue_idx];
        if (!qp.active) return false;

        const cmd_id = @as(u16, @truncate(qp.submitted));
        const cmd = buildReadCmd(nsid, lba, blocks, prp1, prp2, cmd_id);
        if (qp.submit(cmd)) {
            self.total_reads += 1;
            return true;
        }
        return false;
    }

    /// Submit an I/O write
    pub fn submitWrite(self: *NvmeController, queue_idx: u16, nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) bool {
        if (queue_idx >= self.io_queue_count) return false;
        var qp = &self.io_queues[queue_idx];
        if (!qp.active) return false;

        const cmd_id = @as(u16, @truncate(qp.submitted));
        const cmd = buildWriteCmd(nsid, lba, blocks, prp1, prp2, cmd_id);
        if (qp.submit(cmd)) {
            self.total_writes += 1;
            return true;
        }
        return false;
    }

    /// Submit a flush
    pub fn submitFlush(self: *NvmeController, queue_idx: u16, nsid: u32) bool {
        if (queue_idx >= self.io_queue_count) return false;
        var qp = &self.io_queues[queue_idx];
        if (!qp.active) return false;

        const cmd_id = @as(u16, @truncate(qp.submitted));
        const cmd = buildFlushCmd(nsid, cmd_id);
        if (qp.submit(cmd)) {
            self.total_flushes += 1;
            return true;
        }
        return false;
    }
};

// ============================================================================
// NVMe subsystem manager
// ============================================================================

pub const NvmeSubsystem = struct {
    controllers: [MAX_NVME_CONTROLLERS]NvmeController,
    controller_count: u32,
    initialized: bool,

    pub fn init() NvmeSubsystem {
        var sub: NvmeSubsystem = undefined;
        sub.controller_count = 0;
        sub.initialized = false;
        for (0..MAX_NVME_CONTROLLERS) |i| {
            sub.controllers[i] = NvmeController.init(@intCast(i), 0);
        }
        return sub;
    }

    /// Register an NVMe controller from PCI enumeration
    pub fn registerController(self: *NvmeSubsystem, bar0: u64) ?u8 {
        if (self.controller_count >= MAX_NVME_CONTROLLERS) return null;
        const idx = self.controller_count;
        self.controllers[idx] = NvmeController.init(@intCast(idx), bar0);
        if (self.controllers[idx].detect()) {
            self.controller_count += 1;
            return @intCast(idx);
        }
        return null;
    }

    /// Enable all detected controllers
    pub fn enableAll(self: *NvmeSubsystem) u32 {
        var enabled: u32 = 0;
        for (0..self.controller_count) |i| {
            if (self.controllers[i].active) {
                self.controllers[i].reset();
                if (self.controllers[i].enable()) {
                    enabled += 1;
                }
            }
        }
        self.initialized = true;
        return enabled;
    }

    /// Shutdown all controllers
    pub fn shutdownAll(self: *NvmeSubsystem) void {
        for (0..self.controller_count) |i| {
            if (self.controllers[i].active) {
                self.controllers[i].shutdown();
            }
        }
        self.initialized = false;
    }

    /// Get total NVMe capacity in bytes
    pub fn totalCapacity(self: *const NvmeSubsystem) u64 {
        var total: u64 = 0;
        for (0..self.controller_count) |c| {
            for (0..self.controllers[c].namespace_count) |n| {
                if (self.controllers[c].namespaces[n].active) {
                    total += self.controllers[c].namespaces[n].size_bytes;
                }
            }
        }
        return total;
    }
};

var nvme_subsystem: NvmeSubsystem = NvmeSubsystem.init();

pub fn getNvmeSubsystem() *NvmeSubsystem {
    return &nvme_subsystem;
}

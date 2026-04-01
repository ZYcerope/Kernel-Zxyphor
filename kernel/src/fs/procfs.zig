// =============================================================================
// Kernel Zxyphor — procfs (Process/Kernel Info Virtual Filesystem)
// =============================================================================
// Linux-like /proc filesystem exposing kernel and process information:
//   - /proc/<pid>/status, stat, maps, fd, cmdline
//   - /proc/meminfo, cpuinfo, uptime, loadavg, version
//   - /proc/sys/ for sysctl-like tuning
//   - /proc/interrupts, /proc/iomem, /proc/ioports
//   - Read-only virtual files with dynamic content generation
//   - Callback-driven content rendering
//   - Per-process and system-wide nodes
// =============================================================================

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PROC_NODES: usize = 512;
pub const MAX_PROC_NAME: usize = 64;
pub const MAX_PROC_DATA: usize = 4096;
pub const MAX_PROC_CHILDREN: usize = 32;
pub const MAX_PID_DIRS: usize = 256;
pub const MAX_SYSCTL_ENTRIES: usize = 64;

pub const NODE_TYPE_FILE: u8 = 1;
pub const NODE_TYPE_DIR: u8 = 2;
pub const NODE_TYPE_SYMLINK: u8 = 3;
pub const NODE_TYPE_PROC_DIR: u8 = 4; // Per-process directory

// ============================================================================
// Content generator callback
// ============================================================================

pub const ContentGenerator = *const fn (buffer: []u8) usize;

// ============================================================================
// Process info snapshot (per-PID stats)
// ============================================================================

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    state: u8,           // 0=running, 1=sleeping, 2=stopped, 3=zombie
    uid: u32,
    gid: u32,
    comm: [16]u8,        // Process name
    comm_len: u8,
    nice: i8,
    priority: i16,
    num_threads: u32,
    vm_size: u64,        // Virtual memory size (bytes)
    vm_rss: u64,         // Resident set size (pages)
    vm_shared: u64,      // Shared pages
    utime: u64,          // User mode ticks
    stime: u64,          // Kernel mode ticks
    start_time: u64,     // Process start time (ticks since boot)
    cpu_id: u8,          // Last CPU
    voluntary_switches: u64,
    involuntary_switches: u64,
    signal_pending: u64,
    signal_blocked: u64,

    pub fn init() ProcessInfo {
        var info: ProcessInfo = undefined;
        info.pid = 0;
        info.ppid = 0;
        info.state = 0;
        info.uid = 0;
        info.gid = 0;
        info.comm_len = 0;
        info.nice = 0;
        info.priority = 0;
        info.num_threads = 1;
        info.vm_size = 0;
        info.vm_rss = 0;
        info.vm_shared = 0;
        info.utime = 0;
        info.stime = 0;
        info.start_time = 0;
        info.cpu_id = 0;
        info.voluntary_switches = 0;
        info.involuntary_switches = 0;
        info.signal_pending = 0;
        info.signal_blocked = 0;
        for (0..16) |i| info.comm[i] = 0;
        return info;
    }
};

// ============================================================================
// Memory info
// ============================================================================

pub const MemInfo = struct {
    total_pages: u64,
    free_pages: u64,
    available_pages: u64,
    buffers_pages: u64,
    cached_pages: u64,
    swap_total: u64,
    swap_free: u64,
    dirty_pages: u64,
    writeback_pages: u64,
    anon_pages: u64,
    mapped_pages: u64,
    shmem_pages: u64,
    slab_reclaimable: u64,
    slab_unreclaimable: u64,
    page_tables: u64,
    kernel_stack: u64,

    pub fn init() MemInfo {
        return .{
            .total_pages = 0,
            .free_pages = 0,
            .available_pages = 0,
            .buffers_pages = 0,
            .cached_pages = 0,
            .swap_total = 0,
            .swap_free = 0,
            .dirty_pages = 0,
            .writeback_pages = 0,
            .anon_pages = 0,
            .mapped_pages = 0,
            .shmem_pages = 0,
            .slab_reclaimable = 0,
            .slab_unreclaimable = 0,
            .page_tables = 0,
            .kernel_stack = 0,
        };
    }

    pub fn totalKb(self: *const MemInfo) u64 {
        return self.total_pages * 4;
    }

    pub fn freeKb(self: *const MemInfo) u64 {
        return self.free_pages * 4;
    }

    pub fn availableKb(self: *const MemInfo) u64 {
        return self.available_pages * 4;
    }

    pub fn cachedKb(self: *const MemInfo) u64 {
        return self.cached_pages * 4;
    }
};

// ============================================================================
// CPU info
// ============================================================================

pub const CpuInfo = struct {
    cpu_id: u8,
    apic_id: u8,
    online: bool,
    vendor: [16]u8,
    vendor_len: u8,
    model_name: [48]u8,
    model_name_len: u8,
    family: u8,
    model: u8,
    stepping: u8,
    frequency_mhz: u32,
    cache_size_kb: u32,
    features: u64,          // Feature bitmap
    idle_time: u64,         // Ticks in idle
    user_time: u64,         // Ticks in user mode
    system_time: u64,       // Ticks in kernel mode
    irq_time: u64,          // Ticks handling IRQs
    softirq_time: u64,

    pub fn init() CpuInfo {
        var cpu: CpuInfo = undefined;
        cpu.cpu_id = 0;
        cpu.apic_id = 0;
        cpu.online = false;
        cpu.vendor_len = 0;
        cpu.model_name_len = 0;
        cpu.family = 0;
        cpu.model = 0;
        cpu.stepping = 0;
        cpu.frequency_mhz = 0;
        cpu.cache_size_kb = 0;
        cpu.features = 0;
        cpu.idle_time = 0;
        cpu.user_time = 0;
        cpu.system_time = 0;
        cpu.irq_time = 0;
        cpu.softirq_time = 0;
        for (0..16) |i| cpu.vendor[i] = 0;
        for (0..48) |i| cpu.model_name[i] = 0;
        return cpu;
    }
};

// ============================================================================
// /proc node
// ============================================================================

pub const ProcNode = struct {
    name: [MAX_PROC_NAME]u8,
    name_len: u8,
    node_type: u8,
    active: bool,
    mode: u16,
    parent: u32,
    children: [MAX_PROC_CHILDREN]u32,
    child_count: u32,

    // For files: content generator or static data
    generator: ?ContentGenerator,
    static_data: [MAX_PROC_DATA]u8,
    static_len: u32,

    // For per-PID nodes
    pid: u32,

    pub fn init() ProcNode {
        var node: ProcNode = undefined;
        node.name_len = 0;
        node.node_type = 0;
        node.active = false;
        node.mode = 0o444;
        node.parent = 0;
        node.child_count = 0;
        node.generator = null;
        node.static_len = 0;
        node.pid = 0;
        for (0..MAX_PROC_NAME) |i| node.name[i] = 0;
        for (0..MAX_PROC_CHILDREN) |i| node.children[i] = 0;
        for (0..MAX_PROC_DATA) |i| node.static_data[i] = 0;
        return node;
    }

    pub fn setName(self: *ProcNode, name: []const u8) void {
        const len = @min(name.len, MAX_PROC_NAME - 1);
        for (0..len) |i| self.name[i] = name[i];
        self.name[len] = 0;
        self.name_len = @intCast(len);
    }

    pub fn nameEquals(self: *const ProcNode, name: []const u8) bool {
        if (self.name_len != name.len) return false;
        for (0..self.name_len) |i| {
            if (self.name[i] != name[i]) return false;
        }
        return true;
    }

    pub fn read(self: *ProcNode, buffer: []u8) usize {
        if (self.generator) |gen| {
            return gen(buffer);
        }
        if (self.static_len > 0) {
            const to_copy = @min(self.static_len, @as(u32, @intCast(buffer.len)));
            for (0..to_copy) |i| buffer[i] = self.static_data[i];
            return to_copy;
        }
        return 0;
    }
};

// ============================================================================
// Interrupt info (for /proc/interrupts)
// ============================================================================

pub const InterruptInfo = struct {
    irq: u32,
    count: [16]u64,       // Per-CPU counts (up to 16 CPUs)
    name: [32]u8,
    name_len: u8,
    chip_name: [16]u8,
    chip_len: u8,

    pub fn init() InterruptInfo {
        var info: InterruptInfo = undefined;
        info.irq = 0;
        info.name_len = 0;
        info.chip_len = 0;
        for (0..16) |i| info.count[i] = 0;
        for (0..32) |i| info.name[i] = 0;
        for (0..16) |i| info.chip_name[i] = 0;
        return info;
    }
};

// ============================================================================
// Sysctl entry
// ============================================================================

pub const SysctlType = enum(u8) {
    int_val = 0,
    string_val = 1,
    bool_val = 2,
};

pub const SysctlEntry = struct {
    key: [64]u8,
    key_len: u8,
    stype: SysctlType,
    int_value: i64,
    string_value: [128]u8,
    string_len: u8,
    min_val: i64,
    max_val: i64,
    writable: bool,
    active: bool,

    pub fn init() SysctlEntry {
        var e: SysctlEntry = undefined;
        e.key_len = 0;
        e.stype = .int_val;
        e.int_value = 0;
        e.string_len = 0;
        e.min_val = 0;
        e.max_val = 0x7FFFFFFFFFFFFFFF;
        e.writable = true;
        e.active = false;
        for (0..64) |i| e.key[i] = 0;
        for (0..128) |i| e.string_value[i] = 0;
        return e;
    }

    pub fn setKey(self: *SysctlEntry, key: []const u8) void {
        const len = @min(key.len, 63);
        for (0..len) |i| self.key[i] = key[i];
        self.key[len] = 0;
        self.key_len = @intCast(len);
    }

    pub fn keyEquals(self: *const SysctlEntry, key: []const u8) bool {
        if (self.key_len != key.len) return false;
        for (0..self.key_len) |i| {
            if (self.key[i] != key[i]) return false;
        }
        return true;
    }

    pub fn setInt(self: *SysctlEntry, val: i64) bool {
        if (val < self.min_val or val > self.max_val) return false;
        self.int_value = val;
        return true;
    }
};

// ============================================================================
// Load average
// ============================================================================

pub const LoadAvg = struct {
    avg_1: u32,    // Fixed-point *100 (e.g. 125 = 1.25)
    avg_5: u32,
    avg_15: u32,
    nr_running: u32,
    nr_threads: u32,
    last_pid: u32,

    pub fn init() LoadAvg {
        return .{
            .avg_1 = 0,
            .avg_5 = 0,
            .avg_15 = 0,
            .nr_running = 0,
            .nr_threads = 0,
            .last_pid = 0,
        };
    }
};

// ============================================================================
// ProcFS filesystem
// ============================================================================

pub const ProcFS = struct {
    nodes: [MAX_PROC_NODES]ProcNode,
    node_count: u32,
    root_node: u32,
    mounted: bool,

    // System-wide info caches
    mem_info: MemInfo,
    cpu_info: [16]CpuInfo,
    cpu_count: u8,
    load_avg: LoadAvg,
    uptime_seconds: u64,
    uptime_idle: u64,
    irq_info: [256]InterruptInfo,
    irq_count: u32,

    // Sysctl entries (/proc/sys/)
    sysctl: [MAX_SYSCTL_ENTRIES]SysctlEntry,
    sysctl_count: u32,

    // Process table
    processes: [MAX_PID_DIRS]ProcessInfo,
    process_count: u32,

    pub fn init() ProcFS {
        var pfs: ProcFS = undefined;
        pfs.node_count = 0;
        pfs.root_node = 0;
        pfs.mounted = false;
        pfs.mem_info = MemInfo.init();
        pfs.cpu_count = 0;
        pfs.load_avg = LoadAvg.init();
        pfs.uptime_seconds = 0;
        pfs.uptime_idle = 0;
        pfs.irq_count = 0;
        pfs.sysctl_count = 0;
        pfs.process_count = 0;
        for (0..MAX_PROC_NODES) |i| pfs.nodes[i] = ProcNode.init();
        for (0..16) |i| pfs.cpu_info[i] = CpuInfo.init();
        for (0..256) |i| pfs.irq_info[i] = InterruptInfo.init();
        for (0..MAX_SYSCTL_ENTRIES) |i| pfs.sysctl[i] = SysctlEntry.init();
        for (0..MAX_PID_DIRS) |i| pfs.processes[i] = ProcessInfo.init();
        return pfs;
    }

    /// Allocate a new node
    fn allocNode(self: *ProcFS) ?u32 {
        for (0..MAX_PROC_NODES) |i| {
            if (!self.nodes[i].active) {
                self.nodes[i] = ProcNode.init();
                self.nodes[i].active = true;
                self.node_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Mount procfs: create root directory and standard entries
    pub fn mount(self: *ProcFS) bool {
        const root_idx = self.allocNode() orelse return false;
        self.nodes[root_idx].node_type = NODE_TYPE_DIR;
        self.nodes[root_idx].setName("proc");
        self.root_node = root_idx;
        self.mounted = true;

        // Create standard /proc entries
        _ = self.addFile(root_idx, "meminfo", null);
        _ = self.addFile(root_idx, "cpuinfo", null);
        _ = self.addFile(root_idx, "uptime", null);
        _ = self.addFile(root_idx, "loadavg", null);
        _ = self.addFile(root_idx, "version", null);
        _ = self.addFile(root_idx, "stat", null);
        _ = self.addFile(root_idx, "interrupts", null);
        _ = self.addFile(root_idx, "filesystems", null);
        _ = self.addFile(root_idx, "mounts", null);
        _ = self.addFile(root_idx, "cmdline", null);

        // Create /proc/sys/ hierarchy
        if (self.addDir(root_idx, "sys")) |sys_idx| {
            _ = self.addDir(sys_idx, "kernel");
            _ = self.addDir(sys_idx, "vm");
            _ = self.addDir(sys_idx, "net");
            _ = self.addDir(sys_idx, "fs");
        }

        // Create /proc/net/ hierarchy
        if (self.addDir(root_idx, "net")) |net_idx| {
            _ = self.addFile(net_idx, "tcp", null);
            _ = self.addFile(net_idx, "udp", null);
            _ = self.addFile(net_idx, "dev", null);
            _ = self.addFile(net_idx, "arp", null);
            _ = self.addFile(net_idx, "route", null);
        }

        // Populate default sysctl entries
        self.addSysctl("kernel.hostname", .string_val, 0);
        self.addSysctl("kernel.ostype", .string_val, 0);
        self.addSysctl("kernel.osrelease", .string_val, 0);
        self.addSysctl("vm.swappiness", .int_val, 60);
        self.addSysctl("vm.dirty_ratio", .int_val, 20);
        self.addSysctl("vm.dirty_background_ratio", .int_val, 10);
        self.addSysctl("vm.overcommit_memory", .int_val, 0);
        self.addSysctl("vm.min_free_kbytes", .int_val, 1024);
        self.addSysctl("net.ipv4.ip_forward", .int_val, 0);
        self.addSysctl("net.ipv4.tcp_syncookies", .int_val, 1);
        self.addSysctl("fs.file-max", .int_val, 65536);
        self.addSysctl("fs.nr_open", .int_val, 1048576);

        return true;
    }

    /// Add a file node
    pub fn addFile(self: *ProcFS, parent: u32, name: []const u8, gen: ?ContentGenerator) ?u32 {
        const idx = self.allocNode() orelse return null;
        self.nodes[idx].node_type = NODE_TYPE_FILE;
        self.nodes[idx].setName(name);
        self.nodes[idx].parent = parent;
        self.nodes[idx].generator = gen;

        if (parent < MAX_PROC_NODES and self.nodes[parent].child_count < MAX_PROC_CHILDREN) {
            self.nodes[parent].children[self.nodes[parent].child_count] = idx;
            self.nodes[parent].child_count += 1;
        }
        return idx;
    }

    /// Add a directory node
    pub fn addDir(self: *ProcFS, parent: u32, name: []const u8) ?u32 {
        const idx = self.allocNode() orelse return null;
        self.nodes[idx].node_type = NODE_TYPE_DIR;
        self.nodes[idx].setName(name);
        self.nodes[idx].parent = parent;
        self.nodes[idx].mode = 0o555;

        if (parent < MAX_PROC_NODES and self.nodes[parent].child_count < MAX_PROC_CHILDREN) {
            self.nodes[parent].children[self.nodes[parent].child_count] = idx;
            self.nodes[parent].child_count += 1;
        }
        return idx;
    }

    /// Register a sysctl entry
    pub fn addSysctl(self: *ProcFS, key: []const u8, stype: SysctlType, default: i64) void {
        if (self.sysctl_count >= MAX_SYSCTL_ENTRIES) return;
        var entry = &self.sysctl[self.sysctl_count];
        entry.* = SysctlEntry.init();
        entry.setKey(key);
        entry.stype = stype;
        entry.int_value = default;
        entry.active = true;
        self.sysctl_count += 1;
    }

    /// Get sysctl value by key
    pub fn getSysctl(self: *const ProcFS, key: []const u8) ?*const SysctlEntry {
        for (0..self.sysctl_count) |i| {
            if (self.sysctl[i].active and self.sysctl[i].keyEquals(key)) {
                return &self.sysctl[i];
            }
        }
        return null;
    }

    /// Set sysctl value
    pub fn setSysctl(self: *ProcFS, key: []const u8, value: i64) bool {
        for (0..self.sysctl_count) |i| {
            if (self.sysctl[i].active and self.sysctl[i].keyEquals(key)) {
                if (!self.sysctl[i].writable) return false;
                return self.sysctl[i].setInt(value);
            }
        }
        return false;
    }

    /// Register a process
    pub fn registerProcess(self: *ProcFS, info: ProcessInfo) bool {
        if (self.process_count >= MAX_PID_DIRS) return false;
        self.processes[self.process_count] = info;
        self.process_count += 1;
        return true;
    }

    /// Remove a process by PID
    pub fn removeProcess(self: *ProcFS, pid: u32) bool {
        for (0..self.process_count) |i| {
            if (self.processes[i].pid == pid) {
                // Shift remaining
                var j = i;
                while (j + 1 < self.process_count) : (j += 1) {
                    self.processes[j] = self.processes[j + 1];
                }
                self.process_count -= 1;
                return true;
            }
        }
        return false;
    }

    /// Find a process by PID
    pub fn findProcess(self: *const ProcFS, pid: u32) ?*const ProcessInfo {
        for (0..self.process_count) |i| {
            if (self.processes[i].pid == pid) {
                return &self.processes[i];
            }
        }
        return null;
    }

    /// Update memory info
    pub fn updateMemInfo(self: *ProcFS, info: MemInfo) void {
        self.mem_info = info;
    }

    /// Update CPU info
    pub fn updateCpuInfo(self: *ProcFS, cpu_id: u8, info: CpuInfo) void {
        if (cpu_id >= 16) return;
        self.cpu_info[cpu_id] = info;
        if (cpu_id >= self.cpu_count) self.cpu_count = cpu_id + 1;
    }

    /// Update uptime
    pub fn updateUptime(self: *ProcFS, seconds: u64, idle: u64) void {
        self.uptime_seconds = seconds;
        self.uptime_idle = idle;
    }

    /// Update load average
    pub fn updateLoadAvg(self: *ProcFS, avg1: u32, avg5: u32, avg15: u32) void {
        self.load_avg.avg_1 = avg1;
        self.load_avg.avg_5 = avg5;
        self.load_avg.avg_15 = avg15;
    }

    /// Register interrupt info
    pub fn registerInterrupt(self: *ProcFS, irq: u32, name: []const u8, chip: []const u8) void {
        if (self.irq_count >= 256) return;
        var info = &self.irq_info[self.irq_count];
        info.irq = irq;
        const nlen = @min(name.len, 31);
        for (0..nlen) |i| info.name[i] = name[i];
        info.name_len = @intCast(nlen);
        const clen = @min(chip.len, 15);
        for (0..clen) |i| info.chip_name[i] = chip[i];
        info.chip_len = @intCast(clen);
        self.irq_count += 1;
    }

    /// Increment interrupt count
    pub fn incrementIrq(self: *ProcFS, irq: u32, cpu_id: u8) void {
        for (0..self.irq_count) |i| {
            if (self.irq_info[i].irq == irq) {
                if (cpu_id < 16) {
                    self.irq_info[i].count[cpu_id] += 1;
                }
                return;
            }
        }
    }

    /// Lookup a node by path components
    pub fn lookupPath(self: *const ProcFS, components: []const []const u8) ?u32 {
        var current = self.root_node;
        for (components) |comp| {
            var found = false;
            const node = &self.nodes[current];
            for (0..node.child_count) |i| {
                const child_idx = node.children[i];
                if (child_idx < MAX_PROC_NODES and self.nodes[child_idx].active) {
                    if (self.nodes[child_idx].nameEquals(comp)) {
                        current = child_idx;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) return null;
        }
        return current;
    }
};

// ============================================================================
// Global instance
// ============================================================================

var procfs_instance: ProcFS = ProcFS.init();

pub fn getProcFS() *ProcFS {
    return &procfs_instance;
}

pub fn mountProcFS() bool {
    return procfs_instance.mount();
}

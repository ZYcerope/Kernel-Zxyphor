// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - SMP Initialization, NUMA Topology, and MCE
// Multi-processor startup, AP bootstrap, NUMA node discovery,
// distance tables, memory topology, MCE (Machine Check Exception),
// RAS (Reliability Availability Serviceability), e820 memory map
// More advanced than Linux 2026 arch/x86 subsystem

const std = @import("std");

// ============================================================================
// e820 Memory Map
// ============================================================================

pub const E820Type = enum(u32) {
    ram = 1,
    reserved = 2,
    acpi = 3,
    nvs = 4,            // ACPI NVS (Non-Volatile Storage)
    unusable = 5,
    disabled = 6,        // Persistent memory disabled
    pmem = 7,            // Persistent memory
    pram = 12,           // Protected RAM
    soft_reserved = 0xEFFFFFFD,
    // Zxyphor
    zxy_secure = 0xF0000001,
};

pub const E820Entry = struct {
    addr: u64,
    size: u64,
    entry_type: E820Type,

    pub fn end(self: *const E820Entry) u64 {
        return self.addr + self.size;
    }

    pub fn contains(self: *const E820Entry, address: u64) bool {
        return address >= self.addr and address < self.end();
    }

    pub fn size_mb(self: *const E820Entry) u64 {
        return self.size >> 20;
    }

    pub fn is_usable(self: *const E820Entry) bool {
        return self.entry_type == .ram;
    }
};

pub const E820Table = struct {
    entries: [320]E820Entry,
    nr_entries: u32,

    pub fn total_ram(self: *const E820Table) u64 {
        var total: u64 = 0;
        for (self.entries[0..self.nr_entries]) |e| {
            if (e.entry_type == .ram) total += e.size;
        }
        return total;
    }

    pub fn total_ram_mb(self: *const E820Table) u64 {
        return self.total_ram() >> 20;
    }

    pub fn highest_address(self: *const E820Table) u64 {
        var highest: u64 = 0;
        for (self.entries[0..self.nr_entries]) |e| {
            const end_addr = e.end();
            if (end_addr > highest) highest = end_addr;
        }
        return highest;
    }

    pub fn find_region(self: *const E820Table, addr: u64) ?*const E820Entry {
        for (self.entries[0..self.nr_entries]) |*e| {
            if (e.contains(addr)) return e;
        }
        return null;
    }
};

// ============================================================================
// MADT (Multiple APIC Description Table) Parsing
// ============================================================================

pub const MadtEntryType = enum(u8) {
    local_apic = 0,
    io_apic = 1,
    interrupt_override = 2,
    nmi_source = 3,
    local_apic_nmi = 4,
    local_apic_override = 5,
    io_sapic = 6,
    local_sapic = 7,
    platform_interrupt = 8,
    local_x2apic = 9,
    local_x2apic_nmi = 10,
    gicc = 11,
    gicd = 12,
    gic_msi_frame = 13,
    gicr = 14,
    gic_its = 15,
    multiprocessor_wakeup = 16,
};

pub const MadtLocalApic = struct {
    acpi_processor_uid: u8,
    apic_id: u8,
    flags: u32,          // Bit 0: enabled, Bit 1: online capable

    pub fn is_enabled(self: *const MadtLocalApic) bool {
        return (self.flags & 1) != 0;
    }

    pub fn is_online_capable(self: *const MadtLocalApic) bool {
        return (self.flags & 2) != 0;
    }
};

pub const MadtLocalX2apic = struct {
    x2apic_id: u32,
    flags: u32,
    acpi_processor_uid: u32,
};

pub const MadtIoApic = struct {
    io_apic_id: u8,
    io_apic_address: u32,
    gsi_base: u32,
};

pub const MadtInterruptOverride = struct {
    bus: u8,
    source: u8,
    gsi: u32,
    flags: u16,          // Polarity (bits 0-1), Trigger (bits 2-3)
};

// ============================================================================
// SMP Bootstrap
// ============================================================================

pub const CpuState = enum(u8) {
    offline = 0,
    booting = 1,
    online = 2,
    active = 3,
    dying = 4,
    dead = 5,
    // Hotplug
    bring_up = 6,
    teardown = 7,
};

pub const CpuHotplugState = enum(u16) {
    offline = 0,
    // Prepare states (before CPU is online)
    prep_base = 0x0001,
    prep_perf = 0x0010,
    prep_workqueue = 0x0020,
    prep_timers = 0x0030,
    prep_rcutree = 0x0040,
    prep_kvm = 0x0050,
    prep_smpboot = 0x0060,
    // Online states
    online = 0x0100,
    ap_online_idle = 0x0110,
    ap_active = 0x0120,
    ap_online_dyn = 0x0130,
    ap_sched = 0x0140,
    ap_perf_online = 0x0150,
    ap_workqueue_online = 0x0160,
    ap_rcutree_online = 0x0170,
    // Max
    max = 0xFFFF,
};

pub const CpuTopology = struct {
    // IDs
    logical_cpu_id: u32,
    apic_id: u32,
    initial_apic_id: u32,
    // Topology
    core_id: u32,
    die_id: u32,
    package_id: u32,
    // SMT
    smt_id: u32,              // Thread ID within core
    // Cluster
    cluster_id: u32,
    // NUMA
    numa_node: u32,
    // Cache
    llc_id: u32,               // Last level cache ID
    l2c_id: u32,               // L2 cache ID
    // Capabilities
    has_x2apic: bool,
    // Performance
    max_freq_khz: u32,
    base_freq_khz: u32,
    // Microcode
    microcode_rev: u32,
};

pub const SmpBootParams = struct {
    // Trampoline
    trampoline_phys: u64,       // Physical address of AP trampoline code
    trampoline_size: u32,
    // AP startup
    ap_startup_addr: u64,
    ap_stack_size: u64,
    // GDT/IDT for AP
    ap_gdt_phys: u64,
    ap_idt_phys: u64,
    // Page tables
    ap_cr3: u64,
    // AP count
    nr_aps_expected: u32,
    nr_aps_booted: u32,
    // Timeout
    ap_boot_timeout_ms: u32,
    // Status
    bsp_apic_id: u32,
    boot_complete: bool,
};

// ============================================================================
// NUMA Topology
// ============================================================================

pub const MAX_NUMA_NODES: u32 = 64;

pub const NumaNodeState = enum(u8) {
    possible = 0,
    online = 1,
    has_normal_memory = 2,
    has_cpu = 3,
    memory_hotplug_capable = 4,
};

pub const NumaNode = struct {
    node_id: u32,
    // State
    state: u8,           // Bitmask of NumaNodeState
    // Memory ranges
    start_pfn: u64,
    end_pfn: u64,
    present_pages: u64,
    spanned_pages: u64,
    // Memory zones
    zone_normal_pages: u64,
    zone_dma32_pages: u64,
    zone_movable_pages: u64,
    // CPUs
    cpu_mask: [4]u64,    // Up to 256 CPUs
    nr_cpus: u32,
    // Distances
    distances: [MAX_NUMA_NODES]u8,
    // Memory usage
    free_pages: u64,
    active_pages: u64,
    inactive_pages: u64,
    dirty_pages: u64,
    writeback_pages: u64,
    slab_pages: u64,
    // Page cache
    file_pages: u64,
    // Stats
    numa_hit: u64,
    numa_miss: u64,
    numa_foreign: u64,
    interleave_hit: u64,
    local_node: u64,
    other_node: u64,
    // Memory bandwidth (MB/s)
    read_bandwidth: u32,
    write_bandwidth: u32,
    read_latency_ns: u32,
    write_latency_ns: u32,

    pub fn has_memory(self: *const NumaNode) bool {
        return self.present_pages > 0;
    }

    pub fn has_cpus(self: *const NumaNode) bool {
        return self.nr_cpus > 0;
    }

    pub fn distance_to(self: *const NumaNode, other_id: u32) u8 {
        if (other_id >= MAX_NUMA_NODES) return 255;
        return self.distances[other_id];
    }

    pub fn is_local_distance(distance: u8) bool {
        return distance == 10;  // Standard local distance
    }

    pub fn memory_mb(self: *const NumaNode) u64 {
        return (self.present_pages * 4096) >> 20;
    }

    pub fn free_mb(self: *const NumaNode) u64 {
        return (self.free_pages * 4096) >> 20;
    }
};

pub const NumaMemoryTarget = struct {
    proximity_domain: u32,
    base_address: u64,
    length: u64,
    memory_type: NumaMemType,
};

pub const NumaMemType = enum(u8) {
    dram = 0,
    nvdimm = 1,
    hbm = 2,            // High Bandwidth Memory
    cxl_memory = 3,     // CXL attached memory
    pmem = 4,
    // Zxyphor
    zxy_tiered = 10,
};

// ============================================================================
// SRAT (System Resource Affinity Table)
// ============================================================================

pub const SratType = enum(u8) {
    processor_affinity = 0,
    memory_affinity = 1,
    x2apic_affinity = 2,
    gicc_affinity = 3,
    gic_its_affinity = 4,
    generic_initiator = 5,
};

pub const SratProcessorAffinity = struct {
    proximity_domain: u32,
    apic_id: u8,
    flags: u32,
    sapic_eid: u8,
    clock_domain: u32,

    pub fn is_enabled(self: *const SratProcessorAffinity) bool {
        return (self.flags & 1) != 0;
    }
};

pub const SratMemoryAffinity = struct {
    proximity_domain: u32,
    base_address: u64,
    length: u64,
    flags: u32,
    // Memory type
    hot_pluggable: bool,
    non_volatile: bool,

    pub fn is_enabled(self: *const SratMemoryAffinity) bool {
        return (self.flags & 1) != 0;
    }

    pub fn end_address(self: *const SratMemoryAffinity) u64 {
        return self.base_address + self.length;
    }
};

// ============================================================================
// HMAT (Heterogeneous Memory Attribute Table)
// ============================================================================

pub const HmatDataType = enum(u8) {
    access_latency = 0,
    read_latency = 1,
    write_latency = 2,
    access_bandwidth = 3,
    read_bandwidth = 4,
    write_bandwidth = 5,
};

pub const HmatEntry = struct {
    initiator_proximity_domain: u32,
    target_proximity_domain: u32,
    data_type: HmatDataType,
    // Value
    entry_base_unit: u64,
    value: u16,          // Relative to base unit
    // Computed
    latency_ns: u32,
    bandwidth_mbps: u32,
};

// ============================================================================
// MCE (Machine Check Exception)
// ============================================================================

pub const MceBank = struct {
    bank: u8,
    // MCi_CTL
    ctl: u64,
    // MCi_STATUS
    status: MceStatus,
    // MCi_ADDR
    addr: u64,
    // MCi_MISC
    misc: u64,
    // MCi_CTL2
    ctl2: u64,
};

pub const MceStatus = packed struct(u64) {
    mca_error: u16 = 0,     // Error code
    model_specific: u16 = 0, // Model-specific error
    other_info: u6 = 0,
    corrected_count: u15 = 0, // Corrected error count (ThresHold)
    _reserved1: u4 = 0,
    pcc: bool = false,       // Processor context corrupted
    addrv: bool = false,     // MCi_ADDR valid
    miscv: bool = false,     // MCi_MISC valid
    en: bool = false,        // Error enabled
    uc: bool = false,        // Uncorrected error
    overflow: bool = false,  // Error overflow
    val: bool = false,       // MCi_STATUS valid

    pub fn is_valid(self: MceStatus) bool {
        return self.val;
    }

    pub fn is_uncorrected(self: MceStatus) bool {
        return self.uc;
    }

    pub fn is_fatal(self: MceStatus) bool {
        return self.uc and self.pcc;
    }

    pub fn error_type(self: MceStatus) MceErrorType {
        const code = self.mca_error;
        if (code == 0) return .no_error;
        if (code == 0x0001) return .unclassified;
        if (code == 0x0002) return .microcode_rom_parity;
        if (code == 0x0003) return .external;
        if (code == 0x0004) return .frc;
        if (code == 0x0005) return .internal_parity;
        if (code == 0x0400) return .internal_timer;
        if ((code & 0xFF00) == 0x0100) return .tlb;
        if ((code & 0xFF00) == 0x0200) return .memory_controller;
        if ((code & 0xF800) == 0x0800) return .bus_interconnect;
        return .unclassified;
    }
};

pub const MceErrorType = enum(u8) {
    no_error = 0,
    unclassified = 1,
    microcode_rom_parity = 2,
    external = 3,
    frc = 4,
    internal_parity = 5,
    internal_timer = 6,
    tlb = 7,
    memory_controller = 8,
    bus_interconnect = 9,
    cache = 10,
};

pub const MceSeverity = enum(u8) {
    no_severity = 0,
    notice = 1,
    correctable = 2,
    deferred = 3,
    uc_noaddrv = 4,
    uc_nosignalr = 5,
    uc_signalled = 6,
    uc_ar_if_1 = 7,
    uc_ar_eipv = 8,
    uc_context_corrupt = 9,
    panic = 10,
};

pub const MceRecord = struct {
    // Error info
    bank: u8,
    status: MceStatus,
    addr: u64,
    misc: u64,
    // CPU
    cpu: u32,
    apic_id: u32,
    // Severity
    severity: MceSeverity,
    // IP
    ip: u64,
    cs: u16,
    // TSC
    tsc: u64,
    // Wall time
    time: u64,
    // CPUID info
    cpuid: u32,
    cpuvendor: u8,
    // Socket
    socketid: u32,
    // Microcode
    microcode: u32,
    // Recovery
    recovered: bool,
    // Inject
    inject_flags: u8,
};

// ============================================================================
// RAS (Reliability Availability Serviceability)
// ============================================================================

pub const RasErrorType = enum(u8) {
    correctable = 0,
    uncorrectable = 1,
    fatal = 2,
    deferred = 3,
};

pub const RasComponent = enum(u8) {
    cpu = 0,
    memory = 1,
    pcie = 2,
    cache = 3,
    interconnect = 4,
    platform = 5,
    firmware = 6,
    // Zxyphor
    zxy_accelerator = 10,
};

pub const RasEvent = struct {
    error_type: RasErrorType,
    component: RasComponent,
    timestamp_ns: u64,
    // Location
    cpu: u32,
    numa_node: u32,
    socket: u32,
    // Memory specific
    dimm_label: [32]u8,
    dimm_location: [32]u8,
    grain_bits: u8,
    syndrome: u64,
    // PCIe specific
    pcie_bdf: u32,       // Bus:Dev:Function
    // Description
    message: [256]u8,
    message_len: u16,
    // Count
    error_count: u32,
};

pub const RasStats = struct {
    // MCE
    total_mce: u64,
    correctable_mce: u64,
    uncorrectable_mce: u64,
    fatal_mce: u64,
    // Memory (EDAC)
    ce_count: u64,       // Correctable errors
    ue_count: u64,       // Uncorrectable errors
    // PCIe AER
    pcie_correctable: u64,
    pcie_uncorrectable: u64,
    pcie_fatal: u64,
    // CPU
    cpu_correctable: u64,
    cpu_uncorrectable: u64,
    // Threshold exceeded
    threshold_events: u64,
    // CMCI (Corrected Machine Check Interrupt)
    cmci_count: u64,
    // Recovery
    successful_recoveries: u64,
    failed_recoveries: u64,
    panic_count: u64,
};

// ============================================================================
// SMP/NUMA Subsystem Manager
// ============================================================================

pub const SmpNumaSubsystem = struct {
    // e820
    e820_table: E820Table,
    total_ram_mb: u64,
    // SMP
    nr_cpus_possible: u32,
    nr_cpus_present: u32,
    nr_cpus_online: u32,
    nr_cpus_active: u32,
    bsp_apic_id: u32,
    smp_boot_params: SmpBootParams,
    // NUMA
    nr_numa_nodes: u32,
    nr_numa_nodes_online: u32,
    has_numa: bool,
    // Memory tiers
    nr_dram_nodes: u32,
    nr_pmem_nodes: u32,
    nr_cxl_nodes: u32,
    nr_hbm_nodes: u32,
    // MCE
    nr_mce_banks: u8,
    mce_enabled: bool,
    cmci_enabled: bool,
    // RAS
    ras_stats: RasStats,
    edac_enabled: bool,
    // Inter-node distances
    max_distance: u8,
    min_remote_distance: u8,
    // Stats
    cpu_hotplug_online: u64,
    cpu_hotplug_offline: u64,
    last_topology_change_ns: u64,
    // Zxyphor
    zxy_auto_numa_balance: bool,
    zxy_tier_aware_alloc: bool,
    zxy_predictive_ras: bool,
    initialized: bool,
};

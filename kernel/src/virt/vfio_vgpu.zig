// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - VFIO (Virtual Function I/O),
// vGPU (Mediated Device), Hypervisor Detection,
// Virtio Backends, Paravirt Ops, KVM Extensions,
// IOMMU Passthrough, SR-IOV Virtualization Support
// More advanced than Linux 2026 virtualization support

const std = @import("std");

// ============================================================================
// VFIO (Virtual Function I/O)
// ============================================================================

/// VFIO device type
pub const VfioDeviceType = enum(u8) {
    pci = 0,
    platform = 1,
    ap = 2,       // AP (Adjunct Processor) - s390
    ccw = 3,      // CCW - s390
    cdx = 4,      // CDX
    // Zxyphor
    zxy_custom = 100,
};

/// VFIO group status flags
pub const VfioGroupFlags = packed struct(u32) {
    viable: bool = false,
    container_set: bool = false,
    _padding: u30 = 0,
};

/// VFIO device info flags
pub const VfioDevInfoFlags = packed struct(u32) {
    reset: bool = false,          // supports reset
    pci: bool = false,
    platform: bool = false,
    amba: bool = false,
    ccw: bool = false,
    ap: bool = false,
    caps: bool = false,
    cdx: bool = false,
    _padding: u24 = 0,
};

/// VFIO region info
pub const VfioRegionInfo = struct {
    index: u32 = 0,
    flags: VfioRegionFlags = .{},
    size: u64 = 0,
    offset: u64 = 0,
    cap_type_id: u32 = 0,
    // Zxyphor
    zxy_cached: bool = false,
};

pub const VfioRegionFlags = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    mmap: bool = false,
    caps: bool = false,
    _padding: u28 = 0,
};

/// VFIO IRQ info
pub const VfioIrqInfo = struct {
    index: u32 = 0,
    flags: VfioIrqFlags = .{},
    count: u32 = 0,
};

pub const VfioIrqFlags = packed struct(u32) {
    eventfd: bool = false,
    maskable: bool = false,
    automasked: bool = false,
    noresize: bool = false,
    _padding: u28 = 0,
};

/// VFIO PCI config
pub const VfioPciConfig = struct {
    nr_regions: u32 = 0,
    nr_irqs: u32 = 0,
    vga_decode: bool = false,
    igd_opregion: bool = false,
    rom_size: u64 = 0,
    has_flr: bool = false,       // Function Level Reset
    has_pm_reset: bool = false,
    has_bus_reset: bool = false,
    // Migration
    migration_capable: bool = false,
    live_migration: bool = false,
};

/// VFIO DMA mapping
pub const VfioDmaMap = struct {
    iova: u64 = 0,
    size: u64 = 0,
    vaddr: u64 = 0,
    flags: VfioDmaFlags = .{},
};

pub const VfioDmaFlags = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    _padding: u30 = 0,
};

/// VFIO IOMMU types
pub const VfioIommuType = enum(u32) {
    type1 = 1,
    type1v2 = 3,
    spapr_tce = 2,
    spapr_tce_v2 = 7,
    // Zxyphor
    zxy_native = 100,
};

/// VFIO migration state
pub const VfioMigrationState = enum(u32) {
    error = 0,
    stop = 1,
    running = 2,
    stop_copy = 3,
    resuming = 4,
    running_p2p = 5,
    pre_copy = 6,
    pre_copy_p2p = 7,
};

/// VFIO device feature
pub const VfioDevFeature = enum(u32) {
    migration = 1,
    migration_pre_copy = 2,
    dma_logging_start = 3,
    dma_logging_stop = 4,
    dma_logging_report = 5,
    pci_vf_token = 6,
};

// ============================================================================
// Mediated Device / vGPU
// ============================================================================

/// Mediated device type category
pub const MdevTypeCategory = enum(u8) {
    gpu_vgpu = 0,
    gpu_sriov = 1,
    network = 2,
    crypto = 3,
    other = 4,
    // Zxyphor
    zxy_accel = 100,
};

/// Mediated device descriptor
pub const MdevDevDesc = struct {
    uuid: [16]u8 = [_]u8{0} ** 16,
    type_name: [64]u8 = [_]u8{0} ** 64,
    type_name_len: u8 = 0,
    category: MdevTypeCategory = .gpu_vgpu,
    parent_bus: u64 = 0,
    available_instances: u32 = 0,
    max_instances: u32 = 0,
    active: bool = false,
    // vGPU specific
    vgpu_framebuffer_mb: u32 = 0,
    vgpu_max_resolution: [2]u32 = .{ 0, 0 },
    vgpu_heads: u32 = 0,
    vgpu_max_encoders: u32 = 0,
    vgpu_frl_fps: u32 = 0,
};

/// vGPU capabilities
pub const VgpuCaps = packed struct(u64) {
    opengl: bool = false,
    vulkan: bool = false,
    opencl: bool = false,
    cuda: bool = false,
    video_encode: bool = false,
    video_decode: bool = false,
    display: bool = false,
    compute: bool = false,
    // Zxyphor
    zxy_ml_accel: bool = false,
    zxy_raytracing: bool = false,
    _padding: u54 = 0,
};

// ============================================================================
// Hypervisor Detection
// ============================================================================

/// Hypervisor type
pub const HypervisorType = enum(u8) {
    none = 0,
    kvm = 1,
    vmware = 2,
    hyperv = 3,
    xen = 4,
    parallels = 5,
    qemu = 6,
    bhyve = 7,
    acrn = 8,
    // Zxyphor
    zxy_hv = 100,
};

/// Hypervisor detection info
pub const HypervisorInfo = struct {
    hv_type: HypervisorType = .none,
    hv_vendor: [12]u8 = [_]u8{0} ** 12,
    hv_vendor_len: u8 = 0,
    hv_signature: [4]u8 = [_]u8{0} ** 4,
    max_leaf: u32 = 0,
    features: HvFeatures = .{},
    // Timing info
    tsc_frequency: u64 = 0,
    apic_frequency: u64 = 0,
    // Nested
    nested: bool = false,
    nested_hv_type: HypervisorType = .none,
};

pub const HvFeatures = packed struct(u64) {
    clocksource: bool = false,
    clocksource2: bool = false,
    clocksource_stable: bool = false,
    apic: bool = false,
    tpr: bool = false,
    eoi: bool = false,
    ipi: bool = false,
    steal_time: bool = false,
    pv_unhalt: bool = false,
    pv_send_ipi: bool = false,
    poll_control: bool = false,
    pv_sched_yield: bool = false,
    async_pf: bool = false,
    migrate_en: bool = false,
    pv_tlb_flush: bool = false,
    // Zxyphor
    zxy_fast_mmio: bool = false,
    zxy_shared_mem: bool = false,
    _padding: u47 = 0,
};

/// Paravirt clock
pub const PvClockData = extern struct {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [2]u8,
};

// ============================================================================
// Paravirt Operations
// ============================================================================

/// Paravirt patch site type
pub const PvPatchType = enum(u8) {
    none = 0,
    irq_disable = 1,
    irq_enable = 2,
    restore_fl = 3,
    save_fl = 4,
    iret = 5,
    // MMU
    read_cr2 = 10,
    write_cr2 = 11,
    read_cr3 = 12,
    write_cr3 = 13,
    flush_tlb = 14,
    flush_tlb_one = 15,
    // Time
    steal_clock = 20,
    sched_clock = 21,
};

/// Paravirt ops level
pub const PvOpsLevel = enum(u8) {
    native = 0,      // no paravirt
    minimal = 1,     // clock, steal time
    partial = 2,     // + IRQ, spinlocks
    full = 3,        // + MMU, CPU
};

// ============================================================================
// KVM Interface Extensions
// ============================================================================

/// KVM capability
pub const KvmCap = enum(u32) {
    irqchip = 0,
    hlt = 1,
    mmu_shadow_cache_control = 2,
    user_memory = 3,
    set_tss_addr = 4,
    vapic = 6,
    ext_cpuid = 7,
    clocksource = 8,
    nr_vcpus = 9,
    nr_memslots = 10,
    pit = 11,
    nop_io_delay = 12,
    pv_mmu = 13,
    mp_state = 14,
    coalesced_mmio = 15,
    sync_mmu = 16,
    iommu = 18,
    destroy_memory_region_works = 21,
    user_nmi = 22,
    set_guest_debug = 23,
    reinject_control = 24,
    irq_routing = 25,
    irq_inject_status = 26,
    assign_dev_irq = 29,
    join_memory_regions_works = 30,
    mce = 31,
    irqfd = 32,
    pit2 = 33,
    set_boot_cpu_id = 34,
    pit_state2 = 35,
    ioeventfd = 36,
    set_identity_map_addr = 37,
    xen_hvm = 38,
    adjust_clock = 39,
    internal_error_data = 40,
    vcpu_events = 41,
    s390_psw = 42,
    ppc_segstate = 43,
    hyperv = 44,
    hyperv_vapic = 45,
    hyperv_spin = 46,
    pci_segment = 47,
    x86_robust_singlestep = 51,
    debugregs = 50,
    x86_disable_exits = 54,
    // Extended
    nested_state = 68,
    manual_dirty_log_protect = 69,
    manual_dirty_log_protect2 = 70,
    binary_stats = 100,
    exit_on_emulation_failure = 104,
    notify_vmexit = 107,
    // Zxyphor
    zxy_fast_path = 1000,
};

/// KVM exit reason
pub const KvmExitReason = enum(u32) {
    unknown = 0,
    exception = 1,
    io = 2,
    hypercall = 3,
    debug = 4,
    hlt = 5,
    mmio = 6,
    irq_window_open = 7,
    shutdown = 8,
    fail_entry = 9,
    intr = 10,
    set_tpr = 11,
    tpr_access = 12,
    nmi = 16,
    internal_error = 17,
    osi = 18,
    papr_hcall = 19,
    watchdog = 21,
    epr = 23,
    system_event = 24,
    ioapic_eoi = 26,
    hyperv = 27,
    dirty_ring_full = 34,
    ap_reset_hold = 35,
    x86_bus_lock = 36,
    xen = 37,
    riscv_sbi = 38,
    riscv_csr = 39,
    notify = 40,
    // Zxyphor
    zxy_custom = 1000,
};

// ============================================================================
// SR-IOV Virtualization Support
// ============================================================================

/// SR-IOV device info
pub const SriovInfo = struct {
    total_vfs: u16 = 0,
    initial_vfs: u16 = 0,
    num_vfs: u16 = 0,           // currently enabled
    offset: u16 = 0,
    stride: u16 = 0,
    vf_device_id: u16 = 0,
    supported_page_sizes: u32 = 0,
    system_page_size: u32 = 0,
    vf_bar: [6]u64 = [_]u64{0} ** 6,
    vf_bar_size: [6]u64 = [_]u64{0} ** 6,
    ari_capable: bool = false,
    driver_max_vfs: u16 = 0,
};

/// Virtual Function state
pub const VfState = enum(u8) {
    disabled = 0,
    enabled = 1,
    assigned = 2,      // passed through to guest
    error = 3,
};

/// VF descriptor
pub const VfDesc = struct {
    vf_num: u16 = 0,
    pf_bdf: u32 = 0,           // Physical Function BDF
    vf_bdf: u32 = 0,
    state: VfState = .disabled,
    mac_addr: [6]u8 = [_]u8{0} ** 6,
    vlan: u16 = 0,
    qos: u8 = 0,
    spoofchk: bool = true,
    trust: bool = false,
    link_state: u8 = 0,
    min_tx_rate: u32 = 0,
    max_tx_rate: u32 = 0,
};

// ============================================================================
// IOMMU Passthrough
// ============================================================================

/// IOMMU passthrough mode
pub const IommuPassthroughMode = enum(u8) {
    disabled = 0,
    full = 1,              // passthrough for all devices
    per_device = 2,        // per-device passthrough
};

/// IOMMU group descriptor
pub const IommuGroupDesc = struct {
    group_id: u32 = 0,
    nr_devices: u32 = 0,
    viable: bool = false,
    default_domain_type: IommuDomainType = .identity,
};

/// IOMMU domain type
pub const IommuDomainType = enum(u8) {
    identity = 0,          // passthrough
    dma = 1,               // DMA translation
    blocked = 2,
    nested = 3,
    svapasid = 4,          // SVM/SVA
    // Zxyphor
    zxy_smart = 100,
};

// ============================================================================
// Virtualization Subsystem Manager
// ============================================================================

pub const VirtSubsystem = struct {
    hypervisor: HypervisorInfo = .{},
    pv_level: PvOpsLevel = .native,
    nr_vfio_groups: u32 = 0,
    nr_vfio_devices: u32 = 0,
    nr_mdev_devices: u32 = 0,
    nr_sriov_pfs: u32 = 0,
    nr_sriov_vfs: u32 = 0,
    nr_iommu_groups: u32 = 0,
    iommu_passthrough: IommuPassthroughMode = .disabled,
    kvm_loaded: bool = false,
    nested_virt_enabled: bool = false,
    initialized: bool = false,

    pub fn init() VirtSubsystem {
        return VirtSubsystem{
            .initialized = true,
        };
    }
};

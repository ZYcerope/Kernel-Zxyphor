// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Virtio Advanced: virtio-mmio, vhost-user, virtqueue, virtio-blk/net/gpu
// VirtIO 1.2+ specification compatible with Zxyphor enhancements

const std = @import("std");

// ============================================================================
// VirtIO Device Types
// ============================================================================

pub const VIRTIO_DEVICE_NETWORK: u32 = 1;
pub const VIRTIO_DEVICE_BLOCK: u32 = 2;
pub const VIRTIO_DEVICE_CONSOLE: u32 = 3;
pub const VIRTIO_DEVICE_ENTROPY: u32 = 4;
pub const VIRTIO_DEVICE_BALLOON: u32 = 5;
pub const VIRTIO_DEVICE_IOMEM: u32 = 6;
pub const VIRTIO_DEVICE_RPMSG: u32 = 7;
pub const VIRTIO_DEVICE_SCSI: u32 = 8;
pub const VIRTIO_DEVICE_9P: u32 = 9;
pub const VIRTIO_DEVICE_MAC80211: u32 = 10;
pub const VIRTIO_DEVICE_RPROC_SERIAL: u32 = 11;
pub const VIRTIO_DEVICE_CAIF: u32 = 12;
pub const VIRTIO_DEVICE_GPU: u32 = 16;
pub const VIRTIO_DEVICE_INPUT: u32 = 18;
pub const VIRTIO_DEVICE_VSOCK: u32 = 19;
pub const VIRTIO_DEVICE_CRYPTO: u32 = 20;
pub const VIRTIO_DEVICE_SIGNAL_DIST: u32 = 21;
pub const VIRTIO_DEVICE_PSTORE: u32 = 22;
pub const VIRTIO_DEVICE_IOMMU: u32 = 23;
pub const VIRTIO_DEVICE_MEM: u32 = 24;
pub const VIRTIO_DEVICE_SOUND: u32 = 25;
pub const VIRTIO_DEVICE_FS: u32 = 26;
pub const VIRTIO_DEVICE_PMEM: u32 = 27;
pub const VIRTIO_DEVICE_RPMB: u32 = 28;
pub const VIRTIO_DEVICE_MAC80211_HWSIM: u32 = 29;
pub const VIRTIO_DEVICE_VIDEO_ENCODER: u32 = 30;
pub const VIRTIO_DEVICE_VIDEO_DECODER: u32 = 31;
pub const VIRTIO_DEVICE_SCMI: u32 = 32;
pub const VIRTIO_DEVICE_NITRO_SEC_MOD: u32 = 33;
pub const VIRTIO_DEVICE_I2C_ADAPTER: u32 = 34;
pub const VIRTIO_DEVICE_WATCHDOG: u32 = 35;
pub const VIRTIO_DEVICE_CAN: u32 = 36;
pub const VIRTIO_DEVICE_PARAM_SERVER: u32 = 38;
pub const VIRTIO_DEVICE_AUDIO_POLICY: u32 = 39;
pub const VIRTIO_DEVICE_BT: u32 = 40;
pub const VIRTIO_DEVICE_GPIO: u32 = 41;
pub const VIRTIO_DEVICE_RDMA: u32 = 42;

// ============================================================================
// VirtIO Status/Feature Bits
// ============================================================================

pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

pub const VirtioFeatures = packed struct(u64) {
    // Common features
    notify_on_empty: bool = false,
    any_layout: bool = false,
    _reserved_2: u2 = 0,
    ring_indirect_desc: bool = false,
    ring_event_idx: bool = false,
    _reserved_6: u20 = 0,
    unused: bool = false,
    _reserved_27: u1 = 0,
    version_1: bool = false,     // bit 32 in original, mapped here
    access_platform: bool = false,
    ring_packed: bool = false,
    in_order: bool = false,
    order_platform: bool = false,
    sr_iov: bool = false,
    notification_data: bool = false,
    notif_config_data: bool = false,
    ring_reset: bool = false,
    _reserved_rest: u27 = 0,
};

// ============================================================================
// Virtqueue (Split Ring)
// ============================================================================

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;
pub const VRING_DESC_F_AVAIL: u16 = 1 << 7;
pub const VRING_DESC_F_USED: u16 = 1 << 15;

pub const VringDesc = extern struct {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
};

pub const VringAvail = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]u16,    // Variable length, using max
    used_event: u16,
};

pub const VringUsedElem = extern struct {
    id: u32,
    len: u32,
};

pub const VringUsed = extern struct {
    flags: u16,
    idx: u16,
    ring: [256]VringUsedElem,
    avail_event: u16,
};

pub const Vring = struct {
    num: u32,
    desc: ?*VringDesc,
    avail: ?*VringAvail,
    used: ?*VringUsed,
};

// ============================================================================
// Packed Virtqueue (VirtIO 1.1+)
// ============================================================================

pub const VringPackedDescEvent = extern struct {
    off_wrap: u16,
    flags: u16,
};

pub const VringPackedDesc = extern struct {
    addr: u64,
    len: u32,
    id: u16,
    flags: u16,
};

// ============================================================================
// Virtqueue Management
// ============================================================================

pub const MAX_VIRTQUEUES: usize = 32;
pub const VIRTQUEUE_MAX_SIZE: u16 = 32768;

pub const VirtqueueType = enum(u8) {
    split = 0,
    packed = 1,
};

pub const Virtqueue = struct {
    name: [32]u8,
    name_len: u8,
    index: u16,
    num_free: u32,
    num_max: u32,
    vq_type: VirtqueueType,
    // Split ring state
    vring: Vring,
    free_head: u16,
    num_added: u32,
    last_used_idx: u16,
    // Packed ring state
    packed_ring: ?*VringPackedDesc,
    packed_driver_event: ?*VringPackedDescEvent,
    packed_device_event: ?*VringPackedDescEvent,
    next_avail_idx: u16,
    wrap_counter: bool,
    // Device association
    vdev: ?*VirtioDevice,
    // Callback
    callback: ?*const fn (*Virtqueue) void,
    // Stats
    num_kicks: u64,
    num_interrupts: u64,
    total_bytes: u64,
    total_bufs: u64,
    // Suppression
    event_triggered: bool,
    broken: bool,

    pub fn kick(self: *Virtqueue) bool {
        if (self.broken) return false;
        self.num_kicks += 1;
        return true;
    }

    pub fn get_buf(self: *Virtqueue, len: *u32) ?*anyopaque {
        if (self.broken) return null;
        if (self.vq_type == .split) {
            return self.get_buf_split(len);
        } else {
            return self.get_buf_packed(len);
        }
    }

    fn get_buf_split(self: *Virtqueue, len: *u32) ?*anyopaque {
        if (self.last_used_idx == self.vring.used.?.idx) return null;
        const used_idx = self.last_used_idx & @as(u16, @truncate(self.vring.num - 1));
        const elem = self.vring.used.?.ring[used_idx];
        len.* = elem.len;
        self.last_used_idx +%= 1;
        self.num_free += 1;
        return @ptrFromInt(elem.id);
    }

    fn get_buf_packed(self: *Virtqueue, len: *u32) ?*anyopaque {
        _ = self;
        len.* = 0;
        return null;
    }

    pub fn add_buf(self: *Virtqueue, sg_out: []const VringDesc, sg_in: []const VringDesc, data: ?*anyopaque) i32 {
        const total = sg_out.len + sg_in.len;
        if (total == 0 or total > self.num_free) return -28; // ENOSPC
        if (self.broken) return -5; // EIO

        if (self.vq_type == .split) {
            return self.add_buf_split(sg_out, sg_in, data);
        }
        return -95; // EOPNOTSUPP for packed
    }

    fn add_buf_split(self: *Virtqueue, sg_out: []const VringDesc, sg_in: []const VringDesc, data: ?*anyopaque) i32 {
        _ = data;
        var head = self.free_head;
        var idx = head;

        // Output descriptors (device reads)
        for (sg_out) |sg| {
            var desc = &self.vring.desc.?[idx];
            desc.addr = sg.addr;
            desc.len = sg.len;
            desc.flags = VRING_DESC_F_NEXT;
            idx = desc.next;
        }
        // Input descriptors (device writes)
        for (sg_in) |sg| {
            var desc = &self.vring.desc.?[idx];
            desc.addr = sg.addr;
            desc.len = sg.len;
            desc.flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
            idx = desc.next;
        }
        // Last descriptor has no next
        if (sg_out.len + sg_in.len > 0) {
            self.vring.desc.?[idx].flags &= ~@as(u16, VRING_DESC_F_NEXT);
        }

        self.free_head = idx;
        self.num_free -= @intCast(sg_out.len + sg_in.len);
        self.num_added += 1;

        // Add to avail ring
        const avail_idx = self.vring.avail.?.idx;
        const avail_slot = avail_idx & @as(u16, @truncate(self.vring.num - 1));
        self.vring.avail.?.ring[avail_slot] = head;
        self.vring.avail.?.idx = avail_idx +% 1;

        return 0;
    }

    pub fn enable_cb(self: *Virtqueue) bool {
        if (self.vq_type == .split) {
            self.vring.avail.?.flags &= ~@as(u16, 1);
            return self.last_used_idx != self.vring.used.?.idx;
        }
        return false;
    }

    pub fn disable_cb(self: *Virtqueue) void {
        if (self.vq_type == .split) {
            self.vring.avail.?.flags |= 1;
        }
    }
};

// ============================================================================
// VirtIO Device
// ============================================================================

pub const VirtioTransport = enum(u8) {
    pci = 0,
    mmio = 1,
    channel = 2, // S390
};

pub const VirtioDeviceState = enum(u8) {
    reset = 0,
    acknowledged = 1,
    driver_loaded = 2,
    features_ok = 3,
    driver_ok = 4,
    needs_reset = 5,
    failed = 6,
};

pub const VirtioDevice = struct {
    dev_id: u32,
    vendor_id: u32,
    device_type: u32,
    transport: VirtioTransport,
    state: VirtioDeviceState,
    status: u8,
    // Features
    host_features: u64,
    guest_features: u64,
    // Queues
    vqs: [MAX_VIRTQUEUES]Virtqueue,
    nr_vqs: u32,
    // Configuration
    config_space: [256]u8,
    config_len: u32,
    config_generation: u32,
    // Device operations
    ops: ?*const VirtioDeviceOps,
    // Transport operations
    transport_ops: ?*const VirtioTransportOps,
    // MSI-X
    msix_enabled: bool,
    msix_vectors: u16,
    // IOMMU
    iommu_domain: ?*anyopaque,
    // Private data
    priv_data: ?*anyopaque,

    pub fn negotiate_features(self: *VirtioDevice, driver_features: u64) u64 {
        self.guest_features = self.host_features & driver_features;
        return self.guest_features;
    }

    pub fn has_feature(self: *const VirtioDevice, bit: u6) bool {
        return (self.guest_features & (@as(u64, 1) << bit)) != 0;
    }

    pub fn set_status(self: *VirtioDevice, new_status: u8) void {
        self.status |= new_status;
    }

    pub fn reset(self: *VirtioDevice) void {
        self.status = 0;
        self.state = .reset;
    }
};

pub const VirtioDeviceOps = struct {
    init: ?*const fn (*VirtioDevice) i32,
    probe: ?*const fn (*VirtioDevice) i32,
    remove: ?*const fn (*VirtioDevice) void,
    config_changed: ?*const fn (*VirtioDevice) void,
    freeze: ?*const fn (*VirtioDevice) i32,
    restore: ?*const fn (*VirtioDevice) i32,
};

pub const VirtioTransportOps = struct {
    get: ?*const fn (*VirtioDevice, u32, ?*anyopaque, u32) void,
    set: ?*const fn (*VirtioDevice, u32, ?*const anyopaque, u32) void,
    generation: ?*const fn (*VirtioDevice) u32,
    get_status: ?*const fn (*VirtioDevice) u8,
    set_status: ?*const fn (*VirtioDevice, u8) void,
    reset_device: ?*const fn (*VirtioDevice) i32,
    find_vqs: ?*const fn (*VirtioDevice, u32, [*]*Virtqueue) i32,
    del_vqs: ?*const fn (*VirtioDevice) void,
    synchronize_cbs: ?*const fn (*VirtioDevice) void,
    get_features: ?*const fn (*VirtioDevice) u64,
    finalize_features: ?*const fn (*VirtioDevice) i32,
    bus_name: ?*const fn (*VirtioDevice) [*]const u8,
    set_vq_affinity: ?*const fn (*Virtqueue, ?*anyopaque) i32,
    get_vq_affinity: ?*const fn (*VirtioDevice, u32) ?*anyopaque,
    get_shm_region: ?*const fn (*VirtioDevice, *VirtioShmRegion, u8) bool,
    disable_vq_and_reset: ?*const fn (*Virtqueue) i32,
    enable_vq_after_reset: ?*const fn (*Virtqueue) i32,
};

pub const VirtioShmRegion = struct {
    addr: u64,
    len: u64,
};

// ============================================================================
// VirtIO MMIO Transport
// ============================================================================

pub const VIRTIO_MMIO_MAGIC: u32 = 0x74726976; // "virt"
pub const VIRTIO_MMIO_VERSION: u32 = 2;         // VirtIO 1.0+

// MMIO register offsets
pub const VIRTIO_MMIO_REG_MAGIC: u32 = 0x000;
pub const VIRTIO_MMIO_REG_VERSION: u32 = 0x004;
pub const VIRTIO_MMIO_REG_DEVICE_ID: u32 = 0x008;
pub const VIRTIO_MMIO_REG_VENDOR_ID: u32 = 0x00c;
pub const VIRTIO_MMIO_REG_DEVICE_FEATURES: u32 = 0x010;
pub const VIRTIO_MMIO_REG_DEVICE_FEATURES_SEL: u32 = 0x014;
pub const VIRTIO_MMIO_REG_DRIVER_FEATURES: u32 = 0x020;
pub const VIRTIO_MMIO_REG_DRIVER_FEATURES_SEL: u32 = 0x024;
pub const VIRTIO_MMIO_REG_QUEUE_SEL: u32 = 0x030;
pub const VIRTIO_MMIO_REG_QUEUE_NUM_MAX: u32 = 0x034;
pub const VIRTIO_MMIO_REG_QUEUE_NUM: u32 = 0x038;
pub const VIRTIO_MMIO_REG_QUEUE_READY: u32 = 0x044;
pub const VIRTIO_MMIO_REG_QUEUE_NOTIFY: u32 = 0x050;
pub const VIRTIO_MMIO_REG_INTERRUPT_STATUS: u32 = 0x060;
pub const VIRTIO_MMIO_REG_INTERRUPT_ACK: u32 = 0x064;
pub const VIRTIO_MMIO_REG_STATUS: u32 = 0x070;
pub const VIRTIO_MMIO_REG_QUEUE_DESC_LOW: u32 = 0x080;
pub const VIRTIO_MMIO_REG_QUEUE_DESC_HIGH: u32 = 0x084;
pub const VIRTIO_MMIO_REG_QUEUE_AVAIL_LOW: u32 = 0x090;
pub const VIRTIO_MMIO_REG_QUEUE_AVAIL_HIGH: u32 = 0x094;
pub const VIRTIO_MMIO_REG_QUEUE_USED_LOW: u32 = 0x0a0;
pub const VIRTIO_MMIO_REG_QUEUE_USED_HIGH: u32 = 0x0a4;
pub const VIRTIO_MMIO_REG_SHM_SEL: u32 = 0x0ac;
pub const VIRTIO_MMIO_REG_SHM_LEN_LOW: u32 = 0x0b0;
pub const VIRTIO_MMIO_REG_SHM_LEN_HIGH: u32 = 0x0b4;
pub const VIRTIO_MMIO_REG_SHM_BASE_LOW: u32 = 0x0b8;
pub const VIRTIO_MMIO_REG_SHM_BASE_HIGH: u32 = 0x0bc;
pub const VIRTIO_MMIO_REG_CONFIG_GENERATION: u32 = 0x0fc;
pub const VIRTIO_MMIO_REG_CONFIG: u32 = 0x100;

pub const VirtioMmioDevice = struct {
    base_addr: u64,
    irq: u32,
    vdev: VirtioDevice,

    pub fn read_reg(self: *const VirtioMmioDevice, offset: u32) u32 {
        const addr = self.base_addr + offset;
        return @as(*volatile u32, @ptrFromInt(addr)).*;
    }

    pub fn write_reg(self: *VirtioMmioDevice, offset: u32, value: u32) void {
        const addr = self.base_addr + offset;
        @as(*volatile u32, @ptrFromInt(addr)).* = value;
    }

    pub fn verify_magic(self: *const VirtioMmioDevice) bool {
        return self.read_reg(VIRTIO_MMIO_REG_MAGIC) == VIRTIO_MMIO_MAGIC;
    }

    pub fn get_version(self: *const VirtioMmioDevice) u32 {
        return self.read_reg(VIRTIO_MMIO_REG_VERSION);
    }

    pub fn get_device_id(self: *const VirtioMmioDevice) u32 {
        return self.read_reg(VIRTIO_MMIO_REG_DEVICE_ID);
    }

    pub fn get_status(self: *const VirtioMmioDevice) u8 {
        return @truncate(self.read_reg(VIRTIO_MMIO_REG_STATUS));
    }

    pub fn set_status(self: *VirtioMmioDevice, status: u8) void {
        self.write_reg(VIRTIO_MMIO_REG_STATUS, status);
    }

    pub fn select_queue(self: *VirtioMmioDevice, index: u32) void {
        self.write_reg(VIRTIO_MMIO_REG_QUEUE_SEL, index);
    }

    pub fn get_queue_max_size(self: *const VirtioMmioDevice) u32 {
        return self.read_reg(VIRTIO_MMIO_REG_QUEUE_NUM_MAX);
    }

    pub fn set_queue_size(self: *VirtioMmioDevice, size: u32) void {
        self.write_reg(VIRTIO_MMIO_REG_QUEUE_NUM, size);
    }

    pub fn notify_queue(self: *VirtioMmioDevice, index: u32) void {
        self.write_reg(VIRTIO_MMIO_REG_QUEUE_NOTIFY, index);
    }
};

// ============================================================================
// VirtIO PCI Transport
// ============================================================================

pub const VirtioPciCapType = enum(u8) {
    common_cfg = 1,
    notify_cfg = 2,
    isr_cfg = 3,
    device_cfg = 4,
    pci_cfg = 5,
    shared_memory_cfg = 8,
    vendor_cfg = 9,
};

pub const VirtioPciCap = extern struct {
    cap_vndr: u8,
    cap_next: u8,
    cap_len: u8,
    cfg_type: u8,
    bar: u8,
    id: u8,
    padding: [2]u8,
    offset: u32,
    length: u32,
};

pub const VirtioPciCommonCfg = extern struct {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_avail: u64,
    queue_used: u64,
    queue_notify_data: u16,
    queue_reset: u16,
};

pub const VirtioPciDevice = struct {
    pci_bus: u8,
    pci_slot: u8,
    pci_func: u8,
    common_cfg_bar: u8,
    common_cfg_offset: u32,
    notify_bar: u8,
    notify_offset: u32,
    notify_off_multiplier: u32,
    device_cfg_bar: u8,
    device_cfg_offset: u32,
    device_cfg_len: u32,
    isr_bar: u8,
    isr_offset: u32,
    vdev: VirtioDevice,
};

// ============================================================================
// VirtIO Block Device
// ============================================================================

pub const VIRTIO_BLK_F_SIZE_MAX: u32 = 1;
pub const VIRTIO_BLK_F_SEG_MAX: u32 = 2;
pub const VIRTIO_BLK_F_GEOMETRY: u32 = 4;
pub const VIRTIO_BLK_F_RO: u32 = 5;
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
pub const VIRTIO_BLK_F_FLUSH: u32 = 9;
pub const VIRTIO_BLK_F_TOPOLOGY: u32 = 10;
pub const VIRTIO_BLK_F_CONFIG_WCE: u32 = 11;
pub const VIRTIO_BLK_F_MQ: u32 = 12;
pub const VIRTIO_BLK_F_DISCARD: u32 = 13;
pub const VIRTIO_BLK_F_WRITE_ZEROES: u32 = 14;
pub const VIRTIO_BLK_F_SECURE_ERASE: u32 = 16;
pub const VIRTIO_BLK_F_ZONED: u32 = 17;

pub const VirtioBlkConfig = extern struct {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
    unused1: [3]u8,
    max_secure_erase_sectors: u32,
    max_secure_erase_seg: u32,
    secure_erase_sector_alignment: u32,
    // Zoned storage
    zoned: VirtioBlkZonedConfig,
};

pub const VirtioBlkGeometry = extern struct {
    cylinders: u16,
    heads: u8,
    sectors: u8,
};

pub const VirtioBlkTopology = extern struct {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
};

pub const VirtioBlkZonedConfig = extern struct {
    model: u8,
    max_open_zones: u32,
    max_active_zones: u32,
    max_append_sectors: u32,
    write_granularity: u32,
};

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;
pub const VIRTIO_BLK_T_SECURE_ERASE: u32 = 14;
pub const VIRTIO_BLK_T_ZONE_APPEND: u32 = 15;
pub const VIRTIO_BLK_T_ZONE_REPORT: u32 = 16;
pub const VIRTIO_BLK_T_ZONE_OPEN: u32 = 18;
pub const VIRTIO_BLK_T_ZONE_CLOSE: u32 = 20;
pub const VIRTIO_BLK_T_ZONE_FINISH: u32 = 22;
pub const VIRTIO_BLK_T_ZONE_RESET: u32 = 24;
pub const VIRTIO_BLK_T_ZONE_RESET_ALL: u32 = 26;

pub const VirtioBlkReqHdr = extern struct {
    req_type: u32,
    reserved: u32,
    sector: u64,
};

pub const VirtioBlkReqStatus = extern struct {
    status: u8,
};

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;
pub const VIRTIO_BLK_S_ZONE_INVALID_CMD: u8 = 3;
pub const VIRTIO_BLK_S_ZONE_UNALIGNED_WP: u8 = 4;
pub const VIRTIO_BLK_S_ZONE_OPEN_RESOURCE: u8 = 5;
pub const VIRTIO_BLK_S_ZONE_ACTIVE_RESOURCE: u8 = 6;

// ============================================================================
// VirtIO Network Device
// ============================================================================

pub const VIRTIO_NET_F_CSUM: u32 = 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
pub const VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u32 = 2;
pub const VIRTIO_NET_F_MTU: u32 = 3;
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
pub const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
pub const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
pub const VIRTIO_NET_F_HOST_ECN: u32 = 13;
pub const VIRTIO_NET_F_HOST_UFO: u32 = 14;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
pub const VIRTIO_NET_F_STATUS: u32 = 16;
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
pub const VIRTIO_NET_F_CTRL_RX: u32 = 18;
pub const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u32 = 21;
pub const VIRTIO_NET_F_MQ: u32 = 22;
pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;
pub const VIRTIO_NET_F_GUEST_USO4: u32 = 54;
pub const VIRTIO_NET_F_GUEST_USO6: u32 = 55;
pub const VIRTIO_NET_F_HOST_USO: u32 = 56;
pub const VIRTIO_NET_F_HASH_REPORT: u32 = 57;
pub const VIRTIO_NET_F_GUEST_HDRLEN: u32 = 59;
pub const VIRTIO_NET_F_RSS: u32 = 60;
pub const VIRTIO_NET_F_RSC_EXT: u32 = 61;
pub const VIRTIO_NET_F_STANDBY: u32 = 62;
pub const VIRTIO_NET_F_SPEED_DUPLEX: u32 = 63;

pub const VirtioNetConfig = extern struct {
    mac: [6]u8,
    status: u16,
    max_virtqueue_pairs: u16,
    mtu: u16,
    speed: u32,
    duplex: u8,
    rss_max_key_size: u8,
    rss_max_indirection_table_length: u16,
    supported_hash_types: u32,
};

pub const VirtioNetHdr = extern struct {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
    hash_value: u32,       // Only with VIRTIO_NET_F_HASH_REPORT
    hash_report: u16,
    padding_reserved: u16,
};

pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;
pub const VIRTIO_NET_HDR_F_RSC_INFO: u8 = 4;

pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 3;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

// Control VQ commands
pub const VIRTIO_NET_CTRL_RX: u8 = 0;
pub const VIRTIO_NET_CTRL_MAC: u8 = 1;
pub const VIRTIO_NET_CTRL_VLAN: u8 = 2;
pub const VIRTIO_NET_CTRL_ANNOUNCE: u8 = 3;
pub const VIRTIO_NET_CTRL_MQ: u8 = 4;
pub const VIRTIO_NET_CTRL_GUEST_OFFLOADS: u8 = 5;

// ============================================================================
// VirtIO GPU
// ============================================================================

pub const VirtioGpuCtrlType = enum(u32) {
    // 2D commands
    CMD_GET_DISPLAY_INFO = 0x0100,
    CMD_RESOURCE_CREATE_2D = 0x0101,
    CMD_RESOURCE_UNREF = 0x0102,
    CMD_SET_SCANOUT = 0x0103,
    CMD_RESOURCE_FLUSH = 0x0104,
    CMD_TRANSFER_TO_HOST_2D = 0x0105,
    CMD_RESOURCE_ATTACH_BACKING = 0x0106,
    CMD_RESOURCE_DETACH_BACKING = 0x0107,
    CMD_GET_CAPSET_INFO = 0x0108,
    CMD_GET_CAPSET = 0x0109,
    CMD_GET_EDID = 0x010a,
    CMD_RESOURCE_ASSIGN_UUID = 0x010b,
    CMD_RESOURCE_CREATE_BLOB = 0x010c,
    CMD_SET_SCANOUT_BLOB = 0x010d,
    // 3D commands
    CMD_CTX_CREATE = 0x0200,
    CMD_CTX_DESTROY = 0x0201,
    CMD_CTX_ATTACH_RESOURCE = 0x0202,
    CMD_CTX_DETACH_RESOURCE = 0x0203,
    CMD_RESOURCE_CREATE_3D = 0x0204,
    CMD_TRANSFER_TO_HOST_3D = 0x0205,
    CMD_TRANSFER_FROM_HOST_3D = 0x0206,
    CMD_SUBMIT_3D = 0x0207,
    CMD_RESOURCE_MAP_BLOB = 0x0208,
    CMD_RESOURCE_UNMAP_BLOB = 0x0209,
    // Cursor commands
    CMD_UPDATE_CURSOR = 0x0300,
    CMD_MOVE_CURSOR = 0x0301,
    // Responses
    RESP_OK_NODATA = 0x1100,
    RESP_OK_DISPLAY_INFO = 0x1101,
    RESP_OK_CAPSET_INFO = 0x1102,
    RESP_OK_CAPSET = 0x1103,
    RESP_OK_EDID = 0x1104,
    RESP_OK_RESOURCE_UUID = 0x1105,
    RESP_OK_MAP_INFO = 0x1106,
    RESP_ERR_UNSPEC = 0x1200,
    RESP_ERR_OUT_OF_MEMORY = 0x1201,
    RESP_ERR_INVALID_SCANOUT_ID = 0x1202,
    RESP_ERR_INVALID_RESOURCE_ID = 0x1203,
    RESP_ERR_INVALID_CONTEXT_ID = 0x1204,
    RESP_ERR_INVALID_PARAMETER = 0x1205,
};

pub const VirtioGpuCtrlHdr = extern struct {
    ctrl_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    ring_idx: u8,
    padding: [3]u8,
};

pub const VirtioGpuRect = extern struct {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
};

pub const VirtioGpuDisplayInfo = extern struct {
    pmodes: [16]VirtioGpuDisplayOne,
};

pub const VirtioGpuDisplayOne = extern struct {
    r: VirtioGpuRect,
    enabled: u32,
    flags: u32,
};

pub const VirtioGpuResourceCreate2d = extern struct {
    hdr: VirtioGpuCtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
};

pub const VirtioGpuFormats = enum(u32) {
    B8G8R8A8_UNORM = 1,
    B8G8R8X8_UNORM = 2,
    A8R8G8B8_UNORM = 3,
    X8R8G8B8_UNORM = 4,
    R8G8B8A8_UNORM = 67,
    X8B8G8R8_UNORM = 68,
    A8B8G8R8_UNORM = 121,
    R8G8B8X8_UNORM = 134,
};

// ============================================================================
// VirtIO Console
// ============================================================================

pub const VirtioConsoleConfig = extern struct {
    cols: u16,
    rows: u16,
    max_nr_ports: u32,
    emerg_wr: u32,
};

pub const VirtioConsoleControl = extern struct {
    id: u32,
    event: u16,
    value: u16,
};

pub const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
pub const VIRTIO_CONSOLE_DEVICE_ADD: u16 = 1;
pub const VIRTIO_CONSOLE_DEVICE_REMOVE: u16 = 2;
pub const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
pub const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
pub const VIRTIO_CONSOLE_RESIZE: u16 = 5;
pub const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
pub const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

// ============================================================================
// VirtIO FS (virtiofs)
// ============================================================================

pub const VirtioFsConfig = extern struct {
    tag: [36]u8,
    num_request_queues: u32,
    notify_buf_size: u32,
};

pub const VirtioFsSuperBlock = struct {
    vdev: ?*VirtioDevice,
    tag: [36]u8,
    nr_queues: u32,
    dax_dev: ?*anyopaque,
    dax_window: ?*anyopaque,
    dax_window_len: u64,
};

// ============================================================================
// VirtIO Balloon
// ============================================================================

pub const VirtioBalloonConfig = extern struct {
    num_pages: u32,
    actual: u32,
    free_page_hint_cmd_id: u32,
    poison_val: u32,
};

pub const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0;
pub const VIRTIO_BALLOON_F_STATS_VQ: u32 = 1;
pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2;
pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u32 = 3;
pub const VIRTIO_BALLOON_F_PAGE_POISON: u32 = 4;
pub const VIRTIO_BALLOON_F_REPORTING: u32 = 5;

pub const VirtioBalloonStatTag = enum(u16) {
    SWAP_IN = 0,
    SWAP_OUT = 1,
    MAJFLT = 2,
    MINFLT = 3,
    MEMFREE = 4,
    MEMTOT = 5,
    AVAIL = 6,
    DISK_CACHES = 7,
    HUGETLB_PGALLOC = 8,
    HUGETLB_PGFAIL = 9,
    OOM_KILL = 10,
};

pub const VirtioBalloonStat = extern struct {
    tag: u16,
    val: u64,
};

// ============================================================================
// VirtIO VSOCK
// ============================================================================

pub const VirtioVsockConfig = extern struct {
    guest_cid: u64,
};

pub const VirtioVsockHdr = extern struct {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    vsock_type: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
};

pub const VirtioVsockType = enum(u16) {
    STREAM = 1,
    SEQPACKET = 2,
};

pub const VirtioVsockOp = enum(u16) {
    INVALID = 0,
    REQUEST = 1,
    RESPONSE = 2,
    RST = 3,
    SHUTDOWN = 4,
    RW = 5,
    CREDIT_UPDATE = 6,
    CREDIT_REQUEST = 7,
};

// ============================================================================
// Vhost-user Protocol
// ============================================================================

pub const VhostUserRequestType = enum(u32) {
    NONE = 0,
    GET_FEATURES = 1,
    SET_FEATURES = 2,
    SET_OWNER = 3,
    RESET_OWNER = 4,
    SET_MEM_TABLE = 5,
    SET_LOG_BASE = 6,
    SET_LOG_FD = 7,
    SET_VRING_NUM = 8,
    SET_VRING_ADDR = 9,
    SET_VRING_BASE = 10,
    GET_VRING_BASE = 11,
    SET_VRING_KICK = 12,
    SET_VRING_CALL = 13,
    SET_VRING_ERR = 14,
    GET_PROTOCOL_FEATURES = 15,
    SET_PROTOCOL_FEATURES = 16,
    GET_QUEUE_NUM = 17,
    SET_VRING_ENABLE = 18,
    SEND_RARP = 19,
    NET_SET_MTU = 20,
    SET_BACKEND_REQ_FD = 21,
    IOTLB_MSG = 22,
    SET_VRING_ENDIAN = 23,
    GET_CONFIG = 24,
    SET_CONFIG = 25,
    CREATE_CRYPTO_SESSION = 26,
    CLOSE_CRYPTO_SESSION = 27,
    POSTCOPY_ADVISE = 28,
    POSTCOPY_LISTEN = 29,
    POSTCOPY_END = 30,
    GET_INFLIGHT_FD = 31,
    SET_INFLIGHT_FD = 32,
    GPU_SET_SOCKET = 33,
    RESET_DEVICE = 34,
    VRING_KICK = 35,
    GET_MAX_MEM_SLOTS = 36,
    ADD_MEM_REG = 37,
    REM_MEM_REG = 38,
    SET_STATUS = 39,
    GET_STATUS = 40,
};

pub const VhostUserMsgHeader = extern struct {
    request: u32,
    flags: u32,
    size: u32,
};

pub const VhostUserMemoryRegion = extern struct {
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    mmap_offset: u64,
};

pub const VHOST_USER_PROTOCOL_F_MQ: u64 = 0;
pub const VHOST_USER_PROTOCOL_F_LOG_SHMFD: u64 = 1;
pub const VHOST_USER_PROTOCOL_F_RARP: u64 = 2;
pub const VHOST_USER_PROTOCOL_F_REPLY_ACK: u64 = 3;
pub const VHOST_USER_PROTOCOL_F_MTU: u64 = 4;
pub const VHOST_USER_PROTOCOL_F_BACKEND_REQ: u64 = 5;
pub const VHOST_USER_PROTOCOL_F_CROSS_ENDIAN: u64 = 6;
pub const VHOST_USER_PROTOCOL_F_CRYPTO_SESSION: u64 = 7;
pub const VHOST_USER_PROTOCOL_F_PAGEFAULT: u64 = 8;
pub const VHOST_USER_PROTOCOL_F_CONFIG: u64 = 9;
pub const VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD: u64 = 10;
pub const VHOST_USER_PROTOCOL_F_HOST_NOTIFIER: u64 = 11;
pub const VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD: u64 = 12;
pub const VHOST_USER_PROTOCOL_F_RESET_DEVICE: u64 = 13;
pub const VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS: u64 = 14;
pub const VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS: u64 = 15;
pub const VHOST_USER_PROTOCOL_F_STATUS: u64 = 16;

// ============================================================================
// VirtIO Sound
// ============================================================================

pub const VirtioSndConfig = extern struct {
    jacks: u32,
    streams: u32,
    chmaps: u32,
};

pub const VirtioSndHdr = extern struct {
    code: u32,
};

pub const VIRTIO_SND_R_JACK_INFO: u32 = 1;
pub const VIRTIO_SND_R_JACK_REMAP: u32 = 2;
pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;
pub const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

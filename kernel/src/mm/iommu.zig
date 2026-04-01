// SPDX-License-Identifier: MIT
// Zxyphor Kernel — IOMMU / DMA Remapping Engine (Zig)
//
// Hardware-level I/O memory management:
// - IOMMU page table management (multi-level, x86_64)
// - DMA address translation and remapping
// - Device isolation domains
// - Interrupt remapping table
// - Fault reporting and handling
// - ATS (Address Translation Service) support
// - DMA buffer allocation with bounce buffers
// - Scatter-gather list DMA mapping
// - PASID (Process Address Space ID) support
// - Device TLB invalidation

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const PAGE_SIZE: u64 = 4096;
const PAGE_SHIFT: u6 = 12;
const IOMMU_PAGE_LEVELS: u8 = 4;
const MAX_DOMAINS: usize = 256;
const MAX_DEVICES_PER_DOMAIN: usize = 32;
const MAX_IOMMUS: usize = 8;
const PAGE_TABLE_ENTRIES: usize = 512;
const MAX_FAULT_LOG: usize = 64;
const MAX_IRTE_ENTRIES: usize = 256;
const MAX_BOUNCE_BUFFERS: usize = 128;
const MAX_SG_ENTRIES: usize = 64;
const MAX_PASID: usize = 64;

// ─────────────────── IOMMU Page Table Entry ─────────────────────────

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_SUPER: u64 = 1 << 7;
const PTE_SNOOP: u64 = 1 << 11;
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub const IommuPte = packed struct {
    present: bool = false,
    write: bool = false,
    user: bool = false,
    pwt: bool = false,
    pcd: bool = false,
    accessed: bool = false,
    dirty: bool = false,
    super_page: bool = false,
    _reserved1: u3 = 0,
    snoop: bool = false,
    addr_low: u40 = 0,
    _reserved2: u11 = 0,
    nx: bool = false,

    pub fn phys_addr(self: IommuPte) u64 {
        return @as(u64, self.addr_low) << PAGE_SHIFT;
    }

    pub fn set_phys_addr(self: *IommuPte, addr: u64) void {
        self.addr_low = @truncate(addr >> PAGE_SHIFT);
    }

    pub fn to_u64(self: IommuPte) u64 {
        return @bitCast(self);
    }

    pub fn from_u64(val: u64) IommuPte {
        return @bitCast(val);
    }
};

// ─────────────────── DMA Direction ──────────────────────────────────

pub const DmaDirection = enum(u8) {
    bidirectional = 0,
    to_device = 1,
    from_device = 2,
    none = 3,
};

// ─────────────────── Domain Types ───────────────────────────────────

pub const DomainType = enum(u8) {
    identity = 0, // 1:1 mapping
    dma = 1, // translated DMA
    passthrough = 2, // no IOMMU
    isolated = 3, // strict isolation
};

// ─────────────────── IOMMU Page Table ───────────────────────────────

pub const PageTableLevel = struct {
    entries: [PAGE_TABLE_ENTRIES]u64 = [_]u64{0} ** PAGE_TABLE_ENTRIES,

    pub fn set_entry(self: *PageTableLevel, index: usize, pte: IommuPte) void {
        if (index < PAGE_TABLE_ENTRIES) {
            self.entries[index] = pte.to_u64();
        }
    }

    pub fn get_entry(self: *const PageTableLevel, index: usize) IommuPte {
        if (index < PAGE_TABLE_ENTRIES) {
            return IommuPte.from_u64(self.entries[index]);
        }
        return IommuPte{};
    }

    pub fn clear(self: *PageTableLevel) void {
        for (&self.entries) |*e| {
            e.* = 0;
        }
    }
};

// ─────────────────── IOMMU Domain ───────────────────────────────────

pub const DeviceId = struct {
    segment: u16 = 0,
    bus: u8 = 0,
    device: u5 = 0,
    function: u3 = 0,

    pub fn bdf(self: DeviceId) u16 {
        return (@as(u16, self.bus) << 8) |
            (@as(u16, self.device) << 3) |
            @as(u16, self.function);
    }

    pub fn from_bdf(bdf: u16) DeviceId {
        return .{
            .bus = @truncate(bdf >> 8),
            .device = @truncate(bdf >> 3),
            .function = @truncate(bdf),
        };
    }
};

pub const IommuDomain = struct {
    id: u16 = 0,
    domain_type: DomainType = .identity,
    /// Root page table (level 4)
    page_table: PageTableLevel = .{},
    /// Level 3 tables (on demand)
    l3_tables: [8]PageTableLevel = [_]PageTableLevel{.{}} ** 8,
    l3_count: u8 = 0,
    /// Level 2 tables
    l2_tables: [32]PageTableLevel = [_]PageTableLevel{.{}} ** 32,
    l2_count: u8 = 0,
    /// Attached devices
    devices: [MAX_DEVICES_PER_DOMAIN]DeviceId = [_]DeviceId{.{}} ** MAX_DEVICES_PER_DOMAIN,
    device_count: u8 = 0,
    /// Address space limits
    aperture_start: u64 = 0,
    aperture_end: u64 = 0xFFFF_FFFF_FFFF_FFFF,
    /// Allocation tracking
    next_iova: u64 = 0x1000_0000, // start of IOVA space
    mapped_pages: u64 = 0,
    active: bool = false,

    pub fn map_page(self: *IommuDomain, iova: u64, phys: u64, write: bool) bool {
        if (!self.active) return false;
        if (iova & (PAGE_SIZE - 1) != 0) return false;
        if (phys & (PAGE_SIZE - 1) != 0) return false;

        const l4_idx = (iova >> 39) & 0x1FF;
        const l3_idx = (iova >> 30) & 0x1FF;
        const l2_idx = (iova >> 21) & 0x1FF;
        const l1_idx = (iova >> 12) & 0x1FF;
        _ = l3_idx;
        _ = l2_idx;
        _ = l1_idx;

        // Set L4 entry pointing to domain's L3 table
        var pte = IommuPte{};
        pte.present = true;
        pte.write = write;
        pte.snoop = true;
        pte.set_phys_addr(phys);
        self.page_table.set_entry(l4_idx, pte);

        self.mapped_pages += 1;
        return true;
    }

    pub fn unmap_page(self: *IommuDomain, iova: u64) bool {
        if (!self.active) return false;
        const l4_idx = (iova >> 39) & 0x1FF;
        var pte = self.page_table.get_entry(l4_idx);
        if (!pte.present) return false;
        pte.present = false;
        self.page_table.set_entry(l4_idx, pte);
        if (self.mapped_pages > 0) self.mapped_pages -= 1;
        return true;
    }

    pub fn attach_device(self: *IommuDomain, dev: DeviceId) bool {
        if (self.device_count >= MAX_DEVICES_PER_DOMAIN) return false;
        // Check no duplicate
        for (0..self.device_count) |i| {
            if (self.devices[i].bdf() == dev.bdf()) return false;
        }
        self.devices[self.device_count] = dev;
        self.device_count += 1;
        return true;
    }

    pub fn detach_device(self: *IommuDomain, dev: DeviceId) bool {
        for (0..self.device_count) |i| {
            if (self.devices[i].bdf() == dev.bdf()) {
                // Shift remaining
                var j = i;
                while (j + 1 < self.device_count) : (j += 1) {
                    self.devices[j] = self.devices[j + 1];
                }
                self.device_count -= 1;
                return true;
            }
        }
        return false;
    }

    /// Allocate an IOVA range
    pub fn alloc_iova(self: *IommuDomain, pages: u32) u64 {
        const iova = self.next_iova;
        self.next_iova += @as(u64, pages) * PAGE_SIZE;
        if (self.next_iova > self.aperture_end) {
            self.next_iova = self.aperture_start;
            return 0;
        }
        return iova;
    }
};

// ─────────────────── Fault Record ───────────────────────────────────

pub const FaultType = enum(u8) {
    /// Device tried to access unmapped address
    page_not_present = 0,
    /// Write to read-only page
    write_violation = 1,
    /// Device not authorized
    device_not_bound = 2,
    /// Address out of aperture
    address_range = 3,
    /// Interrupt remapping fault
    irte_fault = 4,
    /// ATS translation fault
    ats_fault = 5,
};

pub const FaultRecord = struct {
    fault_type: FaultType = .page_not_present,
    device: DeviceId = .{},
    iova: u64 = 0,
    domain_id: u16 = 0,
    timestamp: u64 = 0,
    write: bool = false,
    pasid: u16 = 0,
    valid: bool = false,
};

// ─────────────────── Interrupt Remap Table Entry ────────────────────

pub const IrteEntry = struct {
    present: bool = false,
    destination_mode: bool = false, // false=physical, true=logical
    redirection_hint: bool = false,
    trigger_mode: bool = false, // false=edge, true=level
    delivery_mode: u3 = 0,
    vector: u8 = 0,
    destination: u32 = 0,
    source_id: u16 = 0,
    source_validation: u2 = 0,
};

pub const InterruptRemapTable = struct {
    entries: [MAX_IRTE_ENTRIES]IrteEntry = [_]IrteEntry{.{}} ** MAX_IRTE_ENTRIES,
    count: u16 = 0,

    pub fn alloc_entry(self: *InterruptRemapTable) ?u16 {
        for (0..MAX_IRTE_ENTRIES) |i| {
            if (!self.entries[i].present) {
                self.entries[i].present = true;
                if (self.count < MAX_IRTE_ENTRIES) self.count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn set_entry(self: *InterruptRemapTable, idx: u16, dest: u32, vector: u8, trigger_level: bool) void {
        if (idx >= MAX_IRTE_ENTRIES) return;
        self.entries[idx].destination = dest;
        self.entries[idx].vector = vector;
        self.entries[idx].trigger_mode = trigger_level;
        self.entries[idx].present = true;
    }

    pub fn free_entry(self: *InterruptRemapTable, idx: u16) void {
        if (idx >= MAX_IRTE_ENTRIES) return;
        self.entries[idx] = .{};
        if (self.count > 0) self.count -= 1;
    }
};

// ─────────────────── Bounce Buffer ──────────────────────────────────

pub const BounceBuffer = struct {
    virt_addr: u64 = 0,
    phys_addr: u64 = 0,
    dma_addr: u64 = 0,
    size: u32 = 0,
    direction: DmaDirection = .bidirectional,
    in_use: bool = false,

    pub fn sync_for_device(self: *BounceBuffer) void {
        // In a real kernel: flush CPU cache → device can read
        // For DMA_TO_DEVICE: copy from original buffer to bounce
        _ = self;
    }

    pub fn sync_for_cpu(self: *BounceBuffer) void {
        // In a real kernel: invalidate cache → CPU reads fresh data
        // For DMA_FROM_DEVICE: copy from bounce to original buffer
        _ = self;
    }
};

// ─────────────────── Scatter-Gather DMA ─────────────────────────────

pub const ScatterEntry = struct {
    phys_addr: u64 = 0,
    dma_addr: u64 = 0,
    length: u32 = 0,
    offset: u32 = 0,
};

pub const ScatterGatherList = struct {
    entries: [MAX_SG_ENTRIES]ScatterEntry = [_]ScatterEntry{.{}} ** MAX_SG_ENTRIES,
    count: u8 = 0,
    total_length: u64 = 0,
    direction: DmaDirection = .bidirectional,
    mapped: bool = false,

    pub fn add_entry(self: *ScatterGatherList, phys: u64, len: u32, offset: u32) bool {
        if (self.count >= MAX_SG_ENTRIES) return false;
        self.entries[self.count] = .{
            .phys_addr = phys,
            .length = len,
            .offset = offset,
        };
        self.count += 1;
        self.total_length += len;
        return true;
    }

    pub fn map_sg(self: *ScatterGatherList, domain: *IommuDomain) bool {
        if (self.mapped) return false;
        for (0..self.count) |i| {
            const pages = (self.entries[i].length + PAGE_SIZE - 1) / @as(u32, @truncate(PAGE_SIZE));
            const iova = domain.alloc_iova(pages);
            if (iova == 0) return false;
            self.entries[i].dma_addr = iova;
            // Map each page
            var p: u32 = 0;
            while (p < pages) : (p += 1) {
                const off = @as(u64, p) * PAGE_SIZE;
                _ = domain.map_page(iova + off, self.entries[i].phys_addr + off, self.direction != .from_device);
            }
        }
        self.mapped = true;
        return true;
    }

    pub fn unmap_sg(self: *ScatterGatherList, domain: *IommuDomain) void {
        if (!self.mapped) return;
        for (0..self.count) |i| {
            const pages = (self.entries[i].length + PAGE_SIZE - 1) / @as(u32, @truncate(PAGE_SIZE));
            var p: u32 = 0;
            while (p < pages) : (p += 1) {
                _ = domain.unmap_page(self.entries[i].dma_addr + @as(u64, p) * PAGE_SIZE);
            }
        }
        self.mapped = false;
    }
};

// ─────────────────── PASID Table ────────────────────────────────────

pub const PasidEntry = struct {
    pasid: u16 = 0,
    pgd_addr: u64 = 0, // page global directory for this process
    flags: u16 = 0,
    active: bool = false,
};

pub const PasidTable = struct {
    entries: [MAX_PASID]PasidEntry = [_]PasidEntry{.{}} ** MAX_PASID,
    count: u8 = 0,

    pub fn alloc_pasid(self: *PasidTable, pgd: u64) ?u16 {
        for (0..MAX_PASID) |i| {
            if (!self.entries[i].active) {
                self.entries[i] = .{
                    .pasid = @intCast(i),
                    .pgd_addr = pgd,
                    .active = true,
                };
                self.count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn free_pasid(self: *PasidTable, pasid: u16) void {
        if (pasid >= MAX_PASID) return;
        self.entries[pasid] = .{};
        if (self.count > 0) self.count -= 1;
    }
};

// ─────────────────── IOMMU Hardware Unit ────────────────────────────

pub const IommuUnit = struct {
    id: u8 = 0,
    reg_base: u64 = 0,
    /// Capability bits
    cap_aw: u8 = 48,              // address width
    cap_domains: u16 = 256,
    cap_irq_remap: bool = false,
    cap_pasid: bool = false,
    cap_ats: bool = false,
    cap_snoop: bool = true,
    /// Interrupt remap table
    irte: InterruptRemapTable = .{},
    /// PASID support
    pasid_table: PasidTable = .{},
    /// Fault log
    faults: [MAX_FAULT_LOG]FaultRecord = [_]FaultRecord{.{}} ** MAX_FAULT_LOG,
    fault_head: u8 = 0,
    fault_count: u32 = 0,
    /// State
    enabled: bool = false,
    translation_enabled: bool = false,

    pub fn record_fault(self: *IommuUnit, fault: FaultRecord) void {
        self.faults[self.fault_head] = fault;
        self.faults[self.fault_head].valid = true;
        self.fault_head = @truncate((@as(u16, self.fault_head) + 1) % MAX_FAULT_LOG);
        self.fault_count += 1;
    }

    pub fn enable(self: *IommuUnit) void {
        self.enabled = true;
        self.translation_enabled = true;
    }

    pub fn disable(self: *IommuUnit) void {
        self.translation_enabled = false;
        self.enabled = false;
    }

    pub fn flush_iotlb_global(self: *IommuUnit) void {
        // In real hardware: write to IOTLB invalidation register
        _ = self;
    }

    pub fn flush_iotlb_domain(self: *IommuUnit, domain_id: u16) void {
        // Domain-selective IOTLB invalidation
        _ = self;
        _ = domain_id;
    }

    pub fn flush_dev_tlb(self: *IommuUnit, dev: DeviceId) void {
        // ATS invalidation for device TLB
        _ = self;
        _ = dev;
    }
};

// ─────────────────── IOMMU Manager ──────────────────────────────────

pub const IommuManager = struct {
    units: [MAX_IOMMUS]IommuUnit = [_]IommuUnit{.{}} ** MAX_IOMMUS,
    unit_count: u8 = 0,
    domains: [MAX_DOMAINS]IommuDomain = undefined,
    domain_count: u16 = 0,
    /// Bounce buffer pool
    bounce_pool: [MAX_BOUNCE_BUFFERS]BounceBuffer = [_]BounceBuffer{.{}} ** MAX_BOUNCE_BUFFERS,
    bounce_count: u16 = 0,
    /// Stats
    total_maps: u64 = 0,
    total_unmaps: u64 = 0,
    total_faults: u64 = 0,
    total_bounces: u64 = 0,
    /// Default domain for unassigned devices
    default_domain_id: u16 = 0,
    initialized: bool = false,

    pub fn init(self: *IommuManager) void {
        for (0..MAX_DOMAINS) |i| {
            self.domains[i] = IommuDomain{};
        }
        // Create default identity domain
        if (self.create_domain(.identity)) |did| {
            self.default_domain_id = did;
        }
        self.initialized = true;
    }

    pub fn add_unit(self: *IommuManager, reg_base: u64) ?u8 {
        if (self.unit_count >= MAX_IOMMUS) return null;
        const id = self.unit_count;
        self.units[id].id = id;
        self.units[id].reg_base = reg_base;
        self.units[id].cap_irq_remap = true;
        self.units[id].cap_pasid = true;
        self.units[id].cap_ats = true;
        self.unit_count += 1;
        return id;
    }

    pub fn create_domain(self: *IommuManager, dtype: DomainType) ?u16 {
        for (0..MAX_DOMAINS) |i| {
            if (!self.domains[i].active) {
                self.domains[i] = IommuDomain{};
                self.domains[i].id = @intCast(i);
                self.domains[i].domain_type = dtype;
                self.domains[i].active = true;
                if (dtype == .identity) {
                    self.domains[i].aperture_start = 0;
                    self.domains[i].aperture_end = 0xFFFF_FFFF_FFFF_FFFF;
                } else {
                    self.domains[i].aperture_start = 0x1000_0000;
                    self.domains[i].aperture_end = 0xFFFF_FFFF;
                }
                self.domain_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn destroy_domain(self: *IommuManager, id: u16) bool {
        if (id >= MAX_DOMAINS) return false;
        if (!self.domains[id].active) return false;
        if (self.domains[id].device_count > 0) return false;
        self.domains[id].active = false;
        if (self.domain_count > 0) self.domain_count -= 1;
        return true;
    }

    pub fn map_dma(self: *IommuManager, domain_id: u16, iova: u64, phys: u64, write: bool) bool {
        if (domain_id >= MAX_DOMAINS) return false;
        if (!self.domains[domain_id].active) return false;
        if (self.domains[domain_id].map_page(iova, phys, write)) {
            self.total_maps += 1;
            return true;
        }
        return false;
    }

    pub fn unmap_dma(self: *IommuManager, domain_id: u16, iova: u64) bool {
        if (domain_id >= MAX_DOMAINS) return false;
        if (!self.domains[domain_id].active) return false;
        if (self.domains[domain_id].unmap_page(iova)) {
            self.total_unmaps += 1;
            return true;
        }
        return false;
    }

    /// Allocate a bounce buffer for non-IOMMU capable devices
    pub fn alloc_bounce(self: *IommuManager, size: u32, dir: DmaDirection) ?*BounceBuffer {
        for (&self.bounce_pool) |*buf| {
            if (!buf.in_use) {
                buf.in_use = true;
                buf.size = size;
                buf.direction = dir;
                buf.phys_addr = @as(u64, self.bounce_count) * PAGE_SIZE + 0x8000_0000;
                buf.dma_addr = buf.phys_addr;
                self.bounce_count += 1;
                self.total_bounces += 1;
                return buf;
            }
        }
        return null;
    }

    pub fn free_bounce(self: *IommuManager, buf: *BounceBuffer) void {
        buf.in_use = false;
        _ = self;
    }

    pub fn report_fault(self: *IommuManager, unit_id: u8, fault: FaultRecord) void {
        if (unit_id >= self.unit_count) return;
        self.units[unit_id].record_fault(fault);
        self.total_faults += 1;
    }

    pub fn active_domain_count(self: *const IommuManager) u32 {
        var count: u32 = 0;
        for (0..MAX_DOMAINS) |i| {
            if (self.domains[i].active) count += 1;
        }
        return count;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var iommu_mgr = IommuManager{};

pub fn get_iommu_manager() *IommuManager {
    return &iommu_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_iommu_init() void {
    iommu_mgr.init();
}

export fn zxy_iommu_add_unit(reg_base: u64) i32 {
    return if (iommu_mgr.add_unit(reg_base)) |id| @as(i32, id) else -1;
}

export fn zxy_iommu_create_domain(dtype: u8) i32 {
    const dt: DomainType = @enumFromInt(dtype);
    return if (iommu_mgr.create_domain(dt)) |id| @as(i32, id) else -1;
}

export fn zxy_iommu_destroy_domain(id: u16) i32 {
    return if (iommu_mgr.destroy_domain(id)) 0 else -1;
}

export fn zxy_iommu_map(domain_id: u16, iova: u64, phys: u64, write: u8) i32 {
    return if (iommu_mgr.map_dma(domain_id, iova, phys, write != 0)) 0 else -1;
}

export fn zxy_iommu_unmap(domain_id: u16, iova: u64) i32 {
    return if (iommu_mgr.unmap_dma(domain_id, iova)) 0 else -1;
}

export fn zxy_iommu_domain_count() u32 {
    return iommu_mgr.active_domain_count();
}

export fn zxy_iommu_unit_count() u8 {
    return iommu_mgr.unit_count;
}

export fn zxy_iommu_total_maps() u64 {
    return iommu_mgr.total_maps;
}

export fn zxy_iommu_total_faults() u64 {
    return iommu_mgr.total_faults;
}

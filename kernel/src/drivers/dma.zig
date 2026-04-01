// =============================================================================
// Kernel Zxyphor — DMA Engine
// =============================================================================
// Direct Memory Access controller and buffer management:
//   - DMA buffer allocation (physically contiguous, cache-coherent)
//   - Scatter-gather list (SGL) support
//   - DMA mapping (virtual → physical) with IOMMU awareness
//   - Channel-based DMA engine (memcpy, mem-fill, XOR, etc.)
//   - Bounce buffer for non-DMA-capable memory
//   - DMA pool (fixed-size allocations from DMA region)
//   - Streaming vs coherent DMA mappings
//   - DMA fence/barrier synchronization
//   - Address mask enforcement (24-bit ISA, 32-bit PCI, 64-bit PCIe)
// =============================================================================

// =============================================================================
// Constants
// =============================================================================

pub const DMA_ZONE_LOW: u64 = 0x00_0000;       // ISA DMA (0-16MB)
pub const DMA_ZONE_HIGH: u64 = 0x01_000000;    // 16MB boundary
pub const DMA_ZONE_32BIT: u64 = 0x01_00000000; // 4GB boundary

pub const DMA_POOL_SIZE: usize = 4 * 1024 * 1024; // 4MB DMA pool
pub const DMA_PAGE_SIZE: usize = 4096;
pub const MAX_DMA_CHANNELS: usize = 16;
pub const MAX_SG_ENTRIES: usize = 64;
pub const MAX_DMA_MAPPINGS: usize = 256;
pub const MAX_BOUNCE_BUFFERS: usize = 32;
pub const MAX_DMA_POOLS: usize = 8;
pub const POOL_MAX_BLOCKS: usize = 256;

// =============================================================================
// DMA direction
// =============================================================================

pub const DmaDirection = enum(u8) {
    to_device = 0,      // Memory → Device (write)
    from_device = 1,    // Device → Memory (read)
    bidirectional = 2,  // Both directions
    none = 3,           // No DMA transfer
};

// =============================================================================
// DMA address mask
// =============================================================================

pub const DmaMask = enum(u8) {
    isa_24bit = 0,      // 0x00FFFFFF
    pci_32bit = 1,      // 0xFFFFFFFF
    pcie_64bit = 2,     // Full 64-bit
};

fn maskValue(mask: DmaMask) u64 {
    return switch (mask) {
        .isa_24bit => 0x00FFFFFF,
        .pci_32bit => 0xFFFFFFFF,
        .pcie_64bit => 0xFFFFFFFFFFFFFFFF,
    };
}

// =============================================================================
// Scatter-gather entry
// =============================================================================

pub const ScatterGatherEntry = struct {
    phys_addr: u64,
    length: u32,
    dma_addr: u64,     // IOMMU-mapped address (or same as phys_addr)
    offset: u32,       // Offset within page
};

pub const ScatterGatherList = struct {
    entries: [MAX_SG_ENTRIES]ScatterGatherEntry,
    count: u32,
    total_length: u64,

    pub fn init() ScatterGatherList {
        var sgl: ScatterGatherList = undefined;
        sgl.count = 0;
        sgl.total_length = 0;
        for (0..MAX_SG_ENTRIES) |i| {
            sgl.entries[i] = .{
                .phys_addr = 0,
                .length = 0,
                .dma_addr = 0,
                .offset = 0,
            };
        }
        return sgl;
    }

    pub fn addEntry(self: *ScatterGatherList, phys: u64, length: u32, offset: u32) bool {
        if (self.count >= MAX_SG_ENTRIES) return false;
        const idx = self.count;
        self.entries[idx] = .{
            .phys_addr = phys,
            .length = length,
            .dma_addr = phys, // Direct mapping (no IOMMU)
            .offset = offset,
        };
        self.count += 1;
        self.total_length += length;
        return true;
    }

    /// Try to merge with last entry if contiguous
    pub fn tryMerge(self: *ScatterGatherList, phys: u64, length: u32) bool {
        if (self.count == 0) return false;
        const last = &self.entries[self.count - 1];
        if (last.phys_addr + last.length == phys) {
            self.entries[self.count - 1].length += length;
            self.total_length += length;
            return true;
        }
        return false;
    }
};

// =============================================================================
// DMA mapping
// =============================================================================

pub const DmaMappingType = enum(u8) {
    coherent = 0,      // Always cache-coherent (slower but simpler)
    streaming = 1,     // Requires explicit sync (faster)
    bounce = 2,        // Using bounce buffer
};

pub const DmaMapping = struct {
    virt_addr: u64,
    phys_addr: u64,
    dma_addr: u64,
    size: u64,
    direction: DmaDirection,
    mapping_type: DmaMappingType,
    active: bool,
    needs_sync: bool,
    bounce_idx: u32,   // Index into bounce buffer array (if type == bounce)
};

// =============================================================================
// Bounce buffer (for devices that can't DMA to high memory)
// =============================================================================

pub const BounceBuffer = struct {
    low_phys: u64,       // Physical address in low memory (< 4GB)
    low_virt: u64,       // Virtual mapping of low buffer
    high_virt: u64,      // Original high-memory virtual address
    size: u64,
    direction: DmaDirection,
    in_use: bool,

    pub fn syncToDevice(self: *BounceBuffer) void {
        if (self.direction == .to_device or self.direction == .bidirectional) {
            // Copy from high memory to bounce buffer
            const src: [*]const u8 = @ptrFromInt(self.high_virt);
            const dst: [*]u8 = @ptrFromInt(self.low_virt);
            @memcpy(dst[0..@intCast(self.size)], src[0..@intCast(self.size)]);
        }
    }

    pub fn syncFromDevice(self: *BounceBuffer) void {
        if (self.direction == .from_device or self.direction == .bidirectional) {
            // Copy from bounce buffer to high memory
            const src: [*]const u8 = @ptrFromInt(self.low_virt);
            const dst: [*]u8 = @ptrFromInt(self.high_virt);
            @memcpy(dst[0..@intCast(self.size)], src[0..@intCast(self.size)]);
        }
    }
};

// =============================================================================
// DMA pool (fixed-size allocated from DMA region)
// =============================================================================

pub const DmaPool = struct {
    name: [16]u8,
    name_len: usize,
    block_size: u32,
    alignment: u32,
    base_phys: u64,
    base_virt: u64,
    total_blocks: u32,
    bitmap: [POOL_MAX_BLOCKS / 8]u8,  // 1 bit per block
    allocated: u32,
    active: bool,

    pub fn init(name: []const u8, block_size: u32, align: u32, base_p: u64, base_v: u64, count: u32) DmaPool {
        var pool: DmaPool = undefined;
        const nlen = @min(name.len, 16);
        @memcpy(pool.name[0..nlen], name[0..nlen]);
        pool.name_len = nlen;
        pool.block_size = block_size;
        pool.alignment = align;
        pool.base_phys = base_p;
        pool.base_virt = base_v;
        pool.total_blocks = @min(count, POOL_MAX_BLOCKS);
        @memset(&pool.bitmap, 0);
        pool.allocated = 0;
        pool.active = true;
        return pool;
    }

    pub fn allocBlock(self: *DmaPool) ?struct { virt: u64, phys: u64 } {
        for (0..self.total_blocks) |i| {
            const byte_idx = i / 8;
            const bit_idx: u3 = @intCast(i % 8);
            if (self.bitmap[byte_idx] & (@as(u8, 1) << bit_idx) == 0) {
                self.bitmap[byte_idx] |= @as(u8, 1) << bit_idx;
                self.allocated += 1;
                const offset = @as(u64, @intCast(i)) * self.block_size;
                return .{
                    .virt = self.base_virt + offset,
                    .phys = self.base_phys + offset,
                };
            }
        }
        return null;
    }

    pub fn freeBlock(self: *DmaPool, virt: u64) void {
        if (virt < self.base_virt) return;
        const offset = virt - self.base_virt;
        const idx = offset / self.block_size;
        if (idx >= self.total_blocks) return;
        const byte_idx = @as(usize, @intCast(idx / 8));
        const bit_idx: u3 = @intCast(idx % 8);
        self.bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        self.allocated -= 1;
    }

    pub fn usagePct(self: *const DmaPool) u32 {
        if (self.total_blocks == 0) return 0;
        return (self.allocated * 100) / self.total_blocks;
    }
};

// =============================================================================
// DMA channel (for DMA engine copy operations)
// =============================================================================

pub const DmaOpType = enum(u8) {
    memcpy = 0,
    memset = 1,
    xor = 2,
    interrupt = 3,
};

pub const DmaDescriptor = struct {
    src_phys: u64,
    dst_phys: u64,
    length: u32,
    op: DmaOpType,
    fill_value: u8,
    completed: bool,
    error: bool,
};

pub const DmaChannel = struct {
    id: u8,
    active: bool,
    busy: bool,
    descriptors: [32]DmaDescriptor,
    desc_count: u32,
    desc_head: u32,         // Next to submit
    desc_tail: u32,         // Next to complete
    completed_count: u64,
    error_count: u64,
    bytes_transferred: u64,

    // MMIO base for hardware DMA (platform-specific)
    mmio_base: u64,

    pub fn init(id: u8) DmaChannel {
        var ch: DmaChannel = undefined;
        ch.id = id;
        ch.active = true;
        ch.busy = false;
        ch.desc_count = 0;
        ch.desc_head = 0;
        ch.desc_tail = 0;
        ch.completed_count = 0;
        ch.error_count = 0;
        ch.bytes_transferred = 0;
        ch.mmio_base = 0;
        for (0..32) |i| {
            ch.descriptors[i] = .{
                .src_phys = 0,
                .dst_phys = 0,
                .length = 0,
                .op = .memcpy,
                .fill_value = 0,
                .completed = false,
                .error = false,
            };
        }
        return ch;
    }

    /// Submit a memcpy DMA operation
    pub fn submitMemcpy(self: *DmaChannel, src: u64, dst: u64, len: u32) bool {
        if (self.desc_count >= 32) return false;
        const idx = self.desc_head;
        self.descriptors[idx] = .{
            .src_phys = src,
            .dst_phys = dst,
            .length = len,
            .op = .memcpy,
            .fill_value = 0,
            .completed = false,
            .error = false,
        };
        self.desc_head = (self.desc_head + 1) % 32;
        self.desc_count += 1;
        self.busy = true;
        return true;
    }

    /// Submit a memset DMA operation
    pub fn submitMemset(self: *DmaChannel, dst: u64, value: u8, len: u32) bool {
        if (self.desc_count >= 32) return false;
        const idx = self.desc_head;
        self.descriptors[idx] = .{
            .src_phys = 0,
            .dst_phys = dst,
            .length = len,
            .op = .memset,
            .fill_value = value,
            .completed = false,
            .error = false,
        };
        self.desc_head = (self.desc_head + 1) % 32;
        self.desc_count += 1;
        self.busy = true;
        return true;
    }

    /// Process completed descriptors (called from interrupt or poll)
    pub fn processCompletions(self: *DmaChannel) u32 {
        var completed: u32 = 0;
        while (self.desc_count > 0) {
            const idx = self.desc_tail;
            if (!self.descriptors[idx].completed) break;

            if (self.descriptors[idx].error) {
                self.error_count += 1;
            } else {
                self.bytes_transferred += self.descriptors[idx].length;
            }
            self.completed_count += 1;
            self.desc_tail = (self.desc_tail + 1) % 32;
            self.desc_count -= 1;
            completed += 1;
        }
        if (self.desc_count == 0) self.busy = false;
        return completed;
    }

    /// Software fallback: execute memcpy in CPU
    pub fn executeSoftware(self: *DmaChannel) void {
        while (self.desc_count > 0) {
            const idx = self.desc_tail;
            const desc = &self.descriptors[idx];

            switch (desc.op) {
                .memcpy => {
                    const src: [*]const u8 = @ptrFromInt(desc.src_phys);
                    const dst: [*]u8 = @ptrFromInt(desc.dst_phys);
                    @memcpy(dst[0..desc.length], src[0..desc.length]);
                },
                .memset => {
                    const dst: [*]u8 = @ptrFromInt(desc.dst_phys);
                    @memset(dst[0..desc.length], desc.fill_value);
                },
                .xor => {
                    // XOR operation (simplified)
                    const src: [*]const u8 = @ptrFromInt(desc.src_phys);
                    const dst: [*]u8 = @ptrFromInt(desc.dst_phys);
                    for (0..desc.length) |i| {
                        dst[i] ^= src[i];
                    }
                },
                .interrupt => {},
            }

            self.descriptors[idx].completed = true;
            self.bytes_transferred += desc.length;
            self.completed_count += 1;
            self.desc_tail = (self.desc_tail + 1) % 32;
            self.desc_count -= 1;
        }
        self.busy = false;
    }
};

// =============================================================================
// DMA engine (global manager)
// =============================================================================

pub const DmaEngine = struct {
    channels: [MAX_DMA_CHANNELS]DmaChannel,
    channel_count: u32,

    mappings: [MAX_DMA_MAPPINGS]DmaMapping,
    mapping_count: u32,

    bounce_buffers: [MAX_BOUNCE_BUFFERS]BounceBuffer,
    bounce_count: u32,

    pools: [MAX_DMA_POOLS]DmaPool,
    pool_count: u32,

    // DMA region
    dma_region_phys: u64,
    dma_region_virt: u64,
    dma_region_size: u64,
    dma_region_used: u64,

    // Global DMA mask
    device_mask: DmaMask,

    // Stats
    total_maps: u64,
    total_unmaps: u64,
    total_bounces: u64,
    total_sg_maps: u64,

    pub fn init(region_phys: u64, region_virt: u64, region_size: u64) DmaEngine {
        var engine: DmaEngine = undefined;
        engine.channel_count = 0;
        engine.mapping_count = 0;
        engine.bounce_count = 0;
        engine.pool_count = 0;
        engine.dma_region_phys = region_phys;
        engine.dma_region_virt = region_virt;
        engine.dma_region_size = region_size;
        engine.dma_region_used = 0;
        engine.device_mask = .pcie_64bit;
        engine.total_maps = 0;
        engine.total_unmaps = 0;
        engine.total_bounces = 0;
        engine.total_sg_maps = 0;

        // Initialize channels
        for (0..MAX_DMA_CHANNELS) |i| {
            engine.channels[i] = DmaChannel.init(@intCast(i));
            engine.channels[i].active = false;
        }
        for (0..MAX_DMA_MAPPINGS) |i| {
            engine.mappings[i].active = false;
        }
        for (0..MAX_BOUNCE_BUFFERS) |i| {
            engine.bounce_buffers[i].in_use = false;
        }
        for (0..MAX_DMA_POOLS) |i| {
            engine.pools[i].active = false;
        }
        return engine;
    }

    /// Allocate a DMA channel
    pub fn allocChannel(self: *DmaEngine) ?u8 {
        for (0..MAX_DMA_CHANNELS) |i| {
            if (!self.channels[i].active) {
                self.channels[i] = DmaChannel.init(@intCast(i));
                self.channel_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Free a DMA channel
    pub fn freeChannel(self: *DmaEngine, id: u8) void {
        if (id >= MAX_DMA_CHANNELS) return;
        self.channels[id].active = false;
        self.channel_count -= 1;
    }

    /// Allocate DMA-capable memory from the region
    fn allocFromRegion(self: *DmaEngine, size: u64, alignment: u64) ?struct { phys: u64, virt: u64 } {
        const aligned = (self.dma_region_used + alignment - 1) & ~(alignment - 1);
        if (aligned + size > self.dma_region_size) return null;
        const phys = self.dma_region_phys + aligned;
        const virt = self.dma_region_virt + aligned;
        self.dma_region_used = aligned + size;
        return .{ .phys = phys, .virt = virt };
    }

    /// Map a buffer for DMA (streaming)
    pub fn mapSingle(self: *DmaEngine, virt: u64, phys: u64, size: u64, dir: DmaDirection) ?u64 {
        // Check if address is within device DMA mask
        const mask = maskValue(self.device_mask);
        var dma_addr = phys;
        var map_type: DmaMappingType = .streaming;

        if (phys > mask) {
            // Need bounce buffer
            const bounce = self.allocBounce(virt, size, dir) orelse return null;
            dma_addr = bounce;
            map_type = .bounce;
            self.total_bounces += 1;
        }

        // Record mapping
        for (0..MAX_DMA_MAPPINGS) |i| {
            if (!self.mappings[i].active) {
                self.mappings[i] = .{
                    .virt_addr = virt,
                    .phys_addr = phys,
                    .dma_addr = dma_addr,
                    .size = size,
                    .direction = dir,
                    .mapping_type = map_type,
                    .active = true,
                    .needs_sync = true,
                    .bounce_idx = 0,
                };
                self.mapping_count += 1;
                self.total_maps += 1;
                return dma_addr;
            }
        }
        return null;
    }

    /// Unmap a DMA buffer
    pub fn unmapSingle(self: *DmaEngine, dma_addr: u64) void {
        for (0..MAX_DMA_MAPPINGS) |i| {
            if (self.mappings[i].active and self.mappings[i].dma_addr == dma_addr) {
                // If bounce, sync back and free
                if (self.mappings[i].mapping_type == .bounce) {
                    self.freeBounce(self.mappings[i].bounce_idx);
                }
                self.mappings[i].active = false;
                self.mapping_count -= 1;
                self.total_unmaps += 1;
                return;
            }
        }
    }

    /// Map scatter-gather list for DMA
    pub fn mapSg(self: *DmaEngine, sgl: *ScatterGatherList, dir: DmaDirection) bool {
        const mask = maskValue(self.device_mask);
        for (0..sgl.count) |i| {
            const entry = &sgl.entries[i];
            if (entry.phys_addr > mask) {
                // Would need per-entry bounce buffers — simplified here
                return false;
            }
            sgl.entries[i].dma_addr = entry.phys_addr;
        }
        self.total_sg_maps += 1;
        return true;
    }

    /// Create a DMA pool
    pub fn createPool(self: *DmaEngine, name: []const u8, block_size: u32, count: u32) ?usize {
        if (self.pool_count >= MAX_DMA_POOLS) return null;
        const total = @as(u64, block_size) * count;
        const alloc = self.allocFromRegion(total, block_size) orelse return null;

        for (0..MAX_DMA_POOLS) |i| {
            if (!self.pools[i].active) {
                self.pools[i] = DmaPool.init(name, block_size, block_size, alloc.phys, alloc.virt, count);
                self.pool_count += 1;
                return i;
            }
        }
        return null;
    }

    fn allocBounce(self: *DmaEngine, high_virt: u64, size: u64, dir: DmaDirection) ?u64 {
        // Allocate low memory bounce buffer
        const alloc = self.allocFromRegion(size, DMA_PAGE_SIZE) orelse return null;

        for (0..MAX_BOUNCE_BUFFERS) |i| {
            if (!self.bounce_buffers[i].in_use) {
                self.bounce_buffers[i] = .{
                    .low_phys = alloc.phys,
                    .low_virt = alloc.virt,
                    .high_virt = high_virt,
                    .size = size,
                    .direction = dir,
                    .in_use = true,
                };
                // Pre-sync for to_device
                self.bounce_buffers[i].syncToDevice();
                return alloc.phys;
            }
        }
        return null;
    }

    fn freeBounce(self: *DmaEngine, idx: u32) void {
        if (idx >= MAX_BOUNCE_BUFFERS) return;
        if (self.bounce_buffers[idx].in_use) {
            // Post-sync for from_device
            self.bounce_buffers[idx].syncFromDevice();
            self.bounce_buffers[idx].in_use = false;
            self.bounce_count -= 1;
        }
    }
};

// =============================================================================
// Global instance
// =============================================================================

var dma_engine: ?DmaEngine = null;

pub fn initDmaEngine(phys: u64, virt: u64, size: u64) void {
    dma_engine = DmaEngine.init(phys, virt, size);
}

pub fn getDmaEngine() ?*DmaEngine {
    if (dma_engine) |*engine| {
        return engine;
    }
    return null;
}

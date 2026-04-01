// SPDX-License-Identifier: MIT
// Zxyphor Kernel — DMA Engine / Transfer Controller (Zig)
//
// Advanced DMA transfer engine with:
// - Multiple DMA channels with independent transfer queues
// - Scatter-gather DMA using descriptor chains
// - Memory-to-memory, device-to-memory, memory-to-device transfers
// - Cyclic DMA (ring buffer) for audio/network streaming
// - Linked list DMA descriptors for chained transfers
// - DMA channel allocation and priority
// - Transfer completion callbacks
// - DMA coherent/streaming mapping
// - DMA fence/sync for GPU operations
// - Bus mastering control

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CHANNELS: usize = 16;
const MAX_DESCRIPTORS: usize = 256;
const MAX_PENDING: usize = 64;
const MAX_SG_ENTRIES: usize = 32;
const MAX_FENCES: usize = 64;
const MAX_ENGINES: usize = 4;

// ─────────────────── Transfer Direction ─────────────────────────────

pub const DmaDirection = enum(u8) {
    mem_to_mem = 0,
    mem_to_dev = 1,
    dev_to_mem = 2,
    dev_to_dev = 3,
};

// ─────────────────── Transfer Type ──────────────────────────────────

pub const DmaTransferType = enum(u8) {
    single = 0,         // Single contiguous transfer
    scatter_gather = 1, // Scatter-gather list
    cyclic = 2,         // Ring buffer (continuous)
    linked = 3,         // Linked descriptor chain
    interleaved = 4,    // Interleaved/strided
};

// ─────────────────── Transfer Width ─────────────────────────────────

pub const DmaBusWidth = enum(u8) {
    width_8 = 0,
    width_16 = 1,
    width_32 = 2,
    width_64 = 3,
    width_128 = 4,
    width_256 = 5,

    pub fn bytes(self: DmaBusWidth) u32 {
        return @as(u32, 1) << @intFromEnum(self);
    }
};

// ─────────────────── Burst Size ─────────────────────────────────────

pub const DmaBurstSize = enum(u8) {
    burst_1 = 0,
    burst_4 = 1,
    burst_8 = 2,
    burst_16 = 3,
    burst_32 = 4,
    burst_64 = 5,
    burst_128 = 6,
    burst_256 = 7,

    pub fn count(self: DmaBurstSize) u32 {
        return switch (self) {
            .burst_1 => 1,
            .burst_4 => 4,
            .burst_8 => 8,
            .burst_16 => 16,
            .burst_32 => 32,
            .burst_64 => 64,
            .burst_128 => 128,
            .burst_256 => 256,
        };
    }
};

// ─────────────────── Channel Priority ───────────────────────────────

pub const DmaPriority = enum(u8) {
    low = 0,
    medium = 1,
    high = 2,
    very_high = 3,
};

// ─────────────────── Descriptor Status ──────────────────────────────

pub const DescStatus = enum(u8) {
    free = 0,
    prepared = 1,
    submitted = 2,
    in_progress = 3,
    completed = 4,
    error = 5,
    aborted = 6,
};

// ─────────────────── DMA Descriptor ─────────────────────────────────

pub const DmaDescriptor = struct {
    /// Source physical address
    src_addr: u64 = 0,
    /// Destination physical address
    dst_addr: u64 = 0,
    /// Transfer length in bytes
    length: u32 = 0,
    /// Next descriptor in chain (linked list DMA)
    next_desc: u16 = 0xFFFF,
    /// Status
    status: DescStatus = .free,
    /// Direction
    direction: DmaDirection = .mem_to_mem,
    /// Transfer type
    transfer_type: DmaTransferType = .single,
    /// Bus width
    src_width: DmaBusWidth = .width_32,
    dst_width: DmaBusWidth = .width_32,
    /// Burst
    src_burst: DmaBurstSize = .burst_4,
    dst_burst: DmaBurstSize = .burst_4,
    /// Flags
    interrupt_on_complete: bool = true,
    src_increment: bool = true,
    dst_increment: bool = true,
    /// ID
    id: u16 = 0,
    /// Cookie from submission
    cookie: u32 = 0,
    /// Bytes transferred so far
    bytes_transferred: u32 = 0,

    /// Calculate optimal number of transfers
    pub fn transfer_count(self: *const DmaDescriptor) u32 {
        const width = @min(self.src_width.bytes(), self.dst_width.bytes());
        if (width == 0) return 0;
        return (self.length + width - 1) / width;
    }
};

// ─────────────────── Scatter-Gather Entry ───────────────────────────

pub const SgEntry = struct {
    phys_addr: u64 = 0,
    length: u32 = 0,
    offset: u32 = 0,
};

pub const SgTable = struct {
    entries: [MAX_SG_ENTRIES]SgEntry = [_]SgEntry{.{}} ** MAX_SG_ENTRIES,
    count: u8 = 0,
    total_length: u32 = 0,

    pub fn add(self: *SgTable, addr: u64, len: u32) bool {
        if (self.count >= MAX_SG_ENTRIES) return false;
        self.entries[self.count] = .{ .phys_addr = addr, .length = len, .offset = 0 };
        self.total_length += len;
        self.count += 1;
        return true;
    }
};

// ─────────────────── DMA Channel ────────────────────────────────────

pub const DmaChannel = struct {
    /// Channel ID
    id: u8 = 0,
    /// Name
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    /// Engine this channel belongs to
    engine_id: u8 = 0,
    /// Priority
    priority: DmaPriority = .medium,
    /// Current descriptor being processed
    current_desc: u16 = 0xFFFF,
    /// Pending descriptor queue (FIFO)
    pending: [MAX_PENDING]u16 = [_]u16{0xFFFF} ** MAX_PENDING,
    pending_head: u8 = 0,
    pending_tail: u8 = 0,
    pending_count: u8 = 0,
    /// Device FIFO address (for dev-to-mem / mem-to-dev)
    dev_addr: u64 = 0,
    /// Configuration
    src_width: DmaBusWidth = .width_32,
    dst_width: DmaBusWidth = .width_32,
    src_burst: DmaBurstSize = .burst_4,
    dst_burst: DmaBurstSize = .burst_4,
    /// State
    busy: bool = false,
    paused: bool = false,
    allocated: bool = false,
    active: bool = false,
    /// Cookie counter
    next_cookie: u32 = 1,
    completed_cookie: u32 = 0,
    /// Stats
    transfers_completed: u64 = 0,
    bytes_transferred: u64 = 0,
    errors: u32 = 0,

    pub fn set_name(self: *DmaChannel, n: []const u8) void {
        const len = @min(n.len, 15);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @truncate(len);
    }

    pub fn enqueue(self: *DmaChannel, desc_id: u16) bool {
        if (self.pending_count >= MAX_PENDING) return false;
        self.pending[self.pending_tail] = desc_id;
        self.pending_tail = @truncate((@as(u16, self.pending_tail) + 1) % MAX_PENDING);
        self.pending_count += 1;
        return true;
    }

    pub fn dequeue(self: *DmaChannel) ?u16 {
        if (self.pending_count == 0) return null;
        const desc_id = self.pending[self.pending_head];
        self.pending_head = @truncate((@as(u16, self.pending_head) + 1) % MAX_PENDING);
        self.pending_count -= 1;
        return desc_id;
    }

    pub fn configure(self: *DmaChannel, dev_addr: u64, src_w: DmaBusWidth, dst_w: DmaBusWidth, src_b: DmaBurstSize, dst_b: DmaBurstSize) void {
        self.dev_addr = dev_addr;
        self.src_width = src_w;
        self.dst_width = dst_w;
        self.src_burst = src_b;
        self.dst_burst = dst_b;
    }

    pub fn pause(self: *DmaChannel) void {
        if (self.busy) self.paused = true;
    }

    pub fn resume_channel(self: *DmaChannel) void {
        self.paused = false;
    }
};

// ─────────────────── DMA Fence ──────────────────────────────────────

pub const FenceState = enum(u8) {
    unsignaled = 0,
    signaled = 1,
    error_state = 2,
};

pub const DmaFence = struct {
    context: u64 = 0,
    seqno: u64 = 0,
    state: FenceState = .unsignaled,
    channel_id: u8 = 0,
    desc_cookie: u32 = 0,
    timestamp: u64 = 0,
    active: bool = false,

    pub fn signal(self: *DmaFence, tick: u64) void {
        self.state = .signaled;
        self.timestamp = tick;
    }

    pub fn is_signaled(self: *const DmaFence) bool {
        return self.state == .signaled;
    }
};

// ─────────────────── DMA Engine ─────────────────────────────────────

pub const DmaEngine = struct {
    channels: [MAX_CHANNELS]DmaChannel = undefined,
    descriptors: [MAX_DESCRIPTORS]DmaDescriptor = undefined,
    fences: [MAX_FENCES]DmaFence = [_]DmaFence{.{}} ** MAX_FENCES,
    channel_count: u8 = 0,
    desc_count: u16 = 0,
    fence_count: u16 = 0,
    next_fence_seq: u64 = 0,
    /// Engine ID
    id: u8 = 0,
    /// Base MMIO address
    base_addr: u64 = 0,
    /// Capabilities
    has_sg: bool = true,
    has_cyclic: bool = true,
    has_interleaved: bool = false,
    max_burst: u32 = 256,
    max_transfer_size: u32 = 0x100000, // 1 MB
    /// Stats
    total_transfers: u64 = 0,
    total_bytes: u64 = 0,
    total_errors: u32 = 0,
    current_tick: u64 = 0,
    active: bool = false,

    pub fn init(self: *DmaEngine, engine_id: u8, base: u64, num_channels: u8) void {
        self.id = engine_id;
        self.base_addr = base;

        for (0..MAX_CHANNELS) |i| {
            self.channels[i] = DmaChannel{};
            self.channels[i].id = @truncate(i);
            self.channels[i].engine_id = engine_id;
        }
        for (0..MAX_DESCRIPTORS) |i| {
            self.descriptors[i] = DmaDescriptor{};
            self.descriptors[i].id = @truncate(i);
        }

        const nc = @min(num_channels, MAX_CHANNELS);
        for (0..nc) |i| {
            self.channels[i].active = true;
        }
        self.channel_count = nc;
        self.active = true;
    }

    /// Allocate a channel
    pub fn alloc_channel(self: *DmaEngine, priority: DmaPriority) ?u8 {
        for (0..self.channel_count) |i| {
            if (self.channels[i].active and !self.channels[i].allocated) {
                self.channels[i].allocated = true;
                self.channels[i].priority = priority;
                return @truncate(i);
            }
        }
        return null;
    }

    /// Free a channel
    pub fn free_channel(self: *DmaEngine, ch: u8) bool {
        if (ch >= self.channel_count) return false;
        if (!self.channels[ch].allocated) return false;
        if (self.channels[ch].busy) return false;
        self.channels[ch].allocated = false;
        return true;
    }

    /// Allocate a descriptor
    fn alloc_desc(self: *DmaEngine) ?u16 {
        for (0..MAX_DESCRIPTORS) |i| {
            if (self.descriptors[i].status == .free) {
                self.descriptors[i] = DmaDescriptor{};
                self.descriptors[i].id = @truncate(i);
                self.desc_count += 1;
                return @truncate(i);
            }
        }
        return null;
    }

    /// Free a descriptor
    fn free_desc(self: *DmaEngine, id: u16) void {
        if (id < MAX_DESCRIPTORS) {
            self.descriptors[id].status = .free;
            if (self.desc_count > 0) self.desc_count -= 1;
        }
    }

    /// Prepare a single DMA transfer
    pub fn prep_single(
        self: *DmaEngine,
        ch: u8,
        src: u64,
        dst: u64,
        length: u32,
        direction: DmaDirection,
    ) ?u16 {
        if (ch >= self.channel_count or !self.channels[ch].allocated) return null;
        if (length > self.max_transfer_size) return null;

        const desc_id = self.alloc_desc() orelse return null;
        self.descriptors[desc_id].src_addr = src;
        self.descriptors[desc_id].dst_addr = dst;
        self.descriptors[desc_id].length = length;
        self.descriptors[desc_id].direction = direction;
        self.descriptors[desc_id].transfer_type = .single;
        self.descriptors[desc_id].src_width = self.channels[ch].src_width;
        self.descriptors[desc_id].dst_width = self.channels[ch].dst_width;
        self.descriptors[desc_id].src_burst = self.channels[ch].src_burst;
        self.descriptors[desc_id].dst_burst = self.channels[ch].dst_burst;
        self.descriptors[desc_id].status = .prepared;
        return desc_id;
    }

    /// Prepare a scatter-gather DMA transfer
    pub fn prep_sg(
        self: *DmaEngine,
        ch: u8,
        sg: *const SgTable,
        dst: u64,
        direction: DmaDirection,
    ) ?u16 {
        if (ch >= self.channel_count or !self.channels[ch].allocated) return null;
        if (!self.has_sg or sg.count == 0) return null;

        var first_desc: u16 = 0xFFFF;
        var prev_desc: u16 = 0xFFFF;

        for (0..sg.count) |i| {
            const desc_id = self.alloc_desc() orelse {
                // Roll back
                if (first_desc != 0xFFFF) self.free_desc_chain(first_desc);
                return null;
            };

            self.descriptors[desc_id].src_addr = sg.entries[i].phys_addr;
            self.descriptors[desc_id].dst_addr = dst + sg.entries[i].offset;
            self.descriptors[desc_id].length = sg.entries[i].length;
            self.descriptors[desc_id].direction = direction;
            self.descriptors[desc_id].transfer_type = .scatter_gather;
            self.descriptors[desc_id].status = .prepared;
            self.descriptors[desc_id].interrupt_on_complete = (i == sg.count - 1);

            if (first_desc == 0xFFFF) {
                first_desc = desc_id;
            }
            if (prev_desc != 0xFFFF) {
                self.descriptors[prev_desc].next_desc = desc_id;
            }
            prev_desc = desc_id;
        }
        return first_desc;
    }

    fn free_desc_chain(self: *DmaEngine, head: u16) void {
        var current = head;
        while (current != 0xFFFF and current < MAX_DESCRIPTORS) {
            const next = self.descriptors[current].next_desc;
            self.free_desc(current);
            current = next;
        }
    }

    /// Prepare cyclic DMA (ring buffer for streaming)
    pub fn prep_cyclic(
        self: *DmaEngine,
        ch: u8,
        buf_addr: u64,
        buf_len: u32,
        period_len: u32,
        direction: DmaDirection,
    ) ?u16 {
        if (ch >= self.channel_count or !self.channels[ch].allocated) return null;
        if (!self.has_cyclic or period_len == 0 or buf_len == 0) return null;

        const periods = buf_len / period_len;
        if (periods == 0 or periods > MAX_DESCRIPTORS / 2) return null;

        var first_desc: u16 = 0xFFFF;
        var prev_desc: u16 = 0xFFFF;

        for (0..periods) |i| {
            const desc_id = self.alloc_desc() orelse {
                if (first_desc != 0xFFFF) self.free_desc_chain(first_desc);
                return null;
            };

            const offset: u64 = @as(u64, @truncate(i)) * period_len;
            self.descriptors[desc_id].src_addr = buf_addr + offset;
            self.descriptors[desc_id].dst_addr = self.channels[ch].dev_addr;
            self.descriptors[desc_id].length = period_len;
            self.descriptors[desc_id].direction = direction;
            self.descriptors[desc_id].transfer_type = .cyclic;
            self.descriptors[desc_id].status = .prepared;
            self.descriptors[desc_id].interrupt_on_complete = true;

            if (first_desc == 0xFFFF) first_desc = desc_id;
            if (prev_desc != 0xFFFF) {
                self.descriptors[prev_desc].next_desc = desc_id;
            }
            prev_desc = desc_id;
        }

        // Make cyclic: last → first
        if (prev_desc != 0xFFFF and first_desc != 0xFFFF) {
            self.descriptors[prev_desc].next_desc = first_desc;
        }

        return first_desc;
    }

    /// Submit a prepared descriptor to a channel
    pub fn submit(self: *DmaEngine, ch: u8, desc_id: u16) ?u32 {
        if (ch >= self.channel_count or !self.channels[ch].allocated) return null;
        if (desc_id >= MAX_DESCRIPTORS) return null;
        if (self.descriptors[desc_id].status != .prepared) return null;

        // Assign cookie
        const cookie = self.channels[ch].next_cookie;
        self.channels[ch].next_cookie +%= 1;
        self.descriptors[desc_id].cookie = cookie;
        self.descriptors[desc_id].status = .submitted;

        if (!self.channels[ch].enqueue(desc_id)) return null;

        return cookie;
    }

    /// Issue pending transfers on a channel
    pub fn issue_pending(self: *DmaEngine, ch: u8) void {
        if (ch >= self.channel_count) return;
        if (self.channels[ch].busy or self.channels[ch].paused) return;

        if (self.channels[ch].dequeue()) |desc_id| {
            self.channels[ch].current_desc = desc_id;
            self.channels[ch].busy = true;
            self.descriptors[desc_id].status = .in_progress;
        }
    }

    /// Simulate transfer completion (called from interrupt or polling)
    pub fn complete_transfer(self: *DmaEngine, ch: u8) void {
        if (ch >= self.channel_count) return;
        if (!self.channels[ch].busy) return;

        const desc_id = self.channels[ch].current_desc;
        if (desc_id >= MAX_DESCRIPTORS) return;

        self.descriptors[desc_id].bytes_transferred = self.descriptors[desc_id].length;
        self.descriptors[desc_id].status = .completed;

        self.channels[ch].transfers_completed += 1;
        self.channels[ch].bytes_transferred += self.descriptors[desc_id].length;
        self.channels[ch].completed_cookie = self.descriptors[desc_id].cookie;
        self.total_transfers += 1;
        self.total_bytes += self.descriptors[desc_id].length;

        // Signal any fences for this cookie
        self.signal_fences(ch, self.descriptors[desc_id].cookie);

        // Handle chained/cyclic
        const next = self.descriptors[desc_id].next_desc;
        if (self.descriptors[desc_id].transfer_type == .cyclic and next != 0xFFFF) {
            // Cyclic: move to next period, don't free
            self.channels[ch].current_desc = next;
            self.descriptors[next].status = .in_progress;
            return;
        }

        // Free completed descriptor (unless SG chain)
        if (self.descriptors[desc_id].transfer_type != .scatter_gather) {
            self.free_desc(desc_id);
        }

        // Try next pending
        self.channels[ch].busy = false;
        self.channels[ch].current_desc = 0xFFFF;
        self.issue_pending(ch);
    }

    /// Report error on transfer
    pub fn report_error(self: *DmaEngine, ch: u8) void {
        if (ch >= self.channel_count) return;
        const desc_id = self.channels[ch].current_desc;
        if (desc_id < MAX_DESCRIPTORS) {
            self.descriptors[desc_id].status = .error;
        }
        self.channels[ch].errors += 1;
        self.total_errors += 1;
        self.channels[ch].busy = false;
        self.channels[ch].current_desc = 0xFFFF;
    }

    /// Terminate all transfers on a channel
    pub fn terminate_all(self: *DmaEngine, ch: u8) void {
        if (ch >= self.channel_count) return;
        // Abort current
        if (self.channels[ch].current_desc != 0xFFFF and self.channels[ch].current_desc < MAX_DESCRIPTORS) {
            self.descriptors[self.channels[ch].current_desc].status = .aborted;
            self.free_desc(self.channels[ch].current_desc);
        }
        // Drain pending
        while (self.channels[ch].dequeue()) |desc_id| {
            self.descriptors[desc_id].status = .aborted;
            self.free_desc(desc_id);
        }
        self.channels[ch].busy = false;
        self.channels[ch].current_desc = 0xFFFF;
    }

    /// Create a DMA fence
    pub fn create_fence(self: *DmaEngine, ch: u8, cookie: u32) ?u16 {
        if (self.fence_count >= MAX_FENCES) return null;
        for (0..MAX_FENCES) |i| {
            if (!self.fences[i].active) {
                self.fences[i] = DmaFence{};
                self.fences[i].context = self.id;
                self.fences[i].seqno = self.next_fence_seq;
                self.fences[i].channel_id = ch;
                self.fences[i].desc_cookie = cookie;
                self.fences[i].active = true;
                self.next_fence_seq += 1;
                self.fence_count += 1;
                return @truncate(i);
            }
        }
        return null;
    }

    fn signal_fences(self: *DmaEngine, ch: u8, cookie: u32) void {
        for (0..MAX_FENCES) |i| {
            if (self.fences[i].active and self.fences[i].channel_id == ch and self.fences[i].desc_cookie == cookie) {
                self.fences[i].signal(self.current_tick);
            }
        }
    }

    pub fn tick(self: *DmaEngine) void {
        self.current_tick += 1;
        // Issue pending on all channels
        for (0..self.channel_count) |i| {
            if (self.channels[i].allocated and !self.channels[i].busy) {
                self.issue_pending(@truncate(i));
            }
        }
    }
};

// ─────────────────── DMA Engine Manager ─────────────────────────────

pub const DmaEngineManager = struct {
    engines: [MAX_ENGINES]DmaEngine = undefined,
    engine_count: u8 = 0,
    initialized: bool = false,

    pub fn init(self: *DmaEngineManager) void {
        for (0..MAX_ENGINES) |i| {
            self.engines[i] = DmaEngine{};
        }
        self.initialized = true;
    }

    pub fn register_engine(self: *DmaEngineManager, base_addr: u64, num_channels: u8) ?u8 {
        if (self.engine_count >= MAX_ENGINES) return null;
        const id = self.engine_count;
        self.engines[id].init(id, base_addr, num_channels);
        self.engine_count += 1;
        return id;
    }

    pub fn get_engine(self: *DmaEngineManager, id: u8) ?*DmaEngine {
        if (id >= self.engine_count) return null;
        if (!self.engines[id].active) return null;
        return &self.engines[id];
    }

    pub fn total_transfers(self: *const DmaEngineManager) u64 {
        var total: u64 = 0;
        for (0..self.engine_count) |i| {
            total += self.engines[i].total_transfers;
        }
        return total;
    }

    pub fn total_bytes(self: *const DmaEngineManager) u64 {
        var total: u64 = 0;
        for (0..self.engine_count) |i| {
            total += self.engines[i].total_bytes;
        }
        return total;
    }

    pub fn tick(self: *DmaEngineManager) void {
        for (0..self.engine_count) |i| {
            if (self.engines[i].active) {
                self.engines[i].tick();
            }
        }
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var dma_eng_mgr = DmaEngineManager{};

pub fn get_dma_engine_manager() *DmaEngineManager {
    return &dma_eng_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_dmaeng_init() void {
    dma_eng_mgr.init();
}

export fn zxy_dmaeng_register(base_addr: u64, num_channels: u8) i32 {
    return if (dma_eng_mgr.register_engine(base_addr, num_channels)) |id| @as(i32, id) else -1;
}

export fn zxy_dmaeng_alloc_channel(engine_id: u8, priority: u8) i32 {
    const eng = dma_eng_mgr.get_engine(engine_id) orelse return -1;
    const p: DmaPriority = @enumFromInt(priority);
    return if (eng.alloc_channel(p)) |ch| @as(i32, ch) else -1;
}

export fn zxy_dmaeng_free_channel(engine_id: u8, ch: u8) bool {
    const eng = dma_eng_mgr.get_engine(engine_id) orelse return false;
    return eng.free_channel(ch);
}

export fn zxy_dmaeng_engine_count() u8 {
    return dma_eng_mgr.engine_count;
}

export fn zxy_dmaeng_total_transfers() u64 {
    return dma_eng_mgr.total_transfers();
}

export fn zxy_dmaeng_total_bytes() u64 {
    return dma_eng_mgr.total_bytes();
}

export fn zxy_dmaeng_tick() void {
    dma_eng_mgr.tick();
}

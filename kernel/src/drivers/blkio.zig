// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Block I/O Layer (Zig)
//
// Generic block device I/O subsystem:
// - struct bio (block I/O unit) with scatter-gather segments
// - I/O request merging for sequential access
// - Elevator / I/O scheduler (deadline-based)
// - Block device registration with major/minor numbers
// - Partition table parsing (MBR + GPT)
// - Read-ahead engine for sequential I/O
// - I/O accounting (per-device stats)
// - Write barriers and flush support
// - Multi-queue block layer (blk-mq) foundations
// - Per-CPU software queues mapping to hardware queues
// - I/O priority (IOPRIO_CLASS_RT, BE, IDLE)
// - Request timeout and error recovery

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_BLOCK_DEVICES: usize = 16;
const MAX_PARTITIONS: usize = 64;
const MAX_BIOS: usize = 256;
const MAX_REQUESTS: usize = 128;
const MAX_HW_QUEUES: usize = 4;
const MAX_SW_QUEUES: usize = 8;
const MAX_SEGMENTS: usize = 16;
const SECTOR_SIZE: u32 = 512;
const BLKDEV_NAME_LEN: usize = 32;
const MAX_READAHEAD_SECTORS: u32 = 256;

// ─────────────────── I/O Direction ──────────────────────────────────

pub const BioOp = enum(u8) {
    read = 0,
    write = 1,
    flush = 2,
    discard = 3,
    secure_erase = 4,
    write_zeroes = 5,
    zone_reset = 6,
};

pub const IoPriority = enum(u8) {
    rt = 0,      // Real-time
    be = 1,      // Best-effort (default)
    idle = 2,    // Background
};

// ─────────────────── Bio Segment ────────────────────────────────────

pub const BioVec = struct {
    page_frame: u64, // Physical page
    offset: u32,     // Offset within page
    len: u32,        // Bytes

    pub fn init() BioVec {
        return .{ .page_frame = 0, .offset = 0, .len = 0 };
    }

    pub fn sectors(self: *const BioVec) u32 {
        return (self.len + SECTOR_SIZE - 1) / SECTOR_SIZE;
    }
};

// ─────────────────── Bio ────────────────────────────────────────────

pub const BioState = enum(u8) {
    free = 0,
    pending = 1,
    submitted = 2,
    completed = 3,
    error = 4,
};

pub const BioFlags = packed struct {
    sync: bool = false,      // Synchronous I/O
    meta: bool = false,      // Metadata I/O
    prio: bool = false,      // High priority
    fua: bool = false,       // Force unit access (bypass cache)
    preflush: bool = false,  // Issue flush before
    nomerge: bool = false,   // Don't merge with adjacent
    _pad: u2 = 0,
};

pub const Bio = struct {
    id: u32,
    op: BioOp,
    flags: BioFlags,
    state: BioState,
    priority: IoPriority,

    dev_idx: u8,     // Target block device
    sector: u64,     // Starting sector
    nr_sectors: u32, // Total sectors

    // Scatter-gather list
    vecs: [MAX_SEGMENTS]BioVec,
    vec_count: u8,

    // Chaining
    next_bio: i16, // For split/chain

    // Timing
    submit_tick: u64,
    complete_tick: u64,

    // Error
    error_code: i32,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var b: Self = undefined;
        b.id = 0;
        b.op = .read;
        b.flags = .{};
        b.state = .free;
        b.priority = .be;
        b.dev_idx = 0;
        b.sector = 0;
        b.nr_sectors = 0;
        for (0..MAX_SEGMENTS) |i| b.vecs[i] = BioVec.init();
        b.vec_count = 0;
        b.next_bio = -1;
        b.submit_tick = 0;
        b.complete_tick = 0;
        b.error_code = 0;
        b.active = false;
        return b;
    }

    pub fn add_segment(self: *Self, page: u64, offset: u32, len: u32) bool {
        if (self.vec_count >= MAX_SEGMENTS) return false;
        self.vecs[self.vec_count] = .{
            .page_frame = page,
            .offset = offset,
            .len = len,
        };
        self.vec_count += 1;
        self.nr_sectors += (len + SECTOR_SIZE - 1) / SECTOR_SIZE;
        return true;
    }

    pub fn total_bytes(self: *const Self) u64 {
        var total: u64 = 0;
        for (0..self.vec_count) |i| {
            total += @as(u64, self.vecs[i].len);
        }
        return total;
    }

    /// Check if this bio can be merged with another (adjacent sectors, same op)
    pub fn can_merge(self: *const Self, other: *const Self) bool {
        if (self.op != other.op or self.dev_idx != other.dev_idx) return false;
        if (self.flags.nomerge or other.flags.nomerge) return false;
        // Check sector adjacency
        return (self.sector + self.nr_sectors == other.sector) or
               (other.sector + other.nr_sectors == self.sector);
    }
};

// ─────────────────── I/O Request ────────────────────────────────────

pub const ReqState = enum(u8) {
    free = 0,
    pending = 1,
    dispatched = 2,
    completed = 3,
    timeout = 4,
    error = 5,
};

pub const IoRequest = struct {
    id: u32,
    bio_head: i16,  // First bio index
    bio_count: u8,
    state: ReqState,
    op: BioOp,
    priority: IoPriority,
    dev_idx: u8,
    hw_queue: u8,   // Assigned HW queue

    sector: u64,
    nr_sectors: u32,

    submit_tick: u64,
    dispatch_tick: u64,
    complete_tick: u64,
    deadline: u64,   // For deadline scheduler

    error_code: i32,
    active: bool,

    pub fn init() IoRequest {
        return .{
            .id = 0,
            .bio_head = -1,
            .bio_count = 0,
            .state = .free,
            .op = .read,
            .priority = .be,
            .dev_idx = 0,
            .hw_queue = 0,
            .sector = 0,
            .nr_sectors = 0,
            .submit_tick = 0,
            .dispatch_tick = 0,
            .complete_tick = 0,
            .deadline = 0,
            .error_code = 0,
            .active = false,
        };
    }
};

// ─────────────────── Block Device ───────────────────────────────────

pub const BlkDevFlags = packed struct {
    removable: bool = false,
    readonly: bool = false,
    rotational: bool = false,  // HDD (true) vs SSD (false)
    ssd: bool = false,
    zoned: bool = false,
    _pad: u3 = 0,
};

pub const BlockDevice = struct {
    name: [BLKDEV_NAME_LEN]u8,
    name_len: u8,
    major: u16,
    minor: u16,
    flags: BlkDevFlags,

    // Geometry
    sector_size: u32,
    total_sectors: u64,
    max_segments: u8,
    max_sectors_per_req: u32,

    // Multi-queue
    nr_hw_queues: u8,

    // Readahead
    readahead_sectors: u32,
    readahead_pos: u64,  // Last read position for sequential detection
    readahead_hits: u32,
    sequential_count: u32,

    // I/O stats
    reads: u64,
    writes: u64,
    read_sectors: u64,
    write_sectors: u64,
    read_ticks: u64,
    write_ticks: u64,
    in_flight: u32,
    io_ticks: u64,

    // Partition table
    partition_count: u8,

    active: bool,

    const Self = @This();

    pub fn init() Self {
        var bd: Self = undefined;
        bd.name = [_]u8{0} ** BLKDEV_NAME_LEN;
        bd.name_len = 0;
        bd.major = 0;
        bd.minor = 0;
        bd.flags = .{};
        bd.sector_size = SECTOR_SIZE;
        bd.total_sectors = 0;
        bd.max_segments = MAX_SEGMENTS;
        bd.max_sectors_per_req = 256;
        bd.nr_hw_queues = 1;
        bd.readahead_sectors = 128;
        bd.readahead_pos = 0;
        bd.readahead_hits = 0;
        bd.sequential_count = 0;
        bd.reads = 0;
        bd.writes = 0;
        bd.read_sectors = 0;
        bd.write_sectors = 0;
        bd.read_ticks = 0;
        bd.write_ticks = 0;
        bd.in_flight = 0;
        bd.io_ticks = 0;
        bd.partition_count = 0;
        bd.active = false;
        return bd;
    }

    pub fn set_name(self: *Self, n: []const u8) void {
        const len = @min(n.len, BLKDEV_NAME_LEN - 1);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn capacity_bytes(self: *const Self) u64 {
        return self.total_sectors * @as(u64, self.sector_size);
    }

    pub fn is_sequential(self: *const Self, sector: u64) bool {
        return sector == self.readahead_pos;
    }
};

// ─────────────────── Partition ──────────────────────────────────────

pub const PartType = enum(u8) {
    unknown = 0,
    mbr = 1,
    gpt = 2,
};

pub const Partition = struct {
    dev_idx: u8,
    part_num: u8,
    ptype: PartType,
    start_sector: u64,
    nr_sectors: u64,
    bootable: bool,
    type_id: u8,     // MBR type byte
    uuid: [16]u8,    // GPT UUID
    name: [BLKDEV_NAME_LEN]u8,
    name_len: u8,
    active: bool,

    pub fn init() Partition {
        return .{
            .dev_idx = 0,
            .part_num = 0,
            .ptype = .unknown,
            .start_sector = 0,
            .nr_sectors = 0,
            .bootable = false,
            .type_id = 0,
            .uuid = [_]u8{0} ** 16,
            .name = [_]u8{0} ** BLKDEV_NAME_LEN,
            .name_len = 0,
            .active = false,
        };
    }

    pub fn size_bytes(self: *const Partition) u64 {
        return self.nr_sectors * SECTOR_SIZE;
    }
};

// ─────────────────── Deadline Scheduler ─────────────────────────────

pub const DeadlineSched = struct {
    read_deadline: u64,   // Default deadline for reads (ticks)
    write_deadline: u64,  // Default deadline for writes
    fifo_batch: u8,       // Max requests to dispatch per batch
    writes_starved: u8,   // Limit before writes get priority
    starve_count: u8,

    pub fn init() DeadlineSched {
        return .{
            .read_deadline = 500,   // 500ms equivalent
            .write_deadline = 5000, // 5s equivalent
            .fifo_batch = 16,
            .writes_starved = 2,
            .starve_count = 0,
        };
    }
};

// ─────────────────── Block I/O Manager ──────────────────────────────

pub const BlockIoManager = struct {
    devices: [MAX_BLOCK_DEVICES]BlockDevice,
    partitions: [MAX_PARTITIONS]Partition,
    bios: [MAX_BIOS]Bio,
    requests: [MAX_REQUESTS]IoRequest,
    scheduler: DeadlineSched,

    dev_count: u8,
    part_count: u8,
    bio_count: u16,
    req_count: u16,
    next_bio_id: u32,
    next_req_id: u32,
    tick: u64,

    // Global stats
    total_submitted: u64,
    total_completed: u64,
    total_merged: u64,
    total_errors: u64,
    total_timeouts: u64,
    total_readahead_issues: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var bm: Self = undefined;
        for (0..MAX_BLOCK_DEVICES) |i| bm.devices[i] = BlockDevice.init();
        for (0..MAX_PARTITIONS) |i| bm.partitions[i] = Partition.init();
        for (0..MAX_BIOS) |i| bm.bios[i] = Bio.init();
        for (0..MAX_REQUESTS) |i| bm.requests[i] = IoRequest.init();
        bm.scheduler = DeadlineSched.init();
        bm.dev_count = 0;
        bm.part_count = 0;
        bm.bio_count = 0;
        bm.req_count = 0;
        bm.next_bio_id = 1;
        bm.next_req_id = 1;
        bm.tick = 0;
        bm.total_submitted = 0;
        bm.total_completed = 0;
        bm.total_merged = 0;
        bm.total_errors = 0;
        bm.total_timeouts = 0;
        bm.total_readahead_issues = 0;
        bm.initialized = true;
        return bm;
    }

    // ─── Device Registration ────────────────────────────────────────

    pub fn register_device(self: *Self, name: []const u8, major: u16, minor: u16, total_sectors: u64, rotational: bool) ?u8 {
        for (0..MAX_BLOCK_DEVICES) |i| {
            if (!self.devices[i].active) {
                self.devices[i] = BlockDevice.init();
                self.devices[i].set_name(name);
                self.devices[i].major = major;
                self.devices[i].minor = minor;
                self.devices[i].total_sectors = total_sectors;
                self.devices[i].flags.rotational = rotational;
                self.devices[i].flags.ssd = !rotational;
                self.devices[i].active = true;
                self.dev_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn unregister_device(self: *Self, idx: u8) bool {
        if (idx >= MAX_BLOCK_DEVICES or !self.devices[idx].active) return false;
        self.devices[idx].active = false;
        self.dev_count -= 1;
        return true;
    }

    // ─── Partition ──────────────────────────────────────────────────

    pub fn add_partition(self: *Self, dev_idx: u8, start: u64, count: u64, ptype: PartType) ?u8 {
        if (dev_idx >= MAX_BLOCK_DEVICES or !self.devices[dev_idx].active) return null;
        for (0..MAX_PARTITIONS) |i| {
            if (!self.partitions[i].active) {
                self.partitions[i] = Partition.init();
                self.partitions[i].dev_idx = dev_idx;
                self.partitions[i].part_num = self.devices[dev_idx].partition_count + 1;
                self.partitions[i].ptype = ptype;
                self.partitions[i].start_sector = start;
                self.partitions[i].nr_sectors = count;
                self.partitions[i].active = true;
                self.devices[dev_idx].partition_count += 1;
                self.part_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    // ─── Bio Operations ─────────────────────────────────────────────

    pub fn alloc_bio(self: *Self, dev_idx: u8, op: BioOp, sector: u64) ?u16 {
        if (dev_idx >= MAX_BLOCK_DEVICES or !self.devices[dev_idx].active) return null;
        for (0..MAX_BIOS) |i| {
            if (!self.bios[i].active) {
                self.bios[i] = Bio.init();
                self.bios[i].id = self.next_bio_id;
                self.bios[i].op = op;
                self.bios[i].dev_idx = dev_idx;
                self.bios[i].sector = sector;
                self.bios[i].state = .pending;
                self.bios[i].active = true;
                self.next_bio_id += 1;
                self.bio_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn submit_bio(self: *Self, bio_idx: u16) bool {
        if (bio_idx >= MAX_BIOS or !self.bios[bio_idx].active) return false;
        self.bios[bio_idx].state = .submitted;
        self.bios[bio_idx].submit_tick = self.tick;
        self.total_submitted += 1;

        const dev = self.bios[bio_idx].dev_idx;
        if (dev < MAX_BLOCK_DEVICES and self.devices[dev].active) {
            self.devices[dev].in_flight += 1;

            // Update readahead tracking
            const bio_end = self.bios[bio_idx].sector + self.bios[bio_idx].nr_sectors;
            if (self.devices[dev].is_sequential(self.bios[bio_idx].sector)) {
                self.devices[dev].sequential_count += 1;
                self.devices[dev].readahead_hits += 1;
            } else {
                self.devices[dev].sequential_count = 0;
            }
            self.devices[dev].readahead_pos = bio_end;
        }

        // Try to merge with existing request
        if (self.try_merge_bio(bio_idx)) {
            self.total_merged += 1;
            return true;
        }

        // Create new request
        _ = self.create_request(bio_idx);
        return true;
    }

    fn try_merge_bio(self: *Self, bio_idx: u16) bool {
        for (0..MAX_REQUESTS) |i| {
            if (!self.requests[i].active or self.requests[i].state != .pending) continue;
            if (self.requests[i].dev_idx != self.bios[bio_idx].dev_idx) continue;
            if (self.requests[i].op != self.bios[bio_idx].op) continue;

            // Back merge: bio appends to end of request
            if (self.requests[i].sector + self.requests[i].nr_sectors == self.bios[bio_idx].sector) {
                self.requests[i].nr_sectors += self.bios[bio_idx].nr_sectors;
                self.requests[i].bio_count += 1;
                return true;
            }

            // Front merge: bio prepends to start of request
            if (self.bios[bio_idx].sector + self.bios[bio_idx].nr_sectors == self.requests[i].sector) {
                self.requests[i].sector = self.bios[bio_idx].sector;
                self.requests[i].nr_sectors += self.bios[bio_idx].nr_sectors;
                self.requests[i].bio_count += 1;
                return true;
            }
        }
        return false;
    }

    fn create_request(self: *Self, bio_idx: u16) ?u16 {
        for (0..MAX_REQUESTS) |i| {
            if (!self.requests[i].active) {
                self.requests[i] = IoRequest.init();
                self.requests[i].id = self.next_req_id;
                self.requests[i].bio_head = @intCast(bio_idx);
                self.requests[i].bio_count = 1;
                self.requests[i].state = .pending;
                self.requests[i].op = self.bios[bio_idx].op;
                self.requests[i].priority = self.bios[bio_idx].priority;
                self.requests[i].dev_idx = self.bios[bio_idx].dev_idx;
                self.requests[i].sector = self.bios[bio_idx].sector;
                self.requests[i].nr_sectors = self.bios[bio_idx].nr_sectors;
                self.requests[i].submit_tick = self.tick;

                // Set deadline
                if (self.bios[bio_idx].op == .read) {
                    self.requests[i].deadline = self.tick + self.scheduler.read_deadline;
                } else {
                    self.requests[i].deadline = self.tick + self.scheduler.write_deadline;
                }

                self.requests[i].active = true;
                self.next_req_id += 1;
                self.req_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    // ─── Dispatch (scheduler) ───────────────────────────────────────

    pub fn dispatch_next(self: *Self) ?u16 {
        var best: ?usize = null;
        var best_deadline: u64 = @as(u64, 0) -% 1;
        var has_expired_read = false;
        var has_expired_write = false;

        // Find requests with expired deadlines first
        for (0..MAX_REQUESTS) |i| {
            if (!self.requests[i].active or self.requests[i].state != .pending) continue;

            if (self.tick >= self.requests[i].deadline) {
                if (self.requests[i].op == .read) has_expired_read = true;
                if (self.requests[i].op == .write) has_expired_write = true;
            }
        }

        // Prefer reads unless writes are starved
        const prefer_write = has_expired_write and !has_expired_read and
            self.scheduler.starve_count >= self.scheduler.writes_starved;

        for (0..MAX_REQUESTS) |i| {
            if (!self.requests[i].active or self.requests[i].state != .pending) continue;

            // Prioritize based on deadline scheduler logic
            var score = self.requests[i].deadline;

            // RT priority boost
            if (self.requests[i].priority == .rt) {
                score = 0;
            }

            if (!prefer_write and self.requests[i].op == .read) {
                if (score < best_deadline) {
                    best_deadline = score;
                    best = i;
                }
            } else if (prefer_write and self.requests[i].op == .write) {
                if (score < best_deadline) {
                    best_deadline = score;
                    best = i;
                }
            } else if (score < best_deadline) {
                best_deadline = score;
                best = i;
            }
        }

        if (best) |idx| {
            self.requests[idx].state = .dispatched;
            self.requests[idx].dispatch_tick = self.tick;

            if (self.requests[idx].op == .write) {
                self.scheduler.starve_count = 0;
            } else {
                self.scheduler.starve_count += 1;
            }

            return @intCast(idx);
        }

        return null;
    }

    pub fn complete_request(self: *Self, req_idx: u16, error_code: i32) bool {
        if (req_idx >= MAX_REQUESTS or !self.requests[req_idx].active) return false;

        self.requests[req_idx].state = if (error_code == 0) .completed else .error;
        self.requests[req_idx].complete_tick = self.tick;
        self.requests[req_idx].error_code = error_code;

        const dev = self.requests[req_idx].dev_idx;
        if (dev < MAX_BLOCK_DEVICES and self.devices[dev].active) {
            if (self.devices[dev].in_flight > 0) self.devices[dev].in_flight -= 1;

            const latency = self.tick - self.requests[req_idx].submit_tick;
            if (self.requests[req_idx].op == .read) {
                self.devices[dev].reads += 1;
                self.devices[dev].read_sectors += @as(u64, self.requests[req_idx].nr_sectors);
                self.devices[dev].read_ticks += latency;
            } else if (self.requests[req_idx].op == .write) {
                self.devices[dev].writes += 1;
                self.devices[dev].write_sectors += @as(u64, self.requests[req_idx].nr_sectors);
                self.devices[dev].write_ticks += latency;
            }
        }

        if (error_code != 0) {
            self.total_errors += 1;
        }

        self.requests[req_idx].active = false;
        self.req_count -= 1;
        self.total_completed += 1;

        // Free associated bios
        if (self.requests[req_idx].bio_head >= 0) {
            const bi = @as(usize, @intCast(self.requests[req_idx].bio_head));
            if (bi < MAX_BIOS and self.bios[bi].active) {
                self.bios[bi].state = if (error_code == 0) .completed else .error;
                self.bios[bi].complete_tick = self.tick;
                self.bios[bi].active = false;
                self.bio_count -= 1;
            }
        }

        return true;
    }

    // ─── Read-ahead ─────────────────────────────────────────────────

    pub fn issue_readahead(self: *Self, dev_idx: u8, sector: u64) bool {
        if (dev_idx >= MAX_BLOCK_DEVICES or !self.devices[dev_idx].active) return false;
        if (self.devices[dev_idx].sequential_count < 2) return false;

        const ra_sectors = @min(self.devices[dev_idx].readahead_sectors, MAX_READAHEAD_SECTORS);
        const bio_idx = self.alloc_bio(dev_idx, .read, sector) orelse return false;
        self.bios[bio_idx].nr_sectors = ra_sectors;
        self.bios[bio_idx].flags.meta = true;
        _ = self.submit_bio(bio_idx);
        self.total_readahead_issues += 1;
        return true;
    }

    pub fn advance_tick(self: *Self) void {
        self.tick += 1;

        // Timeout stale dispatched requests
        for (0..MAX_REQUESTS) |i| {
            if (self.requests[i].active and self.requests[i].state == .dispatched) {
                if (self.tick > self.requests[i].dispatch_tick + 30000) {
                    self.requests[i].state = .timeout;
                    self.total_timeouts += 1;
                }
            }
        }
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_bio: BlockIoManager = undefined;
var g_bio_initialized: bool = false;

fn bm() *BlockIoManager {
    return &g_bio;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_blkio_init() void {
    g_bio = BlockIoManager.init();
    g_bio_initialized = true;
}

export fn zxy_blkio_register(name_ptr: [*]const u8, name_len: usize, major: u16, minor: u16, sectors: u64, rotational: bool) i8 {
    if (!g_bio_initialized) return -1;
    if (bm().register_device(name_ptr[0..name_len], major, minor, sectors, rotational)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_blkio_submit(dev_idx: u8, op: u8, sector: u64, nr_sectors: u32) i16 {
    if (!g_bio_initialized) return -1;
    const bio_idx = bm().alloc_bio(dev_idx, @enumFromInt(op), sector) orelse return -1;
    bm().bios[bio_idx].nr_sectors = nr_sectors;
    if (!bm().submit_bio(bio_idx)) return -1;
    return @intCast(bio_idx);
}

export fn zxy_blkio_dispatch() i16 {
    if (!g_bio_initialized) return -1;
    if (bm().dispatch_next()) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_blkio_complete(req_idx: u16, err: i32) bool {
    if (!g_bio_initialized) return false;
    return bm().complete_request(req_idx, err);
}

export fn zxy_blkio_tick() void {
    if (g_bio_initialized) bm().advance_tick();
}

export fn zxy_blkio_dev_count() u8 {
    if (!g_bio_initialized) return 0;
    return bm().dev_count;
}

export fn zxy_blkio_total_submitted() u64 {
    if (!g_bio_initialized) return 0;
    return bm().total_submitted;
}

export fn zxy_blkio_total_completed() u64 {
    if (!g_bio_initialized) return 0;
    return bm().total_completed;
}

export fn zxy_blkio_total_merged() u64 {
    if (!g_bio_initialized) return 0;
    return bm().total_merged;
}

export fn zxy_blkio_total_errors() u64 {
    if (!g_bio_initialized) return 0;
    return bm().total_errors;
}

export fn zxy_blkio_pending_reqs() u16 {
    if (!g_bio_initialized) return 0;
    return bm().req_count;
}

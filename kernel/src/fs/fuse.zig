// SPDX-License-Identifier: MIT
// Zxyphor Kernel — FUSE (Filesystem in Userspace) Interface (Zig)
//
// Kernel-side FUSE protocol implementation:
// - FUSE init/destroy handshake with userspace daemon
// - Request queue with opcodes (LOOKUP, GETATTR, READ, WRITE, etc.)
// - Request ID tracking for async completion
// - FUSE entry/attr cache with configurable timeout
// - Interrupt support for in-flight requests
// - Writeback cache mode
// - Splice/direct I/O support flags
// - Connection management (max_write, max_read, max_background)
// - Per-mount FUSE sessions
// - FUSE_NOTIFY for server-initiated invalidation

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 38;
const MAX_SESSIONS: usize = 8;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_PROCESSING: usize = 64;
const MAX_CACHE_ENTRIES: usize = 256;
const FUSE_NAME_MAX: usize = 256;
const FUSE_MAX_PAGES: usize = 256;
const FUSE_DEFAULT_MAX_WRITE: u32 = 131072; // 128K
const FUSE_DEFAULT_MAX_READ: u32 = 131072;
const FUSE_DEFAULT_MAX_BACKGROUND: u16 = 12;
const FUSE_DEFAULT_CONGESTION_THRESHOLD: u16 = 9;

// ─────────────────── FUSE Opcodes ───────────────────────────────────

pub const FuseOpcode = enum(u32) {
    lookup = 1,
    forget = 2,
    getattr = 3,
    setattr = 4,
    readlink = 5,
    symlink = 6,
    mknod = 8,
    mkdir = 9,
    unlink = 10,
    rmdir = 11,
    rename = 12,
    link = 13,
    open = 14,
    read = 15,
    write = 16,
    statfs = 17,
    release = 18,
    fsync = 20,
    setxattr = 21,
    getxattr = 22,
    listxattr = 23,
    removexattr = 24,
    flush = 25,
    init = 26,
    opendir = 27,
    readdir = 28,
    releasedir = 29,
    fsyncdir = 30,
    getlk = 31,
    setlk = 32,
    setlkw = 33,
    access = 34,
    create = 35,
    interrupt = 36,
    bmap = 37,
    destroy = 38,
    ioctl = 39,
    poll = 40,
    notify_reply = 41,
    batch_forget = 42,
    fallocate = 43,
    readdirplus = 44,
    rename2 = 45,
    lseek = 46,
    copy_file_range = 47,
    setupmapping = 48,
    removemapping = 49,
};

// ─────────────────── FUSE Protocol Headers ──────────────────────────

pub const FuseInHeader = struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    _padding: u32,
};

pub const FuseOutHeader = struct {
    len: u32,
    error: i32,
    unique: u64,
};

pub const FuseInitIn = struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    flags2: u32,
};

pub const FuseInitOut = struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
};

// ─────────────────── Init Flags ─────────────────────────────────────

pub const FuseInitFlags = packed struct {
    async_read: bool = false,
    posix_locks: bool = false,
    file_ops: bool = false,
    atomic_o_trunc: bool = false,
    export_support: bool = false,
    big_writes: bool = false,
    dont_mask: bool = false,
    splice_write: bool = false,
    splice_move: bool = false,
    splice_read: bool = false,
    flock_locks: bool = false,
    has_ioctl_dir: bool = false,
    auto_inval_data: bool = false,
    do_readdirplus: bool = false,
    readdirplus_auto: bool = false,
    async_dio: bool = false,
    writeback_cache: bool = false,
    no_open_support: bool = false,
    parallel_dirops: bool = false,
    handle_killpriv: bool = false,
    posix_acl: bool = false,
    abort_error: bool = false,
    max_pages: bool = false,
    cache_symlinks: bool = false,
    no_opendir_support: bool = false,
    explicit_inval_data: bool = false,
    map_alignment: bool = false,
    _pad: u5 = 0,
};

// ─────────────────── FUSE Entry/Attr ────────────────────────────────

pub const FuseAttr = struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
};

pub const FuseEntryOut = struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,       // Cache timeout (seconds)
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
};

// ─────────────────── Request State ──────────────────────────────────

pub const RequestState = enum(u8) {
    free = 0,
    pending = 1,
    processing = 2,
    completed = 3,
    interrupted = 4,
    aborted = 5,
};

pub const FuseRequest = struct {
    unique: u64,
    opcode: u32,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    state: RequestState,
    enqueue_tick: u64,
    start_tick: u64,
    complete_tick: u64,
    error: i32,

    // I/O parameters
    offset: u64,
    size: u32,
    flags: u32,

    // Name for lookup/create/etc
    name: [FUSE_NAME_MAX]u8,
    name_len: u16,

    // Response
    out_nodeid: u64,
    out_size: u64,
    out_attr: FuseAttr,

    active: bool,
    interrupted: bool,
    force_sync: bool,

    pub fn init() FuseRequest {
        return .{
            .unique = 0,
            .opcode = 0,
            .nodeid = 0,
            .uid = 0,
            .gid = 0,
            .pid = 0,
            .state = .free,
            .enqueue_tick = 0,
            .start_tick = 0,
            .complete_tick = 0,
            .error = 0,
            .offset = 0,
            .size = 0,
            .flags = 0,
            .name = [_]u8{0} ** FUSE_NAME_MAX,
            .name_len = 0,
            .out_nodeid = 0,
            .out_size = 0,
            .out_attr = std.mem.zeroes(FuseAttr),
            .active = false,
            .interrupted = false,
            .force_sync = false,
        };
    }
};

// ─────────────────── Attr Cache ─────────────────────────────────────

pub const CacheEntry = struct {
    nodeid: u64,
    attr: FuseAttr,
    valid_until: u64, // Tick when cache expires
    generation: u64,
    active: bool,

    pub fn init() CacheEntry {
        return .{
            .nodeid = 0,
            .attr = std.mem.zeroes(FuseAttr),
            .valid_until = 0,
            .generation = 0,
            .active = false,
        };
    }

    pub fn is_valid(self: *const CacheEntry, tick: u64) bool {
        return self.active and tick < self.valid_until;
    }
};

// ─────────────────── Notification Types ─────────────────────────────

pub const NotifyCode = enum(u32) {
    poll = 1,
    inval_inode = 2,
    inval_entry = 3,
    store = 4,
    retrieve = 5,
    delete = 6,
    resend = 7,
};

pub const FuseNotification = struct {
    code: NotifyCode,
    nodeid: u64,
    offset: i64,
    len: i64,
    name: [FUSE_NAME_MAX]u8,
    name_len: u16,
    active: bool,
};

// ─────────────────── FUSE Connection ────────────────────────────────

pub const ConnState = enum(u8) {
    uninitialized = 0,
    initializing = 1,
    active = 2,
    aborting = 3,
    destroyed = 4,
};

pub const FuseConnection = struct {
    conn_id: u32,
    state: ConnState,

    // Protocol negotiation
    proto_major: u32,
    proto_minor: u32,
    init_flags: FuseInitFlags,

    // Limits
    max_write: u32,
    max_read: u32,
    max_readahead: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_pages: u16,
    time_gran: u32,

    // Writeback
    writeback_cache: bool,
    no_open: bool,
    no_opendir: bool,
    parallel_dirops: bool,
    async_read: bool,

    // Mount info
    mount_point: [FUSE_NAME_MAX]u8,
    mount_point_len: u16,
    source: [FUSE_NAME_MAX]u8,
    source_len: u16,
    owner_uid: u32,
    allow_other: bool,

    active: bool,

    pub fn init() FuseConnection {
        return .{
            .conn_id = 0,
            .state = .uninitialized,
            .proto_major = FUSE_KERNEL_VERSION,
            .proto_minor = FUSE_KERNEL_MINOR_VERSION,
            .init_flags = .{},
            .max_write = FUSE_DEFAULT_MAX_WRITE,
            .max_read = FUSE_DEFAULT_MAX_READ,
            .max_readahead = 65536,
            .max_background = FUSE_DEFAULT_MAX_BACKGROUND,
            .congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD,
            .max_pages = FUSE_MAX_PAGES,
            .time_gran = 1,
            .writeback_cache = false,
            .no_open = false,
            .no_opendir = false,
            .parallel_dirops = false,
            .async_read = true,
            .mount_point = [_]u8{0} ** FUSE_NAME_MAX,
            .mount_point_len = 0,
            .source = [_]u8{0} ** FUSE_NAME_MAX,
            .source_len = 0,
            .owner_uid = 0,
            .allow_other = false,
            .active = false,
        };
    }
};

// ─────────────────── FUSE Manager ───────────────────────────────────

pub const FuseManager = struct {
    connections: [MAX_SESSIONS]FuseConnection,
    requests: [MAX_PENDING_REQUESTS]FuseRequest,
    cache: [MAX_CACHE_ENTRIES]CacheEntry,

    conn_count: u8,
    next_conn_id: u32,
    next_unique: u64,
    tick: u64,

    // Stats
    total_requests: u64,
    total_completed: u64,
    total_interrupted: u64,
    total_aborted: u64,
    total_cache_hits: u64,
    total_cache_misses: u64,
    total_notifications: u64,

    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var fm: Self = undefined;
        for (0..MAX_SESSIONS) |i| fm.connections[i] = FuseConnection.init();
        for (0..MAX_PENDING_REQUESTS) |i| fm.requests[i] = FuseRequest.init();
        for (0..MAX_CACHE_ENTRIES) |i| fm.cache[i] = CacheEntry.init();
        fm.conn_count = 0;
        fm.next_conn_id = 1;
        fm.next_unique = 1;
        fm.tick = 0;
        fm.total_requests = 0;
        fm.total_completed = 0;
        fm.total_interrupted = 0;
        fm.total_aborted = 0;
        fm.total_cache_hits = 0;
        fm.total_cache_misses = 0;
        fm.total_notifications = 0;
        fm.initialized = true;
        return fm;
    }

    // ─── Connection Lifecycle ───────────────────────────────────────

    pub fn create_connection(self: *Self, mount_point: []const u8, uid: u32) ?u8 {
        for (0..MAX_SESSIONS) |i| {
            if (!self.connections[i].active) {
                self.connections[i] = FuseConnection.init();
                self.connections[i].conn_id = self.next_conn_id;
                self.connections[i].state = .uninitialized;
                self.connections[i].owner_uid = uid;
                self.connections[i].active = true;
                self.next_conn_id += 1;

                const mlen = @min(mount_point.len, FUSE_NAME_MAX);
                @memcpy(self.connections[i].mount_point[0..mlen], mount_point[0..mlen]);
                self.connections[i].mount_point_len = @intCast(mlen);

                self.conn_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn fuse_init(self: *Self, conn_idx: u8, server_flags: u32) bool {
        if (conn_idx >= MAX_SESSIONS or !self.connections[conn_idx].active) return false;
        var conn = &self.connections[conn_idx];

        conn.state = .initializing;

        // Negotiate capabilities
        const flags: FuseInitFlags = @bitCast(server_flags);
        conn.init_flags = flags;
        conn.writeback_cache = flags.writeback_cache;
        conn.no_open = flags.no_open_support;
        conn.no_opendir = flags.no_opendir_support;
        conn.parallel_dirops = flags.parallel_dirops;
        conn.async_read = flags.async_read;

        if (flags.max_pages) {
            // Server declared max_pages support
            conn.max_pages = FUSE_MAX_PAGES;
        }

        conn.state = .active;
        return true;
    }

    pub fn fuse_destroy(self: *Self, conn_idx: u8) bool {
        if (conn_idx >= MAX_SESSIONS or !self.connections[conn_idx].active) return false;

        self.connections[conn_idx].state = .destroyed;

        // Abort all pending requests for this connection
        for (0..MAX_PENDING_REQUESTS) |i| {
            if (self.requests[i].active and self.requests[i].state != .completed) {
                self.requests[i].state = .aborted;
                self.requests[i].active = false;
                self.total_aborted += 1;
            }
        }

        // Invalidate cache entries
        for (0..MAX_CACHE_ENTRIES) |i| {
            self.cache[i].active = false;
        }

        self.connections[conn_idx].active = false;
        self.conn_count -= 1;
        return true;
    }

    // ─── Request Management ─────────────────────────────────────────

    pub fn submit_request(self: *Self, conn_idx: u8, opcode: FuseOpcode, nodeid: u64, uid: u32, pid: u32) ?u16 {
        if (conn_idx >= MAX_SESSIONS or !self.connections[conn_idx].active) return null;
        if (self.connections[conn_idx].state != .active) return null;

        for (0..MAX_PENDING_REQUESTS) |i| {
            if (!self.requests[i].active) {
                self.requests[i] = FuseRequest.init();
                self.requests[i].unique = self.next_unique;
                self.requests[i].opcode = @intFromEnum(opcode);
                self.requests[i].nodeid = nodeid;
                self.requests[i].uid = uid;
                self.requests[i].pid = pid;
                self.requests[i].state = .pending;
                self.requests[i].enqueue_tick = self.tick;
                self.requests[i].active = true;
                self.next_unique += 1;
                self.total_requests += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn submit_read(self: *Self, conn_idx: u8, nodeid: u64, offset: u64, size: u32, uid: u32, pid: u32) ?u16 {
        const req_idx = self.submit_request(conn_idx, .read, nodeid, uid, pid) orelse return null;
        self.requests[req_idx].offset = offset;
        self.requests[req_idx].size = @min(size, self.connections[conn_idx].max_read);
        return req_idx;
    }

    pub fn submit_write(self: *Self, conn_idx: u8, nodeid: u64, offset: u64, size: u32, uid: u32, pid: u32) ?u16 {
        const req_idx = self.submit_request(conn_idx, .write, nodeid, uid, pid) orelse return null;
        self.requests[req_idx].offset = offset;
        self.requests[req_idx].size = @min(size, self.connections[conn_idx].max_write);
        return req_idx;
    }

    pub fn submit_lookup(self: *Self, conn_idx: u8, parent_nodeid: u64, name: []const u8, uid: u32, pid: u32) ?u16 {
        // Check cache first
        if (self.cache_lookup(parent_nodeid, name)) |_| {
            self.total_cache_hits += 1;
            return null; // Satisfied from cache
        }
        self.total_cache_misses += 1;

        const req_idx = self.submit_request(conn_idx, .lookup, parent_nodeid, uid, pid) orelse return null;
        const nlen = @min(name.len, FUSE_NAME_MAX);
        @memcpy(self.requests[req_idx].name[0..nlen], name[0..nlen]);
        self.requests[req_idx].name_len = @intCast(nlen);
        return req_idx;
    }

    pub fn complete_request(self: *Self, req_idx: u16, error_code: i32) bool {
        if (req_idx >= MAX_PENDING_REQUESTS or !self.requests[req_idx].active) return false;
        if (self.requests[req_idx].state != .pending and self.requests[req_idx].state != .processing) return false;

        self.requests[req_idx].error = error_code;
        self.requests[req_idx].state = .completed;
        self.requests[req_idx].complete_tick = self.tick;
        self.total_completed += 1;

        // Cache the result if it was a lookup
        if (self.requests[req_idx].opcode == @intFromEnum(FuseOpcode.lookup) and error_code == 0) {
            self.cache_insert(self.requests[req_idx].out_nodeid, self.requests[req_idx].out_attr, 300);
        }

        self.requests[req_idx].active = false;
        return true;
    }

    pub fn interrupt_request(self: *Self, req_idx: u16) bool {
        if (req_idx >= MAX_PENDING_REQUESTS or !self.requests[req_idx].active) return false;
        if (self.requests[req_idx].state == .completed) return false;

        self.requests[req_idx].interrupted = true;
        self.requests[req_idx].state = .interrupted;
        self.requests[req_idx].active = false;
        self.total_interrupted += 1;
        return true;
    }

    // ─── Attr Cache ─────────────────────────────────────────────────

    fn cache_lookup(self: *Self, _parent: u64, _name: []const u8) ?*CacheEntry {
        // Would hash parent+name to nodeid; simplified version scans
        _ = _parent;
        _ = _name;
        // For real lookup we'd need a dentry cache mapping name→nodeid
        return null;
    }

    pub fn cache_get_attr(self: *Self, nodeid: u64) ?*CacheEntry {
        for (0..MAX_CACHE_ENTRIES) |i| {
            if (self.cache[i].active and self.cache[i].nodeid == nodeid) {
                if (self.cache[i].is_valid(self.tick)) {
                    self.total_cache_hits += 1;
                    return &self.cache[i];
                } else {
                    self.cache[i].active = false; // Expired
                    return null;
                }
            }
        }
        self.total_cache_misses += 1;
        return null;
    }

    fn cache_insert(self: *Self, nodeid: u64, attr: FuseAttr, timeout_ticks: u64) void {
        // Try to update existing
        for (0..MAX_CACHE_ENTRIES) |i| {
            if (self.cache[i].active and self.cache[i].nodeid == nodeid) {
                self.cache[i].attr = attr;
                self.cache[i].valid_until = self.tick + timeout_ticks;
                self.cache[i].generation += 1;
                return;
            }
        }
        // Find free slot or evict oldest
        var oldest_idx: usize = 0;
        var oldest_tick: u64 = @as(u64, 0) -% 1;
        for (0..MAX_CACHE_ENTRIES) |i| {
            if (!self.cache[i].active) {
                self.cache[i] = CacheEntry.init();
                self.cache[i].nodeid = nodeid;
                self.cache[i].attr = attr;
                self.cache[i].valid_until = self.tick + timeout_ticks;
                self.cache[i].active = true;
                return;
            }
            if (self.cache[i].valid_until < oldest_tick) {
                oldest_tick = self.cache[i].valid_until;
                oldest_idx = i;
            }
        }
        // Evict
        self.cache[oldest_idx].nodeid = nodeid;
        self.cache[oldest_idx].attr = attr;
        self.cache[oldest_idx].valid_until = self.tick + timeout_ticks;
        self.cache[oldest_idx].generation = 0;
    }

    pub fn cache_invalidate(self: *Self, nodeid: u64) void {
        for (0..MAX_CACHE_ENTRIES) |i| {
            if (self.cache[i].active and self.cache[i].nodeid == nodeid) {
                self.cache[i].active = false;
            }
        }
    }

    pub fn cache_invalidate_all(self: *Self) void {
        for (0..MAX_CACHE_ENTRIES) |i| {
            self.cache[i].active = false;
        }
    }

    // ─── Tick / Timeout ─────────────────────────────────────────────

    pub fn advance_tick(self: *Self) void {
        self.tick += 1;

        // Timeout stale requests (> 30s equivalent)
        for (0..MAX_PENDING_REQUESTS) |i| {
            if (self.requests[i].active and self.requests[i].state == .pending) {
                if (self.tick > self.requests[i].enqueue_tick + 30000) {
                    self.requests[i].state = .aborted;
                    self.requests[i].error = -110; // ETIMEDOUT
                    self.requests[i].active = false;
                    self.total_aborted += 1;
                }
            }
        }
    }

    // ─── Stats ──────────────────────────────────────────────────────

    pub fn pending_count(self: *const Self) u32 {
        var count: u32 = 0;
        for (0..MAX_PENDING_REQUESTS) |i| {
            if (self.requests[i].active and self.requests[i].state == .pending) count += 1;
        }
        return count;
    }

    pub fn cache_count(self: *const Self) u32 {
        var count: u32 = 0;
        for (0..MAX_CACHE_ENTRIES) |i| {
            if (self.cache[i].active) count += 1;
        }
        return count;
    }

    pub fn cache_hit_ratio(self: *const Self) u32 {
        const total = self.total_cache_hits + self.total_cache_misses;
        if (total == 0) return 0;
        return @intCast(self.total_cache_hits * 100 / total);
    }
};

// ─────────────────── Global State ───────────────────────────────────

var g_fuse: FuseManager = undefined;
var g_fuse_initialized: bool = false;

fn fm() *FuseManager {
    return &g_fuse;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_fuse_init() void {
    g_fuse = FuseManager.init();
    g_fuse_initialized = true;
}

export fn zxy_fuse_create_conn(mount_ptr: [*]const u8, mount_len: usize, uid: u32) i8 {
    if (!g_fuse_initialized) return -1;
    if (fm().create_connection(mount_ptr[0..mount_len], uid)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_fuse_do_init(conn_idx: u8, flags: u32) bool {
    if (!g_fuse_initialized) return false;
    return fm().fuse_init(conn_idx, flags);
}

export fn zxy_fuse_destroy_conn(conn_idx: u8) bool {
    if (!g_fuse_initialized) return false;
    return fm().fuse_destroy(conn_idx);
}

export fn zxy_fuse_submit_read(conn_idx: u8, nodeid: u64, offset: u64, size: u32, uid: u32, pid: u32) i16 {
    if (!g_fuse_initialized) return -1;
    if (fm().submit_read(conn_idx, nodeid, offset, size, uid, pid)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_fuse_submit_write(conn_idx: u8, nodeid: u64, offset: u64, size: u32, uid: u32, pid: u32) i16 {
    if (!g_fuse_initialized) return -1;
    if (fm().submit_write(conn_idx, nodeid, offset, size, uid, pid)) |idx| return @intCast(idx);
    return -1;
}

export fn zxy_fuse_complete(req_idx: u16, err: i32) bool {
    if (!g_fuse_initialized) return false;
    return fm().complete_request(req_idx, err);
}

export fn zxy_fuse_interrupt(req_idx: u16) bool {
    if (!g_fuse_initialized) return false;
    return fm().interrupt_request(req_idx);
}

export fn zxy_fuse_invalidate(nodeid: u64) void {
    if (g_fuse_initialized) fm().cache_invalidate(nodeid);
}

export fn zxy_fuse_conn_count() u8 {
    if (!g_fuse_initialized) return 0;
    return fm().conn_count;
}

export fn zxy_fuse_total_requests() u64 {
    if (!g_fuse_initialized) return 0;
    return fm().total_requests;
}

export fn zxy_fuse_total_completed() u64 {
    if (!g_fuse_initialized) return 0;
    return fm().total_completed;
}

export fn zxy_fuse_pending_count() u32 {
    if (!g_fuse_initialized) return 0;
    return fm().pending_count();
}

export fn zxy_fuse_cache_count() u32 {
    if (!g_fuse_initialized) return 0;
    return fm().cache_count();
}

export fn zxy_fuse_cache_hit_ratio() u32 {
    if (!g_fuse_initialized) return 0;
    return fm().cache_hit_ratio();
}

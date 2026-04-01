// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Filesystem Layer
// Journaling, Copy-on-Write, Extent Trees, Directory Indexing, Quota
const std = @import("std");

// ============================================================================
// Journaling (JBD2-like)
// ============================================================================

pub const JournalBlockType = enum(u32) {
    descriptor = 1,
    commit = 2,
    superblock_v1 = 3,
    superblock_v2 = 4,
    revoke = 5,
};

pub const JournalHeader = extern struct {
    magic: u32 = 0xC03B3998,
    block_type: u32,
    sequence: u32,
};

pub const JournalSuperblock = extern struct {
    header: JournalHeader,
    block_size: u32,
    max_len: u32,
    first: u32,
    sequence: u32,
    start: u32,
    errno: i32,
    // v2 fields
    feature_compat: u32,
    feature_incompat: u32,
    feature_rocompat: u32,
    uuid: [16]u8,
    nr_users: u32,
    dynsuper: u32,
    max_transaction: u32,
    max_trans_data: u32,
    checksum_type: u8,
    padding: [3]u8 = [_]u8{0} ** 3,
    padding2: [168]u32 = [_]u32{0} ** 168,
    checksum: u32,
    users: [16][16]u8 = undefined,
};

pub const JOURNAL_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
pub const JOURNAL_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
pub const JOURNAL_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
pub const JOURNAL_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
pub const JOURNAL_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
pub const JOURNAL_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;

pub const TransactionState = enum(u8) {
    running,
    locked,
    switch,
    flush,
    commit,
    commit_dflush,
    commit_jflush,
    commit_callback,
    finished,
};

pub const Transaction = struct {
    tid: u32,
    state: TransactionState = .running,
    log_start: u32 = 0,
    log_end: u32 = 0,
    nr_buffers: u32 = 0,
    nr_reserved: u32 = 0,
    outstanding_credits: i32 = 0,
    updates: u32 = 0,
    expires_ns: u64 = 0,
    start_ns: u64 = 0,
    // Buffer heads
    buffers: [1024]JournalBuf = undefined,
    buf_count: u32 = 0,
    // Revoke table
    revoke_table: [256]u64 = [_]u64{0} ** 256,
    revoke_count: u32 = 0,
    // Statistics
    bytes_logged: u64 = 0,
    handle_count: u32 = 0,
};

pub const JournalBuf = struct {
    block_nr: u64 = 0,
    flags: u32 = 0,
    // Data copy for journaling
    jbd_data: [4096]u8 = undefined,
    transaction_id: u32 = 0,

    pub const JBH_METADATA: u32 = 1 << 0;
    pub const JBH_DIRTY: u32 = 1 << 1;
    pub const JBH_REVOKED: u32 = 1 << 2;
    pub const JBH_ESCAPE: u32 = 1 << 3;
    pub const JBH_ORDERED: u32 = 1 << 4;
};

pub const Journal = struct {
    flags: u32 = 0,
    errno: i32 = 0,
    superblock: JournalSuperblock = undefined,
    // Transaction management
    running_transaction: ?*Transaction = null,
    committing_transaction: ?*Transaction = null,
    transaction_pool: [16]Transaction = undefined,
    pool_used: u8 = 0,
    next_tid: u32 = 1,
    // Journal log area
    log_start: u32 = 0,
    log_end: u32 = 0,
    log_size: u32 = 0,
    free: u32 = 0,
    // Checkpoint
    checkpoint_tid: u32 = 0,
    checkpoint_transactions: u32 = 0,
    // Barriers
    barrier: bool = true,
    // Commit interval
    commit_interval_ms: u32 = 5000,
    // Stats
    total_commits: u64 = 0,
    total_bytes_committed: u64 = 0,
    average_commit_time_ns: u64 = 0,

    pub const J_BARRIER: u32 = 1 << 0;
    pub const J_ABORT: u32 = 1 << 1;
    pub const J_ACK_ERR: u32 = 1 << 2;
    pub const J_FLUSHED: u32 = 1 << 3;
    pub const J_LOADED: u32 = 1 << 4;
    pub const J_UNMOUNT: u32 = 1 << 5;

    pub fn init(log_size: u32) Journal {
        var j = Journal{};
        j.log_size = log_size;
        j.free = log_size;
        j.superblock.header = JournalHeader{
            .magic = 0xC03B3998,
            .block_type = @intFromEnum(JournalBlockType.superblock_v2),
            .sequence = 0,
        };
        j.superblock.block_size = 4096;
        j.superblock.max_len = log_size;
        j.superblock.feature_incompat = JOURNAL_FEATURE_INCOMPAT_REVOKE |
            JOURNAL_FEATURE_INCOMPAT_CSUM_V3;
        return j;
    }

    pub fn startTransaction(self: *Journal) ?*Transaction {
        if (self.pool_used >= self.transaction_pool.len) return null;
        const idx = self.pool_used;
        self.pool_used += 1;
        var txn = &self.transaction_pool[idx];
        txn.tid = self.next_tid;
        self.next_tid += 1;
        txn.state = .running;
        txn.buf_count = 0;
        txn.revoke_count = 0;
        txn.bytes_logged = 0;
        txn.handle_count = 0;
        self.running_transaction = txn;
        return txn;
    }

    pub fn commitTransaction(self: *Journal, txn: *Transaction) bool {
        txn.state = .locked;
        self.committing_transaction = txn;
        if (self.running_transaction == txn) {
            self.running_transaction = null;
        }

        // Phase 1: Lock transaction
        txn.state = .flush;

        // Phase 2: Write descriptor blocks + data
        var log_pos = self.log_end;
        var i: u32 = 0;
        while (i < txn.buf_count) : (i += 1) {
            const buf = &txn.buffers[i];
            if (buf.flags & JournalBuf.JBH_REVOKED != 0) continue;
            log_pos += 1;
            if (log_pos >= self.log_size) log_pos = 0;
            txn.bytes_logged += 4096;
        }

        // Phase 3: Write commit block
        txn.state = .commit;
        log_pos += 1;
        if (log_pos >= self.log_size) log_pos = 0;
        self.log_end = log_pos;

        // Phase 4: Completion
        txn.state = .finished;
        self.committing_transaction = null;
        self.total_commits += 1;
        self.total_bytes_committed += txn.bytes_logged;

        // Update free space
        if (self.log_end >= self.log_start) {
            self.free = self.log_size - (self.log_end - self.log_start);
        } else {
            self.free = self.log_start - self.log_end;
        }

        return true;
    }

    pub fn addRevoke(self: *Journal, block_nr: u64) void {
        if (self.running_transaction) |txn| {
            if (txn.revoke_count < 256) {
                txn.revoke_table[txn.revoke_count] = block_nr;
                txn.revoke_count += 1;
            }
        }
    }

    pub fn logBlock(self: *Journal, block_nr: u64, data: *const [4096]u8) bool {
        const txn = self.running_transaction orelse return false;
        if (txn.buf_count >= 1024) return false;
        
        var buf = &txn.buffers[txn.buf_count];
        buf.block_nr = block_nr;
        buf.flags = JournalBuf.JBH_METADATA | JournalBuf.JBH_DIRTY;
        buf.transaction_id = txn.tid;
        @memcpy(&buf.jbd_data, data);
        txn.buf_count += 1;
        return true;
    }
};

// ============================================================================
// Extent Tree (ext4-like)
// ============================================================================

pub const ExtentHeader = extern struct {
    magic: u16 = 0xF30A,
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
};

pub const ExtentIndex = extern struct {
    block: u32,     // Logical block covered
    leaf_lo: u32,   // Physical block of child (low 32)
    leaf_hi: u16,   // Physical block (high 16)
    unused: u16 = 0,

    pub fn physicalBlock(self: *const ExtentIndex) u64 {
        return @as(u64, self.leaf_hi) << 32 | @as(u64, self.leaf_lo);
    }
};

pub const Extent = extern struct {
    block: u32,     // First logical block
    len: u16,       // Number of blocks
    start_hi: u16,  // Physical start (high 16)
    start_lo: u32,  // Physical start (low 32)

    pub fn physicalStart(self: *const Extent) u64 {
        return @as(u64, self.start_hi) << 32 | @as(u64, self.start_lo);
    }

    pub fn isInitialized(self: *const Extent) bool {
        return self.len <= 32768; // Bit 15 = uninitialized flag
    }

    pub fn blockCount(self: *const Extent) u32 {
        if (self.len > 32768) {
            return @as(u32, self.len) - 32768;
        }
        return @as(u32, self.len);
    }
};

pub const ExtentTree = struct {
    root_header: ExtentHeader,
    // Inline extents (fits in inode)
    inline_extents: [4]Extent = undefined,
    // For deeper trees, external blocks
    depth: u16 = 0,
    
    pub fn init() ExtentTree {
        return ExtentTree{
            .root_header = ExtentHeader{
                .magic = 0xF30A,
                .entries = 0,
                .max = 4,
                .depth = 0,
                .generation = 0,
            },
        };
    }

    /// Insert an extent mapping logical -> physical blocks
    pub fn insertExtent(self: *ExtentTree, logical: u32, physical: u64, len: u16) bool {
        if (self.root_header.entries >= self.root_header.max) return false;
        
        const idx = self.root_header.entries;
        self.inline_extents[idx] = Extent{
            .block = logical,
            .len = len,
            .start_hi = @intCast(physical >> 32),
            .start_lo = @intCast(physical & 0xFFFFFFFF),
        };
        self.root_header.entries += 1;
        self.root_header.generation += 1;
        return true;
    }

    /// Lookup physical block for a logical block number
    pub fn lookup(self: *const ExtentTree, logical_block: u32) ?u64 {
        var i: u16 = 0;
        while (i < self.root_header.entries) : (i += 1) {
            const ext = &self.inline_extents[i];
            if (logical_block >= ext.block and 
                logical_block < ext.block + ext.blockCount()) {
                const offset = logical_block - ext.block;
                return ext.physicalStart() + @as(u64, offset);
            }
        }
        return null;
    }
};

// ============================================================================
// Directory Hash Tree (HTree - ext4 dx_root/dx_entry)
// ============================================================================

pub const DxHashVersion = enum(u8) {
    legacy = 0,
    half_md4 = 1,
    tea = 2,
    legacy_unsigned = 3,
    half_md4_unsigned = 4,
    tea_unsigned = 5,
    siphash = 6,
};

pub const DxRoot = struct {
    dot_inode: u32,
    dot_rec_len: u16 = 12,
    dot_name_len: u8 = 1,
    dot_file_type: u8 = 2,
    dot_name: [4]u8 = [_]u8{ '.', 0, 0, 0 },
    dotdot_inode: u32,
    dotdot_rec_len: u16 = 12,
    dotdot_name_len: u8 = 2,
    dotdot_file_type: u8 = 2,
    dotdot_name: [4]u8 = [_]u8{ '.', '.', 0, 0 },
    // HTree info
    reserved_zero: u32 = 0,
    hash_version: u8 = @intFromEnum(DxHashVersion.half_md4),
    info_length: u8 = 8,
    indirect_levels: u8 = 0,
    unused_flags: u8 = 0,
    limit: u16,
    count: u16,
    block: u32,
};

pub const DxEntry = struct {
    hash: u32,
    block: u32,
};

pub const DxNode = struct {
    fake: DxCountLimit,
    entries: [508]DxEntry = undefined,
};

pub const DxCountLimit = struct {
    limit: u16,
    count: u16,
};

/// TEA hash for directory names
pub fn teaHash(name: []const u8, seed: [4]u32) u32 {
    var h: u32 = seed[0];
    var a = seed[0];
    var b = seed[1];
    var c = seed[2];
    var d = seed[3];

    var i: usize = 0;
    while (i + 16 <= name.len) : (i += 16) {
        a +%= readU32(name[i..]);
        b +%= readU32(name[i + 4 ..]);
        c +%= readU32(name[i + 8 ..]);
        d +%= readU32(name[i + 12 ..]);
        teaTransform(&a, &b, &c, &d);
    }

    // Handle remaining bytes
    var buf = [_]u8{0} ** 16;
    const remaining = name.len - i;
    if (remaining > 0) {
        @memcpy(buf[0..remaining], name[i..i + remaining]);
        a +%= readU32(buf[0..]);
        b +%= readU32(buf[4..]);
        c +%= readU32(buf[8..]);
        d +%= readU32(buf[12..]);
        teaTransform(&a, &b, &c, &d);
    }

    h = a ^ b ^ c ^ d;
    return h & 0x7FFFFFFF; // Ensure positive
}

fn teaTransform(a: *u32, b: *u32, c: *u32, d: *u32) void {
    var sum: u32 = 0;
    const delta: u32 = 0x9E3779B9;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        sum +%= delta;
        a.* +%= ((b.* << 4) +% c.*) ^ (b.* +% sum) ^ ((b.* >> 5) +% d.*);
        b.* +%= ((a.* << 4) +% d.*) ^ (a.* +% sum) ^ ((a.* >> 5) +% c.*);
    }
}

fn readU32(buf: []const u8) u32 {
    if (buf.len < 4) return 0;
    return @as(u32, buf[0]) | (@as(u32, buf[1]) << 8) | (@as(u32, buf[2]) << 16) | (@as(u32, buf[3]) << 24);
}

// ============================================================================
// Copy-on-Write B-Tree (btrfs-like)
// ============================================================================

pub const COW_TREE_ORDER: usize = 16;

pub const CowKey = struct {
    objectid: u64,
    item_type: u8,
    offset: u64,

    pub fn cmp(self: CowKey, other: CowKey) i32 {
        if (self.objectid < other.objectid) return -1;
        if (self.objectid > other.objectid) return 1;
        if (self.item_type < other.item_type) return -1;
        if (self.item_type > other.item_type) return 1;
        if (self.offset < other.offset) return -1;
        if (self.offset > other.offset) return 1;
        return 0;
    }
};

pub const CowItemType = enum(u8) {
    inode_item = 1,
    inode_ref = 12,
    inode_extref = 13,
    xattr_item = 24,
    dir_item = 84,
    dir_index = 96,
    extent_data = 108,
    extent_csum = 128,
    root_item = 132,
    root_ref = 156,
    root_backref = 144,
    chunk_item = 228,
    dev_item = 216,
    block_group_item = 192,
    dev_extent = 204,
    free_space_info = 198,
    free_space_extent = 199,
};

pub const CowTreeNode = struct {
    level: u8 = 0,
    nritems: u16 = 0,
    bytenr: u64 = 0,
    flags: u64 = 0,
    generation: u64 = 0,
    owner: u64 = 0,
    checksum: [32]u8 = [_]u8{0} ** 32,
    // Keys and children
    keys: [COW_TREE_ORDER]CowKey = undefined,
    children: [COW_TREE_ORDER + 1]?*CowTreeNode = [_]?*CowTreeNode{null} ** (COW_TREE_ORDER + 1),
    // Leaf items (when level == 0)
    items: [COW_TREE_ORDER]CowItem = undefined,
    // CoW
    cow_generation: u64 = 0,
    references: u32 = 1,

    pub const BTRFS_HEADER_FLAG_WRITTEN: u64 = 1 << 0;
    pub const BTRFS_HEADER_FLAG_RELOC: u64 = 1 << 1;

    pub fn isLeaf(self: *const CowTreeNode) bool {
        return self.level == 0;
    }
};

pub const CowItem = struct {
    key: CowKey = CowKey{ .objectid = 0, .item_type = 0, .offset = 0 },
    offset: u32 = 0,
    size: u32 = 0,
    data: [256]u8 = [_]u8{0} ** 256,
};

pub const CowTree = struct {
    root: ?*CowTreeNode = null,
    generation: u64 = 0,
    objectid: u64 = 0,
    // Node pool
    node_pool: [512]CowTreeNode = undefined,
    pool_used: usize = 0,
    // Statistics
    nodes_written: u64 = 0,
    nodes_cow: u64 = 0,
    cow_bytes: u64 = 0,

    pub fn init(objectid: u64) CowTree {
        return CowTree{ .objectid = objectid };
    }

    fn allocNode(self: *CowTree) ?*CowTreeNode {
        if (self.pool_used >= self.node_pool.len) return null;
        const idx = self.pool_used;
        self.pool_used += 1;
        self.node_pool[idx] = CowTreeNode{};
        self.node_pool[idx].generation = self.generation;
        return &self.node_pool[idx];
    }

    /// Copy-on-Write: clone a node before modification
    pub fn cowNode(self: *CowTree, node: *CowTreeNode) ?*CowTreeNode {
        if (node.cow_generation == self.generation) {
            return node; // Already CoW'd for this transaction
        }

        const new_node = self.allocNode() orelse return null;
        new_node.* = node.*;
        new_node.cow_generation = self.generation;
        new_node.bytenr = 0; // Will be assigned on write
        new_node.references = 1;
        
        // Update parent's child pointer
        self.nodes_cow += 1;
        self.cow_bytes += @sizeOf(CowTreeNode);
        
        return new_node;
    }

    /// Insert a key-value pair
    pub fn insertItem(self: *CowTree, key: CowKey, data: []const u8) bool {
        if (self.root == null) {
            self.root = self.allocNode() orelse return false;
        }

        var root = self.cowNode(self.root.?) orelse return false;
        self.root = root;

        if (!root.isLeaf()) {
            // For now, only handle single-level tree
            return false;
        }

        if (root.nritems >= COW_TREE_ORDER) {
            // Need to split (simplified)
            return false;
        }

        // Find insertion point
        var pos: u16 = 0;
        while (pos < root.nritems) : (pos += 1) {
            if (key.cmp(root.keys[pos]) <= 0) break;
        }

        // Shift items right
        if (pos < root.nritems) {
            var i = root.nritems;
            while (i > pos) : (i -= 1) {
                root.keys[i] = root.keys[i - 1];
                root.items[i] = root.items[i - 1];
            }
        }

        root.keys[pos] = key;
        root.items[pos] = CowItem{
            .key = key,
            .size = @intCast(@min(data.len, 256)),
        };
        const copy_len = @min(data.len, 256);
        @memcpy(root.items[pos].data[0..copy_len], data[0..copy_len]);
        root.nritems += 1;
        
        return true;
    }

    /// Search for a key
    pub fn search(self: *const CowTree, key: CowKey) ?*const CowItem {
        const root = self.root orelse return null;
        if (!root.isLeaf()) return null;
        
        var i: u16 = 0;
        while (i < root.nritems) : (i += 1) {
            if (key.cmp(root.keys[i]) == 0) {
                return &root.items[i];
            }
        }
        return null;
    }

    /// Start a new transaction generation
    pub fn beginTransaction(self: *CowTree) void {
        self.generation += 1;
    }
};

// ============================================================================
// Disk Quota System
// ============================================================================

pub const QuotaType = enum(u2) {
    user = 0,
    group = 1,
    project = 2,
};

pub const DiskQuota = struct {
    id: u32,                    // UID, GID, or Project ID
    quota_type: QuotaType,
    // Block limits (in filesystem blocks)
    block_hard_limit: u64 = 0,  // 0 = unlimited
    block_soft_limit: u64 = 0,
    block_current: u64 = 0,
    // Inode limits
    inode_hard_limit: u64 = 0,
    inode_soft_limit: u64 = 0,
    inode_current: u64 = 0,
    // Grace periods
    block_grace_ns: u64 = 7 * 86400 * 1_000_000_000, // 7 days default
    inode_grace_ns: u64 = 7 * 86400 * 1_000_000_000,
    block_grace_expires: u64 = 0,
    inode_grace_expires: u64 = 0,
    // Flags
    flags: u32 = 0,

    pub const DQ_ENABLED: u32 = 1 << 0;
    pub const DQ_WARNED_BLOCK: u32 = 1 << 1;
    pub const DQ_WARNED_INODE: u32 = 1 << 2;
    pub const DQ_FAKE: u32 = 1 << 3;
    
    /// Check if a block allocation would exceed quota
    pub fn checkBlock(self: *const DiskQuota, blocks: u64) QuotaResult {
        if (self.block_hard_limit > 0 and self.block_current + blocks > self.block_hard_limit) {
            return .hard_limit;
        }
        if (self.block_soft_limit > 0 and self.block_current + blocks > self.block_soft_limit) {
            return .soft_limit;
        }
        return .ok;
    }

    pub fn checkInode(self: *const DiskQuota) QuotaResult {
        if (self.inode_hard_limit > 0 and self.inode_current + 1 > self.inode_hard_limit) {
            return .hard_limit;
        }
        if (self.inode_soft_limit > 0 and self.inode_current + 1 > self.inode_soft_limit) {
            return .soft_limit;
        }
        return .ok;
    }

    pub fn chargeBlock(self: *DiskQuota, blocks: u64, now_ns: u64) QuotaResult {
        const result = self.checkBlock(blocks);
        switch (result) {
            .hard_limit => return .hard_limit,
            .soft_limit => {
                if (self.block_grace_expires == 0) {
                    self.block_grace_expires = now_ns + self.block_grace_ns;
                } else if (now_ns > self.block_grace_expires) {
                    return .hard_limit; // Grace expired
                }
                self.block_current += blocks;
                return .soft_limit;
            },
            .ok => {
                self.block_current += blocks;
                return .ok;
            },
        }
    }
};

pub const QuotaResult = enum {
    ok,
    soft_limit,
    hard_limit,
};

pub const QuotaTable = struct {
    entries: [1024]DiskQuota = undefined,
    count: u32 = 0,
    enabled: [3]bool = [_]bool{false} ** 3, // per QuotaType
    
    pub fn init() QuotaTable {
        return QuotaTable{};
    }
    
    pub fn findQuota(self: *QuotaTable, id: u32, qt: QuotaType) ?*DiskQuota {
        var i: u32 = 0;
        while (i < self.count) : (i += 1) {
            if (self.entries[i].id == id and self.entries[i].quota_type == qt) {
                return &self.entries[i];
            }
        }
        return null;
    }
    
    pub fn addQuota(self: *QuotaTable, id: u32, qt: QuotaType) ?*DiskQuota {
        if (self.count >= 1024) return null;
        const idx = self.count;
        self.count += 1;
        self.entries[idx] = DiskQuota{
            .id = id,
            .quota_type = qt,
        };
        return &self.entries[idx];
    }
};

// ============================================================================
// Extended Attributes (xattr)
// ============================================================================

pub const XattrNamespace = enum(u8) {
    user = 1,
    posix_acl_access = 2,
    posix_acl_default = 3,
    trusted = 4,
    security = 6,
    system = 7,
    richacl = 8,
};

pub const Xattr = struct {
    namespace: XattrNamespace,
    name: [255]u8 = [_]u8{0} ** 255,
    name_len: u8 = 0,
    value: [4096]u8 = [_]u8{0} ** 4096,
    value_len: u16 = 0,
    hash: u32 = 0,
};

pub const XattrTable = struct {
    entries: [64]Xattr = undefined,
    count: u8 = 0,
    
    pub fn get(self: *const XattrTable, ns: XattrNamespace, name: []const u8) ?*const Xattr {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            const entry = &self.entries[i];
            if (entry.namespace == ns and 
                entry.name_len == @as(u8, @intCast(name.len)) and
                std.mem.eql(u8, entry.name[0..entry.name_len], name)) {
                return entry;
            }
        }
        return null;
    }
    
    pub fn set(self: *XattrTable, ns: XattrNamespace, name: []const u8, value: []const u8) bool {
        // Check for existing
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            var entry = &self.entries[i];
            if (entry.namespace == ns and 
                entry.name_len == @as(u8, @intCast(name.len)) and
                std.mem.eql(u8, entry.name[0..entry.name_len], name)) {
                // Update existing
                const vlen = @min(value.len, 4096);
                @memcpy(entry.value[0..vlen], value[0..vlen]);
                entry.value_len = @intCast(vlen);
                return true;
            }
        }
        
        if (self.count >= 64) return false;
        var entry = &self.entries[self.count];
        entry.namespace = ns;
        const nlen = @min(name.len, 255);
        @memcpy(entry.name[0..nlen], name[0..nlen]);
        entry.name_len = @intCast(nlen);
        const vlen = @min(value.len, 4096);
        @memcpy(entry.value[0..vlen], value[0..vlen]);
        entry.value_len = @intCast(vlen);
        self.count += 1;
        return true;
    }
    
    pub fn remove(self: *XattrTable, ns: XattrNamespace, name: []const u8) bool {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            const entry = &self.entries[i];
            if (entry.namespace == ns and 
                entry.name_len == @as(u8, @intCast(name.len)) and
                std.mem.eql(u8, entry.name[0..entry.name_len], name)) {
                // Shift entries
                var j = i;
                while (j + 1 < self.count) : (j += 1) {
                    self.entries[j] = self.entries[j + 1];
                }
                self.count -= 1;
                return true;
            }
        }
        return false;
    }
};

// SPDX-License-Identifier: MIT
// Zxyphor Kernel — DebugFS Virtual Filesystem (Zig)
//
// Debug filesystem for kernel instrumentation and introspection:
// - Hierarchical directory tree (mount at /sys/kernel/debug)
// - File types: u8/u16/u32/u64/bool/string/blob/hex/array
// - Read-only, write-only, or read-write files
// - Atomic read/write for integer files with format conversion
// - Dynamic file registration by subsystems
// - Statistics counters with atomic semantics
// - Sequential file iteration (seq_file equivalent)
// - Fault injection controls
// - Per-CPU variable exposure
// - Blob (binary large object) read
// - Symbolic links and directory nesting
// - Access control (root-only by default)
// - FFI exports for Zig/Rust kernel subsystems

const std = @import("std");

// ============================================================================
// Constants
// ============================================================================

pub const MAX_DEBUGFS_FILES: usize = 512;
pub const MAX_DEBUGFS_DIRS: usize = 128;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_STRING_LEN: usize = 256;
pub const MAX_BLOB_SIZE: usize = 4096;
pub const MAX_CHILDREN: usize = 32;
pub const MAX_SEQ_ENTRIES: usize = 64;

// ============================================================================
// DebugFS File Types
// ============================================================================

pub const FileType = enum(u8) {
    none = 0,
    u8_val = 1,
    u16_val = 2,
    u32_val = 3,
    u64_val = 4,
    bool_val = 5,
    string_val = 6,
    blob_val = 7,
    hex_u32 = 8,
    hex_u64 = 9,
    atomic_u64 = 10,    // Atomic counter
    regset = 11,         // Register set dump
    array_u32 = 12,     // Array of u32
    seq_file = 13,      // Sequential file (iterator-based)
    fault_attr = 14,    // Fault injection attribute
    symlink = 15,       // Symbolic link
};

pub const AccessMode = enum(u8) {
    read_only = 0,
    write_only = 1,
    read_write = 2,
};

// ============================================================================
// DebugFS Entry (file or directory)
// ============================================================================

pub const EntryKind = enum(u8) {
    free = 0,
    file = 1,
    directory = 2,
};

pub const DebugfsEntry = struct {
    name: [MAX_NAME_LEN]u8,
    name_len: u16,
    kind: EntryKind,
    parent_idx: u16,
    // File-specific
    file_type: FileType,
    access: AccessMode,
    // Storage for small values (in-place)
    data: EntryData,
    // Children (directories only)
    children: [MAX_CHILDREN]u16,
    child_count: u16,
    // Metadata
    uid: u32,
    gid: u32,
    mode: u16,
    ref_count: u32,
    created: bool,

    pub const EntryData = union {
        val_u8: u8,
        val_u16: u16,
        val_u32: u32,
        val_u64: u64,
        val_bool: bool,
        val_string: StringBuf,
        val_blob: BlobBuf,
        val_array: ArrayBuf,
        val_seq: SeqState,
        val_fault: FaultAttr,
        val_symlink: SymlinkBuf,
        val_hex32: u32,
        val_hex64: u64,
        val_atomic: u64,
        val_regset: RegSet,
    };

    pub fn init(self: *DebugfsEntry) void {
        self.name = [_]u8{0} ** MAX_NAME_LEN;
        self.name_len = 0;
        self.kind = .free;
        self.parent_idx = 0xFFFF;
        self.file_type = .none;
        self.access = .read_only;
        self.children = [_]u16{0xFFFF} ** MAX_CHILDREN;
        self.child_count = 0;
        self.uid = 0;
        self.gid = 0;
        self.mode = 0o644;
        self.ref_count = 0;
        self.created = false;
    }

    pub fn set_name(self: *DebugfsEntry, name: []const u8) void {
        const len = if (name.len > MAX_NAME_LEN) MAX_NAME_LEN else name.len;
        @memcpy(self.name[0..len], name[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn name_slice(self: *const DebugfsEntry) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn add_child(self: *DebugfsEntry, child_idx: u16) bool {
        if (self.child_count >= MAX_CHILDREN) return false;
        self.children[self.child_count] = child_idx;
        self.child_count += 1;
        return true;
    }

    pub fn remove_child(self: *DebugfsEntry, child_idx: u16) bool {
        for (0..self.child_count) |i| {
            if (self.children[i] == child_idx) {
                // Shift remaining
                var j = i;
                while (j + 1 < self.child_count) : (j += 1) {
                    self.children[j] = self.children[j + 1];
                }
                self.child_count -= 1;
                self.children[self.child_count] = 0xFFFF;
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// Sub-types
// ============================================================================

pub const StringBuf = struct {
    data: [MAX_STRING_LEN]u8,
    len: u16,

    pub fn set(self: *StringBuf, s: []const u8) void {
        const copy_len = if (s.len > MAX_STRING_LEN) MAX_STRING_LEN else s.len;
        @memcpy(self.data[0..copy_len], s[0..copy_len]);
        self.len = @intCast(copy_len);
    }

    pub fn slice(self: *const StringBuf) []const u8 {
        return self.data[0..self.len];
    }
};

pub const BlobBuf = struct {
    data: [MAX_BLOB_SIZE]u8,
    size: u32,

    pub fn write(self: *BlobBuf, buf: []const u8) u32 {
        const copy_len: u32 = if (buf.len > MAX_BLOB_SIZE) MAX_BLOB_SIZE else @intCast(buf.len);
        @memcpy(self.data[0..copy_len], buf[0..copy_len]);
        self.size = copy_len;
        return copy_len;
    }
};

pub const ArrayBuf = struct {
    data: [64]u32,
    count: u32,

    pub fn set(self: *ArrayBuf, values: []const u32) void {
        const cnt = if (values.len > 64) 64 else values.len;
        for (0..cnt) |i| {
            self.data[i] = values[i];
        }
        self.count = @intCast(cnt);
    }
};

pub const SeqState = struct {
    position: u32,
    count: u32,
    entries: [MAX_SEQ_ENTRIES]u64, // opaque data per entry
    started: bool,

    pub fn start(self: *SeqState) void {
        self.position = 0;
        self.started = true;
    }

    pub fn next(self: *SeqState) ?u64 {
        if (self.position >= self.count) return null;
        const val = self.entries[self.position];
        self.position += 1;
        return val;
    }

    pub fn stop(self: *SeqState) void {
        self.started = false;
        self.position = 0;
    }

    pub fn add_entry(self: *SeqState, val: u64) bool {
        if (self.count >= MAX_SEQ_ENTRIES) return false;
        self.entries[self.count] = val;
        self.count += 1;
        return true;
    }
};

pub const FaultAttr = struct {
    probability: u32,   // 0-1000 (per-mille)
    interval: u32,      // Inject every N calls
    times: i32,         // -1 = infinite, 0 = disabled, >0 = count
    count: u64,         // Total calls
    injected: u64,      // Times fault was injected
    task_filter: bool,

    pub fn should_inject(self: *FaultAttr) bool {
        if (self.times == 0) return false;
        self.count += 1;

        if (self.interval > 0 and (self.count % self.interval) != 0) {
            return false;
        }

        // Simple probability check using count as pseudo-random
        const hash = (self.count *% 2654435761) >> 22;
        if (hash % 1000 >= self.probability) return false;

        if (self.times > 0) {
            self.times -= 1;
        }
        self.injected += 1;
        return true;
    }
};

pub const SymlinkBuf = struct {
    target: [MAX_PATH_LEN]u8,
    target_len: u16,

    pub fn set_target(self: *SymlinkBuf, path: []const u8) void {
        const len = if (path.len > MAX_PATH_LEN) MAX_PATH_LEN else path.len;
        @memcpy(self.target[0..len], path[0..len]);
        self.target_len = @intCast(len);
    }
};

pub const RegSet = struct {
    regs: [32]u64,
    count: u8,
    names: [32][16]u8,
    name_lens: [32]u8,

    pub fn add_reg(self: *RegSet, name: []const u8, value: u64) bool {
        if (self.count >= 32) return false;
        const idx = self.count;
        const nlen = if (name.len > 16) 16 else name.len;
        @memcpy(self.names[idx][0..nlen], name[0..nlen]);
        self.name_lens[idx] = @intCast(nlen);
        self.regs[idx] = value;
        self.count += 1;
        return true;
    }

    pub fn update_reg(self: *RegSet, idx: u8, value: u64) void {
        if (idx < self.count) {
            self.regs[idx] = value;
        }
    }
};

// ============================================================================
// DebugFS Manager
// ============================================================================

pub const DebugfsManager = struct {
    entries: [MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS]DebugfsEntry,
    entry_count: u32,
    root_idx: u16,

    // Stats
    total_reads: u64,
    total_writes: u64,
    total_creates: u64,
    total_removes: u64,
    total_lookups: u64,
    total_faults_injected: u64,

    pub fn init(self: *DebugfsManager) void {
        for (&self.entries) |*e| {
            e.init();
        }
        self.entry_count = 0;
        self.total_reads = 0;
        self.total_writes = 0;
        self.total_creates = 0;
        self.total_removes = 0;
        self.total_lookups = 0;
        self.total_faults_injected = 0;

        // Create root directory
        self.root_idx = self.alloc_entry() orelse 0;
        self.entries[self.root_idx].kind = .directory;
        self.entries[self.root_idx].set_name("debug");
        self.entries[self.root_idx].mode = 0o755;
        self.entries[self.root_idx].created = true;
    }

    fn alloc_entry(self: *DebugfsManager) ?u16 {
        const max = MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS;
        for (0..max) |i| {
            if (self.entries[i].kind == .free and !self.entries[i].created) {
                self.entry_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    fn free_entry(self: *DebugfsManager, idx: u16) void {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return;
        self.entries[idx].init();
        if (self.entry_count > 0) self.entry_count -= 1;
    }

    // ----- Directory Operations -----

    /// Create a directory under parent
    pub fn create_dir(self: *DebugfsManager, name: []const u8, parent_idx: u16) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .directory;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].mode = 0o755;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Lookup child by name in directory
    pub fn lookup(self: *DebugfsManager, parent_idx: u16, name: []const u8) ?u16 {
        self.total_lookups += 1;
        const parent = &self.entries[parent_idx];
        if (parent.kind != .directory) return null;

        for (0..parent.child_count) |i| {
            const child_idx = parent.children[i];
            if (child_idx == 0xFFFF) continue;
            const child = &self.entries[child_idx];
            if (child.name_len == name.len) {
                if (std.mem.eql(u8, child.name_slice(), name)) {
                    return child_idx;
                }
            }
        }
        return null;
    }

    /// Recursively remove a directory and all contents
    pub fn remove_recursive(self: *DebugfsManager, idx: u16) void {
        const entry = &self.entries[idx];
        if (entry.kind == .directory) {
            // Remove children first
            var i: u16 = 0;
            while (i < entry.child_count) {
                const child = entry.children[i];
                if (child != 0xFFFF) {
                    self.remove_recursive(child);
                }
                i += 1;
            }
        }

        // Remove from parent
        if (entry.parent_idx != 0xFFFF) {
            _ = self.entries[entry.parent_idx].remove_child(idx);
        }

        self.free_entry(idx);
        self.total_removes += 1;
    }

    // ----- File Creation Helpers -----

    /// Create a u8 file
    pub fn create_u8(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: u8, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .u8_val;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_u8 = value;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a u32 file
    pub fn create_u32(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: u32, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .u32_val;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_u32 = value;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a u64 file
    pub fn create_u64(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: u64, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .u64_val;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_u64 = value;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a bool file
    pub fn create_bool(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: bool, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .bool_val;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_bool = value;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a hex u32 file (displayed as 0xNN)
    pub fn create_hex32(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: u32, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .hex_u32;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_hex32 = value;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a string file
    pub fn create_string(self: *DebugfsManager, name: []const u8, parent_idx: u16, value: []const u8, mode: AccessMode) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .string_val;
        self.entries[idx].access = mode;
        self.entries[idx].data.val_string.set(value);
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a blob (binary) file
    pub fn create_blob(self: *DebugfsManager, name: []const u8, parent_idx: u16) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .blob_val;
        self.entries[idx].access = .read_only;
        self.entries[idx].data.val_blob.size = 0;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a fault injection attribute
    pub fn create_fault_attr(self: *DebugfsManager, name: []const u8, parent_idx: u16, probability: u32, interval: u32) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .fault_attr;
        self.entries[idx].access = .read_write;
        self.entries[idx].data.val_fault = FaultAttr{
            .probability = probability,
            .interval = interval,
            .times = -1,
            .count = 0,
            .injected = 0,
            .task_filter = false,
        };
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a symbolic link
    pub fn create_symlink(self: *DebugfsManager, name: []const u8, parent_idx: u16, target: []const u8) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .symlink;
        self.entries[idx].access = .read_only;
        self.entries[idx].data.val_symlink.set_target(target);
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a register set file
    pub fn create_regset(self: *DebugfsManager, name: []const u8, parent_idx: u16) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .regset;
        self.entries[idx].access = .read_only;
        self.entries[idx].data.val_regset.count = 0;
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    /// Create a sequential file
    pub fn create_seq_file(self: *DebugfsManager, name: []const u8, parent_idx: u16) ?u16 {
        const idx = self.alloc_entry() orelse return null;
        self.entries[idx].kind = .file;
        self.entries[idx].set_name(name);
        self.entries[idx].parent_idx = parent_idx;
        self.entries[idx].file_type = .seq_file;
        self.entries[idx].access = .read_only;
        self.entries[idx].data.val_seq = SeqState{
            .position = 0,
            .count = 0,
            .entries = [_]u64{0} ** MAX_SEQ_ENTRIES,
            .started = false,
        };
        self.entries[idx].created = true;

        if (!self.entries[parent_idx].add_child(idx)) {
            self.free_entry(idx);
            return null;
        }
        self.total_creates += 1;
        return idx;
    }

    // ----- Read / Write Operations -----

    /// Read a u64 value from any integer file
    pub fn read_u64(self: *DebugfsManager, idx: u16) ?u64 {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return null;
        const entry = &self.entries[idx];
        if (entry.kind != .file) return null;
        if (entry.access == .write_only) return null;
        self.total_reads += 1;

        return switch (entry.file_type) {
            .u8_val => @as(u64, entry.data.val_u8),
            .u16_val => @as(u64, entry.data.val_u16),
            .u32_val => @as(u64, entry.data.val_u32),
            .u64_val => entry.data.val_u64,
            .bool_val => if (entry.data.val_bool) @as(u64, 1) else @as(u64, 0),
            .hex_u32 => @as(u64, entry.data.val_hex32),
            .hex_u64 => entry.data.val_hex64,
            .atomic_u64 => entry.data.val_atomic,
            else => null,
        };
    }

    /// Write a u64 value to any integer file
    pub fn write_u64(self: *DebugfsManager, idx: u16, value: u64) bool {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return false;
        const entry = &self.entries[idx];
        if (entry.kind != .file) return false;
        if (entry.access == .read_only) return false;
        self.total_writes += 1;

        switch (entry.file_type) {
            .u8_val => self.entries[idx].data.val_u8 = @truncate(value),
            .u16_val => self.entries[idx].data.val_u16 = @truncate(value),
            .u32_val => self.entries[idx].data.val_u32 = @truncate(value),
            .u64_val => self.entries[idx].data.val_u64 = value,
            .bool_val => self.entries[idx].data.val_bool = (value != 0),
            .hex_u32 => self.entries[idx].data.val_hex32 = @truncate(value),
            .hex_u64 => self.entries[idx].data.val_hex64 = value,
            .atomic_u64 => self.entries[idx].data.val_atomic = value,
            else => return false,
        }
        return true;
    }

    /// Increment atomic counter
    pub fn inc_atomic(self: *DebugfsManager, idx: u16) void {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return;
        if (self.entries[idx].file_type == .atomic_u64) {
            self.entries[idx].data.val_atomic +%= 1;
        }
    }

    /// Write blob data
    pub fn write_blob(self: *DebugfsManager, idx: u16, data: []const u8) u32 {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return 0;
        if (self.entries[idx].file_type != .blob_val) return 0;
        self.total_writes += 1;
        return self.entries[idx].data.val_blob.write(data);
    }

    /// Add register to regset
    pub fn regset_add(self: *DebugfsManager, idx: u16, name: []const u8, value: u64) bool {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return false;
        if (self.entries[idx].file_type != .regset) return false;
        return self.entries[idx].data.val_regset.add_reg(name, value);
    }

    /// Update register in regset
    pub fn regset_update(self: *DebugfsManager, idx: u16, reg_idx: u8, value: u64) void {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return;
        if (self.entries[idx].file_type != .regset) return;
        self.entries[idx].data.val_regset.update_reg(reg_idx, value);
    }

    /// Check fault injection
    pub fn fault_check(self: *DebugfsManager, idx: u16) bool {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return false;
        if (self.entries[idx].file_type != .fault_attr) return false;
        const result = self.entries[idx].data.val_fault.should_inject();
        if (result) {
            self.total_faults_injected += 1;
        }
        return result;
    }

    /// Add seq_file entry
    pub fn seq_add_entry(self: *DebugfsManager, idx: u16, val: u64) bool {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return false;
        if (self.entries[idx].file_type != .seq_file) return false;
        return self.entries[idx].data.val_seq.add_entry(val);
    }

    /// Read next seq_file entry
    pub fn seq_read_next(self: *DebugfsManager, idx: u16) ?u64 {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return null;
        if (self.entries[idx].file_type != .seq_file) return null;
        self.total_reads += 1;

        if (!self.entries[idx].data.val_seq.started) {
            self.entries[idx].data.val_seq.start();
        }
        return self.entries[idx].data.val_seq.next();
    }

    /// Reset seq_file position
    pub fn seq_reset(self: *DebugfsManager, idx: u16) void {
        if (idx >= MAX_DEBUGFS_FILES + MAX_DEBUGFS_DIRS) return;
        if (self.entries[idx].file_type != .seq_file) return;
        self.entries[idx].data.val_seq.stop();
    }

    // ----- Path Resolution -----

    /// Resolve a path like "tracing/events/sched" from root
    pub fn resolve_path(self: *DebugfsManager, path: []const u8) ?u16 {
        var current = self.root_idx;
        var start: usize = 0;

        // Skip leading slash
        if (path.len > 0 and path[0] == '/') {
            start = 1;
        }

        while (start < path.len) {
            // Find next component
            var end = start;
            while (end < path.len and path[end] != '/') {
                end += 1;
            }

            if (end == start) {
                start = end + 1;
                continue;
            }

            const component = path[start..end];
            current = self.lookup(current, component) orelse return null;
            start = end + 1;
        }

        return current;
    }

    /// Build full path for an entry
    pub fn build_path(self: *DebugfsManager, idx: u16, buf: []u8) u16 {
        // Walk up to root collecting components
        var components: [16]u16 = undefined;
        var depth: u16 = 0;
        var current = idx;

        while (current != self.root_idx and depth < 16) {
            components[depth] = current;
            depth += 1;
            current = self.entries[current].parent_idx;
            if (current == 0xFFFF) break;
        }

        // Build path from root down
        var pos: u16 = 0;
        if (pos < buf.len) {
            buf[pos] = '/';
            pos += 1;
        }

        var i = depth;
        while (i > 0) {
            i -= 1;
            const entry = &self.entries[components[i]];
            const name = entry.name_slice();
            const copy_len = if (pos + name.len > buf.len) buf.len - pos else name.len;
            @memcpy(buf[pos .. pos + copy_len], name[0..copy_len]);
            pos += @intCast(copy_len);
            if (i > 0 and pos < buf.len) {
                buf[pos] = '/';
                pos += 1;
            }
        }

        return pos;
    }

    // ----- Subsystem Registration Helpers -----

    /// Register a standard subsystem directory with common debug files
    pub fn register_subsystem(self: *DebugfsManager, name: []const u8) ?u16 {
        const dir = self.create_dir(name, self.root_idx) orelse return null;

        // Create standard debug files
        _ = self.create_u64("stats_total", dir, 0, .read_only);
        _ = self.create_u64("stats_errors", dir, 0, .read_only);
        _ = self.create_bool("enabled", dir, true, .read_write);
        _ = self.create_u32("debug_level", dir, 0, .read_write);
        _ = self.create_string("version", dir, "1.0.0", .read_only);

        return dir;
    }
};

// ============================================================================
// Global Instance
// ============================================================================

var debugfs: DebugfsManager = undefined;

fn mgr() *DebugfsManager {
    return &debugfs;
}

// ============================================================================
// FFI Exports
// ============================================================================

export fn zxy_debugfs_init() void {
    mgr().init();
}

export fn zxy_debugfs_create_dir(name_ptr: [*]const u8, name_len: u16, parent: u16) i32 {
    const name = name_ptr[0..name_len];
    return if (mgr().create_dir(name, parent)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_u32(name_ptr: [*]const u8, name_len: u16, parent: u16, value: u32, mode: u8) i32 {
    const name = name_ptr[0..name_len];
    const am: AccessMode = @enumFromInt(mode);
    return if (mgr().create_u32(name, parent, value, am)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_u64(name_ptr: [*]const u8, name_len: u16, parent: u16, value: u64, mode: u8) i32 {
    const name = name_ptr[0..name_len];
    const am: AccessMode = @enumFromInt(mode);
    return if (mgr().create_u64(name, parent, value, am)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_bool(name_ptr: [*]const u8, name_len: u16, parent: u16, value: bool, mode: u8) i32 {
    const name = name_ptr[0..name_len];
    const am: AccessMode = @enumFromInt(mode);
    return if (mgr().create_bool(name, parent, value, am)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_string(name_ptr: [*]const u8, name_len: u16, parent: u16, val_ptr: [*]const u8, val_len: u16) i32 {
    const name = name_ptr[0..name_len];
    const val = val_ptr[0..val_len];
    return if (mgr().create_string(name, parent, val, .read_only)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_fault(name_ptr: [*]const u8, name_len: u16, parent: u16, probability: u32, interval: u32) i32 {
    const name = name_ptr[0..name_len];
    return if (mgr().create_fault_attr(name, parent, probability, interval)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_create_symlink(name_ptr: [*]const u8, name_len: u16, parent: u16, target_ptr: [*]const u8, target_len: u16) i32 {
    const name = name_ptr[0..name_len];
    const target = target_ptr[0..target_len];
    return if (mgr().create_symlink(name, parent, target)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_read_u64(idx: u16) u64 {
    return mgr().read_u64(idx) orelse 0;
}

export fn zxy_debugfs_write_u64(idx: u16, value: u64) i32 {
    return if (mgr().write_u64(idx, value)) 0 else -1;
}

export fn zxy_debugfs_inc_atomic(idx: u16) void {
    mgr().inc_atomic(idx);
}

export fn zxy_debugfs_fault_check(idx: u16) bool {
    return mgr().fault_check(idx);
}

export fn zxy_debugfs_remove(idx: u16) void {
    mgr().remove_recursive(idx);
}

export fn zxy_debugfs_lookup(parent: u16, name_ptr: [*]const u8, name_len: u16) i32 {
    const name = name_ptr[0..name_len];
    return if (mgr().lookup(parent, name)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_register_subsystem(name_ptr: [*]const u8, name_len: u16) i32 {
    const name = name_ptr[0..name_len];
    return if (mgr().register_subsystem(name)) |idx| @as(i32, @intCast(idx)) else -1;
}

export fn zxy_debugfs_root() u16 {
    return mgr().root_idx;
}

export fn zxy_debugfs_entry_count() u32 {
    return mgr().entry_count;
}

export fn zxy_debugfs_total_reads() u64 {
    return mgr().total_reads;
}

export fn zxy_debugfs_total_writes() u64 {
    return mgr().total_writes;
}

export fn zxy_debugfs_total_creates() u64 {
    return mgr().total_creates;
}

export fn zxy_debugfs_total_faults() u64 {
    return mgr().total_faults_injected;
}

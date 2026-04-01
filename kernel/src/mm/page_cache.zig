// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Page Cache Subsystem
//
// High-performance page cache that acts as the primary interface between the
// VFS and the block device layer. All file I/O passes through this cache,
// which implements a modified clock algorithm for page replacement with
// support for read-ahead, write-back, and memory-mapped file semantics.

const std = @import("std");
const pmm = @import("pmm.zig");
const vmm = @import("vmm.zig");
const slab = @import("slab.zig");
const spinlock = @import("../lib/spinlock.zig");
const rbtree = @import("../lib/rbtree.zig");
const list = @import("../lib/list.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants & Configuration
// ─────────────────────────────────────────────────────────────────────
pub const PAGE_SIZE: usize = 4096;
pub const MAX_PAGE_CACHE_PAGES: usize = 1024 * 1024; // 4 GiB max cache
pub const DIRTY_WRITEBACK_INTERVAL_MS: u64 = 5000;
pub const DIRTY_EXPIRE_MS: u64 = 30000;
pub const READAHEAD_MAX_PAGES: usize = 256; // 1 MiB max read-ahead
pub const WRITEBACK_BATCH_SIZE: usize = 64;
pub const DIRTY_RATIO_PERCENT: u32 = 40;
pub const DIRTY_BACKGROUND_RATIO_PERCENT: u32 = 10;

// ─────────────────────────────────────────────────────────────────────
// Page Cache Flags — bit flags stored per cached page
// ─────────────────────────────────────────────────────────────────────
pub const PageFlags = packed struct {
    valid: bool = false,
    dirty: bool = false,
    referenced: bool = false,
    locked: bool = false,
    writeback: bool = false,
    uptodate: bool = false,
    error_flag: bool = false,
    mmap: bool = false,
    readahead: bool = false,
    reclaim: bool = false,
    private: bool = false,
    swapbacked: bool = false,
    active: bool = false,
    lru: bool = false,
    _reserved: u2 = 0,
};

// ─────────────────────────────────────────────────────────────────────
// CachedPage — Represents a single page in the cache
// ─────────────────────────────────────────────────────────────────────
pub const CachedPage = struct {
    /// Physical frame number of the allocated page
    physical_frame: usize,
    /// Virtual address mapping of this page
    virtual_addr: usize,
    /// Offset within the file (in pages)
    page_index: u64,
    /// Inode number this page belongs to
    inode_id: u64,
    /// Device identifier
    device_id: u32,
    /// Flags describing the state of this page
    flags: PageFlags,
    /// Reference count — how many users hold this page
    ref_count: u32,
    /// Number of times this page has been accessed (for LRU scoring)
    access_count: u32,
    /// Timestamp of last access (kernel ticks)
    last_access_tick: u64,
    /// Timestamp when this page was dirtied
    dirty_timestamp: u64,
    /// Link for the LRU list (active or inactive)
    lru_link: list.ListNode,
    /// Link for the per-inode radix tree
    tree_link: rbtree.RbNode,
    /// Link for the writeback list
    wb_link: list.ListNode,
    /// Wait queue for threads waiting on I/O completion
    waiters_head: ?*WaitEntry,
    /// Lock protecting this page's metadata
    lock: spinlock.SpinLock,

    const Self = @This();

    pub fn init(frame: usize, inode: u64, dev: u32, index: u64) Self {
        return Self{
            .physical_frame = frame,
            .virtual_addr = 0,
            .page_index = index,
            .inode_id = inode,
            .device_id = dev,
            .flags = PageFlags{},
            .ref_count = 1,
            .access_count = 0,
            .last_access_tick = 0,
            .dirty_timestamp = 0,
            .lru_link = list.ListNode{},
            .tree_link = rbtree.RbNode{},
            .wb_link = list.ListNode{},
            .waiters_head = null,
            .lock = spinlock.SpinLock{},
        };
    }

    /// Mark the page as dirty, recording the timestamp
    pub fn markDirty(self: *Self, current_tick: u64) void {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.flags.dirty) {
            self.flags.dirty = true;
            self.dirty_timestamp = current_tick;
        }
        self.flags.referenced = true;
        self.access_count += 1;
        self.last_access_tick = current_tick;
    }

    /// Mark the page as clean (writeback completed)
    pub fn markClean(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        self.flags.dirty = false;
        self.flags.writeback = false;
        self.dirty_timestamp = 0;
    }

    /// Acquire a reference to this page, preventing it from being evicted
    pub fn grab(self: *Self) void {
        self.lock.acquire();
        defer self.lock.release();

        self.ref_count += 1;
        self.flags.referenced = true;
    }

    /// Release a reference to this page. Returns true if the page is now
    /// unreferenced and eligible for eviction.
    pub fn release(self: *Self) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (self.ref_count > 0) {
            self.ref_count -= 1;
        }
        return self.ref_count == 0;
    }

    /// Begin writeback on this page. Returns false if writeback is already
    /// in progress or the page is not dirty.
    pub fn startWriteback(self: *Self) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (!self.flags.dirty or self.flags.writeback) {
            return false;
        }
        self.flags.writeback = true;
        return true;
    }

    /// Check whether this page has expired and needs writeback
    pub fn isDirtyExpired(self: *Self, current_tick: u64) bool {
        if (!self.flags.dirty) return false;
        if (self.dirty_timestamp == 0) return false;
        return (current_tick - self.dirty_timestamp) >= DIRTY_EXPIRE_MS;
    }
};

// ─────────────────────────────────────────────────────────────────────
// WaitEntry — threads waiting for page I/O completion
// ─────────────────────────────────────────────────────────────────────
pub const WaitEntry = struct {
    thread_id: u32,
    next: ?*WaitEntry,
    woken: bool,
};

// ─────────────────────────────────────────────────────────────────────
// AddressSpace — per-inode page cache mapping
// ─────────────────────────────────────────────────────────────────────
pub const AddressSpace = struct {
    /// Inode this address space belongs to
    inode_id: u64,
    /// Device ID
    device_id: u32,
    /// Total number of cached pages for this inode
    nr_pages: u64,
    /// Number of dirty pages
    nr_dirty: u64,
    /// Radix tree root for O(log n) page index lookup
    page_tree_root: ?*rbtree.RbNode,
    /// Read-ahead state
    readahead: ReadaheadState,
    /// Lock protecting th address space
    lock: spinlock.SpinLock,
    /// Operations table for reading/writing pages
    ops: *const AddressSpaceOps,

    const Self = @This();

    pub fn init(inode: u64, dev: u32, ops: *const AddressSpaceOps) Self {
        return Self{
            .inode_id = inode,
            .device_id = dev,
            .nr_pages = 0,
            .nr_dirty = 0,
            .page_tree_root = null,
            .readahead = ReadaheadState.init(),
            .lock = spinlock.SpinLock{},
            .ops = ops,
        };
    }

    /// Look up a page by its offset within the file. Returns null if the
    /// page is not in the cache.
    pub fn findPage(self: *Self, page_index: u64) ?*CachedPage {
        self.lock.acquire();
        defer self.lock.release();

        return self.findPageUnlocked(page_index);
    }

    fn findPageUnlocked(self: *Self, page_index: u64) ?*CachedPage {
        var node = self.page_tree_root;
        while (node) |n| {
            const page = @fieldParentPtr(CachedPage, "tree_link", n);
            if (page_index < page.page_index) {
                node = n.left;
            } else if (page_index > page.page_index) {
                node = n.right;
            } else {
                return page;
            }
        }
        return null;
    }

    /// Insert a new page into this address space's tree
    pub fn insertPage(self: *Self, page: *CachedPage) bool {
        self.lock.acquire();
        defer self.lock.release();

        // Check for duplicate
        if (self.findPageUnlocked(page.page_index) != null) {
            return false;
        }

        // Insert into tree — find the insertion point
        var parent: ?*rbtree.RbNode = null;
        var link_ptr: *?*rbtree.RbNode = &self.page_tree_root;

        while (link_ptr.*) |node| {
            parent = node;
            const existing = @fieldParentPtr(CachedPage, "tree_link", node);
            if (page.page_index < existing.page_index) {
                link_ptr = &node.left;
            } else {
                link_ptr = &node.right;
            }
        }

        link_ptr.* = &page.tree_link;
        page.tree_link.parent = parent;
        page.tree_link.left = null;
        page.tree_link.right = null;

        self.nr_pages += 1;
        if (page.flags.dirty) {
            self.nr_dirty += 1;
        }

        return true;
    }

    /// Remove a page from this address space's tree
    pub fn removePage(self: *Self, page: *CachedPage) void {
        self.lock.acquire();
        defer self.lock.release();

        self.removePageUnlocked(page);
    }

    fn removePageUnlocked(self: *Self, page: *CachedPage) void {
        // Simple BST removal (without rebalancing for now)
        _ = page;
        if (self.nr_pages > 0) {
            self.nr_pages -= 1;
        }
        if (page.flags.dirty and self.nr_dirty > 0) {
            self.nr_dirty -= 1;
        }
    }

    /// Invalidate all cached pages (e.g. on file truncate)
    pub fn invalidateAll(self: *Self) u64 {
        self.lock.acquire();
        defer self.lock.release();

        const count = self.nr_pages;
        self.page_tree_root = null;
        self.nr_pages = 0;
        self.nr_dirty = 0;
        return count;
    }
};

// ─────────────────────────────────────────────────────────────────────
// AddressSpaceOps — virtual dispatch for filesystem-specific I/O
// ─────────────────────────────────────────────────────────────────────
pub const AddressSpaceOps = struct {
    /// Read a page from disk into the supplied buffer
    read_page: ?*const fn (mapping: *AddressSpace, page: *CachedPage) bool,
    /// Write a dirty page to disk
    write_page: ?*const fn (mapping: *AddressSpace, page: *CachedPage) bool,
    /// Set a page dirty (filesystem-specific bookkeeping)
    set_page_dirty: ?*const fn (page: *CachedPage) void,
    /// Release a page (filesystem-specific cleanup)
    release_page: ?*const fn (page: *CachedPage) void,
    /// Direct I/O bypass (reads/writes that skip the page cache)
    direct_io: ?*const fn (mapping: *AddressSpace, offset: u64, buf: [*]u8, len: usize, write: bool) isize,
};

/// Default address space ops for block-backed filesystems
pub const default_block_aops = AddressSpaceOps{
    .read_page = defaultReadPage,
    .write_page = defaultWritePage,
    .set_page_dirty = null,
    .release_page = null,
    .direct_io = null,
};

fn defaultReadPage(_: *AddressSpace, page: *CachedPage) bool {
    // In a real implementation, this would issue a block I/O request
    // to read the page from the device at the appropriate sector offset.
    page.flags.uptodate = true;
    page.flags.valid = true;
    return true;
}

fn defaultWritePage(_: *AddressSpace, page: *CachedPage) bool {
    // In a real implementation, this would issue a block I/O write.
    page.flags.writeback = false;
    page.flags.dirty = false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────
// ReadaheadState — adaptive read-ahead tracking per address space
// ─────────────────────────────────────────────────────────────────────
pub const ReadaheadState = struct {
    /// Start of the current read-ahead window (in pages)
    start: u64,
    /// Size of the current read-ahead window
    size: u32,
    /// Asynchronous read-ahead threshold
    async_size: u32,
    /// Previous read-ahead start position (for detecting sequential access)
    prev_pos: u64,
    /// Number of consecutive sequential reads
    sequential_count: u32,
    /// Maximum read-ahead window size
    ra_max: u32,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .start = 0,
            .size = 4, // Start with 4 pages (16 KiB)
            .async_size = 2,
            .prev_pos = 0,
            .sequential_count = 0,
            .ra_max = READAHEAD_MAX_PAGES,
        };
    }

    /// Update read-ahead state based on the current access pattern.
    /// Returns the recommended number of pages to read ahead.
    pub fn update(self: *Self, current_page: u64) u32 {
        // Check if this access is sequential
        const expected_next = self.prev_pos + 1;
        if (current_page == expected_next or current_page == self.prev_pos) {
            // Sequential access detected — grow the window
            self.sequential_count += 1;
            if (self.sequential_count > 4) {
                // Double the read-ahead window, capped at maximum
                self.size = @min(self.size * 2, self.ra_max);
            }
        } else if (current_page > self.prev_pos and
            (current_page - self.prev_pos) < 8)
        {
            // Near-sequential — modest read-ahead
            self.sequential_count = @max(self.sequential_count, 1) - 1;
            self.size = @max(self.size / 2, 4);
        } else {
            // Random access — reset read-ahead
            self.sequential_count = 0;
            self.size = 4;
        }

        self.prev_pos = current_page;
        self.start = current_page + 1;
        self.async_size = self.size / 4;

        return self.size;
    }

    /// Reset the read-ahead state to initial values
    pub fn reset(self: *Self) void {
        self.start = 0;
        self.size = 4;
        self.async_size = 2;
        self.prev_pos = 0;
        self.sequential_count = 0;
    }
};

// ─────────────────────────────────────────────────────────────────────
// LRU Lists — Active and Inactive lists for page replacement
// ─────────────────────────────────────────────────────────────────────
pub const LruListType = enum {
    active_anon,
    inactive_anon,
    active_file,
    inactive_file,
    unevictable,
};

pub const LruList = struct {
    head: list.ListNode,
    count: u64,
    lock: spinlock.SpinLock,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .head = list.ListNode{},
            .count = 0,
            .lock = spinlock.SpinLock{},
        };
    }

    pub fn pushBack(self: *Self, page: *CachedPage) void {
        self.lock.acquire();
        defer self.lock.release();

        page.lru_link.prev = self.head.prev;
        page.lru_link.next = &self.head;
        if (self.head.prev) |prev| {
            prev.next = &page.lru_link;
        }
        self.head.prev = &page.lru_link;
        if (self.head.next == null) {
            self.head.next = &page.lru_link;
        }
        self.count += 1;
        page.flags.lru = true;
    }

    pub fn remove(self: *Self, page: *CachedPage) void {
        self.lock.acquire();
        defer self.lock.release();

        if (page.lru_link.prev) |prev| {
            prev.next = page.lru_link.next;
        }
        if (page.lru_link.next) |next| {
            next.prev = page.lru_link.prev;
        }
        page.lru_link.prev = null;
        page.lru_link.next = null;
        if (self.count > 0) {
            self.count -= 1;
        }
        page.flags.lru = false;
    }

    /// Pop the least recently used page from the front of the list
    pub fn popFront(self: *Self) ?*CachedPage {
        self.lock.acquire();
        defer self.lock.release();

        const first = self.head.next orelse return null;
        if (first == &self.head) return null;

        const page = @fieldParentPtr(CachedPage, "lru_link", first);

        // Unlink from list
        if (first.next) |next| {
            next.prev = &self.head;
        }
        self.head.next = first.next;
        first.prev = null;
        first.next = null;
        if (self.count > 0) {
            self.count -= 1;
        }
        page.flags.lru = false;

        return page;
    }
};

// ─────────────────────────────────────────────────────────────────────
// PageCacheStats — runtime statistics
// ─────────────────────────────────────────────────────────────────────
pub const PageCacheStats = struct {
    total_pages: u64,
    dirty_pages: u64,
    writeback_pages: u64,
    cache_hits: u64,
    cache_misses: u64,
    readahead_pages: u64,
    evicted_pages: u64,
    writeback_completed: u64,
    direct_io_reads: u64,
    direct_io_writes: u64,
    active_file_pages: u64,
    inactive_file_pages: u64,
    active_anon_pages: u64,
    inactive_anon_pages: u64,

    pub fn init() PageCacheStats {
        return PageCacheStats{
            .total_pages = 0,
            .dirty_pages = 0,
            .writeback_pages = 0,
            .cache_hits = 0,
            .cache_misses = 0,
            .readahead_pages = 0,
            .evicted_pages = 0,
            .writeback_completed = 0,
            .direct_io_reads = 0,
            .direct_io_writes = 0,
            .active_file_pages = 0,
            .inactive_file_pages = 0,
            .active_anon_pages = 0,
            .inactive_anon_pages = 0,
        };
    }

    /// Calculate the cache hit ratio as a percentage (0-100)
    pub fn hitRatio(self: *const PageCacheStats) u32 {
        const total = self.cache_hits + self.cache_misses;
        if (total == 0) return 0;
        return @intCast((self.cache_hits * 100) / total);
    }

    /// Calculate dirty ratio as a percentage of total cached pages
    pub fn dirtyRatio(self: *const PageCacheStats) u32 {
        if (self.total_pages == 0) return 0;
        return @intCast((self.dirty_pages * 100) / self.total_pages);
    }
};

// ─────────────────────────────────────────────────────────────────────
// WritebackControl — parameters for writeback operations
// ─────────────────────────────────────────────────────────────────────
pub const WritebackControl = struct {
    /// Maximum number of pages to write back
    nr_to_write: u64,
    /// How many pages were actually written
    nr_written: u64,
    /// Write back pages older than this timestamp
    older_than: u64,
    /// Only sync dirty pages for a specific inode (0 = all)
    for_inode: u64,
    /// Writeback reason
    reason: WritebackReason,
    /// Whether to block waiting for I/O
    sync_mode: SyncMode,

    pub const WritebackReason = enum {
        background,
        sync,
        reclaim,
        periodic,
        inode_close,
        inode_sync,
    };

    pub const SyncMode = enum {
        none,
        normal,
        wait,
    };

    pub fn init(reason: WritebackReason) WritebackControl {
        return WritebackControl{
            .nr_to_write = WRITEBACK_BATCH_SIZE,
            .nr_written = 0,
            .older_than = 0,
            .for_inode = 0,
            .reason = reason,
            .sync_mode = .normal,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// Global Page Cache State
// ─────────────────────────────────────────────────────────────────────
pub const PageCache = struct {
    /// LRU lists for page replacement (modified clock algorithm)
    active_file: LruList,
    inactive_file: LruList,
    active_anon: LruList,
    inactive_anon: LruList,
    unevictable: LruList,

    /// Global statistics
    stats: PageCacheStats,

    /// Global lock for the page cache
    global_lock: spinlock.SpinLock,

    /// Address space hash table (indexed by inode_id)
    address_spaces: [ADDRESS_SPACE_HASH_SIZE]?*AddressSpace,

    /// Watermarks for triggering background writeback
    dirty_thresh_pages: u64,
    dirty_bg_thresh_pages: u64,

    /// Current kernel tick (updated by timer interrupt)
    current_tick: u64,

    /// Whether background writeback is needed
    writeback_needed: bool,

    const ADDRESS_SPACE_HASH_SIZE: usize = 4096;

    const Self = @This();

    pub fn init() Self {
        var cache = Self{
            .active_file = LruList.init(),
            .inactive_file = LruList.init(),
            .active_anon = LruList.init(),
            .inactive_anon = LruList.init(),
            .unevictable = LruList.init(),
            .stats = PageCacheStats.init(),
            .global_lock = spinlock.SpinLock{},
            .address_spaces = undefined,
            .dirty_thresh_pages = 0,
            .dirty_bg_thresh_pages = 0,
            .current_tick = 0,
            .writeback_needed = false,
        };

        for (&cache.address_spaces) |*slot| {
            slot.* = null;
        }

        return cache;
    }

    /// Register an address space in the global hash table
    pub fn registerAddressSpace(self: *Self, mapping: *AddressSpace) void {
        const hash = self.hashInode(mapping.inode_id);
        self.global_lock.acquire();
        defer self.global_lock.release();

        self.address_spaces[hash] = mapping;
    }

    /// Find an address space by inode ID
    pub fn findAddressSpace(self: *Self, inode_id: u64) ?*AddressSpace {
        const hash = self.hashInode(inode_id);
        self.global_lock.acquire();
        defer self.global_lock.release();

        return self.address_spaces[hash];
    }

    fn hashInode(_: *Self, inode_id: u64) usize {
        // FNV-1a-inspired hash for good distribution
        var hash: u64 = 14695981039346656037;
        const bytes = @as([8]u8, @bitCast(inode_id));
        for (bytes) |b| {
            hash ^= b;
            hash *%= 1099511628211;
        }
        return @intCast(hash % ADDRESS_SPACE_HASH_SIZE);
    }

    /// Look up a page in the cache. If found, grabs a reference and returns it.
    /// If not found, allocates a new page and initiates I/O to fill it.
    pub fn findGetPage(
        self: *Self,
        mapping: *AddressSpace,
        page_index: u64,
    ) ?*CachedPage {
        // Fast path: check the tree
        if (mapping.findPage(page_index)) |page| {
            page.grab();
            self.touchPage(page);
            self.stats.cache_hits += 1;
            return page;
        }

        // Cache miss — allocate and fill
        self.stats.cache_misses += 1;
        return self.allocateAndFill(mapping, page_index);
    }

    /// Allocate a page, insert it into the cache, and initiate read I/O
    fn allocateAndFill(
        self: *Self,
        mapping: *AddressSpace,
        page_index: u64,
    ) ?*CachedPage {
        // Allocate physical frame
        const frame = pmm.allocFrame() orelse {
            // Try to reclaim some pages first
            _ = self.shrinkCache(32);
            return null;
        };

        // Create the cached page descriptor
        var page = CachedPage.init(
            frame,
            mapping.inode_id,
            mapping.device_id,
            page_index,
        );
        page.flags.locked = true;

        // Insert into address space tree
        if (!mapping.insertPage(&page)) {
            // Race condition — another thread inserted the page while we
            // were allocating. Free our frame and return the existing one.
            pmm.freeFrame(frame);
            if (mapping.findPage(page_index)) |existing| {
                existing.grab();
                return existing;
            }
            return null;
        }

        // Initiate I/O to fill the page
        if (mapping.ops.read_page) |read_fn| {
            if (!read_fn(mapping, &page)) {
                page.flags.error_flag = true;
                page.flags.locked = false;
                return null;
            }
        }

        page.flags.locked = false;
        page.flags.uptodate = true;
        page.flags.valid = true;

        // Add to inactive file LRU list
        self.inactive_file.pushBack(&page);
        self.stats.total_pages += 1;
        self.stats.inactive_file_pages += 1;

        // Trigger read-ahead if sequential access is detected
        const ra_pages = mapping.readahead.update(page_index);
        if (ra_pages > 1) {
            self.issueReadahead(mapping, page_index + 1, ra_pages - 1);
        }

        return &page;
    }

    /// Touch a page to update its position in the LRU lists.
    /// Implements the "second chance" / clock algorithm:
    /// - If the page is in the inactive list and recently accessed, promote
    ///   it to the active list.
    /// - If it is already active, just set the referenced bit.
    fn touchPage(self: *Self, page: *CachedPage) void {
        page.lock.acquire();
        defer page.lock.release();

        page.access_count += 1;
        page.last_access_tick = self.current_tick;

        if (!page.flags.active and page.flags.referenced) {
            // Promote from inactive to active list
            self.inactive_file.remove(page);
            self.active_file.pushBack(page);
            page.flags.active = true;
            self.stats.inactive_file_pages -|= 1;
            self.stats.active_file_pages += 1;
        } else {
            page.flags.referenced = true;
        }
    }

    /// Issue read-ahead I/O for sequential access optimization
    fn issueReadahead(
        self: *Self,
        mapping: *AddressSpace,
        start_page: u64,
        count: u32,
    ) void {
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const idx = start_page + i;

            // Skip if already in cache
            if (mapping.findPage(idx) != null) continue;

            // Allocate and issue async read
            const frame = pmm.allocFrame() orelse break;
            var page = CachedPage.init(
                frame,
                mapping.inode_id,
                mapping.device_id,
                idx,
            );
            page.flags.readahead = true;

            if (mapping.insertPage(&page)) {
                if (mapping.ops.read_page) |read_fn| {
                    _ = read_fn(mapping, &page);
                }
                page.flags.uptodate = true;
                page.flags.valid = true;
                self.inactive_file.pushBack(&page);
                self.stats.total_pages += 1;
                self.stats.readahead_pages += 1;
                self.stats.inactive_file_pages += 1;
            } else {
                pmm.freeFrame(frame);
            }
        }
    }

    /// Write a dirty page to disk. Handles the writeback lifecycle.
    pub fn writebackPage(
        self: *Self,
        mapping: *AddressSpace,
        page: *CachedPage,
    ) bool {
        if (!page.startWriteback()) {
            return false;
        }

        self.stats.writeback_pages += 1;

        const success = if (mapping.ops.write_page) |write_fn|
            write_fn(mapping, page)
        else
            false;

        if (success) {
            page.markClean();
            self.stats.writeback_pages -|= 1;
            self.stats.dirty_pages -|= 1;
            self.stats.writeback_completed += 1;
            mapping.nr_dirty -|= 1;
        } else {
            page.lock.acquire();
            page.flags.writeback = false;
            page.flags.error_flag = true;
            page.lock.release();
            self.stats.writeback_pages -|= 1;
        }

        return success;
    }

    /// Run the periodic background writeback, flushing pages that have
    /// been dirty for longer than DIRTY_EXPIRE_MS.
    pub fn backgroundWriteback(self: *Self) u64 {
        var wbc = WritebackControl.init(.background);
        wbc.older_than = if (self.current_tick > DIRTY_EXPIRE_MS)
            self.current_tick - DIRTY_EXPIRE_MS
        else
            0;
        wbc.nr_to_write = WRITEBACK_BATCH_SIZE;

        return self.doWriteback(&wbc);
    }

    /// Perform a full sync — write back all dirty pages and wait
    pub fn syncAll(self: *Self) u64 {
        var wbc = WritebackControl.init(.sync);
        wbc.nr_to_write = self.stats.dirty_pages;
        wbc.sync_mode = .wait;

        return self.doWriteback(&wbc);
    }

    /// Sync all dirty pages belonging to a specific inode
    pub fn syncInode(self: *Self, inode_id: u64) u64 {
        var wbc = WritebackControl.init(.inode_sync);
        wbc.for_inode = inode_id;
        wbc.nr_to_write = @as(u64, @intCast(MAX_PAGE_CACHE_PAGES));
        wbc.sync_mode = .wait;

        return self.doWriteback(&wbc);
    }

    /// Core writeback loop — walks the inactive file list looking for dirty
    /// pages that match the writeback control criteria.
    fn doWriteback(self: *Self, wbc: *WritebackControl) u64 {
        var written: u64 = 0;
        var scanned: u64 = 0;
        const max_scan = self.inactive_file.count + self.active_file.count;

        // Walk both LRU lists looking for dirty pages
        while (written < wbc.nr_to_write and scanned < max_scan) {
            scanned += 1;

            // Try inactive list first
            if (self.inactive_file.popFront()) |page| {
                if (self.shouldWriteback(page, wbc)) {
                    const mapping = self.findAddressSpace(page.inode_id) orelse {
                        self.inactive_file.pushBack(page);
                        continue;
                    };

                    if (self.writebackPage(mapping, page)) {
                        written += 1;
                    }
                }
                // Put the page back in the list (at the end)
                self.inactive_file.pushBack(page);
            } else {
                break;
            }
        }

        wbc.nr_written = written;
        return written;
    }

    fn shouldWriteback(self: *Self, page: *CachedPage, wbc: *WritebackControl) bool {
        if (!page.flags.dirty) return false;
        if (page.flags.writeback) return false;
        if (page.flags.locked) return false;

        // Filter by inode if specified
        if (wbc.for_inode != 0 and page.inode_id != wbc.for_inode) {
            return false;
        }

        // Filter by age for background writeback
        if (wbc.reason == .background and wbc.older_than > 0) {
            if (page.dirty_timestamp > wbc.older_than) {
                return false;
            }
        }

        _ = self;
        return true;
    }

    /// Shrink the page cache by evicting unreferenced, clean pages from the
    /// inactive list. This is the main memory reclaim path.
    ///
    /// Uses a modified clock algorithm:
    /// 1. Scan the inactive file list
    /// 2. If referenced bit is set, clear it and move to end (second chance)
    /// 3. If not referenced and clean, evict
    /// 4. If dirty, schedule writeback but skip for now
    pub fn shrinkCache(self: *Self, nr_to_evict: u64) u64 {
        var evicted: u64 = 0;
        var scanned: u64 = 0;
        const max_scan = self.inactive_file.count * 2; // Scan up to 2x

        while (evicted < nr_to_evict and scanned < max_scan) {
            scanned += 1;

            const page = self.inactive_file.popFront() orelse break;

            // Second chance: if referenced, give another chance
            if (page.flags.referenced) {
                page.flags.referenced = false;
                self.inactive_file.pushBack(page);
                continue;
            }

            // Cannot evict locked or dirty pages
            if (page.flags.locked or page.flags.writeback) {
                self.inactive_file.pushBack(page);
                continue;
            }

            if (page.flags.dirty) {
                // Schedule writeback for this page
                if (page.startWriteback()) {
                    if (self.findAddressSpace(page.inode_id)) |mapping| {
                        _ = self.writebackPage(mapping, page);
                    }
                }
                self.inactive_file.pushBack(page);
                continue;
            }

            // Page is clean and unreferenced — evict it
            if (page.ref_count > 0) {
                self.inactive_file.pushBack(page);
                continue;
            }

            // Remove from the address space tree
            if (self.findAddressSpace(page.inode_id)) |mapping| {
                mapping.removePage(page);
            }

            // Free the physical frame
            pmm.freeFrame(page.physical_frame);

            evicted += 1;
            self.stats.total_pages -|= 1;
            self.stats.inactive_file_pages -|= 1;
            self.stats.evicted_pages += 1;
        }

        // If we didn't evict enough from inactive, demote from active list
        if (evicted < nr_to_evict) {
            self.demoteActivePages((nr_to_evict - evicted) * 2);
        }

        return evicted;
    }

    /// Move pages from the active list to the inactive list when the active
    /// list is too large. This is the "aging" step of the clock algorithm.
    fn demoteActivePages(self: *Self, count: u64) void {
        var demoted: u64 = 0;
        while (demoted < count) {
            const page = self.active_file.popFront() orelse break;

            if (page.flags.referenced) {
                // Recently accessed — give it another lap
                page.flags.referenced = false;
                self.active_file.pushBack(page);
            } else {
                // Demote to inactive list
                page.flags.active = false;
                self.inactive_file.pushBack(page);
                self.stats.active_file_pages -|= 1;
                self.stats.inactive_file_pages += 1;
                demoted += 1;
            }
        }
    }

    /// Update dirty thresholds based on available memory
    pub fn updateThresholds(self: *Self, total_memory_pages: u64) void {
        self.dirty_thresh_pages =
            (total_memory_pages * DIRTY_RATIO_PERCENT) / 100;
        self.dirty_bg_thresh_pages =
            (total_memory_pages * DIRTY_BACKGROUND_RATIO_PERCENT) / 100;
    }

    /// Check if the dirty page ratio exceeds the background threshold
    pub fn needsBackgroundWriteback(self: *Self) bool {
        return self.stats.dirty_pages >= self.dirty_bg_thresh_pages;
    }

    /// Check if the dirty page ratio exceeds the hard limit, which means
    /// we must throttle writers
    pub fn needsThrottling(self: *Self) bool {
        return self.stats.dirty_pages >= self.dirty_thresh_pages;
    }

    /// Advance the tick counter (called from the timer interrupt)
    pub fn tick(self: *Self) void {
        self.current_tick += 1;

        // Check if background writeback is needed
        if (self.current_tick % (DIRTY_WRITEBACK_INTERVAL_MS / 10) == 0) {
            if (self.needsBackgroundWriteback()) {
                self.writeback_needed = true;
            }
        }
    }

    /// Get a snapshot of the current cache statistics
    pub fn getStats(self: *Self) PageCacheStats {
        return self.stats;
    }

    /// Invalidate all pages belonging to a specific inode
    pub fn invalidateInode(self: *Self, inode_id: u64) u64 {
        const mapping = self.findAddressSpace(inode_id) orelse return 0;
        const count = mapping.invalidateAll();
        self.stats.total_pages -|= count;
        return count;
    }

    /// Truncate cached pages beyond (and including) a given page index
    pub fn truncateInode(self: *Self, inode_id: u64, from_page: u64) u64 {
        const mapping = self.findAddressSpace(inode_id) orelse return 0;
        var removed: u64 = 0;

        // Walk the tree and remove all pages >= from_page
        // In a real implementation, this would use tree range iteration
        var scan: u64 = from_page;
        while (scan < from_page + MAX_PAGE_CACHE_PAGES) : (scan += 1) {
            if (mapping.findPage(scan)) |page| {
                // Wait for writeback to complete
                if (page.flags.writeback) continue;

                // Release the page
                mapping.removePage(page);

                if (page.flags.lru) {
                    if (page.flags.active) {
                        self.active_file.remove(page);
                        self.stats.active_file_pages -|= 1;
                    } else {
                        self.inactive_file.remove(page);
                        self.stats.inactive_file_pages -|= 1;
                    }
                }

                pmm.freeFrame(page.physical_frame);
                self.stats.total_pages -|= 1;
                removed += 1;
            } else {
                break; // No more pages beyond this point
            }
        }

        return removed;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Global singleton
// ─────────────────────────────────────────────────────────────────────
var global_page_cache: PageCache = PageCache.init();

pub fn getPageCache() *PageCache {
    return &global_page_cache;
}

// ─────────────────────────────────────────────────────────────────────
// Public API — called from the VFS and filesystem drivers
// ─────────────────────────────────────────────────────────────────────

/// Read a file page through the page cache. This is the primary read path.
pub fn readPage(mapping: *AddressSpace, page_index: u64) ?*CachedPage {
    return global_page_cache.findGetPage(mapping, page_index);
}

/// Mark a page dirty after a write operation
pub fn setPageDirty(page: *CachedPage, tick: u64) void {
    page.markDirty(tick);
    global_page_cache.stats.dirty_pages += 1;
}

/// Release a reference to a cached page
pub fn putPage(page: *CachedPage) void {
    _ = page.release();
}

/// Sync all dirty pages in the cache
pub fn syncAllPages() u64 {
    return global_page_cache.syncAll();
}

/// Sync dirty pages for a specific file
pub fn syncFile(inode_id: u64) u64 {
    return global_page_cache.syncInode(inode_id);
}

/// Perform background writeback (called from the pdflush equivalent)
pub fn periodicWriteback() u64 {
    return global_page_cache.backgroundWriteback();
}

/// Shrink the cache to free memory (called from the memory reclaimer)
pub fn shrinkPageCache(nr_pages: u64) u64 {
    return global_page_cache.shrinkCache(nr_pages);
}

/// Timer tick handler
pub fn pageCacheTick() void {
    global_page_cache.tick();
}

/// Get cache statistics
pub fn getCacheStats() PageCacheStats {
    return global_page_cache.getStats();
}

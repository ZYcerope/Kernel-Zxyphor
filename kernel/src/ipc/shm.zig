// =============================================================================
// Kernel Zxyphor - Shared Memory (SHM)
// =============================================================================
// System V-style shared memory segments that allow multiple processes to
// map the same physical pages into their address spaces. This is the fastest
// IPC mechanism (no copying involved) but requires synchronization.
//
// Operations:
//   shmget: Create or find a shared memory segment
//   shmat:  Attach a segment to the process address space
//   shmdt:  Detach a segment
//   shmctl: Control operations (status, destroy)
//
// Each segment is identified by a key (integer) and has:
//   - Owner UID/GID and permissions
//   - Physical pages backing the segment
//   - Reference count of attached processes
//   - Size (must be page-aligned)
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// Constants
// =============================================================================
pub const MAX_SHM_SEGMENTS: usize = 256;
pub const MAX_SHM_SIZE: usize = 256 * 1024 * 1024; // 256 MB
const PAGE_SIZE: usize = 4096;

// IPC flags
pub const IPC_CREAT: u32 = 0o1000;
pub const IPC_EXCL: u32 = 0o2000;
pub const IPC_RMID: u32 = 0; // Remove segment
pub const IPC_SET: u32 = 1; // Set parameters
pub const IPC_STAT: u32 = 2; // Get status

// shmat flags
pub const SHM_RDONLY: u32 = 0o10000;
pub const SHM_RND: u32 = 0o20000;

// Special keys
pub const IPC_PRIVATE: u32 = 0;

// =============================================================================
// Shared memory segment descriptor
// =============================================================================
pub const ShmSegment = struct {
    // Identity
    id: u32 = 0,
    key: u32 = 0,

    // Size
    size: usize = 0,
    num_pages: usize = 0,

    // Physical page frames backing this segment (up to 256MB / 4KB = 65536 pages)
    pages: [64]u64 = [_]u64{0} ** 64, // Store first 64 page frames
    page_count: usize = 0,

    // Ownership and permissions
    uid: u32 = 0,
    gid: u32 = 0,
    mode: u16 = 0o600,
    creator_uid: u32 = 0,
    creator_gid: u32 = 0,

    // Reference counting
    attach_count: u32 = 0,

    // Timestamps
    create_time: u64 = 0,
    last_attach_time: u64 = 0,
    last_detach_time: u64 = 0,

    // Flags
    is_valid: bool = false,
    marked_for_deletion: bool = false,

    pub fn totalAttached(self: *const ShmSegment) u32 {
        return self.attach_count;
    }
};

// =============================================================================
// Segment table
// =============================================================================
var segments: [MAX_SHM_SEGMENTS]ShmSegment = undefined;
var next_shm_id: u32 = 1;

// =============================================================================
// Initialize
// =============================================================================
pub fn initialize() void {
    for (&segments) |*s| {
        s.* = ShmSegment{};
    }
    main.klog(.info, "shm: initialized ({d} max segments, {d} MB max)", .{
        MAX_SHM_SEGMENTS,
        MAX_SHM_SIZE / (1024 * 1024),
    });
}

// =============================================================================
// shmget — create or find a shared memory segment
// =============================================================================
pub fn shmget(key: u32, size: usize, flags: u32) i32 {
    if (size == 0 or size > MAX_SHM_SIZE) return -1;

    // Round up to page alignment
    const aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    const num_pages = aligned_size / PAGE_SIZE;

    // Check if segment with this key already exists
    if (key != IPC_PRIVATE) {
        for (&segments) |*s| {
            if (s.is_valid and s.key == key) {
                if ((flags & IPC_CREAT) != 0 and (flags & IPC_EXCL) != 0) {
                    return -1; // Already exists
                }
                return @intCast(s.id);
            }
        }
    }

    // Create new segment
    if ((flags & IPC_CREAT) == 0 and key != IPC_PRIVATE) {
        return -1; // Doesn't exist and IPC_CREAT not set
    }

    for (&segments) |*s| {
        if (!s.is_valid) {
            s.* = ShmSegment{};
            s.id = next_shm_id;
            next_shm_id += 1;
            s.key = key;
            s.size = aligned_size;
            s.num_pages = num_pages;
            s.mode = @truncate(flags & 0o777);
            s.is_valid = true;

            // Allocate physical pages
            s.page_count = @min(num_pages, 64);
            var i: usize = 0;
            while (i < s.page_count) : (i += 1) {
                if (main.pmm.allocFrame()) |frame| {
                    s.pages[i] = frame;
                } else {
                    // Failed to allocate — free what we got
                    var j: usize = 0;
                    while (j < i) : (j += 1) {
                        main.pmm.freeFrame(s.pages[j]);
                    }
                    s.is_valid = false;
                    return -1;
                }
            }

            main.klog(.debug, "shm: created segment id={d}, key={d}, size={d}", .{
                s.id, key, aligned_size,
            });

            return @intCast(s.id);
        }
    }

    return -1; // No free segment slots
}

// =============================================================================
// shmat — attach a segment to the current process
// =============================================================================
pub fn shmat(shm_id: u32, addr_hint: u64, flags: u32) ?u64 {
    const seg = findById(shm_id) orelse return null;
    if (seg.marked_for_deletion) return null;

    // Choose a virtual address for the mapping
    var map_addr = addr_hint;
    if (map_addr == 0) {
        // Kernel picks the address — use the shared memory region
        map_addr = 0x0000700000000000 + @as(u64, seg.id) * 0x10000000;
    }

    // Map the physical pages into the current process's address space
    const read_only = (flags & SHM_RDONLY) != 0;
    _ = read_only;

    var i: usize = 0;
    while (i < seg.page_count) : (i += 1) {
        main.paging.mapPage(
            map_addr + i * PAGE_SIZE,
            seg.pages[i],
            true, // present
            true, // writable (TODO: respect SHM_RDONLY)
            true, // user
        ) catch continue;
    }

    seg.attach_count += 1;
    seg.last_attach_time = main.timer.getUnixTimestamp();

    return map_addr;
}

// =============================================================================
// shmdt — detach a segment
// =============================================================================
pub fn shmdt(addr: u64) bool {
    // Find which segment is mapped at this address
    for (&segments) |*s| {
        if (!s.is_valid) continue;

        const expected_addr = 0x0000700000000000 + @as(u64, s.id) * 0x10000000;
        if (addr == expected_addr) {
            // Unmap pages
            var i: usize = 0;
            while (i < s.page_count) : (i += 1) {
                main.paging.unmapPage(addr + i * PAGE_SIZE) catch {};
            }

            if (s.attach_count > 0) s.attach_count -= 1;
            s.last_detach_time = main.timer.getUnixTimestamp();

            // If marked for deletion and no more attachments, destroy
            if (s.marked_for_deletion and s.attach_count == 0) {
                destroySegment(s);
            }

            return true;
        }
    }
    return false;
}

// =============================================================================
// shmctl — control operations
// =============================================================================
pub fn shmctl(shm_id: u32, cmd: u32) bool {
    const seg = findById(shm_id) orelse return false;

    switch (cmd) {
        IPC_RMID => {
            // Mark for deletion (will be destroyed when attach_count reaches 0)
            seg.marked_for_deletion = true;
            if (seg.attach_count == 0) {
                destroySegment(seg);
            }
            return true;
        },
        IPC_STAT => {
            // TODO: copy segment info to user space
            return true;
        },
        IPC_SET => {
            // TODO: update segment parameters from user space
            return true;
        },
        else => return false,
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

fn findById(id: u32) ?*ShmSegment {
    for (&segments) |*s| {
        if (s.is_valid and s.id == id) return s;
    }
    return null;
}

fn destroySegment(seg: *ShmSegment) void {
    // Free physical pages
    var i: usize = 0;
    while (i < seg.page_count) : (i += 1) {
        main.pmm.freeFrame(seg.pages[i]);
    }

    main.klog(.debug, "shm: destroyed segment id={d}", .{seg.id});
    seg.is_valid = false;
}

/// Get statistics
pub fn getStats() struct { total: usize, active: usize, total_memory: usize } {
    var active: usize = 0;
    var memory: usize = 0;
    for (segments) |s| {
        if (s.is_valid) {
            active += 1;
            memory += s.size;
        }
    }
    return .{ .total = MAX_SHM_SEGMENTS, .active = active, .total_memory = memory };
}

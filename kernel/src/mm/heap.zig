// =============================================================================
// Kernel Zxyphor - Kernel Heap Allocator
// =============================================================================
// A general-purpose dynamic memory allocator for the kernel. Uses a
// first-fit free list with block splitting and coalescing. Backed by
// the VMM's page allocator for acquiring new memory from the system.
//
// This allocator provides kmalloc/kfree semantics similar to the Linux
// kernel, with alignment support and size tracking.
//
// Block header layout:
//   [size:u64] [flags:u64] [prev_phys:*Block] [next_phys:*Block] [data...]
//
// The free list is a doubly-linked list sorted by address, which enables
// efficient coalescing of adjacent free blocks.
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Block header — precedes every allocation
// =============================================================================
const BlockHeader = struct {
    size: usize, // Size of the data region (excluding header)
    flags: BlockFlags,
    prev: ?*BlockHeader, // Previous block in physical order (for coalescing)
    next: ?*BlockHeader, // Next block in physical order
    free_prev: ?*BlockHeader, // Previous block in free list
    free_next: ?*BlockHeader, // Next block in free list

    const HEADER_SIZE = @sizeOf(BlockHeader);

    /// Get a pointer to the data region after this header
    fn dataPtr(self: *BlockHeader) [*]u8 {
        return @as([*]u8, @ptrCast(self)) + HEADER_SIZE;
    }

    /// Get the block header from a data pointer
    fn fromDataPtr(ptr: [*]u8) *BlockHeader {
        return @as(*BlockHeader, @ptrCast(@alignCast(ptr - HEADER_SIZE)));
    }

    /// Get the end address of this block (including header + data)
    fn endAddr(self: *BlockHeader) usize {
        return @intFromPtr(self) + HEADER_SIZE + self.size;
    }
};

const BlockFlags = packed struct {
    allocated: bool = false,
    _padding: u63 = 0,
};

// =============================================================================
// Heap state
// =============================================================================
const INITIAL_HEAP_SIZE: usize = 256 * 1024; // 256 KB initial heap
const MIN_BLOCK_SIZE: usize = 32; // Minimum allocation size
const EXPAND_SIZE: usize = 64 * 1024; // Expand by 64 KB at a time

var heap_start: usize = 0;
var heap_end: usize = 0;
var heap_total_size: usize = 0;
var heap_used_bytes: usize = 0;

// Free list head
var free_list_head: ?*BlockHeader = null;

// Statistics
var total_allocations: u64 = 0;
var total_frees: u64 = 0;
var peak_usage: usize = 0;

// Spinlock for thread safety
var lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Initialize the heap allocator
// =============================================================================
pub fn initialize() void {
    // Allocate initial heap pages from the VMM
    const initial_pages = INITIAL_HEAP_SIZE / @as(usize, @truncate(paging.PAGE_SIZE));
    heap_start = @as(usize, @truncate(main.vmm.allocKernelPages(@as(u64, initial_pages)) orelse {
        @panic("Heap: Failed to allocate initial heap memory");
    }));

    heap_end = heap_start + INITIAL_HEAP_SIZE;
    heap_total_size = INITIAL_HEAP_SIZE;

    // Create a single free block spanning the entire heap
    const initial_block = @as(*BlockHeader, @ptrFromInt(heap_start));
    initial_block.* = BlockHeader{
        .size = INITIAL_HEAP_SIZE - BlockHeader.HEADER_SIZE,
        .flags = .{ .allocated = false },
        .prev = null,
        .next = null,
        .free_prev = null,
        .free_next = null,
    };

    free_list_head = initial_block;

    main.klog(.info, "Heap: Initialized at 0x{x}-0x{x} ({d} KB)", .{
        heap_start,
        heap_end,
        INITIAL_HEAP_SIZE / 1024,
    });
}

// =============================================================================
// Allocate memory from the heap
// =============================================================================
pub fn alloc(size: usize) ?[*]u8 {
    return allocAligned(size, 8); // Default 8-byte alignment
}

/// Allocate memory with specific alignment
pub fn allocAligned(requested_size: usize, alignment: usize) ?[*]u8 {
    if (requested_size == 0) return null;

    lock.acquire();
    defer lock.release();

    // Round up to minimum block size and alignment
    const size = @max(alignUpSize(requested_size, alignment), MIN_BLOCK_SIZE);

    // Search the free list for a suitable block (first-fit)
    var current = free_list_head;
    while (current) |block| {
        if (block.size >= size) {
            // Found a suitable block — remove from free list and possibly split
            removeFromFreeList(block);

            // Split if the remaining space is large enough for another block
            const remaining = block.size - size;
            if (remaining > BlockHeader.HEADER_SIZE + MIN_BLOCK_SIZE) {
                splitBlock(block, size);
            }

            block.flags.allocated = true;
            heap_used_bytes += block.size;
            total_allocations += 1;

            if (heap_used_bytes > peak_usage) {
                peak_usage = heap_used_bytes;
            }

            return block.dataPtr();
        }
        current = block.free_next;
    }

    // No suitable block found — expand the heap
    if (expandHeap(size + BlockHeader.HEADER_SIZE)) {
        // Try again after expansion
        return allocAligned(requested_size, alignment);
    }

    main.klog(.warning, "Heap: Allocation of {d} bytes failed (OOM)", .{size});
    return null;
}

// =============================================================================
// Free memory back to the heap
// =============================================================================
pub fn free(ptr: ?[*]u8) void {
    const p = ptr orelse return;

    lock.acquire();
    defer lock.release();

    const block = BlockHeader.fromDataPtr(p);

    if (!block.flags.allocated) {
        main.klog(.warning, "Heap: Double free detected at 0x{x}", .{@intFromPtr(p)});
        return;
    }

    block.flags.allocated = false;
    heap_used_bytes -= block.size;
    total_frees += 1;

    // Add to free list
    addToFreeList(block);

    // Coalesce with adjacent free blocks
    coalesceForward(block);
    _ = coalesceBackward(block);
}

// =============================================================================
// Reallocate (resize) a heap allocation
// =============================================================================
pub fn realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    if (old_ptr == null) return alloc(new_size);
    if (new_size == 0) {
        free(old_ptr);
        return null;
    }

    const old_block = BlockHeader.fromDataPtr(old_ptr.?);
    const old_size = old_block.size;

    // If the block is already large enough, just return it
    if (old_size >= new_size) return old_ptr;

    // Check if we can extend into the next block
    if (old_block.next) |next_block| {
        if (!next_block.flags.allocated) {
            const combined = old_size + BlockHeader.HEADER_SIZE + next_block.size;
            if (combined >= new_size) {
                lock.acquire();
                removeFromFreeList(next_block);
                old_block.size = combined;
                old_block.next = next_block.next;
                if (next_block.next) |nn| {
                    nn.prev = old_block;
                }
                lock.release();
                return old_ptr;
            }
        }
    }

    // Must allocate a new block and copy
    const new_ptr = alloc(new_size) orelse return null;
    const copy_size = @min(old_size, new_size);
    const src = old_ptr.?[0..copy_size];
    const dst = new_ptr[0..copy_size];
    @memcpy(dst, src);
    free(old_ptr);
    return new_ptr;
}

// =============================================================================
// Heap expansion
// =============================================================================
fn expandHeap(min_size: usize) bool {
    const expand = @max(EXPAND_SIZE, alignUpSize(min_size, @as(usize, @truncate(paging.PAGE_SIZE))));
    const pages = expand / @as(usize, @truncate(paging.PAGE_SIZE));

    const new_region = main.vmm.allocKernelPages(@as(u64, pages)) orelse return false;
    const new_start = @as(usize, @truncate(new_region));

    // Create a new free block for the expanded region
    const new_block = @as(*BlockHeader, @ptrFromInt(new_start));
    new_block.* = BlockHeader{
        .size = expand - BlockHeader.HEADER_SIZE,
        .flags = .{ .allocated = false },
        .prev = null,
        .next = null,
        .free_prev = null,
        .free_next = null,
    };

    addToFreeList(new_block);
    heap_end = new_start + expand;
    heap_total_size += expand;

    main.klog(.debug, "Heap: Expanded by {d} KB (total: {d} KB)", .{
        expand / 1024,
        heap_total_size / 1024,
    });

    return true;
}

// =============================================================================
// Free list management
// =============================================================================

/// Add a block to the free list (sorted by address for coalescing)
fn addToFreeList(block: *BlockHeader) void {
    block.free_prev = null;
    block.free_next = null;

    if (free_list_head == null) {
        free_list_head = block;
        return;
    }

    // Find insertion point (sorted by address)
    var current = free_list_head;
    var prev: ?*BlockHeader = null;

    while (current) |c| {
        if (@intFromPtr(block) < @intFromPtr(c)) {
            // Insert before c
            block.free_next = c;
            block.free_prev = prev;
            c.free_prev = block;
            if (prev) |p| {
                p.free_next = block;
            } else {
                free_list_head = block;
            }
            return;
        }
        prev = c;
        current = c.free_next;
    }

    // Insert at end
    if (prev) |p| {
        p.free_next = block;
        block.free_prev = p;
    }
}

/// Remove a block from the free list
fn removeFromFreeList(block: *BlockHeader) void {
    if (block.free_prev) |p| {
        p.free_next = block.free_next;
    } else {
        free_list_head = block.free_next;
    }

    if (block.free_next) |n| {
        n.free_prev = block.free_prev;
    }

    block.free_prev = null;
    block.free_next = null;
}

// =============================================================================
// Block splitting and coalescing
// =============================================================================

/// Split a block into two: one of `size` bytes and a remainder
fn splitBlock(block: *BlockHeader, size: usize) void {
    const new_block_addr = @intFromPtr(block) + BlockHeader.HEADER_SIZE + size;
    const new_block = @as(*BlockHeader, @ptrFromInt(new_block_addr));

    new_block.* = BlockHeader{
        .size = block.size - size - BlockHeader.HEADER_SIZE,
        .flags = .{ .allocated = false },
        .prev = block,
        .next = block.next,
        .free_prev = null,
        .free_next = null,
    };

    if (block.next) |next| {
        next.prev = new_block;
    }

    block.size = size;
    block.next = new_block;

    addToFreeList(new_block);
}

/// Coalesce with the next block if it's free
fn coalesceForward(block: *BlockHeader) void {
    if (block.next) |next| {
        if (!next.flags.allocated) {
            removeFromFreeList(next);
            block.size += BlockHeader.HEADER_SIZE + next.size;
            block.next = next.next;
            if (next.next) |nn| {
                nn.prev = block;
            }
        }
    }
}

/// Coalesce with the previous block if it's free
fn coalesceBackward(block: *BlockHeader) *BlockHeader {
    if (block.prev) |prev| {
        if (!prev.flags.allocated) {
            removeFromFreeList(block);
            prev.size += BlockHeader.HEADER_SIZE + block.size;
            prev.next = block.next;
            if (block.next) |next| {
                next.prev = prev;
            }
            return prev;
        }
    }
    return block;
}

// =============================================================================
// Statistics
// =============================================================================
pub fn totalSize() usize {
    return heap_total_size;
}

pub fn usedSize() usize {
    return heap_used_bytes;
}

pub fn freeSize() usize {
    return heap_total_size - heap_used_bytes;
}

pub fn peakUsage() usize {
    return peak_usage;
}

pub fn allocationCount() u64 {
    return total_allocations;
}

pub fn freeCount() u64 {
    return total_frees;
}

// =============================================================================
// Helper
// =============================================================================
fn alignUpSize(value: usize, alignment: usize) usize {
    return (value + alignment - 1) & ~(alignment - 1);
}

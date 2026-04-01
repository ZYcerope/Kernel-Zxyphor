// =============================================================================
// Kernel Zxyphor - Physical Memory Manager (PMM)
// =============================================================================
// Manages physical memory frames (4KB pages) using a bitmap allocator.
// Each bit in the bitmap represents a 4KB physical frame:
//   0 = free, 1 = allocated/reserved
//
// The PMM is initialized from the Multiboot2 memory map, which tells us
// which physical regions are available (RAM) vs reserved (BIOS, MMIO, etc.).
//
// Design decisions:
//   - Bitmap allocator chosen for simplicity and O(1) free operations
//   - Allocation is O(n) in worst case, but we use a next-fit hint to
//     reduce average allocation time
//   - Thread-safe via spinlock (needed for SMP)
// =============================================================================

const main = @import("../main.zig");
const multiboot = @import("../boot/multiboot.zig");

// =============================================================================
// Constants
// =============================================================================
pub const FRAME_SIZE: u64 = 4096; // 4KB per frame
const MAX_MEMORY: u64 = 16 * 1024 * 1024 * 1024; // Support up to 16GB
const MAX_FRAMES: u64 = MAX_MEMORY / FRAME_SIZE;
const BITMAP_SIZE: usize = @as(usize, @truncate(MAX_FRAMES / 8)); // 1 bit per frame

// =============================================================================
// Bitmap storage — statically allocated
// =============================================================================
// For 16GB of memory at 4KB per frame, we need 4M frames = 512KB bitmap.
// This is placed in BSS and zero-initialized at boot.
// =============================================================================
var bitmap: [BITMAP_SIZE]u8 = [_]u8{0xFF} ** BITMAP_SIZE; // Start all-allocated

var total_frames: u64 = 0;
var free_frames: u64 = 0;
var used_frames: u64 = 0;
var next_free_hint: u64 = 0; // Optimization: start searching from here

// Spinlock for thread safety
var lock: main.spinlock.SpinLock = main.spinlock.SpinLock.init();

// =============================================================================
// Initialize the PMM from the Multiboot2 memory map
// =============================================================================
pub fn initialize(
    memory_map: []const multiboot.MmapEntry,
    map_entries: usize,
    kernel_start: usize,
    kernel_end: usize,
) void {
    _ = map_entries;

    // First pass: mark all available regions as free in the bitmap
    for (memory_map) |entry| {
        if (!entry.isAvailable()) continue;

        // Align the region to frame boundaries
        var base = alignUp(entry.base_addr);
        const end = alignDown(entry.base_addr + entry.length);

        while (base < end) : (base += FRAME_SIZE) {
            const frame_num = base / FRAME_SIZE;
            if (frame_num < MAX_FRAMES) {
                clearBit(frame_num);
                free_frames += 1;
                total_frames += 1;
            }
        }
    }

    // Reserve the first 1MB (BIOS, real mode IVT, VGA memory, etc.)
    var addr: u64 = 0;
    while (addr < 0x100000) : (addr += FRAME_SIZE) {
        reserveFrame(addr);
    }

    // Reserve the kernel's own memory region
    addr = alignDown(@as(u64, kernel_start));
    const kern_end = alignUp(@as(u64, kernel_end));
    while (addr < kern_end) : (addr += FRAME_SIZE) {
        reserveFrame(addr);
    }

    used_frames = total_frames - free_frames;

    main.klog(.info, "PMM: Bitmap at 0x{x}, managing {d} frames ({d} MB)", .{
        @intFromPtr(&bitmap),
        total_frames,
        (total_frames * FRAME_SIZE) / (1024 * 1024),
    });
}

// =============================================================================
// Allocate a single physical frame
// Returns the physical address of the allocated frame, or null if OOM
// =============================================================================
pub fn allocFrame() ?u64 {
    lock.acquire();
    defer lock.release();

    // Search from the hint position (next-fit strategy)
    var i = next_free_hint;
    var searched: u64 = 0;

    while (searched < total_frames) : ({
        i = (i + 1) % total_frames;
        searched += 1;
    }) {
        if (!testBit(i)) {
            // Found a free frame
            setBit(i);
            free_frames -= 1;
            used_frames += 1;
            next_free_hint = (i + 1) % total_frames;
            return i * FRAME_SIZE;
        }
    }

    // Out of physical memory
    main.klog(.err, "PMM: Out of physical memory!", .{});
    return null;
}

/// Allocate contiguous physical frames (for DMA buffers, etc.)
pub fn allocContiguousFrames(count: u64) ?u64 {
    if (count == 0) return null;
    if (count == 1) return allocFrame();

    lock.acquire();
    defer lock.release();

    var start: u64 = 0;
    while (start + count <= total_frames) {
        var found = true;
        var j: u64 = 0;

        while (j < count) : (j += 1) {
            if (testBit(start + j)) {
                found = false;
                start = start + j + 1; // Skip past this allocated frame
                break;
            }
        }

        if (found) {
            // Mark all frames as allocated
            j = 0;
            while (j < count) : (j += 1) {
                setBit(start + j);
            }
            free_frames -= count;
            used_frames += count;
            return start * FRAME_SIZE;
        }
    }

    return null; // Could not find contiguous region
}

// =============================================================================
// Free a physical frame
// =============================================================================
pub fn freeFrame(phys_addr: u64) void {
    lock.acquire();
    defer lock.release();

    const frame_num = phys_addr / FRAME_SIZE;
    if (frame_num >= MAX_FRAMES) return;

    if (testBit(frame_num)) {
        clearBit(frame_num);
        free_frames += 1;
        used_frames -= 1;

        // Update hint for faster next allocation
        if (frame_num < next_free_hint) {
            next_free_hint = frame_num;
        }
    }
}

/// Free contiguous physical frames
pub fn freeContiguousFrames(phys_addr: u64, count: u64) void {
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        freeFrame(phys_addr + i * FRAME_SIZE);
    }
}

// =============================================================================
// Reserve a frame (mark as used without allocating it)
// Used for kernel memory, MMIO regions, etc.
// =============================================================================
pub fn reserveFrame(phys_addr: u64) void {
    const frame_num = phys_addr / FRAME_SIZE;
    if (frame_num >= MAX_FRAMES) return;

    if (!testBit(frame_num)) {
        setBit(frame_num);
        if (free_frames > 0) free_frames -= 1;
        used_frames += 1;
    }
}

/// Reserve a range of physical addresses
pub fn reserveRange(start: u64, size: u64) void {
    var addr = alignDown(start);
    const end = alignUp(start + size);
    while (addr < end) : (addr += FRAME_SIZE) {
        reserveFrame(addr);
    }
}

// =============================================================================
// Statistics
// =============================================================================
pub fn freePageCount() u64 {
    return free_frames;
}

pub fn totalPageCount() u64 {
    return total_frames;
}

pub fn usedPageCount() u64 {
    return used_frames;
}

pub fn freeMemoryBytes() u64 {
    return free_frames * FRAME_SIZE;
}

pub fn usedMemoryBytes() u64 {
    return used_frames * FRAME_SIZE;
}

pub fn totalMemoryBytes() u64 {
    return total_frames * FRAME_SIZE;
}

// =============================================================================
// Bitmap manipulation (private helpers)
// =============================================================================

/// Set a bit (mark frame as allocated)
fn setBit(frame: u64) void {
    const byte_idx = @as(usize, @truncate(frame / 8));
    const bit_idx = @as(u3, @truncate(frame % 8));
    if (byte_idx < BITMAP_SIZE) {
        bitmap[byte_idx] |= @as(u8, 1) << bit_idx;
    }
}

/// Clear a bit (mark frame as free)
fn clearBit(frame: u64) void {
    const byte_idx = @as(usize, @truncate(frame / 8));
    const bit_idx = @as(u3, @truncate(frame % 8));
    if (byte_idx < BITMAP_SIZE) {
        bitmap[byte_idx] &= ~(@as(u8, 1) << bit_idx);
    }
}

/// Test a bit (check if frame is allocated)
fn testBit(frame: u64) bool {
    const byte_idx = @as(usize, @truncate(frame / 8));
    const bit_idx = @as(u3, @truncate(frame % 8));
    if (byte_idx >= BITMAP_SIZE) return true; // Out of range = allocated
    return (bitmap[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
}

/// Align address down to frame boundary
fn alignDown(addr: u64) u64 {
    return addr & ~@as(u64, FRAME_SIZE - 1);
}

/// Align address up to frame boundary
fn alignUp(addr: u64) u64 {
    return (addr + FRAME_SIZE - 1) & ~@as(u64, FRAME_SIZE - 1);
}

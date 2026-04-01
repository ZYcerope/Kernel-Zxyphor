// =============================================================================
// Kernel Zxyphor - Virtual Memory Manager (VMM)
// =============================================================================
// Manages the kernel's virtual address space and provides the interface for
// creating/destroying process address spaces. The VMM sits on top of the
// architecture-specific paging layer and provides higher-level abstractions:
//
//   - Kernel memory mapping (higher-half, shared across all processes)
//   - Process virtual address spaces (each process gets its own PML4)
//   - Demand paging and copy-on-write (COW)
//   - Memory-mapped I/O (MMIO) regions
//   - Guard pages for stack overflow detection
//
// Virtual address space layout (per process):
//   0x0000000000000000 - 0x00007FFFFFFFFFFF : User space (128 TB)
//   0xFFFF800000000000 - 0xFFFFFFFF7FFFFFFF : Kernel heap + mappings
//   0xFFFFFFFF80000000 - 0xFFFFFFFFFFFFFFFF : Kernel image (higher-half)
// =============================================================================

const main = @import("../main.zig");
const paging = @import("../arch/x86_64/paging.zig");

// =============================================================================
// Virtual address space regions
// =============================================================================
pub const USER_SPACE_START: u64 = 0x0000000000400000; // User text starts here
pub const USER_SPACE_END: u64 = 0x00007FFFFFFFFFFF; // End of user space
pub const USER_STACK_TOP: u64 = 0x00007FFFFFFFF000; // Default user stack top
pub const USER_HEAP_START: u64 = 0x0000000040000000; // User heap base

pub const KERNEL_HEAP_START: u64 = 0xFFFF800000000000; // Kernel heap region
pub const KERNEL_HEAP_END: u64 = 0xFFFF8000FFFFFFFF; // 4GB kernel heap max
pub const KERNEL_MMIO_START: u64 = 0xFFFF800100000000; // MMIO mapped here
pub const KERNEL_VMA: u64 = 0xFFFFFFFF80000000; // Kernel image base

// =============================================================================
// Virtual Memory Area (VMA) — describes a contiguous mapped region
// =============================================================================
pub const VmaFlags = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
    user: bool = false,
    shared: bool = false,
    copy_on_write: bool = false,
    locked: bool = false, // Cannot be swapped out
    grows_down: bool = false, // Stack region
};

pub const VmaType = enum {
    anonymous, // Zero-filled memory (heap, stack)
    file_backed, // Mapped from a file
    device, // MMIO region
    shared, // Shared memory (IPC)
};

pub const Vma = struct {
    start: u64, // Start virtual address
    end: u64, // End virtual address (exclusive)
    flags: VmaFlags,
    vma_type: VmaType,
    // For file-backed mappings
    file_offset: u64,
    file_inode: ?*anyopaque, // Pointer to VFS inode
    // Linked list for the process's VMA list
    next: ?*Vma,
    prev: ?*Vma,
};

// =============================================================================
// Address space (one per process)
// =============================================================================
pub const AddressSpace = struct {
    pml4_phys: u64, // Physical address of the PML4 table
    vma_list: ?*Vma, // Head of the VMA linked list
    vma_count: u32, // Number of VMAs
    total_mapped: u64, // Total bytes mapped
    lock: main.spinlock.SpinLock,

    pub fn init(pml4: u64) AddressSpace {
        return AddressSpace{
            .pml4_phys = pml4,
            .vma_list = null,
            .vma_count = 0,
            .total_mapped = 0,
            .lock = main.spinlock.SpinLock.init(),
        };
    }
};

// =============================================================================
// Kernel address space (shared by all processes)
// =============================================================================
var kernel_pml4_phys: u64 = 0;
var kernel_address_space: AddressSpace = undefined;

// MMIO allocation pointer
var next_mmio_addr: u64 = KERNEL_MMIO_START;

// =============================================================================
// Initialize the VMM — called during boot
// =============================================================================
pub fn initialize() void {
    // Allocate a new PML4 for the kernel
    kernel_pml4_phys = main.pmm.allocFrame() orelse {
        @panic("VMM: Failed to allocate kernel PML4");
    };

    // Zero the PML4
    const pml4 = @as(*paging.PageTable, @ptrFromInt(paging.physToVirt(kernel_pml4_phys)));
    pml4.zero();

    // Map the kernel image (higher-half mapping)
    mapKernelImage() catch {
        @panic("VMM: Failed to map kernel image");
    };

    // Identity-map the first 4MB for bootloader compatibility
    mapLowerMemory() catch {
        @panic("VMM: Failed to identity-map lower memory");
    };

    // Switch to our new page tables
    main.registers.writeCr3(kernel_pml4_phys);

    kernel_address_space = AddressSpace.init(kernel_pml4_phys);

    main.klog(.info, "VMM: Kernel PML4 at physical 0x{x}", .{kernel_pml4_phys});
}

/// Map the kernel image into the higher half
fn mapKernelImage() !void {
    // Map the kernel from its physical location to KERNEL_VMA
    const kern_phys_start: u64 = @intFromPtr(&main.__kernel_phys_start);
    const kern_phys_end: u64 = @intFromPtr(&main.__kernel_phys_end);
    const kern_size = kern_phys_end - kern_phys_start;

    // Map with read-write for now; we'll set proper permissions later
    try paging.mapRange(
        kernel_pml4_phys,
        KERNEL_VMA,
        kern_phys_start,
        paging.alignUp(kern_size),
        paging.PAGE_KERNEL_RW | paging.PAGE_GLOBAL,
    );
}

/// Identity-map the first 4MB for early boot compatibility
fn mapLowerMemory() !void {
    var addr: u64 = 0;
    while (addr < 4 * 1024 * 1024) : (addr += paging.PAGE_SIZE) {
        try paging.mapPage(
            kernel_pml4_phys,
            addr,
            addr,
            paging.PAGE_KERNEL_RW,
        );
    }
}

// =============================================================================
// Map physical memory into kernel space (for MMIO, framebuffer, etc.)
// =============================================================================
pub fn mapMmio(phys_addr: u64, size: u64) !u64 {
    const aligned_size = paging.alignUp(size);
    const virt_addr = next_mmio_addr;
    next_mmio_addr += aligned_size;

    try paging.mapRange(
        kernel_pml4_phys,
        virt_addr,
        phys_addr,
        aligned_size,
        paging.PAGE_MMIO,
    );

    return virt_addr;
}

// =============================================================================
// Kernel memory allocation (page-granularity)
// =============================================================================

/// Allocate kernel virtual pages backed by physical memory
pub fn allocKernelPages(count: u64) ?u64 {
    const size = count * paging.PAGE_SIZE;
    const virt = findFreeKernelRange(size) orelse return null;

    var offset: u64 = 0;
    while (offset < size) : (offset += paging.PAGE_SIZE) {
        const frame = main.pmm.allocFrame() orelse {
            // Roll back on failure
            var rollback: u64 = 0;
            while (rollback < offset) : (rollback += paging.PAGE_SIZE) {
                if (paging.unmapPage(kernel_pml4_phys, virt + rollback)) |phys| {
                    main.pmm.freeFrame(phys);
                }
            }
            return null;
        };

        paging.mapPage(kernel_pml4_phys, virt + offset, frame, paging.PAGE_KERNEL_RW) catch {
            main.pmm.freeFrame(frame);
            return null;
        };

        // Zero the page
        const page_ptr = @as([*]u8, @ptrFromInt(@as(usize, @truncate(virt + offset))));
        @memset(page_ptr[0..@as(usize, @truncate(paging.PAGE_SIZE))], 0);
    }

    return virt;
}

/// Free kernel virtual pages and their backing physical memory
pub fn freeKernelPages(virt: u64, count: u64) void {
    var offset: u64 = 0;
    while (offset < count * paging.PAGE_SIZE) : (offset += paging.PAGE_SIZE) {
        if (paging.unmapPage(kernel_pml4_phys, virt + offset)) |phys| {
            main.pmm.freeFrame(phys);
        }
    }
}

// =============================================================================
// Process address space management
// =============================================================================

/// Create a new address space for a process (fork-style: clone kernel mappings)
pub fn createAddressSpace() ?AddressSpace {
    const pml4_phys = main.pmm.allocFrame() orelse return null;
    const pml4 = @as(*paging.PageTable, @ptrFromInt(paging.physToVirt(pml4_phys)));
    pml4.zero();

    // Copy kernel-space entries (upper-half of PML4: indices 256-511)
    const kernel_pml4 = @as(*paging.PageTable, @ptrFromInt(paging.physToVirt(kernel_pml4_phys)));
    var i: usize = 256;
    while (i < 512) : (i += 1) {
        pml4.entries[i] = kernel_pml4.entries[i];
    }

    return AddressSpace.init(pml4_phys);
}

/// Destroy a process's address space and free all associated memory
pub fn destroyAddressSpace(addr_space: *AddressSpace) void {
    // Free all user-space page tables and physical pages
    paging.freePageTableRecursive(addr_space.pml4_phys, true);

    // Free the PML4 itself
    main.pmm.freeFrame(addr_space.pml4_phys);
}

/// Switch to a different address space (used during context switch)
pub fn switchAddressSpace(addr_space: *const AddressSpace) void {
    main.registers.writeCr3(addr_space.pml4_phys);
}

// =============================================================================
// Page fault handler — called from IDT exception handler
// =============================================================================
pub fn handlePageFault(fault_addr: u64, error_code: u64) bool {
    _ = error_code;

    // Check if this address falls in a valid VMA
    // For now, we handle simple demand paging for the kernel heap
    if (fault_addr >= KERNEL_HEAP_START and fault_addr < KERNEL_HEAP_END) {
        // Kernel heap demand paging: allocate a frame and map it
        const frame = main.pmm.allocFrame() orelse return false;
        const page_addr = paging.alignDown(fault_addr);

        paging.mapPage(kernel_pml4_phys, page_addr, frame, paging.PAGE_KERNEL_RW) catch {
            main.pmm.freeFrame(frame);
            return false;
        };

        // Zero the new page
        const page_ptr = @as([*]u8, @ptrFromInt(@as(usize, @truncate(page_addr))));
        @memset(page_ptr[0..@as(usize, @truncate(paging.PAGE_SIZE))], 0);

        return true;
    }

    // TODO: Handle user-space demand paging, COW, stack growth

    return false;
}

// =============================================================================
// Internal helpers
// =============================================================================

var kernel_break: u64 = KERNEL_HEAP_START;

/// Find a free range in kernel virtual address space
fn findFreeKernelRange(size: u64) ?u64 {
    const addr = kernel_break;
    if (addr + size > KERNEL_HEAP_END) return null;
    kernel_break += size;
    return addr;
}

/// Get the kernel PML4 physical address
pub fn getKernelPml4() u64 {
    return kernel_pml4_phys;
}

// =============================================================================
// Kernel Zxyphor - Main Entry Point
// =============================================================================
// This is the primary entry point for the Zxyphor kernel after the bootloader
// transfers control. It orchestrates the initialization of all kernel subsystems
// in the correct dependency order.
//
// Boot sequence:
//   1. Multiboot bootstrap (assembly-level) sets up initial paging
//   2. _start transfers to kmain() here
//   3. We initialize: serial -> GDT -> IDT -> PMM -> VMM -> heap -> scheduler
//   4. Finally, we start the first userspace process (init)
// =============================================================================

const std = @import("std");

// Architecture-specific modules
pub const arch = @import("arch/x86_64/cpu.zig");
pub const gdt = @import("boot/gdt.zig");
pub const idt = @import("boot/idt.zig");
pub const tss = @import("boot/tss.zig");
pub const multiboot = @import("boot/multiboot.zig");
pub const paging = @import("arch/x86_64/paging.zig");
pub const interrupts = @import("arch/x86_64/interrupts.zig");
pub const pic = @import("arch/x86_64/pic.zig");
pub const pit = @import("arch/x86_64/pit.zig");
pub const apic = @import("arch/x86_64/apic.zig");
pub const serial = @import("arch/x86_64/serial.zig");
pub const registers = @import("arch/x86_64/registers.zig");

// Memory management
pub const pmm = @import("mm/pmm.zig");
pub const vmm = @import("mm/vmm.zig");
pub const heap = @import("mm/heap.zig");
pub const slab = @import("mm/slab.zig");
pub const page = @import("mm/page.zig");

// Process and scheduling
pub const process = @import("sched/process.zig");
pub const thread = @import("sched/thread.zig");
pub const scheduler = @import("sched/scheduler.zig");
pub const context = @import("sched/context.zig");

// File systems
pub const vfs = @import("fs/vfs.zig");
pub const zxyfs = @import("fs/zxyfs.zig");
pub const devfs = @import("fs/devfs.zig");
pub const ramfs = @import("fs/ramfs.zig");

// Device drivers
pub const vga = @import("drivers/vga.zig");
pub const keyboard = @import("drivers/keyboard.zig");
pub const timer = @import("drivers/timer.zig");
pub const pci = @import("drivers/pci.zig");
pub const ata = @import("drivers/ata.zig");
pub const rtc = @import("drivers/rtc.zig");

// System calls
pub const syscall_handler = @import("syscall/handler.zig");
pub const syscall_table = @import("syscall/table.zig");

// IPC
pub const pipe = @import("ipc/pipe.zig");
pub const signal = @import("ipc/signal.zig");
pub const shm = @import("ipc/shm.zig");

// Networking
pub const ethernet = @import("net/ethernet.zig");
pub const ip = @import("net/ip.zig");
pub const tcp = @import("net/tcp.zig");
pub const udp = @import("net/udp.zig");
pub const socket = @import("net/socket.zig");
pub const arp = @import("net/arp.zig");

// Security
pub const capabilities = @import("security/capabilities.zig");
pub const access = @import("security/access.zig");

// Kernel libraries
pub const string = @import("lib/string.zig");
pub const list = @import("lib/list.zig");
pub const bitmap = @import("lib/bitmap.zig");
pub const ringbuf = @import("lib/ringbuf.zig");
pub const rbtree = @import("lib/rbtree.zig");
pub const spinlock = @import("lib/spinlock.zig");

// =============================================================================
// Kernel version and build information
// =============================================================================
pub const KERNEL_NAME = "Zxyphor";
pub const KERNEL_VERSION_MAJOR = 1;
pub const KERNEL_VERSION_MINOR = 0;
pub const KERNEL_VERSION_PATCH = 0;
pub const KERNEL_CODENAME = "Genesis";
pub const KERNEL_ARCH = "x86_64";

// =============================================================================
// External linker symbols from linker.ld
// =============================================================================
extern var __kernel_phys_start: u8;
extern var __kernel_phys_end: u8;
extern var __kernel_virt_start: u8;
extern var __kernel_end: u8;
extern var __bss_start: u8;
extern var __bss_end: u8;
extern var __stack_top: u8;
extern var __stack_bottom: u8;

// =============================================================================
// Kernel panic handler — invoked on unrecoverable errors
// =============================================================================
pub fn panic(msg: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    // Disable interrupts immediately to prevent further damage
    arch.disableInterrupts();

    // Output to serial console for debugging
    serial.writer().print("\r\n\r\n", .{}) catch {};
    serial.writer().print("!!! KERNEL PANIC !!!\r\n", .{}) catch {};
    serial.writer().print("Reason: {s}\r\n", .{msg}) catch {};
    serial.writer().print("System halted.\r\n", .{}) catch {};

    // Also display on VGA if available
    vga.setColor(.white, .red);
    vga.clear();
    vga.writeString("\n  !!! KERNEL PANIC !!!\n\n  ");
    vga.writeString(msg);
    vga.writeString("\n\n  System halted. Please restart your computer.\n");

    // Halt the CPU in an infinite loop
    arch.halt();
}

// =============================================================================
// Kernel log facility — structured logging for kernel messages
// =============================================================================
pub const LogLevel = enum(u8) {
    emergency = 0, // System is unusable
    alert = 1, // Action must be taken immediately
    critical = 2, // Critical conditions
    err = 3, // Error conditions
    warning = 4, // Warning conditions
    notice = 5, // Normal but significant condition
    info = 6, // Informational messages
    debug = 7, // Debug-level messages
};

var current_log_level: LogLevel = .info;

pub fn setLogLevel(level: LogLevel) void {
    current_log_level = level;
}

pub fn klog(level: LogLevel, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(level) > @intFromEnum(current_log_level)) return;

    const prefix = switch (level) {
        .emergency => "[EMERG] ",
        .alert => "[ALERT] ",
        .critical => "[CRIT]  ",
        .err => "[ERROR] ",
        .warning => "[WARN]  ",
        .notice => "[NOTE]  ",
        .info => "[INFO]  ",
        .debug => "[DEBUG] ",
    };

    serial.writer().print("{s}", .{prefix}) catch {};
    serial.writer().print(fmt, args) catch {};
    serial.writer().print("\r\n", .{}) catch {};
}

// =============================================================================
// Kernel main — called from bootstrap after initial paging is set up
// =============================================================================
export fn kmain(multiboot_info_addr: u32) callconv(.C) noreturn {
    // -------------------------------------------------------------------------
    // Phase 0: Clear BSS segment (zero-initialize uninitialized globals)
    // -------------------------------------------------------------------------
    const bss_start: [*]u8 = @ptrCast(&__bss_start);
    const bss_end: [*]u8 = @ptrCast(&__bss_end);
    const bss_len = @intFromPtr(bss_end) - @intFromPtr(bss_start);
    @memset(bss_start[0..bss_len], 0);

    // -------------------------------------------------------------------------
    // Phase 1: Early hardware initialization (no memory allocation needed)
    // -------------------------------------------------------------------------
    serial.initialize(.com1, .baud_115200);
    klog(.info, "Zxyphor Kernel v{d}.{d}.{d} \"{s}\" booting...", .{
        KERNEL_VERSION_MAJOR,
        KERNEL_VERSION_MINOR,
        KERNEL_VERSION_PATCH,
        KERNEL_CODENAME,
    });
    klog(.info, "Architecture: {s}", .{KERNEL_ARCH});

    // Initialize VGA text mode for visual output
    vga.initialize();
    vga.setColor(.light_green, .black);
    vga.writeString("  Zxyphor Kernel v1.0.0 \"Genesis\"\n");
    vga.setColor(.light_grey, .black);
    vga.writeString("  Initializing subsystems...\n\n");

    // -------------------------------------------------------------------------
    // Phase 2: CPU tables — GDT, IDT, TSS
    // -------------------------------------------------------------------------
    klog(.info, "Setting up Global Descriptor Table (GDT)...", .{});
    gdt.initialize();

    klog(.info, "Setting up Task State Segment (TSS)...", .{});
    tss.initialize();

    klog(.info, "Setting up Interrupt Descriptor Table (IDT)...", .{});
    idt.initialize();

    // -------------------------------------------------------------------------
    // Phase 3: Interrupt controller setup
    // -------------------------------------------------------------------------
    klog(.info, "Initializing Programmable Interrupt Controller (PIC)...", .{});
    pic.initialize();

    klog(.info, "Initializing Programmable Interval Timer (PIT)...", .{});
    pit.initialize(1000); // 1000 Hz = 1ms tick resolution

    // -------------------------------------------------------------------------
    // Phase 4: Parse multiboot information for memory map
    // -------------------------------------------------------------------------
    klog(.info, "Parsing Multiboot2 information at 0x{x}...", .{multiboot_info_addr});
    const mb_info = multiboot.parse(multiboot_info_addr);
    const total_memory = mb_info.total_memory_kb;
    klog(.info, "Total usable memory: {d} KB ({d} MB)", .{
        total_memory,
        total_memory / 1024,
    });

    // -------------------------------------------------------------------------
    // Phase 5: Physical Memory Manager
    // -------------------------------------------------------------------------
    klog(.info, "Initializing Physical Memory Manager (PMM)...", .{});
    const kernel_phys_start = @intFromPtr(&__kernel_phys_start);
    const kernel_phys_end = @intFromPtr(&__kernel_phys_end);
    pmm.initialize(mb_info.memory_map, mb_info.memory_map_entries, kernel_phys_start, kernel_phys_end);
    klog(.info, "PMM: {d} free pages ({d} MB available)", .{
        pmm.freePageCount(),
        (pmm.freePageCount() * 4096) / (1024 * 1024),
    });

    // -------------------------------------------------------------------------
    // Phase 6: Virtual Memory Manager — set up kernel page tables
    // -------------------------------------------------------------------------
    klog(.info, "Initializing Virtual Memory Manager (VMM)...", .{});
    vmm.initialize();
    klog(.info, "VMM: Kernel mapped to higher half at 0xFFFFFFFF80000000", .{});

    // -------------------------------------------------------------------------
    // Phase 7: Kernel heap allocator
    // -------------------------------------------------------------------------
    klog(.info, "Initializing kernel heap allocator...", .{});
    heap.initialize();
    klog(.info, "Heap: {d} KB initial heap space", .{heap.totalSize() / 1024});

    // -------------------------------------------------------------------------
    // Phase 8: Slab allocator for common kernel objects
    // -------------------------------------------------------------------------
    klog(.info, "Initializing slab allocator...", .{});
    slab.initialize();

    // -------------------------------------------------------------------------
    // Phase 9: Device drivers
    // -------------------------------------------------------------------------
    klog(.info, "Initializing PCI bus...", .{});
    pci.initialize();

    klog(.info, "Initializing keyboard driver...", .{});
    keyboard.initialize();

    klog(.info, "Initializing ATA/IDE disk controller...", .{});
    ata.initialize();

    klog(.info, "Initializing Real-Time Clock (RTC)...", .{});
    rtc.initialize();
    const datetime = rtc.readDateTime();
    klog(.info, "Current date/time: {d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        datetime.year, datetime.month,  datetime.day,
        datetime.hour, datetime.minute, datetime.second,
    });

    // -------------------------------------------------------------------------
    // Phase 10: Virtual File System
    // -------------------------------------------------------------------------
    klog(.info, "Initializing Virtual File System (VFS)...", .{});
    vfs.initialize();

    klog(.info, "Mounting ramfs at /...", .{});
    ramfs.initialize();
    vfs.mount("/", &ramfs.filesystem) catch {
        klog(.err, "Failed to mount root filesystem!", .{});
    };

    klog(.info, "Mounting devfs at /dev...", .{});
    devfs.initialize();
    vfs.mount("/dev", &devfs.filesystem) catch {
        klog(.err, "Failed to mount devfs!", .{});
    };

    // -------------------------------------------------------------------------
    // Phase 11: System call interface
    // -------------------------------------------------------------------------
    klog(.info, "Initializing system call interface...", .{});
    syscall_handler.initialize();

    // -------------------------------------------------------------------------
    // Phase 12: IPC subsystems
    // -------------------------------------------------------------------------
    klog(.info, "Initializing IPC subsystems...", .{});
    pipe.initialize();
    signal.initialize();
    shm.initialize();

    // -------------------------------------------------------------------------
    // Phase 13: Networking stack
    // -------------------------------------------------------------------------
    klog(.info, "Initializing networking stack...", .{});
    arp.initialize();
    ip.initialize();
    tcp.initialize();
    udp.initialize();
    socket.initialize();

    // -------------------------------------------------------------------------
    // Phase 14: Security framework
    // -------------------------------------------------------------------------
    klog(.info, "Initializing capability-based security...", .{});
    capabilities.initialize();
    access.initialize();

    // -------------------------------------------------------------------------
    // Phase 15: Process scheduler and first process
    // -------------------------------------------------------------------------
    klog(.info, "Initializing process scheduler...", .{});
    scheduler.initialize();

    // Create the idle process (PID 0) and init process (PID 1)
    klog(.info, "Creating kernel processes...", .{});
    const idle_proc = process.createKernelProcess("idle", idleTask) catch {
        @panic("Failed to create idle process");
    };
    _ = idle_proc;

    const init_proc = process.createKernelProcess("init", initTask) catch {
        @panic("Failed to create init process");
    };
    _ = init_proc;

    // -------------------------------------------------------------------------
    // Phase 16: Enable interrupts and start scheduling
    // -------------------------------------------------------------------------
    klog(.info, "===================================================", .{});
    klog(.info, " Zxyphor Kernel initialization complete!", .{});
    klog(.info, " All subsystems operational. Starting scheduler.", .{});
    klog(.info, "===================================================", .{});

    vga.setColor(.light_green, .black);
    vga.writeString("  [OK] All subsystems initialized successfully.\n");
    vga.writeString("  [OK] Starting scheduler...\n\n");
    vga.setColor(.white, .black);

    // Enable interrupts and start the scheduler — this never returns
    arch.enableInterrupts();
    scheduler.start();

    // Should never reach here
    unreachable;
}

// =============================================================================
// Idle task — runs when no other process is ready
// =============================================================================
fn idleTask() callconv(.C) noreturn {
    while (true) {
        // HLT instruction puts the CPU into a low-power state until the next
        // interrupt fires. This is essential for power management — without it
        // the idle loop would burn 100% CPU.
        arch.haltUntilInterrupt();
    }
}

// =============================================================================
// Init task — the first kernel process, sets up userspace environment
// =============================================================================
fn initTask() callconv(.C) noreturn {
    klog(.info, "Init process started (PID 1)", .{});

    // Create essential directory structure in ramfs
    const dirs = [_][]const u8{
        "/dev", "/proc", "/sys", "/tmp", "/var",
        "/var/log", "/var/run", "/etc", "/home",
        "/bin", "/sbin", "/lib", "/usr",
    };

    for (dirs) |dir| {
        vfs.mkdir(dir, 0o755) catch |err| {
            klog(.warning, "Could not create {s}: {}", .{ dir, err });
        };
    }

    // Create essential device nodes
    devfs.createNode("null", .char_device, 1, 3) catch {};
    devfs.createNode("zero", .char_device, 1, 5) catch {};
    devfs.createNode("random", .char_device, 1, 8) catch {};
    devfs.createNode("urandom", .char_device, 1, 9) catch {};
    devfs.createNode("tty0", .char_device, 4, 0) catch {};
    devfs.createNode("console", .char_device, 5, 1) catch {};

    klog(.info, "Init: filesystem structure created", .{});
    klog(.info, "Init: system ready", .{});

    // Display welcome message on VGA console
    vga.setColor(.light_cyan, .black);
    vga.writeString("  Welcome to Zxyphor OS!\n");
    vga.setColor(.light_grey, .black);
    vga.writeString("  Type 'help' for available commands.\n\n");
    vga.setColor(.white, .black);
    vga.writeString("  zxyphor> ");

    // Simple kernel shell loop for demonstration
    var cmd_buffer: [256]u8 = undefined;
    var cmd_len: usize = 0;

    while (true) {
        if (keyboard.readChar()) |ch| {
            switch (ch) {
                '\n' => {
                    vga.writeChar('\n');
                    if (cmd_len > 0) {
                        processCommand(cmd_buffer[0..cmd_len]);
                        cmd_len = 0;
                    }
                    vga.writeString("  zxyphor> ");
                },
                '\x08' => { // backspace
                    if (cmd_len > 0) {
                        cmd_len -= 1;
                        vga.backspace();
                    }
                },
                else => {
                    if (cmd_len < cmd_buffer.len - 1) {
                        cmd_buffer[cmd_len] = ch;
                        cmd_len += 1;
                        vga.writeChar(ch);
                    }
                },
            }
        } else {
            // No key available — yield CPU time to other processes
            scheduler.yield();
        }
    }
}

// =============================================================================
// Simple kernel shell command processor
// =============================================================================
fn processCommand(cmd: []const u8) void {
    if (string.equal(cmd, "help")) {
        vga.writeString("  Available commands:\n");
        vga.writeString("    help     - Show this help message\n");
        vga.writeString("    info     - Show kernel information\n");
        vga.writeString("    mem      - Show memory statistics\n");
        vga.writeString("    ps       - List running processes\n");
        vga.writeString("    ls       - List files in current directory\n");
        vga.writeString("    uptime   - Show system uptime\n");
        vga.writeString("    clear    - Clear the screen\n");
        vga.writeString("    reboot   - Restart the system\n");
        vga.writeString("    halt     - Shut down the system\n");
    } else if (string.equal(cmd, "info")) {
        vga.writeString("  Zxyphor Kernel v1.0.0 \"Genesis\"\n");
        vga.writeString("  Architecture: x86_64\n");
        vga.writeString("  Built with Zig + Rust\n");
        const datetime = rtc.readDateTime();
        _ = datetime;
        vga.writeString("  Scheduler: CFS (Completely Fair Scheduler)\n");
    } else if (string.equal(cmd, "mem")) {
        const free_pages = pmm.freePageCount();
        const total_pages = pmm.totalPageCount();
        const used_pages = total_pages - free_pages;
        _ = used_pages;
        vga.writeString("  Memory Statistics:\n");
        // Print memory stats via VGA
        serial.writer().print("  Total: {d} pages, Free: {d} pages, Used: {d} pages\r\n", .{
            total_pages,
            free_pages,
            total_pages - free_pages,
        }) catch {};
    } else if (string.equal(cmd, "ps")) {
        vga.writeString("  PID  STATE    NAME\n");
        vga.writeString("  ---  -----    ----\n");
        process.listProcesses(vga.writer());
    } else if (string.equal(cmd, "ls")) {
        vfs.listDirectory("/", vga.writer()) catch {
            vga.writeString("  Error listing directory.\n");
        };
    } else if (string.equal(cmd, "uptime")) {
        const ticks = pit.getTicks();
        const seconds = ticks / 1000;
        const minutes = seconds / 60;
        const hours = minutes / 60;
        _ = hours;
        vga.writeString("  Uptime: ");
        serial.writer().print("{d}h {d}m {d}s\r\n", .{
            minutes / 60,
            minutes % 60,
            seconds % 60,
        }) catch {};
    } else if (string.equal(cmd, "clear")) {
        vga.clear();
    } else if (string.equal(cmd, "reboot")) {
        vga.writeString("  Rebooting...\n");
        arch.reboot();
    } else if (string.equal(cmd, "halt")) {
        vga.writeString("  System halting...\n");
        arch.shutdown();
    } else {
        vga.writeString("  Unknown command: ");
        vga.writeString(cmd);
        vga.writeString("\n  Type 'help' for available commands.\n");
    }
}

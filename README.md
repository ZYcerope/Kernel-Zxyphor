# Zxyphor Kernel

**Codename: Xceon** — A modern, x86_64 operating system kernel written in Zig and Rust.

```
 ███████╗██╗  ██╗██╗   ██╗██████╗ ██╗  ██╗ ██████╗ ██████╗
 ╚══███╔╝╚██╗██╔╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔═══██╗██╔══██╗
   ███╔╝  ╚███╔╝  ╚████╔╝ ██████╔╝███████║██║   ██║██████╔╝
  ███╔╝   ██╔██╗   ╚██╔╝  ██╔═══╝ ██╔══██║██║   ██║██╔══██╗
 ███████╗██╔╝ ██╗   ██║   ██║     ██║  ██║╚██████╔╝██║  ██║
 ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
                    v0.0.4 Xceon III
```

## Overview

Zxyphor is a from-scratch, Unix-inspired operating system kernel targeting the x86_64 architecture. The primary codebase is written in **Zig** for maximum control over memory layout and systems programming, with performance-critical cryptographic and filesystem modules implemented in **Rust** for memory safety guarantees.

### Design Principles

- **Zero-dependency**: No external libraries — every subsystem is hand-written
- **Higher-half kernel**: Kernel mapped at `0xFFFFFFFF80000000` using 4-level page tables
- **Multiboot2 compatible**: Boots with GRUB2 or any Multiboot2-compliant bootloader
- **Modular architecture**: Clean separation between boot, arch, mm, sched, fs, net, ipc, security, and drivers
- **Linux-inspired syscall ABI**: POSIX-compatible system call interface with 30+ syscalls
- **2026 hardware-aware profile**: CPUID-driven tuning for AVX10, AMX, CET, FRED, PKS, TME, CXL-ready memory tiers, and high queue-count storage/network paths

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    User Space (Ring 3)                        │
├──────────────────────────────────────────────────────────────┤
│  Syscall Interface  │  INT 0x80 / SYSCALL  │  Signal Delivery│
├─────────┬───────────┼──────────┬───────────┼────────┬────────┤
│Scheduler│  IPC      │   VFS    │ Networking│Security│ Drivers│
│ (EEVDF) │Pipe/Shm/  │VNode/    │TCP/IP     │ DAC/   │VGA/KB/ │
│         │  Signal   │Mount     │ Stack     │  Caps  │PCI/ATA │
├─────────┴───────────┼──────────┴───────────┼────────┴────────┤
│   Memory Management │   Kernel Libraries   │  Rust Modules   │
│  PMM/VMM/Heap/Slab  │SpinLock/RbTree/List  │AES/SHA/CSPRNG   │
├─────────────────────┴──────────────────────┴─────────────────┤
│             Architecture Layer (x86_64)                       │
│   GDT/IDT/TSS │ Paging │ APIC/PIC/PIT │ CPU/MSR │ Serial    │
├──────────────────────────────────────────────────────────────┤
│                    Boot (Multiboot2)                          │
└──────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
Kernel Zxyphor/
├── build.zig                  # Zig build system (kernel + QEMU targets)
├── linker.ld                  # Kernel linker script (higher-half)
├── README.md
│
├── kernel/
│   └── src/
│       ├── main.zig           # Kernel entry point, init sequencing
│       │
│       ├── boot/              # Boot subsystem
│       │   ├── multiboot.zig  #   Multiboot2 header & tag parser
│       │   ├── gdt.zig        #   Global Descriptor Table (7 entries)
│       │   ├── idt.zig        #   Interrupt Descriptor Table (256 vectors)
│       │   └── tss.zig        #   Task State Segment with IST stacks
│       │
│       ├── arch/
│       │   └── x86_64/        # Architecture-specific
│       │       ├── cpu.zig        # CPUID, port I/O, MSR, reboot
│       │       ├── registers.zig  # CR0-4, DR0-7, control registers
│       │       ├── paging.zig     # 4-level page tables (PML4)
│       │       ├── interrupts.zig # Nested interrupt control, deferred work
│       │       ├── pic.zig        # 8259 PIC, IRQ remapping
│       │       ├── pit.zig        # 8254 PIT (1000 Hz), callbacks
│       │       ├── apic.zig       # Local APIC, timer, IPI
│       │       └── serial.zig     # UART 16550A (COM1-4)
│       │
│       ├── mm/                # Memory management
│       │   ├── pmm.zig        #   Bitmap physical memory manager
│       │   ├── vmm.zig        #   Virtual memory with VMA tracking
│       │   ├── heap.zig       #   Kernel heap (first-fit, coalescing)
│       │   ├── slab.zig       #   Slab allocator (32B - 4KB classes)
│       │   └── page.zig       #   Page descriptors, ref counting, COW
│       │
│       ├── sched/             # Process & scheduling
│       │   ├── process.zig    #   PCB, process table (4096 max)
│       │   ├── thread.zig     #   TCB, thread table (8192 max)
│       │   ├── scheduler.zig  #   EEVDF scheduler (deadline-based fairness)
│       │   └── context.zig    #   Context switch, FPU save/restore
│       │
│       ├── fs/                # Filesystems
│       │   ├── vfs.zig        #   Virtual Filesystem Switch
│       │   ├── ramfs.zig      #   In-memory filesystem
│       │   ├── devfs.zig      #   Device filesystem (/dev/*)
│       │   └── zxyfs.zig      #   Custom disk-based filesystem
│       │
│       ├── drivers/           # Device drivers
│       │   ├── vga.zig        #   VGA text mode (80x25, scrollback)
│       │   ├── keyboard.zig   #   PS/2 keyboard (scan code set 1)
│       │   ├── timer.zig      #   Timer abstraction, timer wheel
│       │   ├── pci.zig        #   PCI bus enumeration, config space
│       │   ├── ata.zig        #   ATA/IDE PIO (LBA28/LBA48)
│       │   └── rtc.zig        #   CMOS Real-Time Clock
│       │
│       ├── syscall/           # System call interface
│       │   ├── handler.zig    #   SYSCALL/SYSRET + INT 0x80 dispatch
│       │   └── table.zig      #   30+ syscall implementations
│       │
│       ├── ipc/               # Inter-process communication
│       │   ├── pipe.zig       #   Unix pipes (64KB ring buffer)
│       │   ├── signal.zig     #   POSIX signals (31 signals)
│       │   └── shm.zig        #   System V shared memory
│       │
│       ├── net/               # Networking stack
│       │   ├── ethernet.zig   #   Ethernet frames, MAC, CRC-32
│       │   ├── arp.zig        #   ARP with 512-entry cache
│       │   ├── ip.zig         #   IPv4, ICMP, routing table
│       │   ├── tcp.zig        #   TCP (full FSM, congestion control)
│       │   ├── udp.zig        #   UDP with socket interface
│       │   └── socket.zig     #   BSD socket API
│       │
│       ├── security/          # Security subsystem
│       │   ├── capabilities.zig # Linux-compatible capabilities (41)
│       │   └── access.zig     #   DAC, credentials, audit, entropy
│       │
│       └── lib/               # Kernel libraries
│           ├── spinlock.zig   #   Ticket spinlock, RW spinlock
│           ├── string.zig     #   String utilities, formatting, paths
│           ├── list.zig       #   Intrusive doubly-linked list
│           ├── bitmap.zig     #   Static & dynamic bitmaps
│           ├── ringbuf.zig    #   Generic ring buffer
│           └── rbtree.zig     #   Red-black tree
│
└── rust/                      # Rust modules (staticlib)
    ├── Cargo.toml
    └── src/
        ├── lib.rs             # Crate root (#![no_std])
        ├── crypto/
        │   ├── mod.rs
        │   ├── aes.rs         # AES-256 (ECB/CBC/CTR)
        │   ├── sha256.rs      # SHA-256 + HMAC-SHA-256
        │   └── random.rs      # ChaCha20-based CSPRNG
        └── fs/
            ├── mod.rs
            ├── ext4.rs        # ext4 read-only (extent tree)
            └── fat32.rs       # FAT32 read/write (LFN support)
```

## Subsystem Details

### Boot (Multiboot2)

- **Multiboot2 header** with memory map, framebuffer, and module requests
- **GDT**: 7 entries — null, kernel code/data (ring 0), user code/data (ring 3), TSS
- **IDT**: 256 vectors — ISR 0-31 (exceptions), IRQ 32-47 (hardware), INT 0x80 (syscall)
- **TSS**: 3 IST stacks — double fault (16KB), NMI (16KB), machine check (16KB)

### Memory Management

| Component | Description |
|-----------|-------------|
| **PMM** | Bitmap-based, supports up to 16GB physical RAM (4M frames), next-fit allocation |
| **VMM** | Per-process VMA tracking, demand paging, page fault handler |
| **Heap** | First-fit free list with block splitting and coalescing |
| **Slab** | Size classes: 32, 64, 128, 256, 512, 1024, 2048, 4096 bytes |
| **Page** | Descriptors with reference counting and COW (copy-on-write) support |

### Scheduler (EEVDF)

- **Algorithm**: Earliest Eligible Virtual Deadline First with virtual eligible time and virtual deadline
- **Nice levels**: -20 to +19 with Linux-compatible weight table (40 entries)
- **Timeslice**: Hardware-profiled 1.5–3ms adaptive quantum, minimum granularity 0.75ms
- **Preemption**: Tick-driven preemption when current task exceeds ideal runtime
- **Priority**: Eligible processes with the earliest virtual deadline are scheduled first
- **Topology**: NUMA-aware placement, work stealing, and P-core/E-core aware tuning when hybrid CPUs are detected

### Supercomputer Profile

At boot, Zxyphor now synthesizes a runtime "supercomputer profile" from CPUID and ACPI data:

| Signal | Kernel use |
|--------|------------|
| AVX2 / AVX-512 / AVX10 / AMX / VNNI | Raises compute capability score and enables accelerator-aware scheduler hints |
| LA57 / 1GiB pages / CLDEMOTE / TME | Selects NUMA/CXL-ready memory tiering policy |
| x2APIC / UINTR / MOVDIRI / MOVDIR64B / FSRM | Sizes high-throughput interrupt and blk-mq queue budgets |
| CET shadow stack / IBT / FRED / PKS | Selects modern control-flow and supervisor-memory hardening posture |
| ACPI CPU and MCFG data | Derives recommended CPU lanes, NUMA tiers, and PCIe ECAM capability |

### Networking (TCP/IP)

Full networking stack from Layer 2 to Layer 4:

| Layer | Protocol | Features |
|-------|----------|----------|
| L2 | Ethernet | Frame parse/build, VLAN tags, CRC-32, 16 interfaces |
| L2.5 | ARP | 512-entry cache, 5min timeout, gratuitous ARP, static entries |
| L3 | IPv4 | Header checksum (RFC 1071), routing table (64 entries, longest prefix match), ICMP echo |
| L4 | TCP | 11-state FSM, slow start, congestion avoidance, fast retransmit/recovery, 1024 connections |
| L4 | UDP | Per-socket receive queue, connected mode, broadcast support, 256 sockets |
| API | Sockets | BSD socket interface — socket/bind/listen/accept/connect/send/recv/close |

### Security

- **Capabilities**: All 41 Linux capabilities (CAP_CHOWN through CAP_CHECKPOINT_RESTORE)
  - 5 capability sets per process: permitted, effective, inheritable, bounding, ambient
  - `execve()` transformation rules matching Linux behavior
- **DAC**: POSIX permission bits (rwxrwxrwx + setuid/setgid/sticky)
- **Credentials**: Real/effective/saved/filesystem UID/GID, supplementary groups
- **Resource limits**: 16 rlimit types (file size, CPU time, memory, open files, etc.)
- **Entropy pool**: xoshiro256** PRNG with entropy mixing
- **Audit log**: 1024-entry circular buffer for security events
- **Modern x86 hardening**: SMEP, SMAP, UMIP, PCID, CET shadow stack, CET-IBT, PKS, FRED awareness, BHI/IPRED/RRSBA mitigation detection, and Total Memory Encryption detection when exposed by hardware

### Cryptography (Rust)

| Module | Algorithm | Features |
|--------|-----------|----------|
| `aes.rs` | AES-256 | FIPS 197, ECB/CBC/CTR modes, GF(2^8) multiplication |
| `sha256.rs` | SHA-256 | FIPS 180-4, incremental hashing, HMAC-SHA-256 (RFC 2104) |
| `random.rs` | ChaCha20 CSPRNG | RFC 7539 core, entropy pool, backtrack protection, rejection sampling |

All Rust modules expose `#[no_mangle] extern "C"` FFI functions callable from Zig.

### Filesystems

| Filesystem | Language | Mode | Features |
|------------|----------|------|----------|
| **VFS** | Zig | — | VNode abstraction, mount table, path resolution, POSIX ops |
| **ramfs** | Zig | R/W | In-memory, dynamic buffers, max 16MB/file |
| **devfs** | Zig | R/W | /dev/null, /dev/zero, /dev/full, /dev/random, /dev/console |
| **zxyfs** | Zig | R/W | Custom disk-based, extent addressing, inode cache |
| **ext4** | Rust | Read | Superblock, block groups, extent tree, directory parsing |
| **FAT32** | Rust | R/W | BPB, FAT chain, 8.3 names, LFN (VFAT), create/delete |

### IPC

- **Pipes**: Unix-style with 64KB ring buffer, reader/writer reference counting
- **Signals**: 31 POSIX signals, per-process handlers, delivery on return to userspace
- **Shared Memory**: System V style — shmget/shmat/shmdt/shmctl, 256 segments, 256MB max

### Device Drivers

| Driver | Hardware | Features |
|--------|----------|----------|
| VGA | Text mode | 80×25, 16 colors, 200-line scrollback, cursor control |
| Keyboard | PS/2 | Scan code set 1, US layout, modifier tracking, ring buffer |
| Timer | 8254 PIT + APIC | 1000 Hz, 256 software timers, timer wheel (256 slots) |
| PCI | PCI bus | Device enumeration, config space, BAR parsing, MSI detection |
| ATA | IDE/ATA | PIO mode, IDENTIFY, LBA28/LBA48, primary + secondary channels |
| RTC | CMOS | Date/time R/W, BCD/binary, periodic interrupt at 1024 Hz |

### Kernel Libraries

| Library | Type | Features |
|---------|------|----------|
| `spinlock` | Synchronization | Ticket spinlock (FIFO), RW spinlock, simple spinlock |
| `string` | String ops | Compare, split, format int/hex, parse, path utilities |
| `list` | Data structure | Intrusive doubly-linked list, singly-linked list |
| `bitmap` | Data structure | Static (comptime generic), dynamic, bitwise operations |
| `ringbuf` | Data structure | Type-generic ring buffer, byte-optimized variant |
| `rbtree` | Data structure | Red-black tree with insert/delete/find/iterate |

## System Calls

| # | Name | Description |
|---|------|-------------|
| 0 | `read` | Read from file descriptor |
| 1 | `write` | Write to file descriptor |
| 2 | `open` | Open file |
| 3 | `close` | Close file descriptor |
| 4 | `stat` | Get file status |
| 5 | `fstat` | Get file status by FD |
| 8 | `seek` | Reposition read/write offset |
| 9 | `mmap` | Map memory |
| 10 | `mprotect` | Set memory protection |
| 11 | `munmap` | Unmap memory |
| 12 | `brk` | Set program break |
| 20 | `getpid` | Get process ID |
| 39 | `getppid` | Get parent process ID |
| 56 | `clone` | Create child process |
| 57 | `fork` | Fork process |
| 59 | `execve` | Execute program |
| 60 | `exit` | Terminate process |
| 61 | `wait4` | Wait for process |
| 62 | `kill` | Send signal |
| 63 | `uname` | Get system info |
| 80 | `mkdir` | Create directory |
| 83 | `rmdir` | Remove directory |
| 87 | `unlink` | Delete file |
| 89 | `readlink` | Read symbolic link |
| 90 | `chmod` | Change file mode |
| 91 | `chown` | Change file owner |
| 160 | `pipe` | Create pipe pair |
| 169 | `reboot` | Reboot system |

## Building

### Prerequisites

- **Zig** ≥ 0.15.2 (provides the kernel build system)
- **Rust** with `nightly` toolchain + `x86_64-unknown-none` target (for crypto/fs modules)
- **QEMU** (for testing in a virtual machine)
- **GRUB** + `xorriso` (for creating bootable ISO images)

### Build Commands

```bash
# Build the kernel
zig build

# Build and run in QEMU
zig build run

# Build with debug symbols and run with GDB server
zig build debug

# Build Rust modules separately (if needed)
cd rust && cargo build --release --target x86_64-unknown-none
```

### Boot with QEMU

```bash
qemu-system-x86_64 \
    -kernel zig-out/bin/zxyphor \
    -serial stdio \
    -m 256M \
    -no-reboot \
    -no-shutdown
```

### Creating a Bootable ISO

```bash
mkdir -p iso/boot/grub
cp zig-out/bin/zxyphor iso/boot/
cat > iso/boot/grub/grub.cfg << 'EOF'
set timeout=3
set default=0

menuentry "Zxyphor Kernel v0.0.4 Xceon III" {
    multiboot2 /boot/zxyphor
    boot
}
EOF

grub-mkrescue -o zxyphor.iso iso/
```

## Memory Map

```
Virtual Address Space (Higher Half):

0xFFFFFFFF80000000  ┌─────────────────────┐  __kernel_virt_start
                    │   .text (code)       │
                    ├─────────────────────┤
                    │   .rodata            │
                    ├─────────────────────┤
                    │   .data              │
                    ├─────────────────────┤
                    │   .bss               │
                    ├─────────────────────┤
                    │   Kernel Stack       │  64 KB
                    ├─────────────────────┤  __kernel_end
                    │   Kernel Heap        │  Grows upward
                    │                      │
                    └─────────────────────┘

0x0000700000000000  ┌─────────────────────┐  Shared memory region
                    └─────────────────────┘

0x0000000000400000  ┌─────────────────────┐  User space programs
                    └─────────────────────┘
```

## Technical Specifications

| Feature | Specification |
|---------|---------------|
| Architecture | x86_64 (AMD64) |
| Boot protocol | Multiboot2 |
| Max physical RAM | Hardware-profiled via CPUID physical address width |
| Page size | 4 KB with 2 MB, 1 GB, and LA57-aware virtual-address support |
| Max processes | 4096 |
| Max threads | 8192 |
| Max open files | 65536 (system-wide) |
| Max FDs per process | 256 |
| Kernel stack | 64 KB |
| IST stacks | 7 × 16 KB (DF, NMI, MC, DB, BP, PF, VC) |
| Scheduler tick | 1 ms |
| Default timeslice | 1.5–3 ms adaptive EEVDF quantum |
| Max TCP connections | 1024 |
| Max UDP sockets | 256 |
| Supported syscalls | 30+ |
| IPC mechanisms | Pipes, Signals, Shared Memory |
| Filesystems | VFS, ramfs, devfs, zxyfs, ext4, FAT32 |
| 2026 acceleration | AVX10, AVX-512/VNNI, AMX, VAES, VPCLMULQDQ, SHA extensions when present |
| 2026 security | CET, FRED, PKS, TME, BHI/IPRED/RRSBA mitigation detection when present |

## License

Copyright (c) 2025 Zxyphor Project. All rights reserved.

---

*Zxyphor Genesis — Built from the ground up, one instruction at a time.*

// =============================================================================
// Kernel Zxyphor — Rust Components Library Root
// =============================================================================
// This crate provides the Rust-language components for the Zxyphor kernel:
//   - acpi: ACPI table parser (RSDP/MADT/FADT/MCFG/SRAT/DMAR)
//   - blk: Block I/O layer (request queue, blk-mq, elevator schedulers)
//   - compression: Deflate, LZ4, CRC32 — data compression/integrity
//   - crypto: AES-256, SHA-256, ChaCha20 CSPRNG
//   - dev: Block devices, device model, BIO scatter-gather I/O
//   - fs: ext4 read support, FAT32 read/write support
//   - ffi: Cross-language bridge (Zig ↔ Rust callbacks, shared types)
//   - ipc: Message passing, semaphores, futex
//   - logging: Structured kernel logger, ftrace-like tracer, ring log
//   - mm: Memory management (slab allocator, buddy pages, pools, vmalloc)
//   - net: Networking (packets, checksums, firewall, DNS, DHCP, TLS 1.3)
//   - power: CPU frequency governors, suspend/hibernate, cpufreq drivers
//   - proc: Process/thread management (PCB, ELF exec, PID namespaces)
//   - sched: CFS scheduler, cgroup resource control, wait queues
//   - security: MAC, audit trail, integrity measurement
//   - storage: Block cache, I/O scheduling, partition tables, S.M.A.R.T.
//   - task: Async executor, timers, work queues
//
// All functions exposed to the Zig kernel use #[no_mangle] extern "C" ABI.
// This is a no_std, no_alloc crate — everything runs in kernel context.
// =============================================================================

#![no_std]
#![allow(dead_code)]

pub mod acpi;
pub mod blk;
pub mod compression;
pub mod crypto;
pub mod dev;
pub mod ffi;
pub mod fs;
pub mod ipc;
pub mod logging;
pub mod mm;
pub mod net;
pub mod power;
pub mod proc;
pub mod sched;
pub mod security;
pub mod storage;
pub mod task;

/// Kernel panic handler (required for no_std)
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

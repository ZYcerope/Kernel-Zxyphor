// Zxyphor Rust - Page Table Management,
// x86_64 4-level & 5-level paging in Rust,
// Page frame allocator integration,
// TLB shootdown IPI,
// PCID management, KPTI trampolines,
// VMA (Virtual Memory Area) management,
// mmap/munmap implementation hooks
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// Page Table Entry Flags (x86_64)
// ============================================================================

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7;       // PS bit (2MB/1GB page)
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_PAT: u64 = 1 << 7;        // PAT for 4KB pages
pub const PTE_PAT_LARGE: u64 = 1 << 12; // PAT for large pages
pub const PTE_PKEY_BIT0: u64 = 1 << 59;
pub const PTE_PKEY_BIT1: u64 = 1 << 60;
pub const PTE_PKEY_BIT2: u64 = 1 << 61;
pub const PTE_PKEY_BIT3: u64 = 1 << 62;
pub const PTE_NO_EXECUTE: u64 = 1 << 63;
pub const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// Software-defined bits (available for OS use)
pub const PTE_SW_COW: u64 = 1 << 9;   // Copy-on-Write
pub const PTE_SW_SWAPPED: u64 = 1 << 10;
pub const PTE_SW_SOFT_DIRTY: u64 = 1 << 11;

// ============================================================================
// Page Table Entry
// ============================================================================

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & PTE_ADDR_MASK) | flags)
    }

    pub const fn is_present(&self) -> bool {
        self.0 & PTE_PRESENT != 0
    }

    pub const fn is_writable(&self) -> bool {
        self.0 & PTE_WRITABLE != 0
    }

    pub const fn is_user(&self) -> bool {
        self.0 & PTE_USER != 0
    }

    pub const fn is_huge(&self) -> bool {
        self.0 & PTE_HUGE != 0
    }

    pub const fn is_global(&self) -> bool {
        self.0 & PTE_GLOBAL != 0
    }

    pub const fn is_dirty(&self) -> bool {
        self.0 & PTE_DIRTY != 0
    }

    pub const fn is_accessed(&self) -> bool {
        self.0 & PTE_ACCESSED != 0
    }

    pub const fn is_no_execute(&self) -> bool {
        self.0 & PTE_NO_EXECUTE != 0
    }

    pub const fn phys_addr(&self) -> u64 {
        self.0 & PTE_ADDR_MASK
    }

    pub const fn flags(&self) -> u64 {
        self.0 & !PTE_ADDR_MASK
    }

    pub const fn pkey(&self) -> u8 {
        ((self.0 >> 59) & 0xF) as u8
    }

    pub const fn raw(&self) -> u64 {
        self.0
    }

    pub fn set_flags(&mut self, flags: u64) {
        self.0 = (self.0 & PTE_ADDR_MASK) | flags;
    }

    pub fn add_flags(&mut self, flags: u64) {
        self.0 |= flags;
    }

    pub fn remove_flags(&mut self, flags: u64) {
        self.0 &= !flags;
    }

    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ============================================================================
// Page Table (array of 512 entries)
// ============================================================================

pub const PAGE_TABLE_ENTRIES: usize = 512;
pub const PAGE_SIZE_4K: usize = 4096;
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; PAGE_TABLE_ENTRIES],
}

impl PageTable {
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::empty(); PAGE_TABLE_ENTRIES],
        }
    }

    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }
}

// ============================================================================
// Virtual Address Decomposition
// ============================================================================

pub struct VirtAddrParts {
    pub pml4_index: u16,
    pub pdpt_index: u16,
    pub pd_index: u16,
    pub pt_index: u16,
    pub offset: u16,
}

impl VirtAddrParts {
    pub fn from_4level(vaddr: u64) -> Self {
        Self {
            pml4_index: ((vaddr >> 39) & 0x1FF) as u16,
            pdpt_index: ((vaddr >> 30) & 0x1FF) as u16,
            pd_index: ((vaddr >> 21) & 0x1FF) as u16,
            pt_index: ((vaddr >> 12) & 0x1FF) as u16,
            offset: (vaddr & 0xFFF) as u16,
        }
    }
}

pub struct VirtAddr5LevelParts {
    pub pml5_index: u16,
    pub pml4_index: u16,
    pub pdpt_index: u16,
    pub pd_index: u16,
    pub pt_index: u16,
    pub offset: u16,
}

impl VirtAddr5LevelParts {
    pub fn from_5level(vaddr: u64) -> Self {
        Self {
            pml5_index: ((vaddr >> 48) & 0x1FF) as u16,
            pml4_index: ((vaddr >> 39) & 0x1FF) as u16,
            pdpt_index: ((vaddr >> 30) & 0x1FF) as u16,
            pd_index: ((vaddr >> 21) & 0x1FF) as u16,
            pt_index: ((vaddr >> 12) & 0x1FF) as u16,
            offset: (vaddr & 0xFFF) as u16,
        }
    }
}

// ============================================================================
// TLB Shootdown
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TlbFlushType {
    Single = 0,
    Range = 1,
    All = 2,
    AllNonGlobal = 3,
    Asid = 4,
}

pub struct TlbShootdownRequest {
    pub flush_type: TlbFlushType,
    pub start_addr: u64,
    pub end_addr: u64,
    pub asid: u16,
    pub target_cpus: CpuMask,
}

pub struct CpuMask {
    pub bits: [u64; 4],  // support up to 256 CPUs
}

impl CpuMask {
    pub fn new() -> Self {
        Self { bits: [0; 4] }
    }

    pub fn set(&mut self, cpu: usize) {
        if cpu < 256 {
            self.bits[cpu / 64] |= 1u64 << (cpu % 64);
        }
    }

    pub fn clear(&mut self, cpu: usize) {
        if cpu < 256 {
            self.bits[cpu / 64] &= !(1u64 << (cpu % 64));
        }
    }

    pub fn test(&self, cpu: usize) -> bool {
        if cpu < 256 {
            self.bits[cpu / 64] & (1u64 << (cpu % 64)) != 0
        } else {
            false
        }
    }

    pub fn set_all(&mut self) {
        self.bits = [u64::MAX; 4];
    }
}

// ============================================================================
// PCID (Process-Context Identifier) Management
// ============================================================================

pub const PCID_MAX: u16 = 4096;

pub struct PcidAllocator {
    pub next_pcid: AtomicU64,
    pub generation: AtomicU64,
    pub per_cpu_pcid: [PcidState; 256],
}

pub struct PcidState {
    pub current_pcid: u16,
    pub generation: u64,
    pub flushed: bool,
}

impl PcidAllocator {
    pub fn new() -> Self {
        Self {
            next_pcid: AtomicU64::new(1),
            generation: AtomicU64::new(0),
            per_cpu_pcid: [PcidState {
                current_pcid: 0,
                generation: 0,
                flushed: false,
            }; 256],
        }
    }

    pub fn allocate(&self) -> (u16, u64) {
        let next = self.next_pcid.fetch_add(1, Ordering::Relaxed);
        let pcid = (next % PCID_MAX as u64) as u16;
        let gen = if pcid == 0 {
            self.generation.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            self.generation.load(Ordering::Relaxed)
        };
        (if pcid == 0 { 1 } else { pcid }, gen)
    }
}

// ============================================================================
// KPTI (Kernel Page Table Isolation)
// ============================================================================

pub struct KptiConfig {
    pub enabled: bool,
    pub user_cr3_offset: u64,    // offset to user page table
    pub trampoline_addr: u64,    // syscall/interrupt trampoline
    pub cpu_entry_area_base: u64,
}

pub struct KptiTrampoline {
    pub entry_stack_top: u64,
    pub kernel_cr3: u64,
    pub user_cr3: u64,
    pub saved_rsp: u64,
    pub saved_rax: u64,
}

// ============================================================================
// VMA (Virtual Memory Area)
// ============================================================================

#[repr(u64)]
pub enum VmaFlags {
    Read = 0x01,
    Write = 0x02,
    Exec = 0x04,
    Shared = 0x08,
    Growsdown = 0x0100,
    Growsup = 0x0200,
    Denywrite = 0x0800,
    Locked = 0x2000,
    Io = 0x4000,
    Sequential = 0x8000,
    Random = 0x10000,
    DontCopy = 0x20000,
    DontExpand = 0x40000,
    Account = 0x100000,
    Hugepage = 0x400000,
    Nohugepage = 0x800000,
    Mergeable = 0x1000000,
    Stack = 0x20000000,
    Softdirty = 0x40000000,
    Mixedmap = 0x10000000,
    Pfnmap = 0x80000,
}

pub struct VirtualMemoryArea {
    pub vm_start: u64,
    pub vm_end: u64,
    pub vm_flags: u64,
    pub vm_pgoff: u64,
    pub vm_page_prot: u64,
    pub anon_vma: Option<u64>,
    pub vm_file: Option<u64>,
    pub vm_ops: Option<u64>,
}

pub struct MmStruct {
    pub pgd: u64,         // top-level page table physical address
    pub vma_count: u32,
    pub map_count: u32,
    pub total_vm: u64,
    pub locked_vm: u64,
    pub pinned_vm: u64,
    pub data_vm: u64,
    pub exec_vm: u64,
    pub stack_vm: u64,
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
    pub mmap_base: u64,
    pub mmap_legacy_base: u64,
    pub task_size: u64,
    pub highest_vm_end: u64,
    pub flags: MmFlags,
    pub pcid: u16,
    pub context_id: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct MmFlags {
    pub dumpable: u8,
    pub has_pinned: bool,
    pub is_oom_reapable: bool,
    pub notify_addr_fault: bool,
}

// ============================================================================
// Page Fault Handling
// ============================================================================

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum FaultFlags {
    Write = 0x01,
    Mkwrite = 0x02,
    AllowRetry = 0x04,
    Retry = 0x08,
    Killable = 0x10,
    Tried = 0x20,
    User = 0x40,
    Remote = 0x80,
    Locked = 0x100,
    Prefault = 0x200,
    Interruptible = 0x400,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum VmFaultResult {
    Oom = 0x0001,
    Sigbus = 0x0002,
    Major = 0x0004,
    Retry = 0x0008,
    Fallback = 0x0010,
    Done = 0x0020,
    NeedSleep = 0x0040,
    Locked = 0x0200,
    Nopage = 0x0100,
}

pub struct PageFaultInfo {
    pub address: u64,
    pub error_code: u64, // x86 error code from CR2
    pub vma: Option<u64>,
    pub flags: u32,
    pub result: u32,
    pub cow_page: Option<u64>,
    pub page: Option<u64>,
}

// ============================================================================
// Page Table Manager (Zxyphor Rust side)
// ============================================================================

pub struct PageTableManager {
    pub kernel_pgd: u64,
    pub pcid_allocator: PcidAllocator,
    pub kpti: KptiConfig,
    pub five_level: bool,
    pub phys_addr_bits: u8,
    pub virt_addr_bits: u8,
    pub total_mapped_pages: AtomicU64,
    pub page_faults_total: AtomicU64,
    pub cow_faults: AtomicU64,
    pub tlb_shootdowns: AtomicU64,
    pub initialized: bool,
}

impl PageTableManager {
    pub fn new() -> Self {
        Self {
            kernel_pgd: 0,
            pcid_allocator: PcidAllocator::new(),
            kpti: KptiConfig {
                enabled: true,
                user_cr3_offset: 0,
                trampoline_addr: 0,
                cpu_entry_area_base: 0,
            },
            five_level: false,
            phys_addr_bits: 48,
            virt_addr_bits: 48,
            total_mapped_pages: AtomicU64::new(0),
            page_faults_total: AtomicU64::new(0),
            cow_faults: AtomicU64::new(0),
            tlb_shootdowns: AtomicU64::new(0),
            initialized: false,
        }
    }
}

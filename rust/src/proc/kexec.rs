// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kexec / Kdump Subsystem (Rust)
//
// Fast kernel reboot and crash dump mechanisms:
// - Kexec: load a new kernel image and jump to it without BIOS/UEFI
// - Kdump: on panic, switch to crash kernel for dump capture
// - Kernel image validation (ELF header, entry point, segments)
// - Memory reservation for crash kernel
// - CPU shutdown sequence for kexec transition
// - Crash notes (per-CPU register state on panic)
// - Vmcore generation (/proc/vmcore ELF-format)
// - Memory ranges for crash kernel (usable, reserved, ACPI, etc.)
// - Kexec segment loading into reserved memory
// - Machine shutdown hooks for device quiesce

#![no_std]
#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────

const MAX_SEGMENTS: usize = 16;
const MAX_MEMORY_RANGES: usize = 32;
const MAX_CRASH_CPUS: usize = 16;
const MAX_SHUTDOWN_HOOKS: usize = 16;
const ELF_MAGIC: u32 = 0x464C457F; // \x7FELF
const KEXEC_SEGMENT_MAX: usize = 128 * 1024; // 128K per segment data
const CMDLINE_MAX: usize = 256;

// ─────────────────── Kexec Flags ────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u32)]
pub enum KexecFlags {
    None = 0,
    OnCrash = 0x0001,          // Load for crash (kdump)
    PreserveContext = 0x0002,   // Preserve CPU context
    UpdateElfhdrs = 0x0004,
    OnPanic = 0x0008,
    FileLoaded = 0x0010,
}

// ─────────────────── ELF Structures ─────────────────────────────────

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl Elf64Header {
    pub const fn empty() -> Self {
        Self {
            e_ident: [0u8; 16],
            e_type: 0,
            e_machine: 0,
            e_version: 0,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: 0,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.e_ident[0] == 0x7F
            && self.e_ident[1] == b'E'
            && self.e_ident[2] == b'L'
            && self.e_ident[3] == b'F'
            && self.e_ident[4] == 2  // 64-bit
            && self.e_ident[5] == 1  // Little-endian
    }

    pub fn is_x86_64(&self) -> bool {
        self.e_machine == 62 // EM_X86_64
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64Phdr {
    pub const fn empty() -> Self {
        Self {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        }
    }

    pub fn is_load(&self) -> bool {
        self.p_type == 1 // PT_LOAD
    }

    pub fn is_note(&self) -> bool {
        self.p_type == 4 // PT_NOTE
    }
}

// ─────────────────── Kexec Segment ──────────────────────────────────

#[derive(Clone, Copy)]
pub struct KexecSegment {
    pub buf_phys: u64,      // Physical address of source data
    pub buf_size: u64,      // Size of source data
    pub mem_phys: u64,      // Destination physical address
    pub mem_size: u64,      // Size at destination (may be larger for BSS)
    pub loaded: bool,
    pub verified: bool,
}

impl KexecSegment {
    pub const fn empty() -> Self {
        Self {
            buf_phys: 0,
            buf_size: 0,
            mem_phys: 0,
            mem_size: 0,
            loaded: false,
            verified: false,
        }
    }
}

// ─────────────────── Memory Range ───────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MemRangeType {
    Usable = 0,
    Reserved = 1,
    AcpiData = 2,
    AcpiNvs = 3,
    CrashKernel = 4,
    Unusable = 5,
}

#[derive(Clone, Copy)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
    pub range_type: MemRangeType,
    pub active: bool,
}

impl MemoryRange {
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            range_type: MemRangeType::Usable,
            active: false,
        }
    }

    pub fn size(&self) -> u64 {
        if self.end > self.start { self.end - self.start } else { 0 }
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ─────────────────── Crash Notes (per-CPU) ──────────────────────────

#[derive(Clone, Copy)]
pub struct CrashNote {
    pub cpu_id: u32,
    // x86_64 register state
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub ss: u64,
    pub cr0: u64,
    pub cr2: u64, // Faulting address
    pub cr3: u64, // Page table root
    pub cr4: u64,
    pub valid: bool,
}

impl CrashNote {
    pub const fn empty() -> Self {
        Self {
            cpu_id: 0,
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0, rflags: 0, cs: 0, ss: 0,
            cr0: 0, cr2: 0, cr3: 0, cr4: 0,
            valid: false,
        }
    }
}

// ─────────────────── Shutdown Hook ──────────────────────────────────

#[derive(Clone, Copy)]
pub struct ShutdownHook {
    pub name: [u8; 32],
    pub name_len: u8,
    pub priority: i16,  // Lower = called earlier
    pub called: bool,
    pub active: bool,
}

impl ShutdownHook {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            priority: 0,
            called: false,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() < 32 { n.len() } else { 32 };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ─────────────────── Kexec Image ────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ImageState {
    Empty = 0,
    Loading = 1,
    Loaded = 2,
    Verified = 3,
    Executing = 4,
}

#[derive(Clone, Copy)]
pub struct KexecImage {
    pub header: Elf64Header,
    pub segments: [KexecSegment; MAX_SEGMENTS],
    pub segment_count: u8,
    pub entry_point: u64,
    pub state: ImageState,
    pub flags: u32,
    pub cmdline: [u8; CMDLINE_MAX],
    pub cmdline_len: u16,
    pub total_size: u64,

    // Phdrs for vmcore generation
    pub phdrs: [Elf64Phdr; MAX_SEGMENTS],
    pub phdr_count: u8,
}

impl KexecImage {
    pub const fn empty() -> Self {
        Self {
            header: Elf64Header::empty(),
            segments: [KexecSegment::empty(); MAX_SEGMENTS],
            segment_count: 0,
            entry_point: 0,
            state: ImageState::Empty,
            flags: 0,
            cmdline: [0u8; CMDLINE_MAX],
            cmdline_len: 0,
            total_size: 0,
            phdrs: [Elf64Phdr::empty(); MAX_SEGMENTS],
            phdr_count: 0,
        }
    }

    pub fn set_cmdline(&mut self, cmd: &[u8]) {
        let len = if cmd.len() < CMDLINE_MAX { cmd.len() } else { CMDLINE_MAX };
        self.cmdline[..len].copy_from_slice(&cmd[..len]);
        self.cmdline_len = len as u16;
    }

    pub fn add_segment(&mut self, buf: u64, buf_sz: u64, mem: u64, mem_sz: u64) -> bool {
        if self.segment_count as usize >= MAX_SEGMENTS { return false; }
        let i = self.segment_count as usize;
        self.segments[i] = KexecSegment {
            buf_phys: buf,
            buf_size: buf_sz,
            mem_phys: mem,
            mem_size: mem_sz,
            loaded: false,
            verified: false,
        };
        self.segment_count += 1;
        self.total_size += mem_sz;
        true
    }
}

// ─────────────────── Kexec/Kdump Manager ────────────────────────────

pub struct KexecManager {
    // Normal kexec image
    pub kexec_image: KexecImage,
    // Crash kernel image (loaded at boot, used on panic)
    pub crash_image: KexecImage,

    // Crash kernel reserved memory
    pub crash_reserved_start: u64,
    pub crash_reserved_end: u64,
    pub crash_reserved: bool,

    // Memory map
    pub mem_ranges: [MemoryRange; MAX_MEMORY_RANGES],
    pub range_count: u8,

    // Per-CPU crash notes
    pub crash_notes: [CrashNote; MAX_CRASH_CPUS],
    pub nr_cpus: u8,

    // Shutdown hooks
    pub hooks: [ShutdownHook; MAX_SHUTDOWN_HOOKS],
    pub hook_count: u8,

    // State
    pub kexec_loaded: bool,
    pub crash_loaded: bool,
    pub in_crash: bool,

    // Stats
    pub total_kexec_loads: u64,
    pub total_crash_loads: u64,
    pub total_kexec_execs: u64,
    pub total_crash_entries: u64,
    pub total_shutdown_hooks_called: u64,

    pub initialized: bool,
}

impl KexecManager {
    pub fn new() -> Self {
        Self {
            kexec_image: KexecImage::empty(),
            crash_image: KexecImage::empty(),
            crash_reserved_start: 0,
            crash_reserved_end: 0,
            crash_reserved: false,
            mem_ranges: [MemoryRange::empty(); MAX_MEMORY_RANGES],
            range_count: 0,
            crash_notes: [CrashNote::empty(); MAX_CRASH_CPUS],
            nr_cpus: 0,
            hooks: [ShutdownHook::empty(); MAX_SHUTDOWN_HOOKS],
            hook_count: 0,
            kexec_loaded: false,
            crash_loaded: false,
            in_crash: false,
            total_kexec_loads: 0,
            total_crash_loads: 0,
            total_kexec_execs: 0,
            total_crash_entries: 0,
            total_shutdown_hooks_called: 0,
            initialized: true,
        }
    }

    // ─── Memory Range Management ────────────────────────────────────

    pub fn add_memory_range(&mut self, start: u64, end: u64, rtype: MemRangeType) -> bool {
        if self.range_count as usize >= MAX_MEMORY_RANGES { return false; }
        let i = self.range_count as usize;
        self.mem_ranges[i] = MemoryRange {
            start,
            end,
            range_type: rtype,
            active: true,
        };
        self.range_count += 1;
        true
    }

    pub fn reserve_crash_memory(&mut self, start: u64, size: u64) -> bool {
        if self.crash_reserved { return false; }
        self.crash_reserved_start = start;
        self.crash_reserved_end = start + size;
        self.crash_reserved = true;
        self.add_memory_range(start, start + size, MemRangeType::CrashKernel)
    }

    pub fn is_in_crash_region(&self, addr: u64) -> bool {
        self.crash_reserved && addr >= self.crash_reserved_start && addr < self.crash_reserved_end
    }

    // ─── Image Loading ──────────────────────────────────────────────

    pub fn load_kexec_image(&mut self, entry: u64, cmdline: &[u8]) -> bool {
        self.kexec_image = KexecImage::empty();
        self.kexec_image.entry_point = entry;
        self.kexec_image.set_cmdline(cmdline);
        self.kexec_image.state = ImageState::Loading;
        true
    }

    pub fn add_kexec_segment(&mut self, buf: u64, buf_sz: u64, mem: u64, mem_sz: u64) -> bool {
        if self.kexec_image.state != ImageState::Loading { return false; }
        self.kexec_image.add_segment(buf, buf_sz, mem, mem_sz)
    }

    pub fn finalize_kexec_load(&mut self) -> bool {
        if self.kexec_image.state != ImageState::Loading { return false; }
        if self.kexec_image.segment_count == 0 { return false; }

        // Validate: segments don't overlap crash region
        for i in 0..self.kexec_image.segment_count as usize {
            let seg = &self.kexec_image.segments[i];
            if self.is_in_crash_region(seg.mem_phys) {
                return false;
            }
            self.kexec_image.segments[i].loaded = true;
            self.kexec_image.segments[i].verified = true;
        }

        self.kexec_image.state = ImageState::Loaded;
        self.kexec_loaded = true;
        self.total_kexec_loads += 1;
        true
    }

    pub fn load_crash_image(&mut self, entry: u64, cmdline: &[u8]) -> bool {
        if !self.crash_reserved { return false; }

        self.crash_image = KexecImage::empty();
        self.crash_image.entry_point = entry;
        self.crash_image.set_cmdline(cmdline);
        self.crash_image.flags = KexecFlags::OnCrash as u32;
        self.crash_image.state = ImageState::Loading;
        true
    }

    pub fn add_crash_segment(&mut self, buf: u64, buf_sz: u64, mem: u64, mem_sz: u64) -> bool {
        if self.crash_image.state != ImageState::Loading { return false; }
        // Crash segments must be within reserved region
        if !self.is_in_crash_region(mem) { return false; }
        self.crash_image.add_segment(buf, buf_sz, mem, mem_sz)
    }

    pub fn finalize_crash_load(&mut self) -> bool {
        if self.crash_image.state != ImageState::Loading { return false; }
        if self.crash_image.segment_count == 0 { return false; }

        for i in 0..self.crash_image.segment_count as usize {
            self.crash_image.segments[i].loaded = true;
            self.crash_image.segments[i].verified = true;
        }

        self.crash_image.state = ImageState::Loaded;
        self.crash_loaded = true;
        self.total_crash_loads += 1;
        true
    }

    pub fn unload_kexec(&mut self) {
        self.kexec_image = KexecImage::empty();
        self.kexec_loaded = false;
    }

    // ─── Shutdown Hooks ─────────────────────────────────────────────

    pub fn register_shutdown_hook(&mut self, name: &[u8], priority: i16) -> Option<u8> {
        if self.hook_count as usize >= MAX_SHUTDOWN_HOOKS { return None; }
        for i in 0..MAX_SHUTDOWN_HOOKS {
            if !self.hooks[i].active {
                self.hooks[i] = ShutdownHook::empty();
                self.hooks[i].set_name(name);
                self.hooks[i].priority = priority;
                self.hooks[i].active = true;
                self.hook_count += 1;
                return Some(i as u8);
            }
        }
        None
    }

    fn run_shutdown_hooks(&mut self) {
        // Sort by priority (simple selection sort for small N)
        let mut order = [0u8; MAX_SHUTDOWN_HOOKS];
        let mut count = 0usize;
        for i in 0..MAX_SHUTDOWN_HOOKS {
            if self.hooks[i].active && !self.hooks[i].called {
                order[count] = i as u8;
                count += 1;
            }
        }
        // Selection sort by priority
        for i in 0..count {
            let mut min = i;
            for j in (i+1)..count {
                if self.hooks[order[j] as usize].priority < self.hooks[order[min] as usize].priority {
                    min = j;
                }
            }
            if min != i {
                let tmp = order[i];
                order[i] = order[min];
                order[min] = tmp;
            }
        }
        for i in 0..count {
            let idx = order[i] as usize;
            self.hooks[idx].called = true;
            self.total_shutdown_hooks_called += 1;
        }
    }

    // ─── Crash Note Recording ───────────────────────────────────────

    pub fn init_cpus(&mut self, nr_cpus: u8) {
        let cpus = if nr_cpus as usize > MAX_CRASH_CPUS { MAX_CRASH_CPUS as u8 } else { nr_cpus };
        self.nr_cpus = cpus;
        for i in 0..cpus as usize {
            self.crash_notes[i].cpu_id = i as u32;
        }
    }

    pub fn save_crash_note(&mut self, cpu: u32, rip: u64, rsp: u64, rbp: u64, cr2: u64, cr3: u64) -> bool {
        if cpu as usize >= MAX_CRASH_CPUS { return false; }
        let note = &mut self.crash_notes[cpu as usize];
        note.cpu_id = cpu;
        note.rip = rip;
        note.rsp = rsp;
        note.rbp = rbp;
        note.cr2 = cr2;
        note.cr3 = cr3;
        note.valid = true;
        true
    }

    pub fn valid_crash_notes(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.nr_cpus as usize {
            if self.crash_notes[i].valid { count += 1; }
        }
        count
    }

    // ─── Vmcore ELF Header Generation ───────────────────────────────

    pub fn build_vmcore_header(&mut self) -> u8 {
        // Build program headers for vmcore: one PT_NOTE + one PT_LOAD per usable range
        self.crash_image.phdr_count = 0;

        // PT_NOTE for crash notes
        if self.crash_image.phdr_count < MAX_SEGMENTS as u8 {
            let idx = self.crash_image.phdr_count as usize;
            self.crash_image.phdrs[idx] = Elf64Phdr::empty();
            self.crash_image.phdrs[idx].p_type = 4; // PT_NOTE
            self.crash_image.phdrs[idx].p_filesz = (self.nr_cpus as u64) * 256; // Approximate
            self.crash_image.phdr_count += 1;
        }

        // PT_LOAD for each usable range
        for i in 0..self.range_count as usize {
            if !self.mem_ranges[i].active { continue; }
            if self.mem_ranges[i].range_type != MemRangeType::Usable { continue; }
            if self.crash_image.phdr_count as usize >= MAX_SEGMENTS { break; }

            let idx = self.crash_image.phdr_count as usize;
            self.crash_image.phdrs[idx] = Elf64Phdr::empty();
            self.crash_image.phdrs[idx].p_type = 1; // PT_LOAD
            self.crash_image.phdrs[idx].p_paddr = self.mem_ranges[i].start;
            self.crash_image.phdrs[idx].p_memsz = self.mem_ranges[i].size();
            self.crash_image.phdrs[idx].p_filesz = self.mem_ranges[i].size();
            self.crash_image.phdrs[idx].p_flags = 0x04; // PF_R
            self.crash_image.phdr_count += 1;
        }

        self.crash_image.phdr_count
    }

    // ─── Execution ──────────────────────────────────────────────────

    /// Prepare and execute kexec (normal reboot path)
    pub fn kexec_execute(&mut self) -> bool {
        if !self.kexec_loaded { return false; }

        self.run_shutdown_hooks();
        self.kexec_image.state = ImageState::Executing;
        self.total_kexec_execs += 1;
        // In real kernel: disable interrupts, stop other CPUs, jump to entry_point
        true
    }

    /// Enter crash path (called from panic handler)
    pub fn crash_enter(&mut self, cpu: u32, rip: u64, rsp: u64, rbp: u64, cr2: u64, cr3: u64) -> bool {
        if !self.crash_loaded || self.in_crash { return false; }
        self.in_crash = true;

        // Save crash note for faulting CPU
        self.save_crash_note(cpu, rip, rsp, rbp, cr2, cr3);

        // Build vmcore header
        self.build_vmcore_header();

        self.crash_image.state = ImageState::Executing;
        self.total_crash_entries += 1;
        // In real kernel: NMI other CPUs to save their notes, then jump to crash entry
        true
    }
}

// ─────────────────── Global State ───────────────────────────────────

static mut G_KEXEC: Option<KexecManager> = None;
static mut G_KEXEC_INIT: bool = false;

fn km() -> &'static mut KexecManager {
    unsafe { G_KEXEC.as_mut().unwrap() }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_kexec_init(nr_cpus: u8) {
    unsafe {
        G_KEXEC = Some(KexecManager::new());
        G_KEXEC_INIT = true;
    }
    km().init_cpus(nr_cpus);
}

#[no_mangle]
pub extern "C" fn rust_kexec_reserve_crash(start: u64, size: u64) -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().reserve_crash_memory(start, size)
}

#[no_mangle]
pub extern "C" fn rust_kexec_load(entry: u64, cmdline: *const u8, cmdline_len: usize) -> bool {
    if unsafe { !G_KEXEC_INIT } || cmdline.is_null() { return false; }
    let cmd = unsafe { core::slice::from_raw_parts(cmdline, cmdline_len) };
    km().load_kexec_image(entry, cmd)
}

#[no_mangle]
pub extern "C" fn rust_kexec_add_segment(buf: u64, buf_sz: u64, mem: u64, mem_sz: u64) -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().add_kexec_segment(buf, buf_sz, mem, mem_sz)
}

#[no_mangle]
pub extern "C" fn rust_kexec_finalize() -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().finalize_kexec_load()
}

#[no_mangle]
pub extern "C" fn rust_kexec_execute() -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().kexec_execute()
}

#[no_mangle]
pub extern "C" fn rust_kdump_crash_enter(cpu: u32, rip: u64, rsp: u64, rbp: u64, cr2: u64, cr3: u64) -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().crash_enter(cpu, rip, rsp, rbp, cr2, cr3)
}

#[no_mangle]
pub extern "C" fn rust_kexec_loaded() -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().kexec_loaded
}

#[no_mangle]
pub extern "C" fn rust_kdump_loaded() -> bool {
    if unsafe { !G_KEXEC_INIT } { return false; }
    km().crash_loaded
}

#[no_mangle]
pub extern "C" fn rust_kexec_total_loads() -> u64 {
    if unsafe { !G_KEXEC_INIT } { return 0; }
    km().total_kexec_loads
}

#[no_mangle]
pub extern "C" fn rust_kdump_total_entries() -> u64 {
    if unsafe { !G_KEXEC_INIT } { return 0; }
    km().total_crash_entries
}

#[no_mangle]
pub extern "C" fn rust_kdump_valid_notes() -> u32 {
    if unsafe { !G_KEXEC_INIT } { return 0; }
    km().valid_crash_notes()
}

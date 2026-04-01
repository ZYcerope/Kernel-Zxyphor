// SPDX-License-Identifier: MIT
// Zxyphor Kernel — SMP / Inter-Processor Interrupt Handler (Zig)
//
// Symmetric Multi-Processing core:
// - CPU topology detection and tracking
// - AP (Application Processor) bootstrap
// - IPI (Inter-Processor Interrupt) sending/handling
// - CPU hot-plug state machine
// - Per-CPU data areas
// - Cross-CPU function call (smp_call_function)
// - TLB shootdown via IPI
// - CPU affinity masks
// - CPU load balancing info
// - NUMA node tracking

const std = @import("std");

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CPUS: usize = 64;
const MAX_NUMA_NODES: usize = 8;
const IPI_QUEUE_SIZE: usize = 32;
const MAX_CALL_QUEUE: usize = 64;

// ─────────────────── CPU State ──────────────────────────────────────

pub const CpuState = enum(u8) {
    offline = 0,
    booting = 1,
    online = 2,
    idle = 3,
    busy = 4,
    hotplug_prepare = 5,
    hotplug_dead = 6,
    halted = 7,
};

// ─────────────────── IPI Types ──────────────────────────────────────

pub const IpiType = enum(u8) {
    /// Reschedule on target CPU
    reschedule = 0,
    /// Function call
    call_function = 1,
    /// TLB shootdown
    tlb_shootdown = 2,
    /// Stop CPU (panic/shutdown)
    stop = 3,
    /// Timer synchronization
    timer_sync = 4,
    /// IRQ work
    irq_work = 5,
    /// NMI backtrace
    nmi_backtrace = 6,
    /// CPU offline request
    cpu_offline = 7,
};

// ─────────────────── CPU Affinity Mask ──────────────────────────────

pub const CpuMask = struct {
    bits: u64 = 0,

    pub fn set(self: *CpuMask, cpu: u6) void {
        self.bits |= @as(u64, 1) << cpu;
    }

    pub fn clear(self: *CpuMask, cpu: u6) void {
        self.bits &= ~(@as(u64, 1) << cpu);
    }

    pub fn test(self: CpuMask, cpu: u6) bool {
        return (self.bits & (@as(u64, 1) << cpu)) != 0;
    }

    pub fn count(self: CpuMask) u32 {
        return @popCount(self.bits);
    }

    pub fn first(self: CpuMask) ?u6 {
        if (self.bits == 0) return null;
        return @truncate(@ctz(self.bits));
    }

    pub fn next(self: CpuMask, after: u6) ?u6 {
        const shifted = self.bits >> (@as(u6, after) +% 1);
        if (shifted == 0) return null;
        return after +% 1 +% @as(u6, @truncate(@ctz(shifted)));
    }

    pub fn and_mask(self: CpuMask, other: CpuMask) CpuMask {
        return .{ .bits = self.bits & other.bits };
    }

    pub fn or_mask(self: CpuMask, other: CpuMask) CpuMask {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn not_mask(self: CpuMask) CpuMask {
        return .{ .bits = ~self.bits };
    }

    pub const ALL: CpuMask = .{ .bits = 0xFFFFFFFFFFFFFFFF };
    pub const NONE: CpuMask = .{ .bits = 0 };
};

// ─────────────────── Per-CPU Data ───────────────────────────────────

pub const PerCpuData = struct {
    /// CPU identification
    apic_id: u32 = 0,
    acpi_id: u32 = 0,
    numa_node: u8 = 0,
    /// Topology
    package_id: u8 = 0,
    core_id: u8 = 0,
    thread_id: u8 = 0,
    /// State
    state: CpuState = .offline,
    /// TSC calibration
    tsc_khz: u32 = 0,
    tsc_offset: i64 = 0,
    /// Scheduling
    current_task: u32 = 0,
    idle_task: u32 = 0,
    preempt_count: u32 = 0,
    need_resched: bool = false,
    /// IPI queue
    ipi_queue: [IPI_QUEUE_SIZE]IpiMessage = [_]IpiMessage{.{}} ** IPI_QUEUE_SIZE,
    ipi_head: u8 = 0,
    ipi_tail: u8 = 0,
    ipi_pending: u32 = 0,
    /// Statistics
    irq_count: u64 = 0,
    context_switches: u64 = 0,
    idle_time_us: u64 = 0,
    busy_time_us: u64 = 0,
    ipi_sent: u64 = 0,
    ipi_received: u64 = 0,
    /// TLB
    tlb_flush_pending: bool = false,
    tlb_flush_addr: u64 = 0,
    tlb_flush_pages: u32 = 0,

    pub fn enqueue_ipi(self: *PerCpuData, msg: IpiMessage) bool {
        const next = (self.ipi_head + 1) % IPI_QUEUE_SIZE;
        if (next == self.ipi_tail) return false;
        self.ipi_queue[self.ipi_head] = msg;
        self.ipi_head = @truncate(next);
        self.ipi_pending += 1;
        return true;
    }

    pub fn dequeue_ipi(self: *PerCpuData) ?IpiMessage {
        if (self.ipi_tail == self.ipi_head) return null;
        const msg = self.ipi_queue[self.ipi_tail];
        self.ipi_tail = @truncate((@as(u16, self.ipi_tail) + 1) % IPI_QUEUE_SIZE);
        if (self.ipi_pending > 0) self.ipi_pending -= 1;
        return msg;
    }
};

// ─────────────────── IPI Message ────────────────────────────────────

pub const IpiMessage = struct {
    ipi_type: IpiType = .reschedule,
    source_cpu: u8 = 0,
    /// For call_function
    func_addr: u64 = 0,
    func_data: u64 = 0,
    /// For TLB shootdown
    addr: u64 = 0,
    pages: u32 = 0,
    /// Completion flag
    completed: bool = false,
};

// ─────────────────── Cross-CPU Call ─────────────────────────────────

pub const SmpCallEntry = struct {
    func_addr: u64 = 0,
    data: u64 = 0,
    target_mask: CpuMask = CpuMask.NONE,
    wait: bool = false,
    completed_mask: CpuMask = CpuMask.NONE,
    active: bool = false,
};

// ─────────────────── NUMA Node ──────────────────────────────────────

pub const NumaNode = struct {
    id: u8 = 0,
    cpu_mask: CpuMask = CpuMask.NONE,
    mem_start: u64 = 0,
    mem_size: u64 = 0,
    /// Distance to other nodes (10 = local)
    distance: [MAX_NUMA_NODES]u8 = [_]u8{255} ** MAX_NUMA_NODES,
    active: bool = false,

    pub fn add_cpu(self: *NumaNode, cpu: u6) void {
        self.cpu_mask.set(cpu);
    }

    pub fn remove_cpu(self: *NumaNode, cpu: u6) void {
        self.cpu_mask.clear(cpu);
    }

    pub fn cpu_count(self: NumaNode) u32 {
        return self.cpu_mask.count();
    }
};

// ─────────────────── SMP Manager ────────────────────────────────────

pub const SmpManager = struct {
    /// Per-CPU data
    cpus: [MAX_CPUS]PerCpuData = [_]PerCpuData{.{}} ** MAX_CPUS,
    cpu_count: u8 = 0,
    online_mask: CpuMask = CpuMask.NONE,
    present_mask: CpuMask = CpuMask.NONE,
    possible_mask: CpuMask = CpuMask.NONE,
    /// BSP (Bootstrap Processor)
    bsp_id: u8 = 0,
    /// NUMA
    nodes: [MAX_NUMA_NODES]NumaNode = [_]NumaNode{.{}} ** MAX_NUMA_NODES,
    node_count: u8 = 0,
    /// Cross-CPU call queue
    call_queue: [MAX_CALL_QUEUE]SmpCallEntry = [_]SmpCallEntry{.{}} ** MAX_CALL_QUEUE,
    call_count: u16 = 0,
    /// Global stats
    total_ipis: u64 = 0,
    total_tlb_shootdowns: u64 = 0,
    total_reschedules: u64 = 0,
    /// AP boot state
    ap_boot_stack: u64 = 0,
    ap_boot_complete: bool = false,
    initialized: bool = false,

    pub fn init(self: *SmpManager) void {
        // BSP is CPU 0
        self.bsp_id = 0;
        self.cpus[0].state = .online;
        self.cpus[0].apic_id = 0;
        self.cpus[0].numa_node = 0;
        self.online_mask.set(0);
        self.present_mask.set(0);
        self.possible_mask.set(0);
        self.cpu_count = 1;

        // Default NUMA node 0
        self.nodes[0].id = 0;
        self.nodes[0].active = true;
        self.nodes[0].distance[0] = 10; // self distance = 10
        self.nodes[0].add_cpu(0);
        self.node_count = 1;

        self.initialized = true;
    }

    /// Register an AP discovered via ACPI MADT
    pub fn register_cpu(self: *SmpManager, apic_id: u32, acpi_id: u32, numa_node: u8) ?u8 {
        if (self.cpu_count >= MAX_CPUS) return null;
        const cpu_id = self.cpu_count;
        self.cpus[cpu_id].apic_id = apic_id;
        self.cpus[cpu_id].acpi_id = acpi_id;
        self.cpus[cpu_id].numa_node = numa_node;
        self.cpus[cpu_id].state = .offline;
        self.present_mask.set(@truncate(cpu_id));
        self.possible_mask.set(@truncate(cpu_id));
        self.cpu_count += 1;

        // Add to NUMA node
        if (numa_node < self.node_count) {
            self.nodes[numa_node].add_cpu(@truncate(cpu_id));
        }

        return cpu_id;
    }

    /// Boot an AP
    pub fn boot_ap(self: *SmpManager, cpu_id: u8) bool {
        if (cpu_id >= self.cpu_count) return false;
        if (self.cpus[cpu_id].state != .offline) return false;

        self.cpus[cpu_id].state = .booting;

        // In real kernel:
        // 1. Set up AP boot trampoline at < 1MB
        // 2. Send INIT IPI to target APIC
        // 3. Wait 10ms
        // 4. Send SIPI (Startup IPI) with trampoline address
        // 5. Wait for AP to signal completion

        // Simulate successful boot
        self.ap_boot_complete = false;
        // In real HW: send_init_ipi(self.cpus[cpu_id].apic_id)
        // sleep_ms(10)
        // send_sipi(self.cpus[cpu_id].apic_id, trampoline_page)
        // wait for ap_boot_complete

        self.cpus[cpu_id].state = .online;
        self.online_mask.set(@truncate(cpu_id));
        return true;
    }

    /// Take CPU offline
    pub fn offline_cpu(self: *SmpManager, cpu_id: u8) bool {
        if (cpu_id == self.bsp_id) return false; // Can't offline BSP
        if (cpu_id >= self.cpu_count) return false;
        if (self.cpus[cpu_id].state != .online and self.cpus[cpu_id].state != .idle) return false;

        self.cpus[cpu_id].state = .hotplug_prepare;

        // Send STOP IPI
        self.send_ipi(cpu_id, .{
            .ipi_type = .cpu_offline,
            .source_cpu = self.bsp_id,
        });

        self.cpus[cpu_id].state = .hotplug_dead;
        self.online_mask.clear(@truncate(cpu_id));
        return true;
    }

    /// Send IPI to specific CPU
    pub fn send_ipi(self: *SmpManager, target: u8, msg: IpiMessage) bool {
        if (target >= self.cpu_count) return false;
        if (!self.online_mask.test(@truncate(target))) return false;

        if (self.cpus[target].enqueue_ipi(msg)) {
            self.cpus[target].ipi_received += 1;
            self.total_ipis += 1;
            return true;
        }
        return false;
    }

    /// Send IPI to all online CPUs (excluding sender)
    pub fn send_ipi_all(self: *SmpManager, sender: u8, msg: IpiMessage) u32 {
        var sent: u32 = 0;
        var cpu: u8 = 0;
        while (cpu < self.cpu_count) : (cpu += 1) {
            if (cpu != sender and self.online_mask.test(@truncate(cpu))) {
                if (self.send_ipi(cpu, msg)) {
                    sent += 1;
                }
            }
        }
        return sent;
    }

    /// Send IPI to CPUs matching a mask
    pub fn send_ipi_mask(self: *SmpManager, mask: CpuMask, msg: IpiMessage) u32 {
        var sent: u32 = 0;
        const target_mask = mask.and_mask(self.online_mask);
        var cpu: ?u6 = target_mask.first();
        while (cpu) |c| {
            if (self.send_ipi(c, msg)) {
                sent += 1;
            }
            cpu = target_mask.next(c);
        }
        return sent;
    }

    /// Process incoming IPIs for a CPU
    pub fn process_ipis(self: *SmpManager, cpu_id: u8) u32 {
        if (cpu_id >= self.cpu_count) return 0;
        var processed: u32 = 0;

        while (self.cpus[cpu_id].dequeue_ipi()) |msg| {
            switch (msg.ipi_type) {
                .reschedule => {
                    self.cpus[cpu_id].need_resched = true;
                    self.total_reschedules += 1;
                },
                .call_function => {
                    // Execute function (would use func_addr in real kernel)
                    _ = msg.func_addr;
                    _ = msg.func_data;
                },
                .tlb_shootdown => {
                    self.cpus[cpu_id].tlb_flush_pending = true;
                    self.cpus[cpu_id].tlb_flush_addr = msg.addr;
                    self.cpus[cpu_id].tlb_flush_pages = msg.pages;
                    self.flush_tlb_local(cpu_id);
                    self.total_tlb_shootdowns += 1;
                },
                .stop => {
                    self.cpus[cpu_id].state = .halted;
                },
                .cpu_offline => {
                    self.cpus[cpu_id].state = .hotplug_dead;
                    self.online_mask.clear(@truncate(cpu_id));
                },
                .timer_sync => {},
                .irq_work => {},
                .nmi_backtrace => {},
            }
            processed += 1;
        }

        return processed;
    }

    /// TLB shootdown: flush range on all CPUs
    pub fn tlb_shootdown(self: *SmpManager, addr: u64, pages: u32, sender: u8) void {
        const msg = IpiMessage{
            .ipi_type = .tlb_shootdown,
            .source_cpu = sender,
            .addr = addr,
            .pages = pages,
        };
        _ = self.send_ipi_all(sender, msg);
        // Also flush locally
        self.flush_tlb_local(sender);
    }

    fn flush_tlb_local(self: *SmpManager, cpu_id: u8) void {
        // In real kernel: invlpg or full CR3 reload
        self.cpus[cpu_id].tlb_flush_pending = false;
    }

    /// Cross-CPU function call
    pub fn smp_call_function(self: *SmpManager, target_mask: CpuMask, func_addr: u64, data: u64) bool {
        if (self.call_count >= MAX_CALL_QUEUE) return false;

        // Enqueue call entry
        const idx = self.call_count;
        self.call_queue[idx] = .{
            .func_addr = func_addr,
            .data = data,
            .target_mask = target_mask,
            .wait = false,
            .active = true,
        };
        self.call_count += 1;

        // Send IPIs
        const msg = IpiMessage{
            .ipi_type = .call_function,
            .source_cpu = self.bsp_id,
            .func_addr = func_addr,
            .func_data = data,
        };
        _ = self.send_ipi_mask(target_mask, msg);
        return true;
    }

    /// Reschedule on target CPU
    pub fn kick_cpu(self: *SmpManager, cpu_id: u8) bool {
        return self.send_ipi(cpu_id, .{
            .ipi_type = .reschedule,
            .source_cpu = self.bsp_id,
        });
    }

    /// Get online CPU count
    pub fn online_count(self: *const SmpManager) u32 {
        return self.online_mask.count();
    }

    /// Get CPU load info
    pub fn cpu_load(self: *const SmpManager, cpu_id: u8) u32 {
        if (cpu_id >= self.cpu_count) return 0;
        const total = self.cpus[cpu_id].busy_time_us + self.cpus[cpu_id].idle_time_us;
        if (total == 0) return 0;
        return @truncate((self.cpus[cpu_id].busy_time_us * 100) / total);
    }

    /// Find least loaded CPU in mask
    pub fn find_least_loaded(self: *const SmpManager, mask: CpuMask) ?u8 {
        var best: ?u8 = null;
        var best_load: u32 = 101;
        const target = mask.and_mask(self.online_mask);

        var cpu: ?u6 = target.first();
        while (cpu) |c| {
            const load = self.cpu_load(c);
            if (load < best_load) {
                best_load = load;
                best = c;
            }
            cpu = target.next(c);
        }
        return best;
    }

    /// NUMA-aware CPU selection
    pub fn find_cpu_near(self: *const SmpManager, preferred_node: u8) ?u8 {
        if (preferred_node < self.node_count) {
            const node_cpus = self.nodes[preferred_node].cpu_mask.and_mask(self.online_mask);
            if (self.find_least_loaded(node_cpus)) |cpu| {
                return cpu;
            }
        }
        // Fallback to any online CPU
        return self.find_least_loaded(self.online_mask);
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var smp_mgr = SmpManager{};

pub fn get_smp_manager() *SmpManager {
    return &smp_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_smp_init() void {
    smp_mgr.init();
}

export fn zxy_smp_register_cpu(apic_id: u32, acpi_id: u32, numa_node: u8) i32 {
    return if (smp_mgr.register_cpu(apic_id, acpi_id, numa_node)) |id| @as(i32, id) else -1;
}

export fn zxy_smp_boot_ap(cpu_id: u8) i32 {
    return if (smp_mgr.boot_ap(cpu_id)) 0 else -1;
}

export fn zxy_smp_offline_cpu(cpu_id: u8) i32 {
    return if (smp_mgr.offline_cpu(cpu_id)) 0 else -1;
}

export fn zxy_smp_send_ipi(target: u8, ipi_type: u8) i32 {
    const msg = IpiMessage{
        .ipi_type = @enumFromInt(ipi_type),
        .source_cpu = smp_mgr.bsp_id,
    };
    return if (smp_mgr.send_ipi(target, msg)) 0 else -1;
}

export fn zxy_smp_online_count() u32 {
    return smp_mgr.online_count();
}

export fn zxy_smp_cpu_count() u8 {
    return smp_mgr.cpu_count;
}

export fn zxy_smp_process_ipis(cpu_id: u8) u32 {
    return smp_mgr.process_ipis(cpu_id);
}

export fn zxy_smp_tlb_shootdown(addr: u64, pages: u32) void {
    smp_mgr.tlb_shootdown(addr, pages, smp_mgr.bsp_id);
}

export fn zxy_smp_cpu_load(cpu_id: u8) u32 {
    return smp_mgr.cpu_load(cpu_id);
}

export fn zxy_smp_total_ipis() u64 {
    return smp_mgr.total_ipis;
}

export fn zxy_smp_kick_cpu(cpu_id: u8) i32 {
    return if (smp_mgr.kick_cpu(cpu_id)) 0 else -1;
}

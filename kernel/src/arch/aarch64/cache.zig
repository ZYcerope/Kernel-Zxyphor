// =============================================================================
// Zxyphor Kernel — ARM64 Cache Management Operations
// =============================================================================
// Implements all ARMv8-A cache maintenance operations for data coherency
// between CPU caches, DMA devices, and multi-processor cache hierarchies.
//
// Cache maintenance instructions used:
//   DC CIVAC   — Clean and Invalidate by VA to Point of Coherency
//   DC CVAC    — Clean by VA to Point of Coherency
//   DC CVAU    — Clean by VA to Point of Unification
//   DC CVAP    — Clean by VA to Point of Persistence (ARMv8.2)
//   DC CVADP   — Clean by VA to Point of Deep Persistence (ARMv8.5)
//   DC IVAC    — Invalidate by VA to Point of Coherency
//   DC ZVA     — Data Cache Zero by VA (fast zeroing)
//   DC ISW     — Invalidate by Set/Way
//   DC CSW     — Clean by Set/Way
//   DC CISW    — Clean and Invalidate by Set/Way
//   IC IVAU    — Invalidate instruction cache by VA to PoU
//   IC IALLU   — Invalidate all instruction caches to PoU
//   IC IALLUIS — Invalidate all instruction caches to PoU, Inner Shareable
//
// Cache topology detection via CLIDR_EL1, CCSIDR_EL1, CTR_EL0.
// Supports cleaning/invalidating individual lines or entire ranges.
// Used by DMA subsystem, self-modifying code, and kernel text patching.
// =============================================================================

// ── Cache Constants ───────────────────────────────────────────────────────
pub const CacheType = enum(u4) {
    none = 0,
    instruction_only = 1,
    data_only = 2,
    separate = 3,      // Separate I and D caches
    unified = 4,
};

pub const CacheLevel = struct {
    level: u8,         // Cache level (0 = L1, 1 = L2, etc.)
    cache_type: CacheType,
    line_size: u32,    // Cache line size in bytes
    num_sets: u32,     // Number of cache sets
    associativity: u32, // Associativity (number of ways)
    total_size: u64,   // Total cache size in bytes
    write_back: bool,
    read_allocate: bool,
    write_allocate: bool,
    write_through: bool,
};

pub const MAX_CACHE_LEVELS: usize = 7;

pub const CacheTopology = struct {
    levels: [MAX_CACHE_LEVELS]CacheLevel,
    num_levels: u8,
    dminline: u32,     // Minimum D-cache line size (bytes) from CTR_EL0
    iminline: u32,     // Minimum I-cache line size (bytes)
    dic: bool,         // Data Independence of instruction caches
    idc: bool,         // Instruction cache Data Coherence
    cwg: u32,          // Cache Writeback Granule (bytes)
    erg: u32,          // Exclusives Reservation Granule (bytes)
    dczva_block: u32,  // DC ZVA block size (bytes)

    const Self = @This();

    pub fn detect() Self {
        var topo = Self{
            .levels = undefined,
            .num_levels = 0,
            .dminline = 0,
            .iminline = 0,
            .dic = false,
            .idc = false,
            .cwg = 0,
            .erg = 0,
            .dczva_block = 0,
        };

        // Parse CTR_EL0 — Cache Type Register
        const ctr = readCtr();
        topo.iminline = @as(u32, 4) << @as(u5, @truncate(ctr & 0xF));
        topo.dminline = @as(u32, 4) << @as(u5, @truncate((ctr >> 16) & 0xF));
        topo.erg = @as(u32, 4) << @as(u5, @truncate((ctr >> 20) & 0xF));
        topo.cwg = @as(u32, 4) << @as(u5, @truncate((ctr >> 24) & 0xF));
        topo.dic = ((ctr >> 29) & 1) == 1;
        topo.idc = ((ctr >> 28) & 1) == 1;

        // Parse DCZID_EL0 — DC ZVA block size
        const dczid = readDczid();
        if ((dczid & (1 << 4)) == 0) { // DZP = 0 means DC ZVA is permitted
            topo.dczva_block = @as(u32, 4) << @as(u5, @truncate(dczid & 0xF));
        }

        // Parse CLIDR_EL1 — Cache Level ID Register
        const clidr = readClidr();
        var level: u8 = 0;
        while (level < MAX_CACHE_LEVELS) : (level += 1) {
            const ctype = @as(u4, @truncate((clidr >> (@as(u6, level) * 3)) & 0x7));
            if (ctype == 0) break;

            topo.levels[level] = CacheLevel{
                .level = level,
                .cache_type = @enumFromInt(ctype),
                .line_size = 0,
                .num_sets = 0,
                .associativity = 0,
                .total_size = 0,
                .write_back = false,
                .read_allocate = false,
                .write_allocate = false,
                .write_through = false,
            };

            // Query D-cache or unified cache properties
            if (ctype >= 2) {
                queryCacheLevel(&topo.levels[level], level, false);
            }

            topo.num_levels = level + 1;
        }

        return topo;
    }

    fn queryCacheLevel(cl: *CacheLevel, level: u8, is_icache: bool) void {
        // Select cache level and type via CSSELR_EL1
        const csselr = (@as(u64, level) << 1) | @as(u64, @intFromBool(is_icache));
        writeCsselr(csselr);
        isb();

        // Read CCSIDR_EL1
        const ccsidr = readCcsidr();

        // Parse CCSIDR fields (format depends on CCIDX feature)
        cl.line_size = @as(u32, 1) << @as(u5, @truncate((ccsidr & 0x7) + 4));
        cl.associativity = @as(u32, @truncate(((ccsidr >> 3) & 0x3FF) + 1));
        cl.num_sets = @as(u32, @truncate(((ccsidr >> 13) & 0x7FFF) + 1));
        cl.total_size = @as(u64, cl.line_size) * @as(u64, cl.associativity) * @as(u64, cl.num_sets);

        // Cache attributes
        cl.write_through = ((ccsidr >> 28) & 1) == 1;
        cl.write_back = ((ccsidr >> 30) & 1) == 1;
        cl.read_allocate = ((ccsidr >> 29) & 1) == 1;
        cl.write_allocate = ((ccsidr >> 31) & 1) == 1;
    }
};

var cache_topo: CacheTopology = undefined;
var cache_detected: bool = false;

pub fn detectCacheTopology() void {
    cache_topo = CacheTopology.detect();
    cache_detected = true;
}

pub fn getCacheTopology() *const CacheTopology {
    return &cache_topo;
}

// ── Data Cache Operations (by Virtual Address) ───────────────────────────

/// Clean data cache by VA to Point of Coherency (write back dirty lines)
pub fn cleanDcacheRange(start: u64, size: usize) void {
    const line_size = if (cache_detected) cache_topo.dminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("dc cvac, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
}

/// Invalidate data cache by VA to Point of Coherency (discard cache lines)
pub fn invalidateDcacheRange(start: u64, size: usize) void {
    const line_size = if (cache_detected) cache_topo.dminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("dc ivac, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
}

/// Clean and invalidate data cache by VA to PoC
pub fn cleanInvalidateDcacheRange(start: u64, size: usize) void {
    const line_size = if (cache_detected) cache_topo.dminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("dc civac, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
}

/// Clean data cache by VA to Point of Unification (for I/D coherency)
pub fn cleanDcacheToPoU(start: u64, size: usize) void {
    const line_size = if (cache_detected) cache_topo.dminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("dc cvau, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
}

/// Clean data cache by VA to Point of Persistence (for NVM/PMEM, ARMv8.2-DCPoP)
pub fn cleanDcacheToPoP(start: u64, size: usize) void {
    const line_size = if (cache_detected) cache_topo.dminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("dc cvap, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
}

/// Zero a memory range using DC ZVA (very fast, no prior cache fetch)
pub fn zeroDcacheRange(start: u64, size: usize) void {
    if (!cache_detected or cache_topo.dczva_block == 0) {
        // Fallback: use regular memset
        const ptr: [*]u8 = @ptrFromInt(start);
        @memset(ptr[0..size], 0);
        return;
    }

    const block_size = cache_topo.dczva_block;
    var addr = (start + block_size - 1) & ~@as(u64, block_size - 1);
    const end = (start + size) & ~@as(u64, block_size - 1);

    // Zero prefix (unaligned start)
    if (addr > start) {
        const prefix_ptr: [*]u8 = @ptrFromInt(start);
        @memset(prefix_ptr[0..@min(addr - start, size)], 0);
    }

    // Zero aligned blocks using DC ZVA
    while (addr < end) : (addr += block_size) {
        asm volatile ("dc zva, %[addr]" : : [addr] "r" (addr) : "memory");
    }

    // Zero suffix (unaligned end)
    if (addr < start + size) {
        const suffix_ptr: [*]u8 = @ptrFromInt(addr);
        @memset(suffix_ptr[0..(start + size - addr)], 0);
    }
}

// ── Instruction Cache Operations ─────────────────────────────────────────

/// Invalidate instruction cache by VA to Point of Unification
pub fn invalidateIcacheRange(start: u64, size: usize) void {
    if (cache_topo.dic) return; // DIC=1 means I-cache is self-coherent

    const line_size = if (cache_detected) cache_topo.iminline else 64;
    var addr = start & ~@as(u64, line_size - 1);
    const end = start + size;

    while (addr < end) : (addr += line_size) {
        asm volatile ("ic ivau, %[addr]" : : [addr] "r" (addr) : "memory");
    }
    dsb_ish();
    isb();
}

/// Invalidate all instruction caches (this CPU) to PoU
pub fn invalidateIcacheAll() void {
    asm volatile ("ic iallu; dsb ish; isb" ::: "memory");
}

/// Invalidate all instruction caches, Inner Shareable
pub fn invalidateIcacheAllIS() void {
    asm volatile ("ic ialluis; dsb ish; isb" ::: "memory");
}

// ── Full Cache Flush (by Set/Way) ────────────────────────────────────────
// WARNING: Set/Way operations should only be used during power management
// (e.g., CPU power down). For normal use, always prefer VA-based operations.

/// Flush all data caches by set/way (clean + invalidate all levels)
pub fn flushAllDcachesBySetWay() void {
    const clidr = readClidr();
    const loc = @as(u3, @truncate((clidr >> 24) & 0x7)); // Level of Coherence

    var level: u3 = 0;
    while (level < loc) : (level += 1) {
        const ctype = @as(u3, @truncate((clidr >> (@as(u6, level) * 3)) & 0x7));
        if (ctype < 2) continue; // Skip if no data cache at this level

        // Select cache level
        writeCsselr((@as(u64, level) << 1) | 0);
        isb();

        const ccsidr = readCcsidr();
        const line_size = @as(u5, @truncate((ccsidr & 0x7) + 4));
        const num_ways = @as(u32, @truncate(((ccsidr >> 3) & 0x3FF)));
        const num_sets = @as(u32, @truncate(((ccsidr >> 13) & 0x7FFF)));

        // Calculate way shift
        const way_shift: u5 = @truncate(32 - @as(u6, @truncate(countLeadingZeros32(num_ways))));

        var way: u32 = 0;
        while (way <= num_ways) : (way += 1) {
            var set: u32 = 0;
            while (set <= num_sets) : (set += 1) {
                const sw: u64 = (@as(u64, way) << way_shift) |
                               (@as(u64, set) << line_size) |
                               (@as(u64, level) << 1);
                asm volatile ("dc cisw, %[sw]" : : [sw] "r" (sw) : "memory");
            }
        }
    }

    dsb_sy();
    isb();
}

/// Clean all data caches by set/way (write back dirty, don't invalidate)
pub fn cleanAllDcachesBySetWay() void {
    const clidr = readClidr();
    const loc = @as(u3, @truncate((clidr >> 24) & 0x7));

    var level: u3 = 0;
    while (level < loc) : (level += 1) {
        const ctype = @as(u3, @truncate((clidr >> (@as(u6, level) * 3)) & 0x7));
        if (ctype < 2) continue;

        writeCsselr((@as(u64, level) << 1) | 0);
        isb();

        const ccsidr = readCcsidr();
        const line_size = @as(u5, @truncate((ccsidr & 0x7) + 4));
        const num_ways = @as(u32, @truncate(((ccsidr >> 3) & 0x3FF)));
        const num_sets = @as(u32, @truncate(((ccsidr >> 13) & 0x7FFF)));
        const way_shift: u5 = @truncate(32 - @as(u6, @truncate(countLeadingZeros32(num_ways))));

        var way: u32 = 0;
        while (way <= num_ways) : (way += 1) {
            var set: u32 = 0;
            while (set <= num_sets) : (set += 1) {
                const sw: u64 = (@as(u64, way) << way_shift) |
                               (@as(u64, set) << line_size) |
                               (@as(u64, level) << 1);
                asm volatile ("dc csw, %[sw]" : : [sw] "r" (sw) : "memory");
            }
        }
    }

    dsb_sy();
    isb();
}

// ── Convenience Functions for Common Patterns ────────────────────────────

/// Prepare a DMA buffer for device read (clean — device will read)
pub fn dmaMapForDevice(buf_phys: u64, size: usize) void {
    cleanDcacheRange(buf_phys, size);
}

/// Prepare DMA buffer after device write (invalidate — CPU will read)
pub fn dmaUnmapFromDevice(buf_phys: u64, size: usize) void {
    invalidateDcacheRange(buf_phys, size);
}

/// Bidirectional DMA sync (clean + invalidate)
pub fn dmaSyncBidirectional(buf_phys: u64, size: usize) void {
    cleanInvalidateDcacheRange(buf_phys, size);
}

/// Flush code region after text patching (clean D + invalidate I)
pub fn flushCodeRange(start: u64, size: usize) void {
    cleanDcacheToPoU(start, size);
    dsb_ish();
    invalidateIcacheRange(start, size);
    dsb_ish();
    isb();
}

// ── Barriers ──────────────────────────────────────────────────────────────
pub inline fn dsb_sy() void {
    asm volatile ("dsb sy" ::: "memory");
}

pub inline fn dsb_ish() void {
    asm volatile ("dsb ish" ::: "memory");
}

pub inline fn dsb_ishst() void {
    asm volatile ("dsb ishst" ::: "memory");
}

pub inline fn dsb_nsh() void {
    asm volatile ("dsb nsh" ::: "memory");
}

pub inline fn dmb_sy() void {
    asm volatile ("dmb sy" ::: "memory");
}

pub inline fn dmb_ish() void {
    asm volatile ("dmb ish" ::: "memory");
}

pub inline fn dmb_ishld() void {
    asm volatile ("dmb ishld" ::: "memory");
}

pub inline fn dmb_ishst() void {
    asm volatile ("dmb ishst" ::: "memory");
}

pub inline fn isb() void {
    asm volatile ("isb" ::: "memory");
}

// ── System Register Wrappers ──────────────────────────────────────────────
inline fn readCtr() u64 {
    return asm ("mrs %[r], CTR_EL0" : [r] "=r" (-> u64));
}

inline fn readDczid() u64 {
    return asm ("mrs %[r], DCZID_EL0" : [r] "=r" (-> u64));
}

inline fn readClidr() u64 {
    return asm ("mrs %[r], CLIDR_EL1" : [r] "=r" (-> u64));
}

inline fn readCcsidr() u64 {
    return asm ("mrs %[r], CCSIDR_EL1" : [r] "=r" (-> u64));
}

inline fn writeCsselr(val: u64) void {
    asm volatile ("msr CSSELR_EL1, %[v]" : : [v] "r" (val));
}

fn countLeadingZeros32(val: u32) u32 {
    if (val == 0) return 32;
    var v = val;
    var count: u32 = 0;
    while ((v & 0x80000000) == 0) : (count += 1) {
        v <<= 1;
    }
    return count;
}

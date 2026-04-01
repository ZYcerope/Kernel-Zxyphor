// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Memory Compaction & Page Migration (Rust)
//
// Implements Linux-style memory compaction for reducing fragmentation:
// - Zone-based compaction with migration scanner + free scanner
// - Page migration between NUMA nodes and zones
// - Compaction modes: sync, async, direct, kcompactd
// - Fragmentation index calculation per order
// - Migration types: movable, reclaimable, unmovable
// - CMA (Contiguous Memory Allocator) region management
// - Compaction deferral with backoff
// - Huge page compaction proactive mode

#![no_std]
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

pub const MAX_ORDER: usize = 11;
pub const MAX_ZONES: usize = 4;
pub const MAX_PAGES: usize = 16384;
pub const MAX_CMA_REGIONS: usize = 8;
pub const PAGE_SIZE: u64 = 4096;
pub const PAGES_PER_BLOCK: usize = 512; // pageblock_order = 9 => 2^9 pages
pub const MAX_PAGEBLOCKS: usize = MAX_PAGES / PAGES_PER_BLOCK + 1;
pub const COMPACT_CLUSTER_MAX: usize = 32;
pub const MAX_MIGRATE_PAGES: usize = 64;
pub const CMA_MAX_PAGES: usize = 2048;

// ============================================================================
// Zone types
// ============================================================================

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum ZoneType {
    Dma = 0,
    Dma32 = 1,
    Normal = 2,
    Movable = 3,
}

// ============================================================================
// Page migrate type (pageblock grouping)
// ============================================================================

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(u8)]
pub enum MigrateType {
    Unmovable = 0,
    Movable = 1,
    Reclaimable = 2,
    HighAtomic = 3,
    Cma = 4,
    Isolate = 5,
}

// ============================================================================
// Compaction mode
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CompactMode {
    None = 0,
    Async = 1,        // kcompactd background
    Sync = 2,         // Synchronous, can block
    SyncLight = 3,    // Sync but skip locked pages
    Direct = 4,       // Direct reclaim path compaction
}

// ============================================================================
// Compaction result
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum CompactResult {
    NotSuitable = 0,
    Skipped = 1,
    Deferred = 2,
    NoSuitablePage = 3,
    Continue = 4,
    Partial = 5,
    Complete = 6,
    Success = 7,
}

// ============================================================================
// Page state for compaction tracking
// ============================================================================

#[derive(Clone, Copy)]
pub struct PageInfo {
    /// Physical frame number
    pfn: u64,
    /// Page flags
    flags: PageFlags,
    /// Migration type
    migrate_type: MigrateType,
    /// Order (if free): 0 = single page, >0 = buddy merge size
    order: u8,
    /// Zone this page belongs to
    zone: ZoneType,
    /// Owning PID (0 = kernel or free)
    owner_pid: u32,
    /// Virtual address mapping (0 = unmapped)
    vaddr: u64,
    /// Reference count
    refcount: u32,
    /// Mapcount (number of page table mappings)
    mapcount: i32,
}

#[derive(Clone, Copy)]
pub struct PageFlags {
    pub free: bool,
    pub movable: bool,
    pub locked: bool,
    pub dirty: bool,
    pub lru: bool,
    pub active: bool,
    pub slab: bool,
    pub compound: bool,
    pub isolated: bool,
    pub reserved: bool,
    pub mlocked: bool,
    pub huge: bool,
}

impl PageFlags {
    pub const fn empty() -> Self {
        Self {
            free: true,
            movable: false,
            locked: false,
            dirty: false,
            lru: false,
            active: false,
            slab: false,
            compound: false,
            isolated: false,
            reserved: false,
            mlocked: false,
            huge: false,
        }
    }

    pub fn can_migrate(&self) -> bool {
        !self.locked && !self.reserved && !self.slab && !self.mlocked && self.movable
    }
}

impl PageInfo {
    pub const fn new() -> Self {
        Self {
            pfn: 0,
            flags: PageFlags::empty(),
            migrate_type: MigrateType::Movable,
            order: 0,
            zone: ZoneType::Normal,
            owner_pid: 0,
            vaddr: 0,
            refcount: 0,
            mapcount: 0,
        }
    }

    pub fn is_free(&self) -> bool {
        self.flags.free
    }

    pub fn is_movable(&self) -> bool {
        self.flags.movable && !self.flags.locked && !self.flags.reserved
    }

    pub fn is_isolated(&self) -> bool {
        self.flags.isolated
    }
}

// ============================================================================
// Zone compaction state
// ============================================================================

pub struct ZoneCompact {
    zone_type: ZoneType,
    /// Start and end PFN for this zone
    start_pfn: u64,
    end_pfn: u64,
    /// Migration scanner position (scans forward from zone start)
    migrate_pfn: u64,
    /// Free scanner position (scans backward from zone end)
    free_pfn: u64,
    /// Whether compaction is needed at each order
    suitable: [bool; MAX_ORDER],
    /// Free pages at each order (buddy system)
    free_count: [u32; MAX_ORDER],
    /// Total free pages
    total_free: u32,
    /// Fragmentation index per order (0-1000, higher = more fragmented)
    frag_index: [u32; MAX_ORDER],
    /// Compaction deferral state
    defer_shift: u8,
    defer_order: u8,
    defer_score: u32,
    compact_considered: u64,
    compact_deferred: u64,
    /// Stats
    compact_success: u64,
    compact_fail: u64,
    pages_scanned: u64,
    pages_migrated: u64,
    pages_freed: u64,
}

impl ZoneCompact {
    pub const fn new(zone_type: ZoneType) -> Self {
        Self {
            zone_type,
            start_pfn: 0,
            end_pfn: 0,
            migrate_pfn: 0,
            free_pfn: 0,
            suitable: [false; MAX_ORDER],
            free_count: [0u32; MAX_ORDER],
            total_free: 0,
            frag_index: [0u32; MAX_ORDER],
            defer_shift: 0,
            defer_order: 0,
            defer_score: 0,
            compact_considered: 0,
            compact_deferred: 0,
            compact_success: 0,
            compact_fail: 0,
            pages_scanned: 0,
            pages_migrated: 0,
            pages_freed: 0,
        }
    }

    /// Calculate fragmentation index for a given order
    /// Returns 0-1000: 0 = no fragmentation, 1000 = completely fragmented
    pub fn calc_frag_index(&self, order: usize) -> u32 {
        if order >= MAX_ORDER {
            return 0;
        }
        let required = 1u32 << order;
        if self.total_free < required {
            return 0; // Not enough memory at all, not a fragmentation issue
        }

        // Count how many free pages are in blocks >= order
        let mut suitable_free = 0u32;
        for i in order..MAX_ORDER {
            suitable_free += self.free_count[i] * (1u32 << i);
        }

        if suitable_free >= required {
            return 0; // Can satisfy directly
        }

        // Fragmentation: have enough total free but not contiguous
        // Index = (total_free - suitable_free) * 1000 / total_free
        if self.total_free == 0 {
            return 1000;
        }
        let fragmented = self.total_free - suitable_free;
        (fragmented as u64 * 1000 / self.total_free as u64) as u32
    }

    /// Check if compaction should be deferred
    pub fn should_defer(&mut self, order: usize) -> bool {
        self.compact_considered += 1;

        if self.defer_shift == 0 {
            return false;
        }

        let threshold = 1u64 << self.defer_shift;
        if self.compact_considered < threshold {
            self.compact_deferred += 1;
            return true;
        }

        // Reset after deferral period
        self.compact_considered = 0;
        false
    }

    /// Update deferral after compaction attempt
    pub fn update_defer(&mut self, result: CompactResult, order: usize) {
        match result {
            CompactResult::Success | CompactResult::Complete => {
                self.defer_shift = 0;
                self.defer_order = 0;
                self.defer_score = 0;
            }
            CompactResult::NoSuitablePage | CompactResult::Partial => {
                if self.defer_shift < 6 {
                    self.defer_shift += 1;
                }
                self.defer_order = order as u8;
                self.defer_score += 1;
            }
            _ => {}
        }
    }

    /// Reset scanners to zone boundaries
    pub fn reset_scanners(&mut self) {
        self.migrate_pfn = self.start_pfn;
        self.free_pfn = self.end_pfn;
    }

    /// Check if scanners have met (compaction round complete)
    pub fn scanners_met(&self) -> bool {
        self.migrate_pfn >= self.free_pfn
    }
}

// ============================================================================
// CMA Region
// ============================================================================

pub struct CmaRegion {
    name: [u8; 32],
    name_len: u8,
    base_pfn: u64,
    count: u32,   // Number of pages
    bitmap: [u64; CMA_MAX_PAGES / 64],  // Allocation bitmap
    allocated: u32,
    active: bool,
}

impl CmaRegion {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 32],
            name_len: 0,
            base_pfn: 0,
            count: 0,
            bitmap: [0u64; CMA_MAX_PAGES / 64],
            allocated: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > 32 { 32 } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    /// Allocate contiguous pages from CMA
    pub fn alloc_pages(&mut self, count: u32) -> Option<u64> {
        if count == 0 || count > self.count {
            return None;
        }

        // First-fit scan for `count` contiguous free bits
        let mut run_start: u32 = 0;
        let mut run_len: u32 = 0;

        for i in 0..self.count {
            let word = (i / 64) as usize;
            let bit = i % 64;
            if word >= self.bitmap.len() {
                break;
            }

            if (self.bitmap[word] >> bit) & 1 == 0 {
                if run_len == 0 {
                    run_start = i;
                }
                run_len += 1;
                if run_len >= count {
                    // Found a run — mark allocated
                    for j in run_start..run_start + count {
                        let w = (j / 64) as usize;
                        let b = j % 64;
                        self.bitmap[w] |= 1u64 << b;
                    }
                    self.allocated += count;
                    return Some(self.base_pfn + run_start as u64);
                }
            } else {
                run_len = 0;
            }
        }
        None
    }

    /// Free CMA pages
    pub fn free_pages(&mut self, pfn: u64, count: u32) -> bool {
        if pfn < self.base_pfn {
            return false;
        }
        let offset = (pfn - self.base_pfn) as u32;
        if offset + count > self.count {
            return false;
        }

        for i in offset..offset + count {
            let word = (i / 64) as usize;
            let bit = i % 64;
            if word < self.bitmap.len() {
                self.bitmap[word] &= !(1u64 << bit);
            }
        }
        if self.allocated >= count {
            self.allocated -= count;
        }
        true
    }

    pub fn free_count(&self) -> u32 {
        self.count - self.allocated
    }
}

// ============================================================================
// Migration batch
// ============================================================================

struct MigrationEntry {
    src_pfn: u64,
    dst_pfn: u64,
    owner_pid: u32,
    vaddr: u64,
    success: bool,
}

impl MigrationEntry {
    const fn new() -> Self {
        Self {
            src_pfn: 0,
            dst_pfn: 0,
            owner_pid: 0,
            vaddr: 0,
            success: false,
        }
    }
}

// ============================================================================
// Compaction Manager
// ============================================================================

pub struct CompactManager {
    /// All pages in the system
    pages: [PageInfo; MAX_PAGES],
    page_count: u32,

    /// Pageblock migrate types
    pageblock_types: [MigrateType; MAX_PAGEBLOCKS],

    /// Per-zone compaction state
    zones: [ZoneCompact; MAX_ZONES],
    zone_count: u32,

    /// CMA regions
    cma_regions: [CmaRegion; MAX_CMA_REGIONS],
    cma_count: u32,

    /// Current compaction mode
    mode: CompactMode,

    /// Migration batch
    migrate_batch: [MigrationEntry; MAX_MIGRATE_PAGES],
    migrate_batch_count: u32,

    /// Proactive compaction threshold (fragmentation score)
    proactive_threshold: u32,
    proactive_enabled: bool,

    /// Stats
    total_compact_runs: u64,
    total_pages_migrated: u64,
    total_pages_failed: u64,
    total_cma_allocs: u64,
    total_cma_frees: u64,
    total_direct_compacts: u64,
    total_proactive_compacts: u64,
}

impl CompactManager {
    pub const fn new() -> Self {
        Self {
            pages: [const { PageInfo::new() }; MAX_PAGES],
            page_count: 0,
            pageblock_types: [MigrateType::Movable; MAX_PAGEBLOCKS],
            zones: [
                ZoneCompact::new(ZoneType::Dma),
                ZoneCompact::new(ZoneType::Dma32),
                ZoneCompact::new(ZoneType::Normal),
                ZoneCompact::new(ZoneType::Movable),
            ],
            zone_count: 0,
            cma_regions: [const { CmaRegion::new() }; MAX_CMA_REGIONS],
            cma_count: 0,
            mode: CompactMode::None,
            migrate_batch: [const { MigrationEntry::new() }; MAX_MIGRATE_PAGES],
            migrate_batch_count: 0,
            proactive_threshold: 500, // 50% fragmentation triggers proactive
            proactive_enabled: true,
            total_compact_runs: 0,
            total_pages_migrated: 0,
            total_pages_failed: 0,
            total_cma_allocs: 0,
            total_cma_frees: 0,
            total_direct_compacts: 0,
            total_proactive_compacts: 0,
        }
    }

    /// Initialize zones
    pub fn init_zone(&mut self, zone_type: ZoneType, start_pfn: u64, end_pfn: u64) {
        let idx = zone_type as usize;
        if idx >= MAX_ZONES {
            return;
        }
        self.zones[idx].zone_type = zone_type;
        self.zones[idx].start_pfn = start_pfn;
        self.zones[idx].end_pfn = end_pfn;
        self.zones[idx].migrate_pfn = start_pfn;
        self.zones[idx].free_pfn = end_pfn;
        if idx >= self.zone_count as usize {
            self.zone_count = idx as u32 + 1;
        }

        // Initialize pages in this zone
        for pfn in start_pfn..end_pfn {
            if (pfn as usize) < MAX_PAGES {
                self.pages[pfn as usize].pfn = pfn;
                self.pages[pfn as usize].zone = zone_type;
                self.pages[pfn as usize].flags.free = true;
                self.page_count = self.page_count.max(pfn as u32 + 1);
            }
        }

        // Set pageblock types
        let start_block = (start_pfn as usize) / PAGES_PER_BLOCK;
        let end_block = (end_pfn as usize) / PAGES_PER_BLOCK;
        for b in start_block..=end_block {
            if b < MAX_PAGEBLOCKS {
                self.pageblock_types[b] = if zone_type == ZoneType::Movable {
                    MigrateType::Movable
                } else {
                    MigrateType::Movable // Default all to movable
                };
            }
        }
    }

    /// Mark a page as allocated
    pub fn mark_allocated(&mut self, pfn: u64, pid: u32, vaddr: u64, movable: bool) {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return;
        }
        self.pages[idx].flags.free = false;
        self.pages[idx].flags.movable = movable;
        self.pages[idx].owner_pid = pid;
        self.pages[idx].vaddr = vaddr;
        self.pages[idx].refcount = 1;
        self.pages[idx].mapcount = 1;

        // Update zone free count
        let zone_idx = self.pages[idx].zone as usize;
        if zone_idx < MAX_ZONES && self.zones[zone_idx].total_free > 0 {
            self.zones[zone_idx].total_free -= 1;
        }
    }

    /// Mark a page as free
    pub fn mark_free(&mut self, pfn: u64, order: u8) {
        let idx = pfn as usize;
        if idx >= MAX_PAGES {
            return;
        }
        self.pages[idx].flags = PageFlags::empty();
        self.pages[idx].order = order;
        self.pages[idx].owner_pid = 0;
        self.pages[idx].vaddr = 0;
        self.pages[idx].refcount = 0;
        self.pages[idx].mapcount = 0;

        let zone_idx = self.pages[idx].zone as usize;
        if zone_idx < MAX_ZONES {
            self.zones[zone_idx].total_free += 1;
            if (order as usize) < MAX_ORDER {
                self.zones[zone_idx].free_count[order as usize] += 1;
            }
        }
    }

    /// Update fragmentation indices for all zones
    pub fn update_frag_indices(&mut self) {
        for z in 0..self.zone_count as usize {
            for order in 0..MAX_ORDER {
                self.zones[z].frag_index[order] = self.zones[z].calc_frag_index(order);
            }
        }
    }

    /// Run compaction on a specific zone for a target order
    pub fn compact_zone(&mut self, zone_idx: usize, order: usize, mode: CompactMode) -> CompactResult {
        if zone_idx >= self.zone_count as usize || order >= MAX_ORDER {
            return CompactResult::NotSuitable;
        }

        let zone = &mut self.zones[zone_idx];

        // Check deferral
        if mode == CompactMode::Async && zone.should_defer(order) {
            return CompactResult::Deferred;
        }

        // Check if compaction is worthwhile
        let frag = zone.calc_frag_index(order);
        if frag < 100 { // Less than 10% fragmented
            return CompactResult::NotSuitable;
        }

        // Reset scanners if they've met
        if zone.scanners_met() {
            zone.reset_scanners();
        }

        self.mode = mode;
        self.migrate_batch_count = 0;
        self.total_compact_runs += 1;

        if mode == CompactMode::Direct {
            self.total_direct_compacts += 1;
        }

        // Phase 1: Migration scanner — find movable pages
        let migrate_limit = if mode == CompactMode::Async {
            COMPACT_CLUSTER_MAX / 2
        } else {
            COMPACT_CLUSTER_MAX
        };

        let mut movable_found = 0u32;
        let migrate_start = self.zones[zone_idx].migrate_pfn;
        let migrate_end = self.zones[zone_idx].free_pfn;

        let mut pfn = migrate_start;
        while pfn < migrate_end && movable_found < migrate_limit as u32 {
            let idx = pfn as usize;
            if idx < MAX_PAGES && !self.pages[idx].is_free() && self.pages[idx].is_movable() {
                // Skip isolated pages
                if !self.pages[idx].is_isolated() {
                    if (self.migrate_batch_count as usize) < MAX_MIGRATE_PAGES {
                        let batch_idx = self.migrate_batch_count as usize;
                        self.migrate_batch[batch_idx].src_pfn = pfn;
                        self.migrate_batch[batch_idx].owner_pid = self.pages[idx].owner_pid;
                        self.migrate_batch[batch_idx].vaddr = self.pages[idx].vaddr;
                        self.migrate_batch[batch_idx].success = false;
                        self.migrate_batch_count += 1;
                        movable_found += 1;
                    }
                }
            }
            self.zones[zone_idx].pages_scanned += 1;
            pfn += 1;
        }
        self.zones[zone_idx].migrate_pfn = pfn;

        if movable_found == 0 {
            let result = CompactResult::NoSuitablePage;
            self.zones[zone_idx].update_defer(result, order);
            self.zones[zone_idx].compact_fail += 1;
            return result;
        }

        // Phase 2: Free scanner — find free pages to migrate to
        let mut free_found = 0u32;
        let free_end = self.zones[zone_idx].migrate_pfn;
        pfn = self.zones[zone_idx].free_pfn;

        while pfn > free_end && free_found < movable_found {
            pfn -= 1;
            let idx = pfn as usize;
            if idx < MAX_PAGES && self.pages[idx].is_free() {
                // Assign as destination for a migration entry
                if (free_found as usize) < self.migrate_batch_count as usize {
                    self.migrate_batch[free_found as usize].dst_pfn = pfn;
                    free_found += 1;
                }
            }
        }
        self.zones[zone_idx].free_pfn = pfn;

        if free_found == 0 {
            let result = CompactResult::NoSuitablePage;
            self.zones[zone_idx].update_defer(result, order);
            self.zones[zone_idx].compact_fail += 1;
            return result;
        }

        // Phase 3: Execute migrations
        let migrate_count = if free_found < movable_found { free_found } else { movable_found };
        let mut migrated = 0u32;

        for i in 0..migrate_count as usize {
            let entry = &mut self.migrate_batch[i];
            let src = entry.src_pfn as usize;
            let dst = entry.dst_pfn as usize;

            if src >= MAX_PAGES || dst >= MAX_PAGES {
                continue;
            }

            // Check page is still movable (may have changed)
            if !self.pages[src].is_movable() || !self.pages[dst].is_free() {
                self.total_pages_failed += 1;
                continue;
            }

            // For sync mode, check if page is locked
            if mode == CompactMode::SyncLight && self.pages[src].flags.locked {
                self.total_pages_failed += 1;
                continue;
            }

            // Perform the migration:
            // 1. Isolate source page
            self.pages[src].flags.isolated = true;

            // 2. Copy page data (represented by copying metadata)
            let saved = self.pages[src];
            self.pages[dst] = saved;
            self.pages[dst].pfn = entry.dst_pfn;
            self.pages[dst].flags.isolated = false;

            // 3. Free source page
            self.pages[src] = PageInfo::new();
            self.pages[src].pfn = entry.src_pfn;
            self.pages[src].zone = saved.zone;

            // 4. Update page table mapping (notify external)
            extern "C" {
                fn rust_compact_remap_page(pid: u32, vaddr: u64, old_pfn: u64, new_pfn: u64);
            }
            unsafe {
                rust_compact_remap_page(
                    entry.owner_pid,
                    entry.vaddr,
                    entry.src_pfn,
                    entry.dst_pfn,
                );
            }

            entry.success = true;
            migrated += 1;
            self.total_pages_migrated += 1;
            self.zones[zone_idx].pages_migrated += 1;
        }

        // Update zone free counts after migration
        self.recalc_zone_free(zone_idx);

        // Determine result
        let result = if migrated > 0 {
            // Check if we now have a free block of the required order
            if self.zones[zone_idx].free_count[order] > 0 {
                CompactResult::Success
            } else if migrated >= migrate_count / 2 {
                CompactResult::Partial
            } else {
                CompactResult::Continue
            }
        } else {
            CompactResult::NoSuitablePage
        };

        self.zones[zone_idx].update_defer(result, order);
        if result == CompactResult::Success || result == CompactResult::Complete {
            self.zones[zone_idx].compact_success += 1;
        } else {
            self.zones[zone_idx].compact_fail += 1;
        }

        result
    }

    /// Recalculate free page counts for a zone
    fn recalc_zone_free(&mut self, zone_idx: usize) {
        if zone_idx >= MAX_ZONES {
            return;
        }
        let zone = &mut self.zones[zone_idx];
        for i in 0..MAX_ORDER {
            zone.free_count[i] = 0;
        }
        zone.total_free = 0;

        for pfn in zone.start_pfn..zone.end_pfn {
            let idx = pfn as usize;
            if idx < MAX_PAGES && self.pages[idx].is_free() {
                zone.total_free += 1;
                let order = self.pages[idx].order as usize;
                if order < MAX_ORDER {
                    zone.free_count[order] += 1;
                }
            }
        }
    }

    /// Direct compaction: called when allocation of order N fails
    pub fn try_direct_compact(&mut self, order: usize, zone_type: ZoneType) -> CompactResult {
        let zone_idx = zone_type as usize;
        self.compact_zone(zone_idx, order, CompactMode::Direct)
    }

    /// Proactive compaction: run by kcompactd periodically
    pub fn proactive_compact(&mut self) -> u32 {
        if !self.proactive_enabled {
            return 0;
        }

        let mut compacted = 0u32;

        for z in 0..self.zone_count as usize {
            // Check fragmentation score
            let mut max_frag = 0u32;
            for order in 0..MAX_ORDER {
                let frag = self.zones[z].calc_frag_index(order);
                if frag > max_frag {
                    max_frag = frag;
                }
            }

            if max_frag >= self.proactive_threshold {
                // Find the highest order that's fragmented
                for order in (0..MAX_ORDER).rev() {
                    if self.zones[z].frag_index[order] >= self.proactive_threshold {
                        let result = self.compact_zone(z, order, CompactMode::Async);
                        if result == CompactResult::Success || result == CompactResult::Partial {
                            compacted += 1;
                            self.total_proactive_compacts += 1;
                        }
                        break;
                    }
                }
            }
        }

        compacted
    }

    /// Register a CMA region
    pub fn register_cma(&mut self, name: &[u8], base_pfn: u64, count: u32) -> Option<u16> {
        if self.cma_count as usize >= MAX_CMA_REGIONS || count as usize > CMA_MAX_PAGES {
            return None;
        }
        let idx = self.cma_count as usize;
        self.cma_regions[idx].set_name(name);
        self.cma_regions[idx].base_pfn = base_pfn;
        self.cma_regions[idx].count = count;
        self.cma_regions[idx].allocated = 0;
        self.cma_regions[idx].bitmap = [0u64; CMA_MAX_PAGES / 64];
        self.cma_regions[idx].active = true;

        // Mark pages as CMA type
        for pfn in base_pfn..base_pfn + count as u64 {
            let page_idx = pfn as usize;
            if page_idx < MAX_PAGES {
                self.pages[page_idx].migrate_type = MigrateType::Cma;
            }
            let block = page_idx / PAGES_PER_BLOCK;
            if block < MAX_PAGEBLOCKS {
                self.pageblock_types[block] = MigrateType::Cma;
            }
        }

        self.cma_count += 1;
        Some(idx as u16)
    }

    /// Allocate from CMA
    pub fn cma_alloc(&mut self, region: u16, count: u32) -> Option<u64> {
        if region as usize >= self.cma_count as usize {
            return None;
        }
        if !self.cma_regions[region as usize].active {
            return None;
        }

        // First try to migrate any in-use pages out of the requested range
        // (simplified: just try to allocate from bitmap)
        let result = self.cma_regions[region as usize].alloc_pages(count);
        if result.is_some() {
            self.total_cma_allocs += 1;
        }
        result
    }

    /// Free CMA allocation
    pub fn cma_free(&mut self, region: u16, pfn: u64, count: u32) -> bool {
        if region as usize >= self.cma_count as usize {
            return false;
        }
        let result = self.cma_regions[region as usize].free_pages(pfn, count);
        if result {
            self.total_cma_frees += 1;
        }
        result
    }

    /// Migrate a specific page to a new location
    pub fn migrate_page(&mut self, src_pfn: u64, dst_pfn: u64) -> bool {
        let src = src_pfn as usize;
        let dst = dst_pfn as usize;

        if src >= MAX_PAGES || dst >= MAX_PAGES {
            return false;
        }
        if !self.pages[src].is_movable() || !self.pages[dst].is_free() {
            return false;
        }

        let saved = self.pages[src];
        self.pages[dst] = saved;
        self.pages[dst].pfn = dst_pfn;

        self.pages[src] = PageInfo::new();
        self.pages[src].pfn = src_pfn;
        self.pages[src].zone = saved.zone;

        extern "C" {
            fn rust_compact_remap_page(pid: u32, vaddr: u64, old_pfn: u64, new_pfn: u64);
        }
        unsafe {
            rust_compact_remap_page(saved.owner_pid, saved.vaddr, src_pfn, dst_pfn);
        }

        self.total_pages_migrated += 1;
        true
    }

    /// NUMA migration: migrate a page to a different node's zone
    pub fn migrate_to_node(&mut self, pfn: u64, target_zone: ZoneType) -> bool {
        let src = pfn as usize;
        if src >= MAX_PAGES || self.pages[src].is_free() {
            return false;
        }

        let zone_idx = target_zone as usize;
        if zone_idx >= self.zone_count as usize {
            return false;
        }

        // Find a free page in the target zone
        let zone = &self.zones[zone_idx];
        for dst_pfn in zone.start_pfn..zone.end_pfn {
            let dst = dst_pfn as usize;
            if dst < MAX_PAGES && self.pages[dst].is_free() {
                return self.migrate_page(pfn, dst_pfn);
            }
        }
        false
    }

    /// Periodic tick: proactive compaction + fragmentation update
    pub fn tick(&mut self, tick_count: u64) {
        // Update fragmentation indices every 10 ticks
        if tick_count % 10 == 0 {
            self.update_frag_indices();
        }

        // Proactive compaction every 50 ticks
        if tick_count % 50 == 0 {
            self.proactive_compact();
        }
    }
}

// ============================================================================
// Global instance
// ============================================================================

static mut COMPACT_MGR: CompactManager = CompactManager::new();

fn mgr() -> &'static mut CompactManager {
    unsafe { &mut COMPACT_MGR }
}

// ============================================================================
// FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_compact_init() {
    let m = mgr();
    *m = CompactManager::new();
}

#[no_mangle]
pub extern "C" fn rust_compact_init_zone(zone_type: u8, start_pfn: u64, end_pfn: u64) {
    let zt: ZoneType = match zone_type {
        0 => ZoneType::Dma,
        1 => ZoneType::Dma32,
        2 => ZoneType::Normal,
        3 => ZoneType::Movable,
        _ => return,
    };
    mgr().init_zone(zt, start_pfn, end_pfn);
}

#[no_mangle]
pub extern "C" fn rust_compact_mark_alloc(pfn: u64, pid: u32, vaddr: u64, movable: u8) {
    mgr().mark_allocated(pfn, pid, vaddr, movable != 0);
}

#[no_mangle]
pub extern "C" fn rust_compact_mark_free(pfn: u64, order: u8) {
    mgr().mark_free(pfn, order);
}

#[no_mangle]
pub extern "C" fn rust_compact_zone(zone: u8, order: u8, mode: u8) -> u8 {
    let m: CompactMode = match mode {
        1 => CompactMode::Async,
        2 => CompactMode::Sync,
        3 => CompactMode::SyncLight,
        4 => CompactMode::Direct,
        _ => CompactMode::Async,
    };
    mgr().compact_zone(zone as usize, order as usize, m) as u8
}

#[no_mangle]
pub extern "C" fn rust_compact_direct(order: u8, zone: u8) -> u8 {
    let zt: ZoneType = match zone {
        0 => ZoneType::Dma,
        1 => ZoneType::Dma32,
        2 => ZoneType::Normal,
        3 => ZoneType::Movable,
        _ => ZoneType::Normal,
    };
    mgr().try_direct_compact(order as usize, zt) as u8
}

#[no_mangle]
pub extern "C" fn rust_compact_proactive() -> u32 {
    mgr().proactive_compact()
}

#[no_mangle]
pub extern "C" fn rust_compact_migrate(src: u64, dst: u64) -> u8 {
    if mgr().migrate_page(src, dst) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn rust_compact_migrate_node(pfn: u64, zone: u8) -> u8 {
    let zt: ZoneType = match zone {
        0 => ZoneType::Dma,
        1 => ZoneType::Dma32,
        2 => ZoneType::Normal,
        3 => ZoneType::Movable,
        _ => ZoneType::Normal,
    };
    if mgr().migrate_to_node(pfn, zt) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn rust_compact_register_cma(base_pfn: u64, count: u32) -> i32 {
    match mgr().register_cma(b"default", base_pfn, count) {
        Some(idx) => idx as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_compact_cma_alloc(region: u16, count: u32) -> i64 {
    match mgr().cma_alloc(region, count) {
        Some(pfn) => pfn as i64,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_compact_cma_free(region: u16, pfn: u64, count: u32) -> u8 {
    if mgr().cma_free(region, pfn, count) { 1 } else { 0 }
}

#[no_mangle]
pub extern "C" fn rust_compact_tick(tick_count: u64) {
    mgr().tick(tick_count);
}

#[no_mangle]
pub extern "C" fn rust_compact_total_migrated() -> u64 {
    mgr().total_pages_migrated
}

#[no_mangle]
pub extern "C" fn rust_compact_total_failed() -> u64 {
    mgr().total_pages_failed
}

#[no_mangle]
pub extern "C" fn rust_compact_total_runs() -> u64 {
    mgr().total_compact_runs
}

#[no_mangle]
pub extern "C" fn rust_compact_total_cma_allocs() -> u64 {
    mgr().total_cma_allocs
}

#[no_mangle]
pub extern "C" fn rust_compact_frag_index(zone: u8, order: u8) -> u32 {
    let z = zone as usize;
    let o = order as usize;
    if z >= MAX_ZONES || o >= MAX_ORDER {
        return 0;
    }
    mgr().zones[z].calc_frag_index(o)
}

#[no_mangle]
pub extern "C" fn rust_compact_set_proactive(enabled: u8, threshold: u32) {
    let m = mgr();
    m.proactive_enabled = enabled != 0;
    if threshold > 0 && threshold <= 1000 {
        m.proactive_threshold = threshold;
    }
}

// =============================================================================
// Zxyphor Kernel — Btrfs B-tree Engine
// =============================================================================
// Core B-tree traversal, search, insertion, deletion, and splitting/merging
// for the Btrfs copy-on-write B-tree. All modifications create new nodes
// (CoW semantics) rather than modifying existing ones.
//
// B-tree Properties:
//   - Variable fanout B-tree (not B+ tree — all nodes carry data)
//   - Leaf nodes: contain items (key + data)
//   - Internal nodes: contain key pointers (key + child block pointer)
//   - Copy-on-Write: modified nodes are written to new locations
//   - Reference counting for shared nodes (snapshots)
//   - Node checksumming for integrity verification
// =============================================================================

#![no_std]
#![allow(dead_code)]

use super::ondisk::*;

/// Maximum number of items in a leaf node
pub const MAX_LEAF_ITEMS: usize = 256;

/// Maximum number of key pointers in an internal node
pub const MAX_NODE_KEYS: usize = 128;

/// B-tree path element — tracks position during tree traversal
#[derive(Clone, Copy)]
pub struct BtrfsPathNode {
    pub bytenr: u64,          // Logical byte number of node
    pub generation: u64,      // Generation of node
    pub slot: u32,            // Current slot index within node
    pub level: u8,            // Level of this node (0 = leaf)
    pub nritems: u32,         // Number of items in this node
    pub dirty: bool,          // Node modified (needs CoW writeback)
}

impl BtrfsPathNode {
    pub const fn empty() -> Self {
        Self {
            bytenr: 0,
            generation: 0,
            slot: 0,
            level: 0,
            nritems: 0,
            dirty: false,
        }
    }
}

/// B-tree path — tracks traversal from root to leaf
pub struct BtrfsPath {
    pub nodes: [BtrfsPathNode; BTRFS_MAX_LEVEL as usize + 1],
    pub depth: u8,
    pub search_for_split: bool,   // Hint: we'll insert after search
    pub search_for_extension: bool,
    pub skip_locking: bool,
    pub keep_locks: bool,
    pub lowest_level: u8,
    pub min_trans: u64,
}

impl BtrfsPath {
    pub fn new() -> Self {
        Self {
            nodes: [BtrfsPathNode::empty(); BTRFS_MAX_LEVEL as usize + 1],
            depth: 0,
            search_for_split: false,
            search_for_extension: false,
            skip_locking: false,
            keep_locks: false,
            lowest_level: 0,
            min_trans: 0,
        }
    }

    pub fn release(&mut self) {
        // Release all held node references/locks
        for node in self.nodes.iter_mut() {
            node.bytenr = 0;
            node.dirty = false;
        }
        self.depth = 0;
    }

    pub fn leaf(&self) -> &BtrfsPathNode {
        &self.nodes[0]
    }

    pub fn leaf_slot(&self) -> u32 {
        self.nodes[0].slot
    }
}

/// Search result
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SearchResult {
    Found,          // Exact key match found
    NotFound,       // Key not found, path points to insertion position
    Error,          // I/O or structural error
}

/// Comparison result for B-tree keys
fn compare_keys(a: &BtrfsKey, b: &BtrfsKey) -> core::cmp::Ordering {
    if a.objectid != b.objectid {
        return a.objectid.cmp(&b.objectid);
    }
    if a.item_type != b.item_type {
        return a.item_type.cmp(&b.item_type);
    }
    a.offset.cmp(&b.offset)
}

/// Binary search within a leaf node for the given key
/// Returns (found, slot) where slot is the position of the key or
/// the position where it should be inserted
pub fn leaf_binary_search(
    keys: &[BtrfsKey],
    nritems: usize,
    target: &BtrfsKey,
) -> (bool, usize) {
    if nritems == 0 {
        return (false, 0);
    }

    let mut low: usize = 0;
    let mut high: usize = nritems;

    while low < high {
        let mid = low + (high - low) / 2;
        match compare_keys(&keys[mid], target) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => return (true, mid),
        }
    }

    (false, low)
}

/// Binary search within an internal node for the child pointer
/// Returns the slot index of the child that could contain the key
pub fn node_binary_search(
    keys: &[BtrfsKey],
    nritems: usize,
    target: &BtrfsKey,
) -> usize {
    if nritems == 0 {
        return 0;
    }

    let mut low: usize = 0;
    let mut high: usize = nritems;

    while low < high {
        let mid = low + (high - low) / 2;
        match compare_keys(&keys[mid], target) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => return mid,
        }
    }

    // Return the slot that precedes the target
    if low > 0 { low - 1 } else { 0 }
}

/// Leaf free space calculation
pub struct LeafSpace {
    pub total_data_size: u32,   // Total data area size in leaf
    pub used_data_size: u32,    // Used data area
    pub nritems: u32,
    pub item_overhead: u32,     // Per-item overhead (key + offset + size)
}

impl LeafSpace {
    pub fn new(nodesize: u32, nritems: u32, data_used: u32) -> Self {
        let header_size = core::mem::size_of::<BtrfsHeader>() as u32;
        let item_size = core::mem::size_of::<BtrfsItem>() as u32;

        Self {
            total_data_size: nodesize - header_size,
            used_data_size: data_used + nritems * item_size,
            nritems,
            item_overhead: item_size,
        }
    }

    pub fn free_space(&self) -> u32 {
        if self.used_data_size >= self.total_data_size {
            return 0;
        }
        self.total_data_size - self.used_data_size
    }

    pub fn can_fit(&self, data_size: u32) -> bool {
        self.free_space() >= data_size + self.item_overhead
    }

    pub fn should_split(&self) -> bool {
        // Split when less than 1/4 of the leaf is free
        self.free_space() < self.total_data_size / 4
    }
}

/// Node split point calculation for balanced splits
pub fn calculate_split_point(
    nritems: u32,
    items_data_sizes: &[u32],
    total_data_size: u32,
) -> u32 {
    // Find the midpoint by data size (not item count) for balanced splits
    let target = total_data_size / 2;
    let mut running = 0u32;
    let mut split_at = nritems / 2; // Default: middle

    for i in 0..nritems as usize {
        running += items_data_sizes[i];
        if running >= target {
            split_at = i as u32;
            break;
        }
    }

    // Ensure at least one item on each side
    if split_at == 0 {
        split_at = 1;
    } else if split_at >= nritems {
        split_at = nritems - 1;
    }

    split_at
}

/// CoW node state tracking
pub struct CowContext {
    pub current_generation: u64,  // Current transaction generation
    pub root_bytenr: u64,        // Root node byte number
    pub root_generation: u64,    // Root generation
    pub root_level: u8,          // Root level
}

impl CowContext {
    pub fn new(gen: u64) -> Self {
        Self {
            current_generation: gen,
            root_bytenr: 0,
            root_generation: 0,
            root_level: 0,
        }
    }

    pub fn needs_cow(&self, node_gen: u64) -> bool {
        // A node needs CoW if its generation is older than the current transaction
        node_gen < self.current_generation
    }
}

/// Transaction handle for B-tree modifications
pub struct BtrfsTransaction {
    pub transid: u64,
    pub num_writers: u32,
    pub state: TransactionState,
    pub start_time_ns: u64,
    pub bytes_allocated: u64,
    pub bytes_freed: u64,
    pub nodes_cowed: u64,
    pub nodes_created: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    Running,
    Blocked,
    Commit,
    CommitDoing,
    Committed,
    Completed,
    Aborted,
}

impl BtrfsTransaction {
    pub fn new(transid: u64) -> Self {
        Self {
            transid,
            num_writers: 0,
            state: TransactionState::Running,
            start_time_ns: 0,
            bytes_allocated: 0,
            bytes_freed: 0,
            nodes_cowed: 0,
            nodes_created: 0,
        }
    }
}

/// Extent buffer — in-memory representation of a B-tree node
pub struct ExtentBuffer {
    pub data: [u8; 16384],     // Node data (up to 16KB nodesize)
    pub bytenr: u64,           // Logical byte number
    pub len: u32,              // Actual size
    pub refs: u32,             // Reference count
    pub flags: u32,
    pub generation: u64,
    pub level: u8,
    pub dirty: bool,
    pub uptodate: bool,
    pub locked: bool,
    pub tree_objectid: u64,
}

impl ExtentBuffer {
    pub fn new() -> Self {
        Self {
            data: [0u8; 16384],
            bytenr: 0,
            len: 0,
            refs: 1,
            flags: 0,
            generation: 0,
            level: 0,
            dirty: false,
            uptodate: false,
            locked: false,
            tree_objectid: 0,
        }
    }

    pub fn header(&self) -> &BtrfsHeader {
        unsafe { &*(self.data.as_ptr() as *const BtrfsHeader) }
    }

    pub fn nritems(&self) -> u32 {
        self.header().nritems
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Get key pointer at slot (for internal nodes)
    pub fn key_ptr(&self, slot: usize) -> Option<&BtrfsKeyPtr> {
        if self.is_leaf() { return None; }
        let header_size = core::mem::size_of::<BtrfsHeader>();
        let kp_size = core::mem::size_of::<BtrfsKeyPtr>();
        let offset = header_size + slot * kp_size;
        if offset + kp_size > self.len as usize { return None; }
        unsafe { Some(&*(self.data.as_ptr().add(offset) as *const BtrfsKeyPtr)) }
    }

    /// Get item at slot (for leaf nodes)
    pub fn item(&self, slot: usize) -> Option<&BtrfsItem> {
        if !self.is_leaf() { return None; }
        let header_size = core::mem::size_of::<BtrfsHeader>();
        let item_size = core::mem::size_of::<BtrfsItem>();
        let offset = header_size + slot * item_size;
        if offset + item_size > self.len as usize { return None; }
        unsafe { Some(&*(self.data.as_ptr().add(offset) as *const BtrfsItem)) }
    }

    /// Get item data for a leaf item
    pub fn item_data(&self, item: &BtrfsItem) -> &[u8] {
        let data_offset = core::mem::size_of::<BtrfsHeader>() + item.offset as usize;
        let end = data_offset + item.size as usize;
        if end > self.len as usize {
            return &[];
        }
        &self.data[data_offset..end]
    }

    pub fn verify_checksum(&self) -> bool {
        let computed = crc32c(&self.data[BTRFS_CSUM_SIZE..self.len as usize]);
        let stored = u32::from_le_bytes([
            self.data[0], self.data[1], self.data[2], self.data[3]
        ]);
        computed == stored
    }

    pub fn compute_and_set_checksum(&mut self) {
        let computed = crc32c(&self.data[BTRFS_CSUM_SIZE..self.len as usize]);
        let bytes = computed.to_le_bytes();
        self.data[0..4].copy_from_slice(&bytes);
    }
}

/// Ordered extent — tracks in-flight writes for data integrity
pub struct OrderedExtent {
    pub inode_objectid: u64,
    pub file_offset: u64,
    pub num_bytes: u64,
    pub disk_bytenr: u64,
    pub disk_num_bytes: u64,
    pub ram_bytes: u64,
    pub compression: u8,
    pub state: OrderedExtentState,
    pub generation: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OrderedExtentState {
    Pending,      // Waiting for IO submission
    IoStarted,    // IO submitted
    IoComplete,   // IO completed, waiting for transaction commit
    Complete,     // Fully committed
    Error,        // IO error
}

/// Delayed reference — batched reference counting for CoW
pub struct DelayedRef {
    pub bytenr: u64,
    pub num_bytes: u64,
    pub ref_mod: i64,     // +1 for add, -1 for drop
    pub parent: u64,
    pub root: u64,
    pub generation: u64,
    pub action: DelayedRefAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DelayedRefAction {
    Add,
    Drop,
    FullBackref,
}

/// Statistics for B-tree operations
pub struct BtreeStats {
    pub searches: u64,
    pub inserts: u64,
    pub deletes: u64,
    pub splits: u64,
    pub merges: u64,
    pub cow_operations: u64,
    pub nodes_read: u64,
    pub nodes_written: u64,
    pub checksum_errors: u64,
}

impl BtreeStats {
    pub const fn new() -> Self {
        Self {
            searches: 0,
            inserts: 0,
            deletes: 0,
            splits: 0,
            merges: 0,
            cow_operations: 0,
            nodes_read: 0,
            nodes_written: 0,
            checksum_errors: 0,
        }
    }
}

static mut BTREE_STATS: BtreeStats = BtreeStats::new();

pub fn get_stats() -> &'static BtreeStats {
    unsafe { &BTREE_STATS }
}

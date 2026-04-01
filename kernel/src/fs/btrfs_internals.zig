// Zxyphor Kernel - Btrfs Filesystem Internals (Zig),
// Superblock, Tree Structures, Item Types,
// Chunk/Device, Extent Tree, Subvolumes/Snapshots,
// Free Space Cache, RAID Profiles, Scrub, Balance,
// Send/Receive, Compression, Deduplication,
// Zoned Mode, RAID56 (Parity), Quotas (qgroups)
//
// SPDX-License-Identifier: GPL-2.0 OR MIT

const std = @import("std");

// ============================================================================
// Btrfs Magic & Constants
// ============================================================================

pub const BTRFS_MAGIC: u64 = 0x4D5F53665248425F;  // "_BHRfS_M"
pub const BTRFS_CSUM_SIZE: u32 = 32;
pub const BTRFS_UUID_SIZE: u32 = 16;
pub const BTRFS_LABEL_SIZE: u32 = 256;
pub const BTRFS_SYSTEM_CHUNK_ARRAY_SIZE: u32 = 2048;
pub const BTRFS_NUM_BACKUP_ROOTS: u32 = 4;
pub const BTRFS_MAX_LEVEL: u32 = 8;
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;
pub const BTRFS_LAST_FREE_OBJECTID: u64 = 0xFFFFFFFFFFFFFF00;

// Well-known object IDs
pub const BtrfsObjectId = enum(u64) {
    root_tree = 1,
    extent_tree = 2,
    chunk_tree = 3,
    dev_tree = 4,
    fs_tree = 5,
    root_tree_dir = 6,
    csum_tree = 7,
    quota_tree = 8,
    uuid_tree = 9,
    free_space_tree = 10,
    block_group_tree = 11,
    raid_stripe_tree = 12,
    // Special
    dev_stats = 0,
    balance_item = 0xFFFFFFFFFFFFFFEC,
    orphan_item = 0xFFFFFFFFFFFFFFFB,
    tree_log = 0xFFFFFFFFFFFFFFFC,
    tree_log_fixup = 0xFFFFFFFFFFFFFFFD,
    tree_reloc = 0xFFFFFFFFFFFFFFFE,
    data_reloc_tree = 0xFFFFFFFFFFFFFFFF,
};

// ============================================================================
// Btrfs Key
// ============================================================================

pub const BtrfsKey = extern struct {
    objectid: u64,
    item_type: u8,
    offset: u64,
};

pub const BtrfsItemType = enum(u8) {
    inode_item = 1,
    inode_ref = 12,
    inode_extref = 13,
    xattr_item = 24,
    verity_desc = 36,
    verity_merkle = 37,
    orphan_item = 48,
    dir_log_item = 60,
    dir_log_index = 72,
    dir_item = 84,
    dir_index = 96,
    extent_data = 108,
    extent_csum = 128,
    root_item = 132,
    root_backref = 144,
    root_ref = 156,
    extent_item = 168,
    metadata_item = 169,
    tree_block_ref = 176,
    extent_data_ref = 178,
    shared_block_ref = 182,
    shared_data_ref = 184,
    block_group_item = 192,
    free_space_info = 198,
    free_space_extent = 199,
    free_space_bitmap = 200,
    dev_extent = 204,
    dev_item = 216,
    chunk_item = 228,
    qgroup_status = 240,
    qgroup_info = 242,
    qgroup_limit = 244,
    qgroup_relation = 246,
    balance_item = 248,
    temp_item = 248,
    dev_stats = 249,
    persistent_item = 249,
    dev_replace = 250,
    uuid_key_subvol = 251,
    uuid_key_recv_subvol = 252,
    string_item = 253,
    raid_stripe = 254,
};

// ============================================================================
// Btrfs Superblock
// ============================================================================

pub const BtrfsSuperblock = extern struct {
    csum: [BTRFS_CSUM_SIZE]u8,
    fsid: [BTRFS_UUID_SIZE]u8,
    bytenr: u64,             // Physical address of this block
    flags: u64,
    magic: u64,              // BTRFS_MAGIC
    generation: u64,
    root: u64,               // Root tree logical address
    chunk_root: u64,
    log_root: u64,
    log_root_transid: u64,
    total_bytes: u64,
    bytes_used: u64,
    root_dir_objectid: u64,
    num_devices: u64,
    sectorsize: u32,
    nodesize: u32,
    leafsize: u32,           // Unused (same as nodesize)
    stripesize: u32,
    sys_chunk_array_size: u32,
    chunk_root_generation: u64,
    compat_flags: u64,
    compat_ro_flags: u64,
    incompat_flags: u64,
    csum_type: u16,
    root_level: u8,
    chunk_root_level: u8,
    log_root_level: u8,
    dev_item: BtrfsDevItem,
    label: [BTRFS_LABEL_SIZE]u8,
    cache_generation: u64,
    uuid_tree_generation: u64,
    metadata_uuid: [BTRFS_UUID_SIZE]u8,
    nr_global_roots: u64,
    _reserved: [27]u64,
    sys_chunk_array: [BTRFS_SYSTEM_CHUNK_ARRAY_SIZE]u8,
    super_roots: [BTRFS_NUM_BACKUP_ROOTS]BtrfsRootBackup,
    padding: [565]u8,
};

// ============================================================================
// Btrfs Incompat Feature Flags
// ============================================================================

pub const BtrfsIncompatFlags = packed struct(u64) {
    mixed_backref: bool = false,
    default_subvol: bool = false,
    mixed_groups: bool = false,
    compress_lzo: bool = false,
    compress_zstd: bool = false,
    big_metadata: bool = false,
    extended_iref: bool = false,
    raid56: bool = false,
    skinny_metadata: bool = false,
    no_holes: bool = false,
    metadata_uuid: bool = false,
    raid1c34: bool = false,
    zoned: bool = false,
    extent_tree_v2: bool = false,
    raid_stripe_tree: bool = false,
    block_group_tree: bool = false,
    _reserved: u48 = 0,
};

// ============================================================================
// Device Item
// ============================================================================

pub const BtrfsDevItem = extern struct {
    devid: u64,
    total_bytes: u64,
    bytes_used: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    type_flags: u64,
    generation: u64,
    start_offset: u64,
    dev_group: u32,
    seek_speed: u8,
    bandwidth: u8,
    uuid: [BTRFS_UUID_SIZE]u8,
    fsid: [BTRFS_UUID_SIZE]u8,
};

// ============================================================================
// Chunk & Stripe
// ============================================================================

pub const BtrfsChunk = extern struct {
    length: u64,
    owner: u64,              // Object ID of the root referencing
    stripe_len: u64,
    chunk_type: u64,
    io_align: u32,
    io_width: u32,
    sector_size: u32,
    num_stripes: u16,
    sub_stripes: u16,
    // Followed by num_stripes × BtrfsStripe
};

pub const BtrfsStripe = extern struct {
    devid: u64,
    offset: u64,
    dev_uuid: [BTRFS_UUID_SIZE]u8,
};

pub const BtrfsChunkTypeFlags = packed struct(u64) {
    data: bool = false,
    system: bool = false,
    metadata: bool = false,
    _reserved1: bool = false,
    raid0: bool = false,
    raid1: bool = false,
    dup: bool = false,
    raid10: bool = false,
    raid5: bool = false,
    raid6: bool = false,
    raid1c3: bool = false,
    raid1c4: bool = false,
    _reserved2: u52 = 0,
};

// ============================================================================
// Btrfs Inode Item
// ============================================================================

pub const BtrfsInodeItem = extern struct {
    generation: u64,
    transid: u64,
    size: u64,
    nbytes: u64,
    block_group: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u64,
    flags: u64,
    sequence: u64,
    _reserved: [4]u64,
    atime: BtrfsTimespec,
    ctime: BtrfsTimespec,
    mtime: BtrfsTimespec,
    otime: BtrfsTimespec,
};

pub const BtrfsTimespec = extern struct {
    sec: u64,
    nsec: u32,
};

pub const BtrfsInodeFlags = packed struct(u64) {
    nodatasum: bool = false,
    nodatacow: bool = false,
    readonly: bool = false,
    nocompress: bool = false,
    prealloc: bool = false,
    sync: bool = false,
    immutable: bool = false,
    append: bool = false,
    nodump: bool = false,
    noatime: bool = false,
    dirsync: bool = false,
    compress: bool = false,
    _reserved: u52 = 0,
};

// ============================================================================
// File Extent Item
// ============================================================================

pub const BtrfsFileExtentItem = extern struct {
    generation: u64,
    ram_bytes: u64,           // Uncompressed size
    compression: u8,
    encryption: u8,
    other_encoding: u16,
    extent_type: u8,
    // For regular extents:
    disk_bytenr: u64,        // Physical location
    disk_num_bytes: u64,      // On-disk size (compressed)
    offset: u64,              // Offset within extent
    num_bytes: u64,           // Logical size
};

pub const BtrfsExtentType = enum(u8) {
    inline_extent = 0,
    regular = 1,
    prealloc = 2,
};

pub const BtrfsCompress = enum(u8) {
    none = 0,
    zlib = 1,
    lzo = 2,
    zstd = 3,
};

// ============================================================================
// Block Group Item
// ============================================================================

pub const BtrfsBlockGroupItem = extern struct {
    used: u64,
    chunk_objectid: u64,
    flags: u64,
};

// ============================================================================
// Root Item (Subvolume)
// ============================================================================

pub const BtrfsRootItem = extern struct {
    inode: BtrfsInodeItem,
    generation: u64,
    root_dirid: u64,
    bytenr: u64,
    byte_limit: u64,
    bytes_used: u64,
    last_snapshot: u64,
    flags: u64,
    refs: u32,
    drop_progress: BtrfsKey,
    drop_level: u8,
    level: u8,
    generation_v2: u64,
    uuid: [BTRFS_UUID_SIZE]u8,
    parent_uuid: [BTRFS_UUID_SIZE]u8,
    received_uuid: [BTRFS_UUID_SIZE]u8,
    ctransid: u64,
    otransid: u64,
    stransid: u64,
    rtransid: u64,
    ctime: BtrfsTimespec,
    otime: BtrfsTimespec,
    stime: BtrfsTimespec,
    rtime: BtrfsTimespec,
    _reserved: [8]u64,
};

pub const BtrfsRootBackup = extern struct {
    tree_root: u64,
    tree_root_gen: u64,
    chunk_root: u64,
    chunk_root_gen: u64,
    extent_root: u64,
    extent_root_gen: u64,
    fs_root: u64,
    fs_root_gen: u64,
    dev_root: u64,
    dev_root_gen: u64,
    csum_root: u64,
    csum_root_gen: u64,
    total_bytes: u64,
    bytes_used: u64,
    num_devices: u64,
    _unused: [4]u64,
    tree_root_level: u8,
    chunk_root_level: u8,
    extent_root_level: u8,
    fs_root_level: u8,
    dev_root_level: u8,
    csum_root_level: u8,
    _padding: [10]u8,
};

// ============================================================================
// Btrfs RAID Profiles
// ============================================================================

pub const BtrfsRaidProfile = enum(u8) {
    single = 0,
    dup = 1,
    raid0 = 2,
    raid1 = 3,
    raid10 = 4,
    raid5 = 5,
    raid6 = 6,
    raid1c3 = 7,
    raid1c4 = 8,
};

pub const BtrfsRaidInfo = struct {
    profile: BtrfsRaidProfile,
    min_devices: u8,
    max_tolerable_failures: u8,
    data_copies: u8,
    parity_stripes: u8,
    stripe_unit: u32,
};

pub const RAID_PROFILES = [_]BtrfsRaidInfo{
    .{ .profile = .single, .min_devices = 1, .max_tolerable_failures = 0, .data_copies = 1, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .dup, .min_devices = 1, .max_tolerable_failures = 0, .data_copies = 2, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .raid0, .min_devices = 1, .max_tolerable_failures = 0, .data_copies = 1, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .raid1, .min_devices = 2, .max_tolerable_failures = 1, .data_copies = 2, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .raid10, .min_devices = 4, .max_tolerable_failures = 1, .data_copies = 2, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .raid5, .min_devices = 2, .max_tolerable_failures = 1, .data_copies = 1, .parity_stripes = 1, .stripe_unit = 65536 },
    .{ .profile = .raid6, .min_devices = 3, .max_tolerable_failures = 2, .data_copies = 1, .parity_stripes = 2, .stripe_unit = 65536 },
    .{ .profile = .raid1c3, .min_devices = 3, .max_tolerable_failures = 2, .data_copies = 3, .parity_stripes = 0, .stripe_unit = 65536 },
    .{ .profile = .raid1c4, .min_devices = 4, .max_tolerable_failures = 3, .data_copies = 4, .parity_stripes = 0, .stripe_unit = 65536 },
};

// ============================================================================
// Btrfs Qgroups (Quota Groups)
// ============================================================================

pub const BtrfsQgroupStatus = extern struct {
    version: u64,
    generation: u64,
    flags: u64,
    rescan: u64,
    enable_gen: u64,
};

pub const BtrfsQgroupInfo = extern struct {
    generation: u64,
    rfer: u64,              // Referenced bytes
    rfer_cmpr: u64,         // Referenced compressed
    excl: u64,              // Exclusive bytes
    excl_cmpr: u64,         // Exclusive compressed
};

pub const BtrfsQgroupLimit = extern struct {
    flags: u64,
    max_rfer: u64,
    max_excl: u64,
    rsv_rfer: u64,
    rsv_excl: u64,
};

pub const BtrfsQgroupLimitFlags = packed struct(u64) {
    max_rfer: bool = false,
    max_excl: bool = false,
    rsv_rfer: bool = false,
    rsv_excl: bool = false,
    _reserved: u60 = 0,
};

// ============================================================================
// Btrfs Balance
// ============================================================================

pub const BtrfsBalanceArgs = struct {
    profiles: u64,          // RAID profile bitmask
    usage_min: u64,
    usage_max: u64,
    devid: u64,
    pstart: u64,            // Physical start
    pend: u64,              // Physical end
    vstart: u64,            // Virtual start
    vend: u64,              // Virtual end
    target: u64,            // Target RAID profile
    flags: u64,
    limit_min: u64,
    limit_max: u64,
    stripes_min: u32,
    stripes_max: u32,
};

pub const BtrfsBalanceState = enum(u8) {
    idle = 0,
    running = 1,
    paused = 2,
    cancel_req = 3,
    completed = 4,
    error_state = 5,
};

pub const BtrfsBalanceProgress = struct {
    state: BtrfsBalanceState,
    expected: u64,
    considered: u64,
    completed_chunks: u64,
};

// ============================================================================
// Btrfs Scrub
// ============================================================================

pub const BtrfsScrubProgress = struct {
    data_extents_scrubbed: u64,
    tree_extents_scrubbed: u64,
    data_bytes_scrubbed: u64,
    tree_bytes_scrubbed: u64,
    read_errors: u64,
    csum_errors: u64,
    verify_errors: u64,
    no_csum: u64,
    csum_discards: u64,
    super_errors: u64,
    malloc_errors: u64,
    uncorrectable_errors: u64,
    corrected_errors: u64,
    last_physical: u64,
    unverified_errors: u64,
};

// ============================================================================
// Btrfs Send/Receive
// ============================================================================

pub const BtrfsSendCmd = enum(u16) {
    unspec = 0,
    subvol = 1,
    snapshot = 2,
    mkfile = 3,
    mkdir = 4,
    mknod = 5,
    mkfifo = 6,
    mksock = 7,
    symlink = 8,
    rename = 9,
    link = 10,
    unlink = 11,
    rmdir = 12,
    set_xattr = 13,
    remove_xattr = 14,
    write = 15,
    clone = 16,
    truncate = 17,
    chmod = 18,
    chown = 19,
    utimes = 20,
    end_cmd = 21,
    update_extent = 22,
    encoded_write = 23,
    enable_verity = 24,
    fallocate = 25,
    fileattr = 26,
};

// ============================================================================
// Btrfs Csum Types
// ============================================================================

pub const BtrfsCsumType = enum(u16) {
    crc32c = 0,
    xxhash = 1,
    sha256 = 2,
    blake2b = 3,
};

// ============================================================================
// Btrfs Zoned Mode
// ============================================================================

pub const BtrfsZonedMode = enum(u8) {
    disabled = 0,
    host_managed = 1,
    host_aware = 2,
};

pub const BtrfsZoneInfo = struct {
    zone_size: u64,
    nr_zones: u32,
    max_active_zones: u32,
    max_open_zones: u32,
    zoned_mode: BtrfsZonedMode,
};

// ============================================================================
// Btrfs Filesystem Manager (Zxyphor)
// ============================================================================

pub const BtrfsFsManager = struct {
    nr_mounted: u32,
    nr_devices: u16,
    nr_subvolumes: u32,
    total_bytes: u64,
    bytes_used: u64,
    metadata_ratio: u8,      // % of space for metadata
    data_profile: BtrfsRaidProfile,
    metadata_profile: BtrfsRaidProfile,
    system_profile: BtrfsRaidProfile,
    csum_type: BtrfsCsumType,
    zoned: BtrfsZonedMode,
    compression: BtrfsCompress,
    balance_progress: BtrfsBalanceProgress,
    scrub_progress: BtrfsScrubProgress,
    qgroups_enabled: bool,
    free_space_tree: bool,
    block_group_tree: bool,
    raid_stripe_tree: bool,
    initialized: bool,

    pub fn init() BtrfsFsManager {
        return .{
            .nr_mounted = 0,
            .nr_devices = 0,
            .nr_subvolumes = 0,
            .total_bytes = 0,
            .bytes_used = 0,
            .metadata_ratio = 10,
            .data_profile = .single,
            .metadata_profile = .dup,
            .system_profile = .dup,
            .csum_type = .crc32c,
            .zoned = .disabled,
            .compression = .none,
            .balance_progress = std.mem.zeroes(BtrfsBalanceProgress),
            .scrub_progress = std.mem.zeroes(BtrfsScrubProgress),
            .qgroups_enabled = false,
            .free_space_tree = true,
            .block_group_tree = false,
            .raid_stripe_tree = false,
            .initialized = true,
        };
    }
};

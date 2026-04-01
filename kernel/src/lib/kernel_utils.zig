// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - lib utilities: printf/snprintf, sort algorithms,
// kfifo, notifier chains, kobject lifecycle, refcount, kref,
// completion, wait_event, bitmap ops, string utilities
// More advanced than Linux 2026 kernel library

const std = @import("std");

// ============================================================================
// Printf Format Specifiers & Kernel Print
// ============================================================================

pub const PrintLevel = enum(u8) {
    emerg = 0,     // KERN_EMERG
    alert = 1,     // KERN_ALERT
    crit = 2,      // KERN_CRIT
    err = 3,       // KERN_ERR
    warning = 4,   // KERN_WARNING
    notice = 5,    // KERN_NOTICE
    info = 6,      // KERN_INFO
    debug = 7,     // KERN_DEBUG
    // Zxyphor
    trace = 8,     // KERN_TRACE
    verbose = 9,   // KERN_VERBOSE
};

pub const FmtSpec = struct {
    // Flags
    left_justify: bool,
    sign: bool,
    space: bool,
    hash: bool,
    zero_pad: bool,
    // Width & precision
    width: i32,
    precision: i32,
    // Length modifier
    length: FmtLength,
    // Conversion
    specifier: FmtSpecifier,
};

pub const FmtLength = enum(u8) {
    none = 0,
    hh = 1,        // char
    h = 2,         // short
    l = 3,         // long
    ll = 4,        // long long
    z = 5,         // size_t
    t = 6,         // ptrdiff_t
    L = 7,         // long double
};

pub const FmtSpecifier = enum(u8) {
    d = 'd',       // Signed decimal
    i = 'i',       // Signed decimal
    u = 'u',       // Unsigned decimal
    o = 'o',       // Octal
    x = 'x',       // Lowercase hex
    X = 'X',       // Uppercase hex
    c = 'c',       // Character
    s = 's',       // String
    p = 'p',       // Pointer
    n = 'n',       // Characters written (disabled for safety)
    percent = '%',
    // Kernel extensions
    pS = 'S',      // Symbolic name + offset
    pB = 'B',      // Buffer as hex
    pI = 'I',      // IP address
    pM = 'M',      // MAC address
    pU = 'U',      // UUID
    pE = 'E',      // Escaped string
    pN = 'N',      // NUMA bitmask
};

// Log buffer Ring buffer entry
pub const LogEntry = struct {
    timestamp_ns: u64,
    level: PrintLevel,
    facility: u16,
    // Message
    msg_offset: u32,
    msg_len: u16,
    // Dict (structured data)
    dict_offset: u32,
    dict_len: u16,
    // Source
    caller_addr: u64,
    cpu: u16,
    // Sequence
    seq: u64,
};

pub const LOG_BUF_SIZE: u32 = 1 << 18;  // 256 KB default
pub const LOG_LINE_MAX: u32 = 1024;

// ============================================================================
// Sort Algorithms
// ============================================================================

pub const SortAlgorithm = enum(u8) {
    insertion = 0,
    heapsort = 1,        // Kernel default (in-place, O(1) extra)
    introsort = 2,       // Hybrid (quicksort + heapsort + insertion)
    timsort = 3,
    radix = 4,
    // Zxyphor
    zxy_adaptive = 10,
};

pub const SortConfig = struct {
    algorithm: SortAlgorithm,
    element_size: usize,
    // For small arrays
    insertion_threshold: u32,
    // For radix sort
    radix_bits: u8,
    // Stability
    stable: bool,
};

// ============================================================================
// kfifo (Kernel FIFO)
// ============================================================================

pub const KfifoFlags = packed struct(u32) {
    initialized: bool = false,
    locked: bool = false,
    // Zxyphor
    zxy_lockless: bool = false,
    _reserved: u29 = 0,
};

pub const Kfifo = struct {
    // Buffer
    buffer_addr: u64,
    buffer_size: u32,       // Must be power of 2
    mask: u32,              // buffer_size - 1
    // Indices (lockless single producer/single consumer)
    in_idx: u32,            // Write index
    out_idx: u32,           // Read index
    // Element size
    esize: u32,
    // Flags
    flags: KfifoFlags,
    // Stats
    total_put: u64,
    total_get: u64,
    overflow_count: u64,
    underflow_count: u64,

    pub fn len(self: *const Kfifo) u32 {
        return self.in_idx - self.out_idx;
    }

    pub fn is_empty(self: *const Kfifo) bool {
        return self.in_idx == self.out_idx;
    }

    pub fn is_full(self: *const Kfifo) bool {
        return self.len() >= self.buffer_size;
    }

    pub fn avail(self: *const Kfifo) u32 {
        return self.buffer_size - self.len();
    }
};

// ============================================================================
// Notifier Chains
// ============================================================================

pub const NotifierPriority = enum(i32) {
    first = 0x7FFFFFFF,
    high = 1000,
    default = 0,
    low = -1000,
    last = -0x7FFFFFFF,
};

pub const NotifierAction = enum(u32) {
    done = 0x0000,
    ok = 0x0001,
    bad = 0x0002,
    stop = 0x8000,
    // Combined
    stop_ok = 0x8001,
    stop_bad = 0x8002,
};

pub const NotifierBlock = struct {
    // Callback
    callback_fn: u64,       // Function pointer
    // Priority
    priority: i32,
    // Chain linkage
    next: ?*NotifierBlock,
};

pub const NotifierChainType = enum(u8) {
    atomic = 0,            // Called in atomic/IRQ context
    blocking = 1,          // May sleep
    raw = 2,               // No locking
    srcu = 3,              // SRCU-protected
};

pub const NotifierChain = struct {
    chain_type: NotifierChainType,
    head: ?*NotifierBlock,
    nr_blocks: u32,
    // Stats
    total_calls: u64,
    total_stops: u64,
};

// Well-known notifier chains
pub const NotifierEvent = enum(u32) {
    // CPU
    cpu_up_prepare = 0x0001,
    cpu_up_canceled = 0x0002,
    cpu_online = 0x0003,
    cpu_down_prepare = 0x0004,
    cpu_down_failed = 0x0005,
    cpu_dead = 0x0006,
    cpu_dying = 0x0007,
    cpu_starting = 0x0008,
    // Memory
    memory_going_online = 0x0100,
    memory_cancel_online = 0x0101,
    memory_online = 0x0102,
    memory_going_offline = 0x0103,
    memory_cancel_offline = 0x0104,
    memory_offline = 0x0105,
    // Reboot
    sys_restart = 0x0200,
    sys_halt = 0x0201,
    sys_power_off = 0x0202,
    // Netdev
    netdev_up = 0x0300,
    netdev_going_down = 0x0301,
    netdev_down = 0x0302,
    netdev_register = 0x0303,
    netdev_unregister = 0x0304,
    netdev_change = 0x0305,
    netdev_changename = 0x0306,
    netdev_feat_change = 0x0307,
    // PM
    pm_hibernation_prepare = 0x0400,
    pm_post_hibernation = 0x0401,
    pm_suspend_prepare = 0x0402,
    pm_post_suspend = 0x0403,
    pm_restore_prepare = 0x0404,
    pm_post_restore = 0x0405,
    // Panic
    panic_notifier = 0x0500,
    die_notifier = 0x0501,
    // Module
    module_load = 0x0600,
    module_free = 0x0601,
    // USB
    usb_device_add = 0x0700,
    usb_device_remove = 0x0701,
    // Keyboard
    keyboard_keycode = 0x0800,
    keyboard_unbound = 0x0801,
    keyboard_unicode = 0x0802,
    _,
};

// ============================================================================
// Reference Counting
// ============================================================================

pub const RefcountState = enum(u8) {
    normal = 0,
    saturated = 1,
    dead = 2,
};

pub const Refcount = struct {
    count: i32,

    pub fn read(self: *const Refcount) i32 {
        return self.count;
    }

    pub fn is_zero(self: *const Refcount) bool {
        return self.count == 0;
    }
};

pub const Kref = struct {
    refcount: Refcount,
};

// ============================================================================
// Completion
// ============================================================================

pub const Completion = struct {
    done: u32,
    // Wait queue embedded
    wait_head: u64,         // Wait queue head pointer
};

// ============================================================================
// Bitmap Operations
// ============================================================================

pub const BITS_PER_LONG: u32 = 64;

pub const BitmapOp = enum(u8) {
    set = 0,
    clear = 1,
    test = 2,
    test_and_set = 3,
    test_and_clear = 4,
    find_first_bit = 5,
    find_first_zero = 6,
    find_next_bit = 7,
    find_next_zero = 8,
    find_last_bit = 9,
    popcount = 10,
    and_op = 11,
    or_op = 12,
    xor_op = 13,
    not_op = 14,
    andnot = 15,
    equal = 16,
    subset = 17,
    intersects = 18,
    shift_right = 19,
    shift_left = 20,
};

// ============================================================================
// String Utilities
// ============================================================================

pub const StringOp = enum(u8) {
    copy = 0,           // strlcpy
    cat = 1,            // strlcat
    cmp = 2,            // strcmp
    ncmp = 3,           // strncmp
    casecmp = 4,        // strcasecmp
    chr = 5,            // strchr
    rchr = 6,           // strrchr
    str = 7,            // strstr
    nstr = 8,           // strnstr
    len = 9,            // strlen
    nlen = 10,          // strnlen
    sep = 11,           // strsep
    dup = 12,           // kstrdup
    ndup = 13,          // kstrndup
    to_upper = 14,
    to_lower = 15,
    trim = 16,          // strim
    skip_spaces = 17,
    // Conversion
    to_ul = 20,         // kstrtoul
    to_l = 21,          // kstrtol
    to_u64 = 22,        // kstrtou64
    to_s64 = 23,        // kstrtos64
    to_uint = 24,       // kstrtouint
    to_int = 25,        // kstrtoint
    to_bool = 26,       // kstrtobool
    // Memory
    memcpy = 30,
    memmove = 31,
    memset = 32,
    memcmp = 33,
    memchr = 34,
    memscan = 35,
};

// ============================================================================
// IDR (ID Radix Tree) / IDA (ID Allocator)
// ============================================================================

pub const IdrConfig = struct {
    min_id: u32,
    max_id: u32,
    // Pre-allocation
    preload_count: u32,
    // Stats
    total_allocated: u64,
    total_freed: u64,
    current_count: u32,
    max_count: u32,
};

pub const IdaConfig = struct {
    min_id: u32,
    max_id: u32,
    // Bitmap-based allocation for dense ranges
    bitmap_count: u32,
    // Stats
    total_allocated: u64,
    total_freed: u64,
    current_count: u32,
};

// ============================================================================
// Error Codes (errno)
// ============================================================================

pub const Errno = enum(i32) {
    SUCCESS = 0,
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    EDEADLK = 35,
    ENAMETOOLONG = 36,
    ENOLCK = 37,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENOMSG = 42,
    EIDRM = 43,
    ENOSTR = 60,
    ENODATA = 61,
    ETIME = 62,
    ENOSR = 63,
    ENONET = 64,
    EPROTO = 71,
    EBADMSG = 74,
    EOVERFLOW = 75,
    EILSEQ = 84,
    EUSERS = 87,
    ENOTSOCK = 88,
    EDESTADDRREQ = 89,
    EMSGSIZE = 90,
    EPROTOTYPE = 91,
    ENOPROTOOPT = 92,
    EPROTONOSUPPORT = 93,
    ESOCKTNOSUPPORT = 94,
    EOPNOTSUPP = 95,
    EPFNOSUPPORT = 96,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    ENETDOWN = 100,
    ENETUNREACH = 101,
    ENETRESET = 102,
    ECONNABORTED = 103,
    ECONNRESET = 104,
    ENOBUFS = 105,
    EISCONN = 106,
    ENOTCONN = 107,
    ESHUTDOWN = 108,
    ETOOMANYREFS = 109,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EHOSTDOWN = 112,
    EHOSTUNREACH = 113,
    EALREADY = 114,
    EINPROGRESS = 115,
    ESTALE = 116,
    EDQUOT = 122,
    ENOMEDIUM = 123,
    EMEDIUMTYPE = 124,
    ECANCELED = 125,
    ENOKEY = 126,
    EKEYEXPIRED = 127,
    EKEYREVOKED = 128,
    EKEYREJECTED = 129,
    EOWNERDEAD = 130,
    ENOTRECOVERABLE = 131,
    ERFKILL = 132,
    EHWPOISON = 133,
    // Zxyphor extensions
    EZXYPERM = 512,
    EZXYQUOTA = 513,
    EZXYCRYPTO = 514,
    _,

    pub fn is_error(self: Errno) bool {
        return @intFromEnum(self) != 0;
    }

    pub fn name(self: Errno) []const u8 {
        return switch (self) {
            .SUCCESS => "Success",
            .EPERM => "Operation not permitted",
            .ENOENT => "No such file or directory",
            .ESRCH => "No such process",
            .EINTR => "Interrupted system call",
            .EIO => "I/O error",
            .ENOMEM => "Out of memory",
            .EACCES => "Permission denied",
            .EFAULT => "Bad address",
            .EBUSY => "Device or resource busy",
            .EEXIST => "File exists",
            .ENODEV => "No such device",
            .EINVAL => "Invalid argument",
            .ENOSPC => "No space left on device",
            .ENOSYS => "Function not implemented",
            .ETIMEDOUT => "Connection timed out",
            .ECONNREFUSED => "Connection refused",
            else => "Unknown error",
        };
    }
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const KernelLibSubsystem = struct {
    // Print
    print_level: PrintLevel,
    console_loglevel: u8,
    default_message_loglevel: u8,
    minimum_console_loglevel: u8,
    log_buf_size: u32,
    log_seq: u64,
    // Sort
    default_sort: SortAlgorithm,
    // Notifiers
    nr_notifier_chains: u32,
    total_notifier_calls: u64,
    // kfifo
    nr_active_fifos: u32,
    // IDR/IDA
    nr_active_idrs: u32,
    nr_active_idas: u32,
    // Stats
    total_printk_calls: u64,
    total_sort_calls: u64,
    total_string_ops: u64,
    total_bitmap_ops: u64,
    total_refcount_saturations: u64,
    // Zxyphor
    zxy_structured_logging: bool,
    initialized: bool,
};

// =============================================================================
// Kernel Zxyphor - Device File System (devfs)
// =============================================================================
// Provides a /dev directory with device nodes that map to kernel drivers.
// Each device node (e.g., /dev/null, /dev/zero, /dev/random, /dev/console,
// /dev/tty, /dev/sda) is a VNode with special read/write operations that
// route to the appropriate device driver.
//
// Device types:
//   - Character devices: byte-oriented (serial ports, terminals, /dev/null)
//   - Block devices: block-oriented (disks, partitions)
//
// Following the Unix tradition, "everything is a file."
// =============================================================================

const main = @import("../main.zig");
const vfs = main.vfs;

// =============================================================================
// Constants
// =============================================================================
pub const MAX_DEVICES: usize = 256;

// Well-known device major numbers
pub const DEV_MEM: u16 = 1; // /dev/null, /dev/zero, /dev/full, /dev/random
pub const DEV_TTY: u16 = 4; // /dev/tty*
pub const DEV_CONSOLE: u16 = 5; // /dev/console
pub const DEV_SERIAL: u16 = 6; // /dev/ttyS*
pub const DEV_DISK: u16 = 8; // /dev/sd*
pub const DEV_RTC: u16 = 10; // /dev/rtc

// Minor numbers for mem devices
pub const MINOR_NULL: u16 = 3;
pub const MINOR_ZERO: u16 = 5;
pub const MINOR_FULL: u16 = 7;
pub const MINOR_RANDOM: u16 = 8;
pub const MINOR_URANDOM: u16 = 9;
pub const MINOR_KMSG: u16 = 11;

// =============================================================================
// Device registration
// =============================================================================
pub const DeviceDriver = struct {
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    major: u16 = 0,
    dev_type: vfs.FileType = .char_device,

    read: ?*const fn (minor: u16, buffer: []u8, offset: u64) vfs.VfsError!usize = null,
    write: ?*const fn (minor: u16, data: []const u8, offset: u64) vfs.VfsError!usize = null,
    ioctl: ?*const fn (minor: u16, cmd: u32, arg: u64) vfs.VfsError!i64 = null,

    is_registered: bool = false,
};

var device_drivers: [MAX_DEVICES]DeviceDriver = undefined;
var dev_root: ?*vfs.VNode = null;
var devfs_initialized: bool = false;

// =============================================================================
// devfs operations table
// =============================================================================
const devfs_ops = vfs.VNodeOps{
    .read = devfsRead,
    .write = devfsWrite,
    .lookup = devfsLookup,
    .readdir = devfsReaddir,
    .getattr = devfsGetattr,
    .ioctl = devfsIoctl,
};

// =============================================================================
// Initialize devfs
// =============================================================================
pub fn initialize() void {
    for (&device_drivers) |*d| {
        d.* = DeviceDriver{};
    }

    // Create /dev directory
    dev_root = vfs.mkdir("/dev", 0o755) catch null;
    if (dev_root) |root| {
        root.ops = &devfs_ops;
    }

    // Register built-in pseudo-devices
    registerMemDevices();
    registerConsoleDevice();

    devfs_initialized = true;
    main.klog(.info, "devfs: initialized at /dev", .{});
}

// =============================================================================
// Register a device driver
// =============================================================================
pub fn registerDriver(driver: DeviceDriver) bool {
    for (&device_drivers) |*d| {
        if (!d.is_registered) {
            d.* = driver;
            d.is_registered = true;
            return true;
        }
    }
    return false;
}

// =============================================================================
// Create a device node in /dev
// =============================================================================
pub fn createNode(name: []const u8, major: u16, minor: u16, dev_type: vfs.FileType) ?*vfs.VNode {
    const root = dev_root orelse return null;

    const node = vfs.allocVNode() orelse return null;
    node.file_type = dev_type;
    node.mode = if (dev_type == .char_device) 0o666 else 0o660;
    node.dev_major = major;
    node.dev_minor = minor;
    node.setName(name);
    node.ops = &devfs_ops;
    root.addChild(node);

    return node;
}

// =============================================================================
// Find driver for a device node
// =============================================================================
fn findDriver(major: u16) ?*DeviceDriver {
    for (&device_drivers) |*d| {
        if (d.is_registered and d.major == major) {
            return d;
        }
    }
    return null;
}

// =============================================================================
// devfs VNode operations
// =============================================================================

fn devfsRead(node: *vfs.VNode, buffer: []u8, offset: u64) vfs.VfsError!usize {
    if (findDriver(node.dev_major)) |driver| {
        if (driver.read) |read_fn| {
            return read_fn(node.dev_minor, buffer, offset);
        }
    }
    return vfs.VfsError.NotSupported;
}

fn devfsWrite(node: *vfs.VNode, data: []const u8, offset: u64) vfs.VfsError!usize {
    if (findDriver(node.dev_major)) |driver| {
        if (driver.write) |write_fn| {
            return write_fn(node.dev_minor, data, offset);
        }
    }
    return vfs.VfsError.NotSupported;
}

fn devfsLookup(dir: *vfs.VNode, name: []const u8) vfs.VfsError!*vfs.VNode {
    return dir.findChild(name) orelse return vfs.VfsError.NotFound;
}

fn devfsReaddir(dir: *vfs.VNode, buffer: []vfs.DirEntry, offset: *u64) vfs.VfsError!usize {
    _ = offset;
    var count: usize = 0;
    var child = dir.children_head;

    while (child) |c| {
        if (count >= buffer.len) break;
        buffer[count].inode = c.inode;
        buffer[count].file_type = c.file_type;
        const name = c.getName();
        const len = @min(name.len, vfs.MAX_FILENAME_LEN);
        @memcpy(buffer[count].name[0..len], name[0..len]);
        buffer[count].name_len = @truncate(len);
        count += 1;
        child = c.sibling_next;
    }

    return count;
}

fn devfsGetattr(node: *vfs.VNode) vfs.VfsError!vfs.VNodeAttr {
    return vfs.VNodeAttr{
        .file_type = node.file_type,
        .mode = node.mode,
        .uid = node.uid,
        .gid = node.gid,
        .size = node.size,
        .dev_major = node.dev_major,
        .dev_minor = node.dev_minor,
    };
}

fn devfsIoctl(node: *vfs.VNode, cmd: u32, arg: u64) vfs.VfsError!i64 {
    if (findDriver(node.dev_major)) |driver| {
        if (driver.ioctl) |ioctl_fn| {
            return ioctl_fn(node.dev_minor, cmd, arg);
        }
    }
    return vfs.VfsError.NotSupported;
}

// =============================================================================
// Built-in pseudo-device drivers
// =============================================================================

fn registerMemDevices() void {
    var mem_driver = DeviceDriver{};
    const name = "mem";
    @memcpy(mem_driver.name[0..name.len], name);
    mem_driver.name_len = name.len;
    mem_driver.major = DEV_MEM;
    mem_driver.dev_type = .char_device;
    mem_driver.read = memDeviceRead;
    mem_driver.write = memDeviceWrite;
    _ = registerDriver(mem_driver);

    // Create device nodes
    _ = createNode("null", DEV_MEM, MINOR_NULL, .char_device);
    _ = createNode("zero", DEV_MEM, MINOR_ZERO, .char_device);
    _ = createNode("full", DEV_MEM, MINOR_FULL, .char_device);
    _ = createNode("random", DEV_MEM, MINOR_RANDOM, .char_device);
    _ = createNode("urandom", DEV_MEM, MINOR_URANDOM, .char_device);
}

fn memDeviceRead(minor: u16, buffer: []u8, _: u64) vfs.VfsError!usize {
    switch (minor) {
        MINOR_NULL => {
            return 0; // /dev/null: always returns EOF
        },
        MINOR_ZERO => {
            // /dev/zero: fills with zeros
            @memset(buffer, 0);
            return buffer.len;
        },
        MINOR_FULL => {
            // /dev/full: fills with zeros (write returns ENOSPC)
            @memset(buffer, 0);
            return buffer.len;
        },
        MINOR_RANDOM, MINOR_URANDOM => {
            // /dev/random: pseudo-random data (simple PRNG)
            fillRandom(buffer);
            return buffer.len;
        },
        else => return vfs.VfsError.NotSupported,
    }
}

fn memDeviceWrite(minor: u16, data: []const u8, _: u64) vfs.VfsError!usize {
    switch (minor) {
        MINOR_NULL => {
            return data.len; // /dev/null: discards everything
        },
        MINOR_ZERO => {
            return data.len; // /dev/zero: accepts writes silently
        },
        MINOR_FULL => {
            return vfs.VfsError.NoSpace; // /dev/full: always full
        },
        MINOR_RANDOM, MINOR_URANDOM => {
            // Writing to /dev/random adds entropy (we just accept it)
            return data.len;
        },
        else => return vfs.VfsError.NotSupported,
    }
}

fn registerConsoleDevice() void {
    var con_driver = DeviceDriver{};
    const name = "console";
    @memcpy(con_driver.name[0..name.len], name);
    con_driver.name_len = name.len;
    con_driver.major = DEV_CONSOLE;
    con_driver.dev_type = .char_device;
    con_driver.read = consoleRead;
    con_driver.write = consoleWrite;
    _ = registerDriver(con_driver);

    _ = createNode("console", DEV_CONSOLE, 0, .char_device);
    _ = createNode("tty", DEV_TTY, 0, .char_device);
}

fn consoleRead(_: u16, buffer: []u8, _: u64) vfs.VfsError!usize {
    // Read from keyboard
    if (buffer.len > 0) {
        if (main.keyboard.readChar()) |ch| {
            buffer[0] = ch;
            return 1;
        }
    }
    return 0;
}

fn consoleWrite(_: u16, data: []const u8, _: u64) vfs.VfsError!usize {
    // Write to VGA console
    for (data) |ch| {
        main.vga.writeChar(ch);
    }
    return data.len;
}

// =============================================================================
// Simple PRNG for /dev/random
// =============================================================================
var prng_state: u64 = 0x853c49e6748fea9b; // Seed

fn fillRandom(buffer: []u8) void {
    for (buffer) |*b| {
        // xorshift64
        prng_state ^= prng_state << 13;
        prng_state ^= prng_state >> 7;
        prng_state ^= prng_state << 17;
        b.* = @truncate(prng_state);
    }
}

/// Get the /dev root node
pub fn getRoot() ?*vfs.VNode {
    return dev_root;
}

// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Kobject / Kernel Object Model
//
// Implements a reference-counted kernel object hierarchy inspired by Linux's
// kobject/kset system. Every device, driver, and bus in the kernel is
// represented as a kobject, enabling sysfs-style visibility, hotplug
// notifications, and automatic lifetime management.

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");
const list = @import("../lib/list.zig");
const string = @import("../lib/string.zig");

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────
pub const KOBJECT_NAME_MAX: usize = 128;
pub const KOBJ_ATTR_NAME_MAX: usize = 64;
pub const KOBJ_MAX_CHILDREN: usize = 256;
pub const KOBJ_UEVENT_BUFFER_SIZE: usize = 2048;

// ─────────────────────────────────────────────────────────────────────
// Uevent actions — sent to userspace on kobject state changes
// ─────────────────────────────────────────────────────────────────────
pub const UeventAction = enum {
    add,
    remove,
    change,
    move,
    online,
    offline,
    bind,
    unbind,

    pub fn toString(self: UeventAction) []const u8 {
        return switch (self) {
            .add => "add",
            .remove => "remove",
            .change => "change",
            .move => "move",
            .online => "online",
            .offline => "offline",
            .bind => "bind",
            .unbind => "unbind",
        };
    }
};

// ─────────────────────────────────────────────────────────────────────
// KobjType — type descriptor for a class of kobjects
// ─────────────────────────────────────────────────────────────────────
pub const KobjType = struct {
    /// Human-readable type name (e.g. "device", "driver", "bus")
    name: [KOBJ_ATTR_NAME_MAX]u8,
    name_len: u8,

    /// Called when the last reference is dropped (destructor)
    release: ?*const fn (kobj: *Kobject) void,

    /// Default attribute list for sysfs representation
    default_attrs: ?*const KobjAttribute,
    default_attr_count: u16,

    /// Called to generate the sysfs group path
    sysfs_ops: ?*const SysfsOps,

    /// Uevent filter — return false to suppress uevent delivery
    uevent_filter: ?*const fn (kobj: *Kobject, action: UeventAction) bool,

    /// Custom uevent environment variables
    uevent_env: ?*const fn (kobj: *Kobject, env: *UeventEnv) void,

    pub fn init(name: []const u8) KobjType {
        var ktype = KobjType{
            .name = [_]u8{0} ** KOBJ_ATTR_NAME_MAX,
            .name_len = 0,
            .release = null,
            .default_attrs = null,
            .default_attr_count = 0,
            .sysfs_ops = null,
            .uevent_filter = null,
            .uevent_env = null,
        };
        const len = @min(name.len, KOBJ_ATTR_NAME_MAX);
        @memcpy(ktype.name[0..len], name[0..len]);
        ktype.name_len = @intCast(len);
        return ktype;
    }
};

// ─────────────────────────────────────────────────────────────────────
// SysfsOps — operations for reading/writing sysfs attributes
// ─────────────────────────────────────────────────────────────────────
pub const SysfsOps = struct {
    show: ?*const fn (kobj: *Kobject, attr: *const KobjAttribute, buf: []u8) isize,
    store: ?*const fn (kobj: *Kobject, attr: *const KobjAttribute, buf: []const u8) isize,
};

// ─────────────────────────────────────────────────────────────────────
// KobjAttribute — a single attribute exposed via sysfs
// ─────────────────────────────────────────────────────────────────────
pub const KobjAttribute = struct {
    name: [KOBJ_ATTR_NAME_MAX]u8,
    name_len: u8,
    mode: u16, // File permissions (e.g. 0o444 for read-only)
    show: ?*const fn (kobj: *Kobject, buf: []u8) isize,
    store: ?*const fn (kobj: *Kobject, buf: []const u8) isize,

    pub fn init(name: []const u8, mode: u16) KobjAttribute {
        var attr = KobjAttribute{
            .name = [_]u8{0} ** KOBJ_ATTR_NAME_MAX,
            .name_len = 0,
            .mode = mode,
            .show = null,
            .store = null,
        };
        const len = @min(name.len, KOBJ_ATTR_NAME_MAX);
        @memcpy(attr.name[0..len], name[0..len]);
        attr.name_len = @intCast(len);
        return attr;
    }

    pub fn getName(self: *const KobjAttribute) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn isReadable(self: *const KobjAttribute) bool {
        return (self.mode & 0o444) != 0;
    }

    pub fn isWritable(self: *const KobjAttribute) bool {
        return (self.mode & 0o222) != 0;
    }
};

// ─────────────────────────────────────────────────────────────────────
// UeventEnv — environment builder for uevent notifications
// ─────────────────────────────────────────────────────────────────────
pub const UeventEnv = struct {
    buffer: [KOBJ_UEVENT_BUFFER_SIZE]u8,
    offset: usize,
    env_count: u16,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .buffer = [_]u8{0} ** KOBJ_UEVENT_BUFFER_SIZE,
            .offset = 0,
            .env_count = 0,
        };
    }

    /// Append a KEY=VALUE pair to the uevent environment
    pub fn addVar(self: *Self, key: []const u8, value: []const u8) bool {
        const needed = key.len + 1 + value.len + 1; // KEY=VALUE\0
        if (self.offset + needed >= KOBJ_UEVENT_BUFFER_SIZE) {
            return false;
        }

        @memcpy(self.buffer[self.offset .. self.offset + key.len], key);
        self.offset += key.len;
        self.buffer[self.offset] = '=';
        self.offset += 1;
        @memcpy(self.buffer[self.offset .. self.offset + value.len], value);
        self.offset += value.len;
        self.buffer[self.offset] = 0;
        self.offset += 1;
        self.env_count += 1;

        return true;
    }

    /// Append an integer value
    pub fn addVarInt(self: *Self, key: []const u8, value: u64) bool {
        var num_buf: [20]u8 = undefined;
        const num_str = formatU64(value, &num_buf);
        return self.addVar(key, num_str);
    }

    pub fn getData(self: *Self) []const u8 {
        return self.buffer[0..self.offset];
    }
};

fn formatU64(val: u64, buf: *[20]u8) []const u8 {
    if (val == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var v = val;
    var pos: usize = 20;
    while (v > 0) {
        pos -= 1;
        buf[pos] = @intCast((v % 10) + '0');
        v /= 10;
    }
    return buf[pos..20];
}

// ─────────────────────────────────────────────────────────────────────
// Kobject — the core kernel object structure
// ─────────────────────────────────────────────────────────────────────
pub const Kobject = struct {
    /// Object name (visible in sysfs)
    name: [KOBJECT_NAME_MAX]u8,
    name_len: u8,

    /// Reference count — object is freed when this reaches zero
    ref_count: u32,

    /// Parent kobject (forms the hierarchy tree)
    parent: ?*Kobject,

    /// Type descriptor
    ktype: ?*const KobjType,

    /// Kset this object belongs to (if any)
    kset: ?*Kset,

    /// Children list (forms a tree structure)
    children: [KOBJ_MAX_CHILDREN]?*Kobject,
    child_count: u16,

    /// State flags
    state_initialized: bool,
    state_in_sysfs: bool,
    state_add_uevent_sent: bool,
    state_remove_uevent_sent: bool,

    /// Lock protecting this kobject's state
    lock: spinlock.SpinLock,

    /// Private data pointer — set by the owner
    priv_data: ?*anyopaque,

    /// Unique ID assigned at registration time
    unique_id: u64,

    const Self = @This();

    pub fn init(name: []const u8, ktype: ?*const KobjType) Self {
        var kobj = Self{
            .name = [_]u8{0} ** KOBJECT_NAME_MAX,
            .name_len = 0,
            .ref_count = 1,
            .parent = null,
            .ktype = ktype,
            .kset = null,
            .children = [_]?*Kobject{null} ** KOBJ_MAX_CHILDREN,
            .child_count = 0,
            .state_initialized = true,
            .state_in_sysfs = false,
            .state_add_uevent_sent = false,
            .state_remove_uevent_sent = false,
            .lock = spinlock.SpinLock{},
            .priv_data = null,
            .unique_id = 0,
        };
        const len = @min(name.len, KOBJECT_NAME_MAX);
        @memcpy(kobj.name[0..len], name[0..len]);
        kobj.name_len = @intCast(len);
        return kobj;
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Rename this kobject. Sends a "move" uevent notification.
    pub fn rename(self: *Self, new_name: []const u8) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (new_name.len == 0 or new_name.len > KOBJECT_NAME_MAX) {
            return false;
        }

        @memset(&self.name, 0);
        const len = @min(new_name.len, KOBJECT_NAME_MAX);
        @memcpy(self.name[0..len], new_name[0..len]);
        self.name_len = @intCast(len);

        return true;
    }

    /// Add this kobject to the hierarchy (creates sysfs entry)
    pub fn add(self: *Self, parent: ?*Kobject) bool {
        if (!self.state_initialized) return false;

        self.lock.acquire();
        defer self.lock.release();

        self.parent = parent;

        // If we have a parent, add ourselves as a child
        if (parent) |p| {
            p.lock.acquire();
            defer p.lock.release();

            if (p.child_count >= KOBJ_MAX_CHILDREN) {
                return false;
            }

            // Find a free slot
            for (&p.children) |*slot| {
                if (slot.* == null) {
                    slot.* = self;
                    p.child_count += 1;
                    break;
                }
            }

            // Take a reference on the parent
            p.ref_count += 1;
        }

        // If this kobject belongs to a kset, register with it
        if (self.kset) |kset| {
            _ = kset.addKobject(self);
        }

        self.state_in_sysfs = true;

        return true;
    }

    /// Remove this kobject from the hierarchy (removes sysfs entry)
    pub fn del(self: *Self) void {
        self.lock.acquire();

        if (!self.state_in_sysfs) {
            self.lock.release();
            return;
        }

        self.state_in_sysfs = false;

        // Detach from parent
        if (self.parent) |parent| {
            parent.lock.acquire();
            for (&parent.children) |*slot| {
                if (slot.* == self) {
                    slot.* = null;
                    parent.child_count -= 1;
                    break;
                }
            }
            parent.lock.release();

            // Release reference on parent
            self.parent = null;
        }

        // Remove from kset
        if (self.kset) |kset| {
            kset.removeKobject(self);
        }

        self.lock.release();
    }

    /// Increment the reference count
    pub fn get(self: *Self) *Self {
        _ = @atomicRmw(u32, &self.ref_count, .Add, 1, .seq_cst);
        return self;
    }

    /// Decrement the reference count. If it reaches zero, the type's
    /// release function is called to clean up the object.
    pub fn put(self: *Self) void {
        const old = @atomicRmw(u32, &self.ref_count, .Sub, 1, .seq_cst);
        if (old == 1) {
            // Last reference dropped — invoke destructor
            if (self.ktype) |ktype| {
                if (ktype.release) |release_fn| {
                    release_fn(self);
                }
            }
        }
    }

    /// Send a uevent notification for this kobject
    pub fn uevent(self: *Self, action: UeventAction) void {
        // Check uevent filter
        if (self.ktype) |ktype| {
            if (ktype.uevent_filter) |filter| {
                if (!filter(self, action)) return;
            }
        }

        // Build uevent environment
        var env = UeventEnv.init();
        _ = env.addVar("ACTION", action.toString());
        _ = env.addVar("DEVPATH", self.getName());
        _ = env.addVarInt("SEQNUM", self.unique_id);

        // Add subsystem name
        if (self.kset) |kset| {
            _ = env.addVar("SUBSYSTEM", kset.kobj.getName());
        }

        // Allow type-specific environment additions
        if (self.ktype) |ktype| {
            if (ktype.uevent_env) |env_fn| {
                env_fn(self, &env);
            }
        }

        // Deliver to registered uevent listeners
        deliverUevent(self, action, &env);

        // Update state
        switch (action) {
            .add => self.state_add_uevent_sent = true,
            .remove => self.state_remove_uevent_sent = true,
            else => {},
        }
    }

    /// Build the full path from root to this kobject
    pub fn getPath(self: *const Self, buf: []u8) usize {
        // Walk up the tree to count levels
        var depth: usize = 0;
        var ancestors: [32]*const Kobject = undefined;
        var current: ?*const Kobject = self;

        while (current) |kobj| {
            if (depth >= 32) break;
            ancestors[depth] = kobj;
            depth += 1;
            current = kobj.parent;
        }

        // Build path from root to leaf
        var offset: usize = 0;
        if (offset < buf.len) {
            buf[offset] = '/';
            offset += 1;
        }

        var i: usize = depth;
        while (i > 0) {
            i -= 1;
            const name = ancestors[i].getName();
            if (offset + name.len + 1 >= buf.len) break;
            @memcpy(buf[offset .. offset + name.len], name);
            offset += name.len;
            if (i > 0) {
                buf[offset] = '/';
                offset += 1;
            }
        }

        return offset;
    }

    /// Find a child kobject by name (linear scan)
    pub fn findChild(self: *Self, name: []const u8) ?*Kobject {
        self.lock.acquire();
        defer self.lock.release();

        for (self.children) |child_opt| {
            if (child_opt) |child| {
                if (std.mem.eql(u8, child.getName(), name)) {
                    return child;
                }
            }
        }
        return null;
    }

    /// Count the total number of descendants (recursive)
    pub fn countDescendants(self: *Self) u64 {
        var count: u64 = 0;
        for (self.children) |child_opt| {
            if (child_opt) |child| {
                count += 1 + child.countDescendants();
            }
        }
        return count;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Kset — a collection of kobjects of the same type
// ─────────────────────────────────────────────────────────────────────
pub const Kset = struct {
    /// The kset's own kobject representation
    kobj: Kobject,

    /// Registered members
    members: [KSET_MAX_MEMBERS]?*Kobject,
    member_count: u16,

    /// Lock
    lock: spinlock.SpinLock,

    /// Uevent filter for the entire kset
    uevent_ops: ?*const KsetUeventOps,

    const KSET_MAX_MEMBERS: usize = 512;

    const Self = @This();

    pub fn init(name: []const u8, ktype: ?*const KobjType) Self {
        return Self{
            .kobj = Kobject.init(name, ktype),
            .members = [_]?*Kobject{null} ** KSET_MAX_MEMBERS,
            .member_count = 0,
            .lock = spinlock.SpinLock{},
            .uevent_ops = null,
        };
    }

    /// Add a kobject to this kset
    pub fn addKobject(self: *Self, kobj: *Kobject) bool {
        self.lock.acquire();
        defer self.lock.release();

        if (self.member_count >= KSET_MAX_MEMBERS) {
            return false;
        }

        for (&self.members) |*slot| {
            if (slot.* == null) {
                slot.* = kobj;
                self.member_count += 1;
                kobj.kset = self;
                return true;
            }
        }

        return false;
    }

    /// Remove a kobject from this kset
    pub fn removeKobject(self: *Self, kobj: *Kobject) void {
        self.lock.acquire();
        defer self.lock.release();

        for (&self.members) |*slot| {
            if (slot.* == kobj) {
                slot.* = null;
                self.member_count -= 1;
                kobj.kset = null;
                return;
            }
        }
    }

    /// Find a member by name
    pub fn findMember(self: *Self, name: []const u8) ?*Kobject {
        self.lock.acquire();
        defer self.lock.release();

        for (self.members) |member_opt| {
            if (member_opt) |member| {
                if (std.mem.eql(u8, member.getName(), name)) {
                    return member;
                }
            }
        }
        return null;
    }

    /// Iterate over all members, calling a callback for each
    pub fn forEach(self: *Self, callback: *const fn (*Kobject) void) void {
        self.lock.acquire();
        defer self.lock.release();

        for (self.members) |member_opt| {
            if (member_opt) |member| {
                callback(member);
            }
        }
    }

    /// Get the kset's kobject for hierarchy integration
    pub fn getKobj(self: *Self) *Kobject {
        return &self.kobj;
    }
};

// ─────────────────────────────────────────────────────────────────────
// KsetUeventOps — kset-level uevent operations
// ─────────────────────────────────────────────────────────────────────
pub const KsetUeventOps = struct {
    filter: ?*const fn (kobj: *Kobject) bool,
    name: ?*const fn (kobj: *Kobject) []const u8,
    uevent: ?*const fn (kobj: *Kobject, env: *UeventEnv) void,
};

// ─────────────────────────────────────────────────────────────────────
// Device Model — high-level device representation built on kobjects
// ─────────────────────────────────────────────────────────────────────
pub const Bus = struct {
    name: [KOBJECT_NAME_MAX]u8,
    name_len: u8,
    kset: Kset,
    drivers_kset: Kset,
    devices_kset: Kset,

    /// Match function: determines if a driver can handle a device
    match_fn: ?*const fn (dev: *Device, drv: *Driver) bool,
    /// Probe function: called when a driver is bound to a device
    probe: ?*const fn (dev: *Device) i32,
    /// Remove function: called when a driver is unbound
    remove_fn: ?*const fn (dev: *Device) void,
    /// Shutdown function: called during system shutdown
    shutdown: ?*const fn (dev: *Device) void,

    /// PM (Power Management) operations
    pm_ops: ?*const BusPmOps,

    const Self = @This();

    pub fn init(name: []const u8) Self {
        var bus = Self{
            .name = [_]u8{0} ** KOBJECT_NAME_MAX,
            .name_len = 0,
            .kset = Kset.init(name, null),
            .drivers_kset = Kset.init("drivers", null),
            .devices_kset = Kset.init("devices", null),
            .match_fn = null,
            .probe = null,
            .remove_fn = null,
            .shutdown = null,
            .pm_ops = null,
        };
        const len = @min(name.len, KOBJECT_NAME_MAX);
        @memcpy(bus.name[0..len], name[0..len]);
        bus.name_len = @intCast(len);
        return bus;
    }

    pub fn getName(self: *const Self) []const u8 {
        return self.name[0..self.name_len];
    }

    /// Register a device on this bus
    pub fn registerDevice(self: *Self, dev: *Device) bool {
        dev.bus = self;
        return self.devices_kset.addKobject(&dev.kobj);
    }

    /// Register a driver on this bus
    pub fn registerDriver(self: *Self, drv: *Driver) bool {
        drv.bus = self;
        return self.drivers_kset.addKobject(&drv.kobj);
    }

    /// Attempt to match and probe all unbound devices against a new driver
    pub fn probeDriver(self: *Self, drv: *Driver) u32 {
        var bound: u32 = 0;
        for (self.devices_kset.members) |dev_opt| {
            if (dev_opt) |kobj| {
                const dev = @fieldParentPtr(Device, "kobj", kobj);
                if (dev.driver != null) continue; // Already bound

                if (self.match_fn) |match| {
                    if (match(dev, drv)) {
                        dev.driver = drv;
                        if (self.probe) |probe_fn| {
                            const result = probe_fn(dev);
                            if (result == 0) {
                                bound += 1;
                                dev.kobj.uevent(.bind);
                            } else {
                                dev.driver = null;
                            }
                        } else {
                            bound += 1;
                        }
                    }
                }
            }
        }
        return bound;
    }
};

pub const BusPmOps = struct {
    suspend_fn: ?*const fn (dev: *Device) i32,
    resume_fn: ?*const fn (dev: *Device) i32,
    freeze: ?*const fn (dev: *Device) i32,
    thaw: ?*const fn (dev: *Device) i32,
    poweroff: ?*const fn (dev: *Device) i32,
    restore: ?*const fn (dev: *Device) i32,
    runtime_suspend: ?*const fn (dev: *Device) i32,
    runtime_resume: ?*const fn (dev: *Device) i32,
    runtime_idle: ?*const fn (dev: *Device) i32,
};

// ─────────────────────────────────────────────────────────────────────
// Device
// ─────────────────────────────────────────────────────────────────────
pub const DeviceType = enum {
    platform,
    pci,
    usb,
    block,
    char,
    network,
    input,
    sound,
    gpu,
    virtual,
};

pub const Device = struct {
    kobj: Kobject,
    device_type: DeviceType,
    bus: ?*Bus,
    driver: ?*Driver,
    parent: ?*Device,
    device_id: u64,

    /// Power state
    power_state: PowerState,

    /// DMA mask — indicates addressable DMA range
    dma_mask: u64,
    coherent_dma_mask: u64,

    /// Device-specific operations
    dev_ops: ?*const DeviceOps,

    /// List of resources (I/O ports, memory regions, IRQs)
    resources: [MAX_DEVICE_RESOURCES]Resource,
    resource_count: u8,

    /// Private driver data
    driver_data: ?*anyopaque,

    /// Device state flags
    is_registered: bool,
    is_dead: bool,
    is_virtual: bool,

    const MAX_DEVICE_RESOURCES = 16;

    const Self = @This();

    pub fn init(name: []const u8, dtype: DeviceType) Self {
        return Self{
            .kobj = Kobject.init(name, null),
            .device_type = dtype,
            .bus = null,
            .driver = null,
            .parent = null,
            .device_id = 0,
            .power_state = .on,
            .dma_mask = 0xFFFFFFFF,
            .coherent_dma_mask = 0xFFFFFFFF,
            .dev_ops = null,
            .resources = [_]Resource{Resource{}} ** MAX_DEVICE_RESOURCES,
            .resource_count = 0,
            .driver_data = null,
            .is_registered = false,
            .is_dead = false,
            .is_virtual = false,
        };
    }

    /// Register this device with its bus and send an "add" uevent
    pub fn register(self: *Self) bool {
        if (self.is_registered) return false;

        if (self.bus) |bus| {
            if (!bus.registerDevice(self)) return false;
        }

        self.is_registered = true;
        self.kobj.uevent(.add);
        return true;
    }

    /// Unregister this device
    pub fn unregister(self: *Self) void {
        if (!self.is_registered) return;

        self.kobj.uevent(.remove);
        self.kobj.del();
        self.is_registered = false;
        self.is_dead = true;
    }

    /// Add a resource to this device
    pub fn addResource(self: *Self, res: Resource) bool {
        if (self.resource_count >= MAX_DEVICE_RESOURCES) return false;
        self.resources[self.resource_count] = res;
        self.resource_count += 1;
        return true;
    }

    /// Find a resource by type
    pub fn findResource(self: *const Self, rtype: ResourceType) ?*const Resource {
        for (self.resources[0..self.resource_count]) |*res| {
            if (res.rtype == rtype) return res;
        }
        return null;
    }
};

pub const PowerState = enum {
    on,
    standby,
    suspend,
    hibernate,
    off,
};

pub const ResourceType = enum {
    mmio,
    pio,
    irq,
    dma,
    bus_number,
};

pub const Resource = struct {
    start: u64 = 0,
    end: u64 = 0,
    rtype: ResourceType = .mmio,
    flags: u32 = 0,
    name: [32]u8 = [_]u8{0} ** 32,
};

pub const DeviceOps = struct {
    open: ?*const fn (dev: *Device) i32,
    close: ?*const fn (dev: *Device) i32,
    read: ?*const fn (dev: *Device, buf: [*]u8, len: usize, offset: u64) isize,
    write: ?*const fn (dev: *Device, buf: [*]const u8, len: usize, offset: u64) isize,
    ioctl: ?*const fn (dev: *Device, cmd: u32, arg: u64) i32,
    mmap: ?*const fn (dev: *Device, vaddr: usize, size: usize) i32,
};

// ─────────────────────────────────────────────────────────────────────
// Driver
// ─────────────────────────────────────────────────────────────────────
pub const Driver = struct {
    kobj: Kobject,
    bus: ?*Bus,

    /// Probe: called when a matching device is found
    probe: ?*const fn (dev: *Device) i32,
    /// Remove: called when the driver is unbound from a device
    remove_fn: ?*const fn (dev: *Device) void,
    /// Shutdown: called during system shutdown
    shutdown: ?*const fn (dev: *Device) void,
    /// Suspend: called for power management
    suspend_fn: ?*const fn (dev: *Device) i32,
    /// Resume: called to wake up from suspend
    resume_fn: ?*const fn (dev: *Device) i32,

    /// Module that owns this driver (for reference counting)
    owner_module: ?*anyopaque,

    /// Devices currently bound to this driver
    bound_devices: [MAX_BOUND_DEVICES]?*Device,
    bound_count: u16,

    const MAX_BOUND_DEVICES: usize = 128;

    const Self = @This();

    pub fn init(name: []const u8) Self {
        return Self{
            .kobj = Kobject.init(name, null),
            .bus = null,
            .probe = null,
            .remove_fn = null,
            .shutdown = null,
            .suspend_fn = null,
            .resume_fn = null,
            .owner_module = null,
            .bound_devices = [_]?*Device{null} ** MAX_BOUND_DEVICES,
            .bound_count = 0,
        };
    }

    /// Register this driver with its bus and attempt to bind devices
    pub fn register(self: *Self) bool {
        if (self.bus) |bus| {
            if (!bus.registerDriver(self)) return false;
            _ = bus.probeDriver(self);
        }
        return true;
    }

    /// Unregister this driver, unbinding all devices first
    pub fn unregister(self: *Self) void {
        // Unbind all devices
        for (&self.bound_devices) |*slot| {
            if (slot.*) |dev| {
                if (self.remove_fn) |remove| {
                    remove(dev);
                }
                dev.driver = null;
                dev.kobj.uevent(.unbind);
                slot.* = null;
                self.bound_count -= 1;
            }
        }

        self.kobj.del();
    }
};

// ─────────────────────────────────────────────────────────────────────
// Class — groups devices sharing a common interface
// ─────────────────────────────────────────────────────────────────────
pub const Class = struct {
    name: [KOBJECT_NAME_MAX]u8,
    name_len: u8,
    kset: Kset,

    /// Called when a device is added to this class
    dev_uevent: ?*const fn (dev: *Device, env: *UeventEnv) void,
    /// Called to release devices owned by this class
    dev_release: ?*const fn (dev: *Device) void,

    /// Class-level attributes visible in sysfs
    class_attrs: [16]?*const KobjAttribute,
    class_attr_count: u8,

    const Self = @This();

    pub fn init(name: []const u8) Self {
        var cls = Self{
            .name = [_]u8{0} ** KOBJECT_NAME_MAX,
            .name_len = 0,
            .kset = Kset.init(name, null),
            .dev_uevent = null,
            .dev_release = null,
            .class_attrs = [_]?*const KobjAttribute{null} ** 16,
            .class_attr_count = 0,
        };
        const len = @min(name.len, KOBJECT_NAME_MAX);
        @memcpy(cls.name[0..len], name[0..len]);
        cls.name_len = @intCast(len);
        return cls;
    }

    pub fn addDevice(self: *Self, dev: *Device) bool {
        return self.kset.addKobject(&dev.kobj);
    }

    pub fn removeDevice(self: *Self, dev: *Device) void {
        self.kset.removeKobject(&dev.kobj);
    }

    pub fn addAttribute(self: *Self, attr: *const KobjAttribute) bool {
        if (self.class_attr_count >= 16) return false;
        self.class_attrs[self.class_attr_count] = attr;
        self.class_attr_count += 1;
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────
// Uevent delivery infrastructure
// ─────────────────────────────────────────────────────────────────────
const MAX_UEVENT_LISTENERS: usize = 32;

pub const UeventListener = struct {
    callback: *const fn (kobj: *Kobject, action: UeventAction, env: *UeventEnv) void,
    filter_subsystem: ?[KOBJ_ATTR_NAME_MAX]u8,
    active: bool,
};

var uevent_listeners: [MAX_UEVENT_LISTENERS]UeventListener = undefined;
var uevent_listener_count: u8 = 0;
var uevent_lock: spinlock.SpinLock = spinlock.SpinLock{};
var uevent_seqnum: u64 = 0;

/// Register a uevent listener
pub fn registerUeventListener(
    callback: *const fn (*Kobject, UeventAction, *UeventEnv) void,
) bool {
    uevent_lock.acquire();
    defer uevent_lock.release();

    if (uevent_listener_count >= MAX_UEVENT_LISTENERS) return false;

    uevent_listeners[uevent_listener_count] = UeventListener{
        .callback = callback,
        .filter_subsystem = null,
        .active = true,
    };
    uevent_listener_count += 1;
    return true;
}

/// Deliver a uevent to all registered listeners
fn deliverUevent(kobj: *Kobject, action: UeventAction, env: *UeventEnv) void {
    uevent_lock.acquire();
    defer uevent_lock.release();

    uevent_seqnum += 1;
    kobj.unique_id = uevent_seqnum;

    var i: u8 = 0;
    while (i < uevent_listener_count) : (i += 1) {
        const listener = &uevent_listeners[i];
        if (listener.active) {
            listener.callback(kobj, action, env);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Global Bus Registration
// ─────────────────────────────────────────────────────────────────────
const MAX_BUSES: usize = 32;
var registered_buses: [MAX_BUSES]?*Bus = [_]?*Bus{null} ** MAX_BUSES;
var bus_count: u8 = 0;

pub fn registerBus(bus: *Bus) bool {
    if (bus_count >= MAX_BUSES) return false;
    registered_buses[bus_count] = bus;
    bus_count += 1;
    return true;
}

pub fn findBus(name: []const u8) ?*Bus {
    for (registered_buses[0..bus_count]) |bus_opt| {
        if (bus_opt) |bus| {
            if (std.mem.eql(u8, bus.getName(), name)) {
                return bus;
            }
        }
    }
    return null;
}

// ─────────────────────────────────────────────────────────────────────
// Initialization
// ─────────────────────────────────────────────────────────────────────
pub fn init() void {
    // Initialize the uevent listener array
    for (&uevent_listeners) |*listener| {
        listener.* = UeventListener{
            .callback = undefined,
            .filter_subsystem = null,
            .active = false,
        };
    }
    uevent_listener_count = 0;
    uevent_seqnum = 0;
    bus_count = 0;
}

// =============================================================================
// Kernel Zxyphor — Rust sysfs Virtual Filesystem
// =============================================================================
// Linux sysfs-inspired virtual filesystem exposing kernel objects:
//   - Kobject hierarchy (bus/device/driver/class/module/firmware)
//   - Attribute files (show/store callbacks)
//   - Attribute groups
//   - Symlink support (e.g. device → driver)
//   - Uevent generation for hotplug
//   - Binary attributes (firmware blobs)
//   - Per-CPU, per-node topology views
//   - Power state attributes
//   - Device class subsystem enumeration
// =============================================================================

/// Maximum nodes in sysfs tree
const MAX_SYSFS_NODES: usize = 1024;
/// Maximum attributes per node
const MAX_ATTRS_PER_NODE: usize = 32;
/// Maximum children per node
const MAX_CHILDREN: usize = 64;
/// Maximum attribute value length
const MAX_ATTR_VALUE: usize = 256;
/// Maximum path length
const MAX_PATH: usize = 256;
/// Maximum symlinks
const MAX_SYMLINKS: usize = 128;
/// Maximum uevent queue
const MAX_UEVENTS: usize = 64;

// ---------------------------------------------------------------------------
// Kobject type
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum KobjType {
    Root       = 0,
    Bus        = 1,
    Device     = 2,
    Driver     = 3,
    Class      = 4,
    Module     = 5,
    Firmware   = 6,
    Block      = 7,
    Power      = 8,
    Cpu        = 9,
    Memory     = 10,
    Node       = 11,
    Platform   = 12,
    Subsystem  = 13,
}

// ---------------------------------------------------------------------------
// Attribute mode (permissions)
// ---------------------------------------------------------------------------

#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AttrMode {
    ReadOnly    = 0o444,
    ReadWrite   = 0o644,
    WriteOnly   = 0o200,
    RootOnly    = 0o600,
    WorldRead   = 0o444,
    OwnerWrite  = 0o644,
}

// ---------------------------------------------------------------------------
// Attribute type
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum AttrType {
    String   = 0,
    Integer  = 1,
    Unsigned = 2,
    Boolean  = 3,
    Hex      = 4,
    Binary   = 5,
    Enum     = 6,
}

// ---------------------------------------------------------------------------
// Sysfs Attribute
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SysfsAttr {
    pub name: [u8; 64],
    pub name_len: u8,
    pub attr_type: AttrType,
    pub mode: AttrMode,
    pub value: [u8; MAX_ATTR_VALUE],
    pub value_len: u16,
    pub int_value: i64,
    pub active: bool,
}

impl SysfsAttr {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            attr_type: AttrType::String,
            mode: AttrMode::ReadOnly,
            value: [0u8; MAX_ATTR_VALUE],
            value_len: 0,
            int_value: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_string(&mut self, v: &[u8]) {
        let len = if v.len() > MAX_ATTR_VALUE { MAX_ATTR_VALUE } else { v.len() };
        self.value[..len].copy_from_slice(&v[..len]);
        self.value_len = len as u16;
        self.attr_type = AttrType::String;
    }

    pub fn set_int(&mut self, v: i64) {
        self.int_value = v;
        self.attr_type = AttrType::Integer;
        // Format into value buffer
        let mut buf = [0u8; 24];
        let len = format_i64(v, &mut buf);
        self.value[..len].copy_from_slice(&buf[..len]);
        self.value_len = len as u16;
    }

    pub fn set_bool(&mut self, v: bool) {
        self.int_value = if v { 1 } else { 0 };
        self.attr_type = AttrType::Boolean;
        if v {
            self.value[0] = b'1';
        } else {
            self.value[0] = b'0';
        }
        self.value_len = 1;
    }

    pub fn name_matches(&self, n: &[u8]) -> bool {
        if n.len() != self.name_len as usize { return false; }
        for i in 0..self.name_len as usize {
            if self.name[i] != n[i] { return false; }
        }
        true
    }
}

/// Format i64 to decimal ASCII
fn format_i64(mut val: i64, buf: &mut [u8; 24]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let negative = val < 0;
    if negative { val = -val; }
    let mut pos = 23usize;
    while val > 0 {
        buf[pos] = b'0' + (val % 10) as u8;
        val /= 10;
        if pos == 0 { break; }
        pos -= 1;
    }
    if negative {
        buf[pos] = b'-';
    } else {
        pos += 1;
    }
    let len = 24 - pos;
    // Shift to beginning
    let mut i = 0;
    while i < len {
        buf[i] = buf[pos + i];
        i += 1;
    }
    len
}

// ---------------------------------------------------------------------------
// Sysfs Node (kobject directory)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SysfsNode {
    pub id: u32,
    pub kobj_type: KobjType,
    pub name: [u8; 64],
    pub name_len: u8,
    pub parent_id: u32,      // 0 = root
    pub attrs: [SysfsAttr; MAX_ATTRS_PER_NODE],
    pub attr_count: u8,
    pub children: [u32; MAX_CHILDREN],
    pub child_count: u8,
    pub active: bool,
    pub uevent_seq: u32,
}

impl SysfsNode {
    pub const fn new() -> Self {
        Self {
            id: 0,
            kobj_type: KobjType::Root,
            name: [0u8; 64],
            name_len: 0,
            parent_id: 0,
            attrs: [const { SysfsAttr::new() }; MAX_ATTRS_PER_NODE],
            attr_count: 0,
            children: [0u32; MAX_CHILDREN],
            child_count: 0,
            active: false,
            uevent_seq: 0,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn name_matches(&self, n: &[u8]) -> bool {
        if n.len() != self.name_len as usize { return false; }
        for i in 0..self.name_len as usize {
            if self.name[i] != n[i] { return false; }
        }
        true
    }

    /// Add attribute to this node
    pub fn add_attr(&mut self, name: &[u8], attr_type: AttrType, mode: AttrMode) -> Option<usize> {
        if self.attr_count as usize >= MAX_ATTRS_PER_NODE { return None; }
        let idx = self.attr_count as usize;
        self.attrs[idx] = SysfsAttr::new();
        self.attrs[idx].set_name(name);
        self.attrs[idx].attr_type = attr_type;
        self.attrs[idx].mode = mode;
        self.attrs[idx].active = true;
        self.attr_count += 1;
        Some(idx)
    }

    /// Find attribute by name
    pub fn find_attr(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.attr_count as usize {
            if self.attrs[i].active && self.attrs[i].name_matches(name) {
                return Some(i);
            }
        }
        None
    }

    /// Add child node ID
    pub fn add_child(&mut self, child_id: u32) -> bool {
        if self.child_count as usize >= MAX_CHILDREN { return false; }
        self.children[self.child_count as usize] = child_id;
        self.child_count += 1;
        true
    }

    /// Remove a child by ID
    pub fn remove_child(&mut self, child_id: u32) -> bool {
        for i in 0..self.child_count as usize {
            if self.children[i] == child_id {
                let mut j = i;
                while j + 1 < self.child_count as usize {
                    self.children[j] = self.children[j + 1];
                    j += 1;
                }
                self.child_count -= 1;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Sysfs Symlink
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct SysfsSymlink {
    pub source_id: u32,
    pub target_id: u32,
    pub name: [u8; 64],
    pub name_len: u8,
    pub active: bool,
}

impl SysfsSymlink {
    pub const fn new() -> Self {
        Self { source_id: 0, target_id: 0, name: [0u8; 64], name_len: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Uevent
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum UeventAction {
    Add    = 0,
    Remove = 1,
    Change = 2,
    Move   = 3,
    Online = 4,
    Offline= 5,
    Bind   = 6,
    Unbind = 7,
}

#[derive(Clone, Copy)]
pub struct Uevent {
    pub action: UeventAction,
    pub node_id: u32,
    pub seq: u32,
    pub timestamp: u64,
    pub active: bool,
}

impl Uevent {
    pub const fn new() -> Self {
        Self { action: UeventAction::Add, node_id: 0, seq: 0, timestamp: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Sysfs filesystem
// ---------------------------------------------------------------------------

pub struct Sysfs {
    nodes: [SysfsNode; MAX_SYSFS_NODES],
    node_count: u32,
    next_id: u32,
    symlinks: [SysfsSymlink; MAX_SYMLINKS],
    symlink_count: u32,
    uevents: [Uevent; MAX_UEVENTS],
    uevent_head: u32,
    uevent_tail: u32,
    uevent_seq: u32,
    initialized: bool,
}

impl Sysfs {
    pub const fn new() -> Self {
        Self {
            nodes: [const { SysfsNode::new() }; MAX_SYSFS_NODES],
            node_count: 0,
            next_id: 1,
            symlinks: [const { SysfsSymlink::new() }; MAX_SYMLINKS],
            symlink_count: 0,
            uevents: [const { Uevent::new() }; MAX_UEVENTS],
            uevent_head: 0,
            uevent_tail: 0,
            uevent_seq: 0,
            initialized: false,
        }
    }

    /// Initialize sysfs with standard hierarchy
    pub fn mount(&mut self) {
        if self.initialized { return; }

        // Create root node
        let root = self.create_node(b"", KobjType::Root, 0);

        // Standard top-level dirs
        if let Some(root_id) = root {
            self.create_node(b"bus", KobjType::Bus, root_id);
            self.create_node(b"devices", KobjType::Device, root_id);
            self.create_node(b"class", KobjType::Class, root_id);
            self.create_node(b"module", KobjType::Module, root_id);
            self.create_node(b"firmware", KobjType::Firmware, root_id);
            self.create_node(b"block", KobjType::Block, root_id);
            self.create_node(b"power", KobjType::Power, root_id);

            // Create /sys/bus subtree
            if let Some(bus_id) = self.find_child(root_id, b"bus") {
                self.create_node(b"pci", KobjType::Bus, bus_id);
                self.create_node(b"usb", KobjType::Bus, bus_id);
                self.create_node(b"platform", KobjType::Platform, bus_id);
                self.create_node(b"i2c", KobjType::Bus, bus_id);
                self.create_node(b"spi", KobjType::Bus, bus_id);
                self.create_node(b"virtio", KobjType::Bus, bus_id);
            }

            // Create /sys/class subtree
            if let Some(class_id) = self.find_child(root_id, b"class") {
                self.create_node(b"net", KobjType::Class, class_id);
                self.create_node(b"block", KobjType::Class, class_id);
                self.create_node(b"tty", KobjType::Class, class_id);
                self.create_node(b"input", KobjType::Class, class_id);
                self.create_node(b"drm", KobjType::Class, class_id);
                self.create_node(b"sound", KobjType::Class, class_id);
                self.create_node(b"hwmon", KobjType::Class, class_id);
            }

            // Create /sys/devices/system with CPU topology
            if let Some(dev_id) = self.find_child(root_id, b"devices") {
                if let Some(sys_id) = self.create_node(b"system", KobjType::Subsystem, dev_id) {
                    if let Some(cpu_id) = self.create_node(b"cpu", KobjType::Cpu, sys_id) {
                        // Create cpu0 with attributes
                        if let Some(cpu0) = self.create_node(b"cpu0", KobjType::Cpu, cpu_id) {
                            self.add_attr_string(cpu0, b"online", b"1");
                            self.add_attr_int(cpu0, b"core_id", 0);
                            self.add_attr_int(cpu0, b"physical_package_id", 0);
                        }
                    }
                    self.create_node(b"memory", KobjType::Memory, sys_id);
                    self.create_node(b"node", KobjType::Node, sys_id);
                }
            }

            // Create /sys/power
            if let Some(power_id) = self.find_child(root_id, b"power") {
                self.add_attr_string(power_id, b"state", b"mem freeze disk");
                self.add_attr_string(power_id, b"mem_sleep", b"s2idle deep");
                self.add_attr_string(power_id, b"disk", b"platform shutdown reboot suspend");
                self.add_attr_int(power_id, b"pm_async", 1);
            }
        }

        self.initialized = true;
    }

    /// Create a node in the sysfs tree
    pub fn create_node(&mut self, name: &[u8], kobj_type: KobjType, parent_id: u32) -> Option<u32> {
        if self.node_count as usize >= MAX_SYSFS_NODES { return None; }

        for i in 0..MAX_SYSFS_NODES {
            if !self.nodes[i].active {
                let id = self.next_id;
                self.nodes[i] = SysfsNode::new();
                self.nodes[i].id = id;
                self.nodes[i].set_name(name);
                self.nodes[i].kobj_type = kobj_type;
                self.nodes[i].parent_id = parent_id;
                self.nodes[i].active = true;
                self.node_count += 1;
                self.next_id += 1;

                // Add to parent's children
                if parent_id > 0 {
                    for j in 0..MAX_SYSFS_NODES {
                        if self.nodes[j].active && self.nodes[j].id == parent_id {
                            self.nodes[j].add_child(id);
                            break;
                        }
                    }
                }

                self.emit_uevent(UeventAction::Add, id);
                return Some(id);
            }
        }
        None
    }

    /// Remove a node and its children
    pub fn remove_node(&mut self, node_id: u32) -> bool {
        for i in 0..MAX_SYSFS_NODES {
            if self.nodes[i].active && self.nodes[i].id == node_id {
                // Recursively remove children
                let cc = self.nodes[i].child_count;
                for c in 0..cc as usize {
                    let child_id = self.nodes[i].children[c];
                    self.remove_node(child_id);
                }

                // Remove from parent
                let parent_id = self.nodes[i].parent_id;
                if parent_id > 0 {
                    for j in 0..MAX_SYSFS_NODES {
                        if self.nodes[j].active && self.nodes[j].id == parent_id {
                            self.nodes[j].remove_child(node_id);
                            break;
                        }
                    }
                }

                self.emit_uevent(UeventAction::Remove, node_id);
                self.nodes[i].active = false;
                self.node_count -= 1;
                return true;
            }
        }
        false
    }

    /// Find a child node by name
    pub fn find_child(&self, parent_id: u32, name: &[u8]) -> Option<u32> {
        for i in 0..MAX_SYSFS_NODES {
            if self.nodes[i].active && self.nodes[i].parent_id == parent_id && self.nodes[i].name_matches(name) {
                return Some(self.nodes[i].id);
            }
        }
        None
    }

    /// Find node by ID
    fn find_node(&self, id: u32) -> Option<usize> {
        for i in 0..MAX_SYSFS_NODES {
            if self.nodes[i].active && self.nodes[i].id == id {
                return Some(i);
            }
        }
        None
    }

    /// Add string attribute to a node
    pub fn add_attr_string(&mut self, node_id: u32, name: &[u8], value: &[u8]) -> bool {
        if let Some(idx) = self.find_node(node_id) {
            if let Some(a) = self.nodes[idx].add_attr(name, AttrType::String, AttrMode::ReadOnly) {
                self.nodes[idx].attrs[a].set_string(value);
                return true;
            }
        }
        false
    }

    /// Add integer attribute to a node  
    pub fn add_attr_int(&mut self, node_id: u32, name: &[u8], value: i64) -> bool {
        if let Some(idx) = self.find_node(node_id) {
            if let Some(a) = self.nodes[idx].add_attr(name, AttrType::Integer, AttrMode::ReadOnly) {
                self.nodes[idx].attrs[a].set_int(value);
                return true;
            }
        }
        false
    }

    /// Add writable attribute
    pub fn add_attr_rw(&mut self, node_id: u32, name: &[u8], value: &[u8]) -> bool {
        if let Some(idx) = self.find_node(node_id) {
            if let Some(a) = self.nodes[idx].add_attr(name, AttrType::String, AttrMode::ReadWrite) {
                self.nodes[idx].attrs[a].set_string(value);
                return true;
            }
        }
        false
    }

    /// Write to an attribute (if writable)
    pub fn write_attr(&mut self, node_id: u32, attr_name: &[u8], value: &[u8]) -> bool {
        if let Some(idx) = self.find_node(node_id) {
            if let Some(a) = self.nodes[idx].find_attr(attr_name) {
                let mode = self.nodes[idx].attrs[a].mode;
                if mode == AttrMode::ReadWrite || mode == AttrMode::WriteOnly || mode == AttrMode::RootOnly {
                    self.nodes[idx].attrs[a].set_string(value);
                    self.emit_uevent(UeventAction::Change, node_id);
                    return true;
                }
            }
        }
        false
    }

    /// Create a symlink
    pub fn create_symlink(&mut self, source: u32, target: u32, name: &[u8]) -> bool {
        if self.symlink_count as usize >= MAX_SYMLINKS { return false; }
        let idx = self.symlink_count as usize;
        self.symlinks[idx] = SysfsSymlink::new();
        self.symlinks[idx].source_id = source;
        self.symlinks[idx].target_id = target;
        let len = if name.len() > 63 { 63 } else { name.len() };
        self.symlinks[idx].name[..len].copy_from_slice(&name[..len]);
        self.symlinks[idx].name_len = len as u8;
        self.symlinks[idx].active = true;
        self.symlink_count += 1;
        true
    }

    /// Emit a uevent
    fn emit_uevent(&mut self, action: UeventAction, node_id: u32) {
        let idx = self.uevent_head as usize % MAX_UEVENTS;
        self.uevents[idx] = Uevent {
            action,
            node_id,
            seq: self.uevent_seq,
            timestamp: 0, // would use kernel clock
            active: true,
        };
        self.uevent_head += 1;
        self.uevent_seq += 1;
    }

    /// Dequeue a uevent
    pub fn dequeue_uevent(&mut self) -> Option<Uevent> {
        if self.uevent_tail >= self.uevent_head { return None; }
        let idx = self.uevent_tail as usize % MAX_UEVENTS;
        self.uevent_tail += 1;
        Some(self.uevents[idx])
    }

    /// Register a device under /sys/devices
    pub fn register_device(&mut self, bus: &[u8], dev_name: &[u8], vendor: &[u8], device: &[u8]) -> Option<u32> {
        // Find /sys/bus/<bus>/
        let root = 1u32; // root is always 1
        let bus_id = self.find_child(root, b"bus")?;
        let bus_dir = self.find_child(bus_id, bus)?;

        // Create devices subdir under bus if needed
        let devices_dir = if let Some(d) = self.find_child(bus_dir, b"devices") {
            d
        } else {
            self.create_node(b"devices", KobjType::Device, bus_dir)?
        };

        // Create the device node
        let dev_id = self.create_node(dev_name, KobjType::Device, devices_dir)?;
        self.add_attr_string(dev_id, b"vendor", vendor);
        self.add_attr_string(dev_id, b"device", device);
        self.add_attr_string(dev_id, b"uevent", b"");
        self.add_attr_int(dev_id, b"numa_node", -1);

        Some(dev_id)
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut SYSFS: Sysfs = Sysfs::new();

fn sysfs() -> &'static mut Sysfs {
    unsafe { &mut SYSFS }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_mount() -> i32 {
    sysfs().mount();
    0
}

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_create_node(
    name_ptr: *const u8, name_len: u32,
    kobj_type: u8, parent_id: u32,
) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let kt = match kobj_type {
        0 => KobjType::Root, 1 => KobjType::Bus, 2 => KobjType::Device,
        3 => KobjType::Driver, 4 => KobjType::Class, 5 => KobjType::Module,
        _ => KobjType::Subsystem,
    };
    match sysfs().create_node(name, kt, parent_id) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_remove_node(node_id: u32) -> i32 {
    if sysfs().remove_node(node_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_add_attr(
    node_id: u32, name_ptr: *const u8, name_len: u32,
    value_ptr: *const u8, value_len: u32,
) -> i32 {
    if name_ptr.is_null() || value_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let value = unsafe { core::slice::from_raw_parts(value_ptr, value_len as usize) };
    if sysfs().add_attr_string(node_id, name, value) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_node_count() -> u32 {
    sysfs().node_count
}

#[no_mangle]
pub extern "C" fn zxyphor_sysfs_register_pci_device(
    name_ptr: *const u8, name_len: u32,
    vendor_ptr: *const u8, vendor_len: u32,
    device_ptr: *const u8, device_len: u32,
) -> i32 {
    if name_ptr.is_null() || vendor_ptr.is_null() || device_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let vendor = unsafe { core::slice::from_raw_parts(vendor_ptr, vendor_len as usize) };
    let device = unsafe { core::slice::from_raw_parts(device_ptr, device_len as usize) };
    match sysfs().register_device(b"pci", name, vendor, device) {
        Some(id) => id as i32,
        None => -1,
    }
}

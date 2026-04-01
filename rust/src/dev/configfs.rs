// =============================================================================
// Kernel Zxyphor — Rust configfs Virtual Filesystem
// =============================================================================
// Linux configfs-inspired filesystem for user-driven kernel object configuration:
//   - User creates/deletes directories to create/destroy kernel objects
//   - Subsystem registration (USB gadgets, targets, RDMA)
//   - Config groups and items with typed attributes
//   - Commit/uncommit lifecycle for atomic configuration
//   - Default groups auto-created on mkdir
//   - Dependent subsystems (cross-references)
//   - Config item hierarchy (groups contain items+subgroups)
// =============================================================================

/// Maximum subsystems
const MAX_SUBSYSTEMS: usize = 32;
/// Maximum config groups per subsystem
const MAX_GROUPS: usize = 128;
/// Maximum config items per group
const MAX_ITEMS: usize = 256;
/// Maximum attributes per item
const MAX_ITEM_ATTRS: usize = 16;
/// Maximum links (cross-references)
const MAX_LINKS: usize = 64;

// ---------------------------------------------------------------------------
// Config attribute
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ConfigAttr {
    pub name: [u8; 48],
    pub name_len: u8,
    pub value: [u8; 128],
    pub value_len: u16,
    pub writable: bool,
    pub active: bool,
}

impl ConfigAttr {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 48],
            name_len: 0,
            value: [0u8; 128],
            value_len: 0,
            writable: true,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 47 { 47 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn set_value(&mut self, v: &[u8]) {
        let len = if v.len() > 127 { 127 } else { v.len() };
        self.value[..len].copy_from_slice(&v[..len]);
        self.value_len = len as u16;
    }
}

// ---------------------------------------------------------------------------
// Config item state
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ItemState {
    Created    = 0,
    Configured = 1,
    Committed  = 2,
    Active     = 3,
    Error      = 4,
}

// ---------------------------------------------------------------------------
// Config item
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ConfigItem {
    pub id: u32,
    pub group_id: u32,
    pub name: [u8; 64],
    pub name_len: u8,
    pub state: ItemState,
    pub attrs: [ConfigAttr; MAX_ITEM_ATTRS],
    pub attr_count: u8,
    pub active: bool,
}

impl ConfigItem {
    pub const fn new() -> Self {
        Self {
            id: 0,
            group_id: 0,
            name: [0u8; 64],
            name_len: 0,
            state: ItemState::Created,
            attrs: [const { ConfigAttr::new() }; MAX_ITEM_ATTRS],
            attr_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn add_attr(&mut self, name: &[u8], default: &[u8], writable: bool) -> Option<u8> {
        if self.attr_count as usize >= MAX_ITEM_ATTRS { return None; }
        let idx = self.attr_count;
        self.attrs[idx as usize] = ConfigAttr::new();
        self.attrs[idx as usize].set_name(name);
        self.attrs[idx as usize].set_value(default);
        self.attrs[idx as usize].writable = writable;
        self.attrs[idx as usize].active = true;
        self.attr_count += 1;
        Some(idx)
    }

    pub fn find_attr(&self, name: &[u8]) -> Option<usize> {
        for i in 0..self.attr_count as usize {
            if !self.attrs[i].active { continue; }
            if name.len() != self.attrs[i].name_len as usize { continue; }
            let mut eq = true;
            for j in 0..name.len() {
                if name[j] != self.attrs[i].name[j] { eq = false; break; }
            }
            if eq { return Some(i); }
        }
        None
    }

    pub fn write_attr(&mut self, attr_name: &[u8], value: &[u8]) -> bool {
        if let Some(idx) = self.find_attr(attr_name) {
            if self.attrs[idx].writable {
                self.attrs[idx].set_value(value);
                return true;
            }
        }
        false
    }

    pub fn commit(&mut self) -> bool {
        if self.state != ItemState::Configured { return false; }
        self.state = ItemState::Committed;
        true
    }

    pub fn uncommit(&mut self) -> bool {
        if self.state != ItemState::Committed && self.state != ItemState::Active { return false; }
        self.state = ItemState::Configured;
        true
    }
}

// ---------------------------------------------------------------------------
// Config group (directory that contains items or subgroups)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum GroupType {
    Default    = 0,  // auto-created with subsystem
    UserMkdir  = 1,  // user creates instances
    Composite  = 2,  // contains default subgroups
}

#[derive(Clone, Copy)]
pub struct ConfigGroup {
    pub id: u32,
    pub subsystem_id: u32,
    pub parent_group_id: u32,
    pub name: [u8; 64],
    pub name_len: u8,
    pub group_type: GroupType,
    pub item_ids: [u32; 64],
    pub item_count: u8,
    pub subgroup_ids: [u32; 16],
    pub subgroup_count: u8,
    pub active: bool,
}

impl ConfigGroup {
    pub const fn new() -> Self {
        Self {
            id: 0, subsystem_id: 0, parent_group_id: 0,
            name: [0u8; 64], name_len: 0,
            group_type: GroupType::Default,
            item_ids: [0u32; 64], item_count: 0,
            subgroup_ids: [0u32; 16], subgroup_count: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    pub fn add_item(&mut self, item_id: u32) -> bool {
        if self.item_count as usize >= 64 { return false; }
        self.item_ids[self.item_count as usize] = item_id;
        self.item_count += 1;
        true
    }

    pub fn remove_item(&mut self, item_id: u32) -> bool {
        for i in 0..self.item_count as usize {
            if self.item_ids[i] == item_id {
                let mut j = i;
                while j + 1 < self.item_count as usize {
                    self.item_ids[j] = self.item_ids[j + 1];
                    j += 1;
                }
                self.item_count -= 1;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Configfs subsystem
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ConfigSubsystem {
    pub id: u32,
    pub name: [u8; 64],
    pub name_len: u8,
    pub root_group_id: u32,
    pub active: bool,
}

impl ConfigSubsystem {
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; 64], name_len: 0,
            root_group_id: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = if n.len() > 63 { 63 } else { n.len() };
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

// ---------------------------------------------------------------------------
// Configfs link (cross-reference between items)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub struct ConfigLink {
    pub source_item_id: u32,
    pub target_item_id: u32,
    pub name: [u8; 48],
    pub name_len: u8,
    pub active: bool,
}

impl ConfigLink {
    pub const fn new() -> Self {
        Self { source_item_id: 0, target_item_id: 0, name: [0u8; 48], name_len: 0, active: false }
    }
}

// ---------------------------------------------------------------------------
// Configfs filesystem
// ---------------------------------------------------------------------------

pub struct Configfs {
    subsystems: [ConfigSubsystem; MAX_SUBSYSTEMS],
    sub_count: u32,
    groups: [ConfigGroup; MAX_GROUPS],
    group_count: u32,
    items: [ConfigItem; MAX_ITEMS],
    item_count: u32,
    links: [ConfigLink; MAX_LINKS],
    link_count: u32,
    next_id: u32,
    initialized: bool,
}

impl Configfs {
    pub const fn new() -> Self {
        Self {
            subsystems: [const { ConfigSubsystem::new() }; MAX_SUBSYSTEMS],
            sub_count: 0,
            groups: [const { ConfigGroup::new() }; MAX_GROUPS],
            group_count: 0,
            items: [const { ConfigItem::new() }; MAX_ITEMS],
            item_count: 0,
            links: [const { ConfigLink::new() }; MAX_LINKS],
            link_count: 0,
            next_id: 1,
            initialized: false,
        }
    }

    /// Mount configfs and register built-in subsystems
    pub fn mount(&mut self) {
        if self.initialized { return; }

        // Register standard subsystems
        self.register_subsystem(b"usb_gadget");
        self.register_subsystem(b"target");
        self.register_subsystem(b"nvmet");
        self.register_subsystem(b"acpi");

        self.initialized = true;
    }

    /// Register a new configfs subsystem
    pub fn register_subsystem(&mut self, name: &[u8]) -> Option<u32> {
        if self.sub_count as usize >= MAX_SUBSYSTEMS { return None; }

        let sub_id = self.next_id;
        self.next_id += 1;

        // Create root group for subsystem
        let group_id = self.create_group(name, sub_id, 0, GroupType::UserMkdir)?;

        for i in 0..MAX_SUBSYSTEMS {
            if !self.subsystems[i].active {
                self.subsystems[i] = ConfigSubsystem::new();
                self.subsystems[i].id = sub_id;
                self.subsystems[i].set_name(name);
                self.subsystems[i].root_group_id = group_id;
                self.subsystems[i].active = true;
                self.sub_count += 1;
                return Some(sub_id);
            }
        }
        None
    }

    /// Create a config group
    fn create_group(&mut self, name: &[u8], sub_id: u32, parent_id: u32, gtype: GroupType) -> Option<u32> {
        if self.group_count as usize >= MAX_GROUPS { return None; }

        let id = self.next_id;
        self.next_id += 1;

        for i in 0..MAX_GROUPS {
            if !self.groups[i].active {
                self.groups[i] = ConfigGroup::new();
                self.groups[i].id = id;
                self.groups[i].subsystem_id = sub_id;
                self.groups[i].parent_group_id = parent_id;
                self.groups[i].set_name(name);
                self.groups[i].group_type = gtype;
                self.groups[i].active = true;
                self.group_count += 1;

                // Register as subgroup in parent
                if parent_id > 0 {
                    for j in 0..MAX_GROUPS {
                        if self.groups[j].active && self.groups[j].id == parent_id {
                            if (self.groups[j].subgroup_count as usize) < 16 {
                                self.groups[j].subgroup_ids[self.groups[j].subgroup_count as usize] = id;
                                self.groups[j].subgroup_count += 1;
                            }
                            break;
                        }
                    }
                }

                return Some(id);
            }
        }
        None
    }

    /// Create a config item in a group (like mkdir in configfs)
    pub fn make_item(&mut self, group_id: u32, name: &[u8]) -> Option<u32> {
        if self.item_count as usize >= MAX_ITEMS { return None; }

        let id = self.next_id;
        self.next_id += 1;

        for i in 0..MAX_ITEMS {
            if !self.items[i].active {
                self.items[i] = ConfigItem::new();
                self.items[i].id = id;
                self.items[i].group_id = group_id;
                self.items[i].set_name(name);
                self.items[i].state = ItemState::Created;
                self.items[i].active = true;
                self.item_count += 1;

                // Add to group
                for j in 0..MAX_GROUPS {
                    if self.groups[j].active && self.groups[j].id == group_id {
                        self.groups[j].add_item(id);
                        break;
                    }
                }

                return Some(id);
            }
        }
        None
    }

    /// Remove a config item (like rmdir in configfs)
    pub fn drop_item(&mut self, item_id: u32) -> bool {
        for i in 0..MAX_ITEMS {
            if self.items[i].active && self.items[i].id == item_id {
                if self.items[i].state == ItemState::Committed || self.items[i].state == ItemState::Active {
                    return false; // must uncommit first
                }

                let group_id = self.items[i].group_id;
                self.items[i].active = false;
                self.item_count -= 1;

                // Remove from group
                for j in 0..MAX_GROUPS {
                    if self.groups[j].active && self.groups[j].id == group_id {
                        self.groups[j].remove_item(item_id);
                        break;
                    }
                }

                // Remove any links
                for l in 0..MAX_LINKS {
                    if self.links[l].active
                        && (self.links[l].source_item_id == item_id || self.links[l].target_item_id == item_id)
                    {
                        self.links[l].active = false;
                        self.link_count -= 1;
                    }
                }

                return true;
            }
        }
        false
    }

    /// Write attribute on an item
    pub fn write_item_attr(&mut self, item_id: u32, attr_name: &[u8], value: &[u8]) -> bool {
        for i in 0..MAX_ITEMS {
            if self.items[i].active && self.items[i].id == item_id {
                let ok = self.items[i].write_attr(attr_name, value);
                if ok && self.items[i].state == ItemState::Created {
                    self.items[i].state = ItemState::Configured;
                }
                return ok;
            }
        }
        false
    }

    /// Commit item (activate in kernel)
    pub fn commit_item(&mut self, item_id: u32) -> bool {
        for i in 0..MAX_ITEMS {
            if self.items[i].active && self.items[i].id == item_id {
                return self.items[i].commit();
            }
        }
        false
    }

    /// Create a cross-reference link between items
    pub fn create_link(&mut self, source: u32, target: u32, name: &[u8]) -> bool {
        if self.link_count as usize >= MAX_LINKS { return false; }
        for i in 0..MAX_LINKS {
            if !self.links[i].active {
                self.links[i] = ConfigLink::new();
                self.links[i].source_item_id = source;
                self.links[i].target_item_id = target;
                let len = if name.len() > 47 { 47 } else { name.len() };
                self.links[i].name[..len].copy_from_slice(&name[..len]);
                self.links[i].name_len = len as u8;
                self.links[i].active = true;
                self.link_count += 1;
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

static mut CONFIGFS: Configfs = Configfs::new();

fn configfs() -> &'static mut Configfs {
    unsafe { &mut CONFIGFS }
}

// ---------------------------------------------------------------------------
// FFI exports
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn zxyphor_configfs_mount() -> i32 {
    configfs().mount();
    0
}

#[no_mangle]
pub extern "C" fn zxyphor_configfs_register_subsystem(
    name_ptr: *const u8, name_len: u32,
) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match configfs().register_subsystem(name) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_configfs_make_item(
    group_id: u32, name_ptr: *const u8, name_len: u32,
) -> i32 {
    if name_ptr.is_null() { return -1; }
    let name = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    match configfs().make_item(group_id, name) {
        Some(id) => id as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_configfs_drop_item(item_id: u32) -> i32 {
    if configfs().drop_item(item_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_configfs_commit(item_id: u32) -> i32 {
    if configfs().commit_item(item_id) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn zxyphor_configfs_item_count() -> u32 {
    configfs().item_count
}

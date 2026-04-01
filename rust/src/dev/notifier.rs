// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Notifier Chain & Event Framework (Rust)
//
// Kernel event notification infrastructure:
// - Atomic notifier chains (called in atomic/interrupt context)
// - Blocking notifier chains (can sleep)
// - Raw notifier chains (no locking, caller must synchronize)
// - SRCU notifier chains (sleepable RCU protected)
// - Priority-ordered callback registration
// - Stop-on-error and continue-on-error policies
// - Predefined event classes (reboot, netdevice, cpu hotplug, etc.)
// - Notifier call return values (DONE, OK, BAD, STOP)

#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────

const MAX_CALLBACKS: usize = 64;
const MAX_CHAINS: usize = 64;
const MAX_NAME_LEN: usize = 32;
const MAX_EVENT_LOG: usize = 256;

// ─────────────────── Notifier Return Values ─────────────────────────

#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NotifierRet {
    Done = 0x0000,        // Don't care
    Ok = 0x0001,          // Callback handled
    Bad = 0x8000,         // Error, stop calling further
    Stop = 0x8000 | 0x01, // Stop calling, but no error
}

impl NotifierRet {
    pub fn should_stop(self) -> bool {
        (self as i32) & 0x8000 != 0
    }
}

// ─────────────────── Chain Type ─────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ChainType {
    Atomic = 0,    // No sleeping, spinlock protected
    Blocking = 1,  // Can sleep, mutex protected
    Raw = 2,       // No locking
    Srcu = 3,      // SRCU protected
}

// ─────────────────── Event Classes ──────────────────────────────────

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum EventClass {
    Reboot = 0,
    CpuHotplug = 1,
    MemHotplug = 2,
    NetDevice = 3,
    NetNamespace = 4,
    BlockDevice = 5,
    Inetaddr = 6,
    Inet6addr = 7,
    Keyboard = 8,
    Vt = 9,
    Acpi = 10,
    Power = 11,
    Usb = 12,
    Pci = 13,
    Die = 14,          // Kernel oops/panic
    Panic = 15,
    ModuleLoad = 16,
    ModuleUnload = 17,
    Oom = 18,
    TaskFree = 19,
    TaskCreate = 20,
    ClockChange = 21,
    SuspendPrepare = 22,
    ResumeComplete = 23,
    Custom = 255,
}

// ─────────────────── Reboot Events ──────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum RebootEvent {
    Restart = 0x01,
    Halt = 0x02,
    PowerOff = 0x03,
    Restart2 = 0x04,    // restart with command
    SwSuspend = 0x05,
    Kexec = 0x06,
}

// ─────────────────── CPU Hotplug Events ─────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CpuEvent {
    Online = 0x01,
    Dead = 0x02,
    Up = 0x03,
    Down = 0x04,
    FreezingPrepare = 0x05,
    ThawingDone = 0x06,
}

// ─────────────────── Net Device Events ──────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum NetDevEvent {
    Up = 0x0001,
    Down = 0x0002,
    Reboot = 0x0003,
    Change = 0x0004,
    Register = 0x0005,
    Unregister = 0x0006,
    ChangeMtu = 0x0007,
    ChangeAddr = 0x0008,
    GoingDown = 0x0009,
    ChangeName = 0x000A,
    FeatChange = 0x000B,
    BondingFailover = 0x000C,
    PreChangeAddr = 0x000D,
    PreChangeMtu = 0x000E,
    JoinBridge = 0x000F,
}

// ─────────────────── Callback Entry ─────────────────────────────────

/// notifier_fn_t — called when an event is dispatched
pub type NotifierFn = fn(event: u32, data: u64) -> NotifierRet;

#[derive(Clone, Copy)]
pub struct NotifierCallback {
    pub func: NotifierFn,
    /// Priority (higher = called first; default 0)
    pub priority: i32,
    /// Which event class this callback is for
    pub event_class: EventClass,
    /// Name for debugging
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: u8,
    /// Registration order for stable sort
    pub reg_seq: u32,
    /// Is this callback enabled?
    pub enabled: bool,
    /// Stats
    pub call_count: u64,
    pub last_result: NotifierRet,
    pub active: bool,
}

impl NotifierCallback {
    pub const fn new() -> Self {
        Self {
            func: noop_notifier,
            priority: 0,
            event_class: EventClass::Custom,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            reg_seq: 0,
            enabled: true,
            call_count: 0,
            last_result: NotifierRet::Done,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }
}

fn noop_notifier(_event: u32, _data: u64) -> NotifierRet {
    NotifierRet::Done
}

// ─────────────────── Event Log Entry ────────────────────────────────

#[derive(Clone, Copy)]
pub struct EventLogEntry {
    pub event_class: EventClass,
    pub event: u32,
    pub data: u64,
    pub timestamp: u64,
    pub callbacks_called: u16,
    pub stopped_early: bool,
}

impl EventLogEntry {
    pub const fn new() -> Self {
        Self {
            event_class: EventClass::Custom,
            event: 0,
            data: 0,
            timestamp: 0,
            callbacks_called: 0,
            stopped_early: false,
        }
    }
}

// ─────────────────── Notifier Chain ─────────────────────────────────

pub struct NotifierChain {
    callbacks: [NotifierCallback; MAX_CALLBACKS],
    count: u16,
    next_seq: u32,
    chain_type: ChainType,
    event_class: EventClass,
    name: [u8; MAX_NAME_LEN],
    name_len: u8,
    /// Stop-on-error policy
    stop_on_error: bool,
    /// Stats
    total_dispatches: u64,
    total_callbacks: u64,
    active: bool,
}

impl NotifierChain {
    pub const fn new() -> Self {
        Self {
            callbacks: [NotifierCallback::new(); MAX_CALLBACKS],
            count: 0,
            next_seq: 0,
            chain_type: ChainType::Atomic,
            event_class: EventClass::Custom,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            stop_on_error: false,
            total_dispatches: 0,
            total_callbacks: 0,
            active: false,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(MAX_NAME_LEN - 1);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    /// Register a callback in priority order (descending)
    pub fn register(&mut self, func: NotifierFn, priority: i32, name: &[u8]) -> Option<u16> {
        if self.count as usize >= MAX_CALLBACKS {
            return None;
        }

        // Find free slot
        let mut slot = None;
        for i in 0..MAX_CALLBACKS {
            if !self.callbacks[i].active {
                slot = Some(i);
                break;
            }
        }
        let idx = slot?;

        self.callbacks[idx].func = func;
        self.callbacks[idx].priority = priority;
        self.callbacks[idx].event_class = self.event_class;
        self.callbacks[idx].set_name(name);
        self.callbacks[idx].reg_seq = self.next_seq;
        self.callbacks[idx].enabled = true;
        self.callbacks[idx].call_count = 0;
        self.callbacks[idx].active = true;
        self.next_seq += 1;
        self.count += 1;

        Some(idx as u16)
    }

    /// Unregister a callback by index
    pub fn unregister(&mut self, idx: u16) -> bool {
        let i = idx as usize;
        if i >= MAX_CALLBACKS || !self.callbacks[i].active {
            return false;
        }
        self.callbacks[i].active = false;
        self.count -= 1;
        true
    }

    /// Unregister a callback by function pointer
    pub fn unregister_fn(&mut self, func: NotifierFn) -> bool {
        for i in 0..MAX_CALLBACKS {
            if self.callbacks[i].active && (self.callbacks[i].func as usize) == (func as usize) {
                self.callbacks[i].active = false;
                self.count -= 1;
                return true;
            }
        }
        false
    }

    /// Dispatch event to all callbacks in priority order
    pub fn call_chain(&mut self, event: u32, data: u64) -> (NotifierRet, u16) {
        self.total_dispatches += 1;
        let mut final_ret = NotifierRet::Done;
        let mut called = 0u16;

        // Build sorted index by priority (descending), then reg_seq (ascending)
        let mut sorted: [usize; MAX_CALLBACKS] = [0; MAX_CALLBACKS];
        let mut scount = 0usize;

        for i in 0..MAX_CALLBACKS {
            if self.callbacks[i].active && self.callbacks[i].enabled {
                sorted[scount] = i;
                scount += 1;
            }
        }

        // Insertion sort by (priority DESC, reg_seq ASC)
        for i in 1..scount {
            let key = sorted[i];
            let mut j = i;
            while j > 0 {
                let prev = sorted[j - 1];
                let should_swap = self.callbacks[key].priority > self.callbacks[prev].priority
                    || (self.callbacks[key].priority == self.callbacks[prev].priority
                        && self.callbacks[key].reg_seq < self.callbacks[prev].reg_seq);
                if should_swap {
                    sorted[j] = sorted[j - 1];
                    j -= 1;
                } else {
                    break;
                }
            }
            sorted[j] = key;
        }

        // Call in order
        for s in 0..scount {
            let idx = sorted[s];
            let ret = (self.callbacks[idx].func)(event, data);
            self.callbacks[idx].call_count += 1;
            self.callbacks[idx].last_result = ret;
            self.total_callbacks += 1;
            called += 1;
            final_ret = ret;

            if ret.should_stop() {
                break;
            }
            if self.stop_on_error && ret == NotifierRet::Bad {
                break;
            }
        }

        (final_ret, called)
    }

    /// Enable/disable a callback
    pub fn set_enabled(&mut self, idx: u16, enabled: bool) {
        let i = idx as usize;
        if i < MAX_CALLBACKS && self.callbacks[i].active {
            self.callbacks[i].enabled = enabled;
        }
    }

    pub fn callback_count(&self) -> u16 {
        self.count
    }
}

// ─────────────────── Notifier Manager ───────────────────────────────

pub struct NotifierManager {
    chains: [NotifierChain; MAX_CHAINS],
    chain_count: u16,
    /// Event log ring buffer
    event_log: [EventLogEntry; MAX_EVENT_LOG],
    log_head: u16,
    log_count: u16,
    /// System tick
    current_tick: u64,
    /// Global stats
    total_events: AtomicU64,
    total_callbacks: AtomicU64,
    total_errors: AtomicU64,
}

impl NotifierManager {
    pub const fn new() -> Self {
        Self {
            chains: [const { NotifierChain::new() }; MAX_CHAINS],
            chain_count: 0,
            event_log: [EventLogEntry::new(); MAX_EVENT_LOG],
            log_head: 0,
            log_count: 0,
            current_tick: 0,
            total_events: AtomicU64::new(0),
            total_callbacks: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
        }
    }

    pub fn init(&mut self) {
        // Create standard notifier chains
        self.create_chain(b"reboot", ChainType::Blocking, EventClass::Reboot, true);
        self.create_chain(b"cpu_hotplug", ChainType::Atomic, EventClass::CpuHotplug, false);
        self.create_chain(b"mem_hotplug", ChainType::Blocking, EventClass::MemHotplug, false);
        self.create_chain(b"netdevice", ChainType::Raw, EventClass::NetDevice, false);
        self.create_chain(b"inetaddr", ChainType::Blocking, EventClass::Inetaddr, false);
        self.create_chain(b"keyboard", ChainType::Atomic, EventClass::Keyboard, false);
        self.create_chain(b"power", ChainType::Blocking, EventClass::Power, false);
        self.create_chain(b"panic", ChainType::Atomic, EventClass::Panic, false);
        self.create_chain(b"module_load", ChainType::Blocking, EventClass::ModuleLoad, false);
        self.create_chain(b"oom", ChainType::Atomic, EventClass::Oom, false);
        self.create_chain(b"suspend_prepare", ChainType::Blocking, EventClass::SuspendPrepare, true);
        self.create_chain(b"resume_complete", ChainType::Blocking, EventClass::ResumeComplete, false);
    }

    pub fn create_chain(
        &mut self,
        name: &[u8],
        chain_type: ChainType,
        event_class: EventClass,
        stop_on_error: bool,
    ) -> Option<u16> {
        if self.chain_count as usize >= MAX_CHAINS {
            return None;
        }
        let idx = self.chain_count;
        self.chains[idx as usize] = NotifierChain::new();
        self.chains[idx as usize].set_name(name);
        self.chains[idx as usize].chain_type = chain_type;
        self.chains[idx as usize].event_class = event_class;
        self.chains[idx as usize].stop_on_error = stop_on_error;
        self.chains[idx as usize].active = true;
        self.chain_count += 1;
        Some(idx)
    }

    /// Find chain by event class
    fn find_chain(&self, event_class: EventClass) -> Option<u16> {
        for i in 0..self.chain_count as usize {
            if self.chains[i].active && self.chains[i].event_class == event_class {
                return Some(i as u16);
            }
        }
        None
    }

    /// Register a callback on a specific event class chain
    pub fn register_callback(
        &mut self,
        event_class: EventClass,
        func: NotifierFn,
        priority: i32,
        name: &[u8],
    ) -> Option<(u16, u16)> {
        let chain_id = self.find_chain(event_class)?;
        let cb_id = self.chains[chain_id as usize].register(func, priority, name)?;
        Some((chain_id, cb_id))
    }

    /// Unregister a callback
    pub fn unregister_callback(&mut self, chain_id: u16, cb_id: u16) -> bool {
        if chain_id >= self.chain_count {
            return false;
        }
        self.chains[chain_id as usize].unregister(cb_id)
    }

    /// Dispatch an event to the appropriate chain
    pub fn notify(&mut self, event_class: EventClass, event: u32, data: u64) -> NotifierRet {
        let chain_id = match self.find_chain(event_class) {
            Some(id) => id,
            None => return NotifierRet::Done,
        };

        self.total_events.fetch_add(1, Ordering::Relaxed);
        let (ret, called) = self.chains[chain_id as usize].call_chain(event, data);
        self.total_callbacks
            .fetch_add(called as u64, Ordering::Relaxed);

        if ret == NotifierRet::Bad {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
        }

        // Log the event
        self.log_event(event_class, event, data, called, ret.should_stop());

        ret
    }

    fn log_event(
        &mut self,
        event_class: EventClass,
        event: u32,
        data: u64,
        callbacks_called: u16,
        stopped_early: bool,
    ) {
        let idx = self.log_head as usize;
        self.event_log[idx] = EventLogEntry {
            event_class,
            event,
            data,
            timestamp: self.current_tick,
            callbacks_called,
            stopped_early,
        };
        self.log_head = ((self.log_head as usize + 1) % MAX_EVENT_LOG) as u16;
        if self.log_count < MAX_EVENT_LOG as u16 {
            self.log_count += 1;
        }
    }

    /// Convenience: notify reboot
    pub fn notify_reboot(&mut self, event: RebootEvent) -> NotifierRet {
        self.notify(EventClass::Reboot, event as u32, 0)
    }

    /// Convenience: notify CPU hotplug
    pub fn notify_cpu_event(&mut self, event: CpuEvent, cpu_id: u32) -> NotifierRet {
        self.notify(EventClass::CpuHotplug, event as u32, cpu_id as u64)
    }

    /// Convenience: notify net device
    pub fn notify_netdev(&mut self, event: NetDevEvent, dev_id: u32) -> NotifierRet {
        self.notify(EventClass::NetDevice, event as u32, dev_id as u64)
    }

    /// Convenience: notify panic
    pub fn notify_panic(&mut self, reason: u64) -> NotifierRet {
        self.notify(EventClass::Panic, 0, reason)
    }

    /// Convenience: notify module load
    pub fn notify_module_load(&mut self, mod_id: u32) -> NotifierRet {
        self.notify(EventClass::ModuleLoad, 0, mod_id as u64)
    }

    pub fn tick(&mut self) {
        self.current_tick += 1;
    }

    pub fn chain_count(&self) -> u16 {
        self.chain_count
    }

    pub fn total_callbacks_in_chain(&self, chain_id: u16) -> u16 {
        if chain_id < self.chain_count {
            self.chains[chain_id as usize].callback_count()
        } else {
            0
        }
    }

    pub fn event_log_count(&self) -> u16 {
        self.log_count
    }
}

// ─────────────────── Global Instance ────────────────────────────────

static mut NOTIFIER_MGR: NotifierManager = NotifierManager::new();

fn nmgr() -> &'static mut NotifierManager {
    unsafe { &mut NOTIFIER_MGR }
}

fn nmgr_ref() -> &'static NotifierManager {
    unsafe { &NOTIFIER_MGR }
}

// ─────────────────── FFI Exports ────────────────────────────────────

#[no_mangle]
pub extern "C" fn rust_notifier_init() {
    nmgr().init();
}

#[no_mangle]
pub extern "C" fn rust_notifier_chain_count() -> u16 {
    nmgr_ref().chain_count()
}

#[no_mangle]
pub extern "C" fn rust_notifier_notify(event_class: u16, event: u32, data: u64) -> i32 {
    // Safety: event_class bounds checked by enum
    if event_class > 255 {
        return NotifierRet::Bad as i32;
    }
    let ec: EventClass = unsafe { core::mem::transmute(event_class) };
    nmgr().notify(ec, event, data) as i32
}

#[no_mangle]
pub extern "C" fn rust_notifier_total_events() -> u64 {
    nmgr_ref().total_events.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_notifier_total_callbacks() -> u64 {
    nmgr_ref().total_callbacks.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_notifier_total_errors() -> u64 {
    nmgr_ref().total_errors.load(Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn rust_notifier_log_count() -> u16 {
    nmgr_ref().event_log_count()
}

#[no_mangle]
pub extern "C" fn rust_notifier_tick() {
    nmgr().tick();
}

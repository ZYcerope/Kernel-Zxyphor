// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Epoll Wrapper (FFI to Zig epoll subsystem)
//
// Provides safe Rust abstractions over the Zig epoll implementation
// including builder patterns, iterators, and async-ready interfaces.

#![allow(dead_code)]

// ─────────────────── Constants ──────────────────────────────────────
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

pub const MAX_EPOLL_EVENTS: usize = 1024;

// ─────────────────── FFI Declarations ───────────────────────────────
extern "C" {
    fn zxy_epoll_create(flags: u32) -> i32;
    fn zxy_epoll_ctl(epfd: i32, op: i32, fd: i32, events: u32, data: u64) -> i32;
    fn zxy_epoll_wait(epfd: i32, events: *mut EpollEvent, max_events: i32, timeout: i32) -> i32;
    fn zxy_epoll_close(epfd: i32) -> i32;
}

// ─────────────────── Event Structure ────────────────────────────────
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EpollEvent {
    pub events: u32,
    pub data: EpollData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub union EpollData {
    pub ptr: u64,
    pub fd: i32,
    pub u32_val: u32,
    pub u64_val: u64,
}

impl Default for EpollEvent {
    fn default() -> Self {
        Self {
            events: 0,
            data: EpollData { u64_val: 0 },
        }
    }
}

impl EpollEvent {
    pub fn new(events: u32, fd: i32) -> Self {
        Self {
            events,
            data: EpollData { fd },
        }
    }

    pub fn with_data(events: u32, data: u64) -> Self {
        Self {
            events,
            data: EpollData { u64_val: data },
        }
    }

    pub fn is_readable(&self) -> bool {
        self.events & EPOLLIN != 0
    }

    pub fn is_writable(&self) -> bool {
        self.events & EPOLLOUT != 0
    }

    pub fn is_error(&self) -> bool {
        self.events & EPOLLERR != 0
    }

    pub fn is_hangup(&self) -> bool {
        self.events & EPOLLHUP != 0
    }

    pub fn is_peer_shutdown(&self) -> bool {
        self.events & EPOLLRDHUP != 0
    }

    pub fn fd(&self) -> i32 {
        unsafe { self.data.fd }
    }

    pub fn user_data(&self) -> u64 {
        unsafe { self.data.u64_val }
    }
}

// ─────────────────── Epoll Interest Builder ─────────────────────────
pub struct Interest {
    events: u32,
}

impl Interest {
    pub fn new() -> Self {
        Self { events: 0 }
    }

    pub fn readable(mut self) -> Self {
        self.events |= EPOLLIN;
        self
    }

    pub fn writable(mut self) -> Self {
        self.events |= EPOLLOUT;
        self
    }

    pub fn error(mut self) -> Self {
        self.events |= EPOLLERR;
        self
    }

    pub fn hangup(mut self) -> Self {
        self.events |= EPOLLHUP;
        self
    }

    pub fn peer_shutdown(mut self) -> Self {
        self.events |= EPOLLRDHUP;
        self
    }

    pub fn edge_triggered(mut self) -> Self {
        self.events |= EPOLLET;
        self
    }

    pub fn oneshot(mut self) -> Self {
        self.events |= EPOLLONESHOT;
        self
    }

    pub fn exclusive(mut self) -> Self {
        self.events |= EPOLLEXCLUSIVE;
        self
    }

    pub fn raw(&self) -> u32 {
        self.events
    }
}

// ─────────────────── Epoll Instance ─────────────────────────────────
pub struct Epoll {
    fd: i32,
    events_buf: [EpollEvent; MAX_EPOLL_EVENTS],
    registered_count: u32,
}

impl Epoll {
    /// Create a new epoll instance
    pub fn create() -> Result<Self, EpollError> {
        let fd = unsafe { zxy_epoll_create(0) };
        if fd < 0 {
            return Err(EpollError::CreateFailed(fd));
        }
        Ok(Self {
            fd,
            events_buf: [EpollEvent::default(); MAX_EPOLL_EVENTS],
            registered_count: 0,
        })
    }

    /// Create with CLOEXEC flag
    pub fn create_cloexec() -> Result<Self, EpollError> {
        let fd = unsafe { zxy_epoll_create(1) };
        if fd < 0 {
            return Err(EpollError::CreateFailed(fd));
        }
        Ok(Self {
            fd,
            events_buf: [EpollEvent::default(); MAX_EPOLL_EVENTS],
            registered_count: 0,
        })
    }

    /// Register a file descriptor with epoll
    pub fn add(&mut self, fd: i32, interest: &Interest) -> Result<(), EpollError> {
        self.add_with_data(fd, interest, fd as u64)
    }

    /// Register a file descriptor with custom user data
    pub fn add_with_data(&mut self, fd: i32, interest: &Interest, data: u64) -> Result<(), EpollError> {
        let ret = unsafe {
            zxy_epoll_ctl(self.fd, EPOLL_CTL_ADD, fd, interest.raw(), data)
        };
        if ret < 0 {
            return Err(EpollError::CtlFailed(ret));
        }
        self.registered_count += 1;
        Ok(())
    }

    /// Modify the interest set for a registered fd
    pub fn modify(&mut self, fd: i32, interest: &Interest) -> Result<(), EpollError> {
        self.modify_with_data(fd, interest, fd as u64)
    }

    /// Modify with custom user data
    pub fn modify_with_data(&mut self, fd: i32, interest: &Interest, data: u64) -> Result<(), EpollError> {
        let ret = unsafe {
            zxy_epoll_ctl(self.fd, EPOLL_CTL_MOD, fd, interest.raw(), data)
        };
        if ret < 0 {
            return Err(EpollError::CtlFailed(ret));
        }
        Ok(())
    }

    /// Remove a file descriptor from epoll
    pub fn remove(&mut self, fd: i32) -> Result<(), EpollError> {
        let ret = unsafe {
            zxy_epoll_ctl(self.fd, EPOLL_CTL_DEL, fd, 0, 0)
        };
        if ret < 0 {
            return Err(EpollError::CtlFailed(ret));
        }
        if self.registered_count > 0 {
            self.registered_count -= 1;
        }
        Ok(())
    }

    /// Wait for events with timeout (milliseconds, -1 for infinite)
    pub fn wait(&mut self, timeout_ms: i32) -> Result<&[EpollEvent], EpollError> {
        let max = MAX_EPOLL_EVENTS.min(self.registered_count as usize + 1);
        let ret = unsafe {
            zxy_epoll_wait(
                self.fd,
                self.events_buf.as_mut_ptr(),
                max as i32,
                timeout_ms,
            )
        };
        if ret < 0 {
            return Err(EpollError::WaitFailed(ret));
        }
        Ok(&self.events_buf[..ret as usize])
    }

    /// Wait with no timeout (blocks indefinitely)
    pub fn wait_indefinite(&mut self) -> Result<&[EpollEvent], EpollError> {
        self.wait(-1)
    }

    /// Non-blocking poll (timeout = 0)
    pub fn poll(&mut self) -> Result<&[EpollEvent], EpollError> {
        self.wait(0)
    }

    /// Get the raw epoll file descriptor
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// Number of registered file descriptors
    pub fn registered_count(&self) -> u32 {
        self.registered_count
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { zxy_epoll_close(self.fd); }
            self.fd = -1;
        }
    }
}

// ─────────────────── Error Type ─────────────────────────────────────
#[derive(Debug, Clone, Copy)]
pub enum EpollError {
    CreateFailed(i32),
    CtlFailed(i32),
    WaitFailed(i32),
    InvalidFd,
    TooManyEvents,
}

// ─────────────────── Event Loop ─────────────────────────────────────
/// A simple event loop built on top of epoll for driver use
pub struct EventLoop {
    epoll: Epoll,
    handlers: [Option<EventHandler>; 256],
    handler_count: usize,
    running: bool,
}

pub struct EventHandler {
    fd: i32,
    callback_id: u32,
    interest: u32,
    oneshot: bool,
}

impl EventHandler {
    pub fn new(fd: i32, callback_id: u32, interest: &Interest) -> Self {
        Self {
            fd,
            callback_id,
            interest: interest.raw(),
            oneshot: interest.raw() & EPOLLONESHOT != 0,
        }
    }
}

/// Result from dispatching events
pub struct DispatchResult {
    pub events_processed: u32,
    pub errors: u32,
    pub handlers_triggered: [u32; 64],
    pub handler_count: u32,
}

impl Default for DispatchResult {
    fn default() -> Self {
        Self {
            events_processed: 0,
            errors: 0,
            handlers_triggered: [0; 64],
            handler_count: 0,
        }
    }
}

impl EventLoop {
    pub fn new() -> Result<Self, EpollError> {
        const NONE_HANDLER: Option<EventHandler> = None;
        Ok(Self {
            epoll: Epoll::create()?,
            handlers: [NONE_HANDLER; 256],
            handler_count: 0,
            running: false,
        })
    }

    /// Register a file descriptor with an event handler
    pub fn register(&mut self, fd: i32, callback_id: u32, interest: &Interest) -> Result<(), EpollError> {
        self.epoll.add_with_data(fd, interest, callback_id as u64)?;

        let handler = EventHandler::new(fd, callback_id, interest);
        for slot in self.handlers.iter_mut() {
            if slot.is_none() {
                *slot = Some(handler);
                self.handler_count += 1;
                return Ok(());
            }
        }
        Err(EpollError::TooManyEvents)
    }

    /// Unregister a file descriptor
    pub fn unregister(&mut self, fd: i32) -> Result<(), EpollError> {
        self.epoll.remove(fd)?;

        for slot in self.handlers.iter_mut() {
            if let Some(handler) = slot {
                if handler.fd == fd {
                    *slot = None;
                    if self.handler_count > 0 {
                        self.handler_count -= 1;
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    /// Run one iteration of the event loop
    pub fn poll_once(&mut self, timeout_ms: i32) -> Result<DispatchResult, EpollError> {
        let events = self.epoll.wait(timeout_ms)?;
        let mut result = DispatchResult::default();

        for event in events {
            result.events_processed += 1;

            let callback_id = event.user_data() as u32;
            if result.handler_count < 64 {
                result.handlers_triggered[result.handler_count as usize] = callback_id;
                result.handler_count += 1;
            }

            // If oneshot, remove the handler
            if event.events & EPOLLONESHOT != 0 {
                for slot in self.handlers.iter_mut() {
                    if let Some(handler) = slot {
                        if handler.callback_id == callback_id && handler.oneshot {
                            *slot = None;
                            if self.handler_count > 0 {
                                self.handler_count -= 1;
                            }
                            break;
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Run the event loop until stopped
    pub fn run(&mut self) -> Result<(), EpollError> {
        self.running = true;
        while self.running {
            let _ = self.poll_once(100)?;
        }
        Ok(())
    }

    /// Stop the event loop
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Check if the event loop is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Number of registered handlers
    pub fn handler_count(&self) -> usize {
        self.handler_count
    }
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_epoll_create() -> i32 {
    match Epoll::create() {
        Ok(epoll) => {
            let fd = epoll.fd;
            core::mem::forget(epoll); // Prevent drop from closing fd
            fd
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_epoll_add(epfd: i32, fd: i32, events: u32, data: u64) -> i32 {
    unsafe { zxy_epoll_ctl(epfd, EPOLL_CTL_ADD, fd, events, data) }
}

#[no_mangle]
pub extern "C" fn rust_epoll_mod(epfd: i32, fd: i32, events: u32, data: u64) -> i32 {
    unsafe { zxy_epoll_ctl(epfd, EPOLL_CTL_MOD, fd, events, data) }
}

#[no_mangle]
pub extern "C" fn rust_epoll_del(epfd: i32, fd: i32) -> i32 {
    unsafe { zxy_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, 0, 0) }
}

#[no_mangle]
pub extern "C" fn rust_epoll_wait(epfd: i32, events: *mut EpollEvent, max_events: i32, timeout: i32) -> i32 {
    unsafe { zxy_epoll_wait(epfd, events, max_events, timeout) }
}

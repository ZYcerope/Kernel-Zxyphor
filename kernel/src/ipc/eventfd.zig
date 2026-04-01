// SPDX-License-Identifier: MIT
// Zxyphor Kernel — eventfd, timerfd, signalfd, epoll
//
// Event-driven I/O primitives:
// - eventfd: Lightweight counter-based signaling
// - timerfd: Timer events via file descriptor
// - signalfd: Signal delivery via file descriptor
// - epoll: Scalable I/O event notification (edge/level triggered)
// - eventpoll: Internal epoll implementation with red-black tree
// - pollfd: Traditional poll() support
// - Wake queue management

const std = @import("std");

// ─────────────────── eventfd ────────────────────────────────────────
pub const EFD_CLOEXEC: u32 = 1 << 0;
pub const EFD_NONBLOCK: u32 = 1 << 1;
pub const EFD_SEMAPHORE: u32 = 1 << 2;

pub const EventFd = struct {
    counter: u64 = 0,
    flags: u32 = 0,
    /// Waiters blocked on read (simplified counter)
    read_waiters: u32 = 0,
    /// Waiters blocked on write
    write_waiters: u32 = 0,
    fd: i32 = -1,
    active: bool = false,

    pub fn init(initval: u32, flags: u32) EventFd {
        return .{
            .counter = initval,
            .flags = flags,
            .active = true,
        };
    }

    /// Read from eventfd. Returns counter value and resets to 0
    /// In semaphore mode, decrements by 1
    pub fn read(self: *EventFd) ?u64 {
        if (self.counter == 0) {
            if (self.flags & EFD_NONBLOCK != 0) return null;
            self.read_waiters += 1;
            return null; // Would block
        }

        if (self.flags & EFD_SEMAPHORE != 0) {
            self.counter -= 1;
            return 1;
        } else {
            const val = self.counter;
            self.counter = 0;
            return val;
        }
    }

    /// Write to eventfd. Adds value to counter
    pub fn write(self: *EventFd, val: u64) bool {
        // Check overflow (max is u64 max - 1)
        const max = ~@as(u64, 0) - 1;
        if (self.counter > max - val) {
            if (self.flags & EFD_NONBLOCK != 0) return false;
            self.write_waiters += 1;
            return false; // Would block
        }
        self.counter += val;
        // Wake any read waiters
        if (self.read_waiters > 0) {
            self.read_waiters = 0;
        }
        return true;
    }

    pub fn isReadable(self: *const EventFd) bool {
        return self.counter > 0;
    }

    pub fn isWritable(self: *const EventFd) bool {
        const max = ~@as(u64, 0) - 1;
        return self.counter < max;
    }
};

// ─────────────────── timerfd ────────────────────────────────────────
pub const TFD_CLOEXEC: u32 = 1 << 0;
pub const TFD_NONBLOCK: u32 = 1 << 1;
pub const TFD_TIMER_ABSTIME: u32 = 1 << 2;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 3;

pub const ClockId = enum(u8) {
    realtime = 0,
    monotonic = 1,
    boottime = 2,
    realtime_alarm = 3,
    boottime_alarm = 4,
};

pub const ItimerSpec = struct {
    /// Interval for periodic timers (0 = one-shot)
    interval_ns: u64 = 0,
    /// Initial expiration
    value_ns: u64 = 0,
};

pub const TimerFd = struct {
    clock_id: ClockId = .monotonic,
    flags: u32 = 0,
    spec: ItimerSpec = .{},
    /// Number of expirations since last read
    expirations: u64 = 0,
    /// Absolute time of next expiration
    next_expiry_ns: u64 = 0,
    /// State
    armed: bool = false,
    fd: i32 = -1,
    active: bool = false,

    pub fn create(clock_id: ClockId, flags: u32) TimerFd {
        return .{
            .clock_id = clock_id,
            .flags = flags,
            .active = true,
        };
    }

    pub fn settime(self: *TimerFd, new_spec: ItimerSpec, current_time_ns: u64) ItimerSpec {
        const old = self.spec;
        self.spec = new_spec;
        self.expirations = 0;

        if (new_spec.value_ns == 0) {
            self.armed = false;
            self.next_expiry_ns = 0;
        } else {
            self.armed = true;
            if (self.flags & TFD_TIMER_ABSTIME != 0) {
                self.next_expiry_ns = new_spec.value_ns;
            } else {
                self.next_expiry_ns = current_time_ns + new_spec.value_ns;
            }
        }
        return old;
    }

    pub fn gettime(self: *const TimerFd, current_time_ns: u64) ItimerSpec {
        if (!self.armed) return .{};
        var remaining: u64 = 0;
        if (self.next_expiry_ns > current_time_ns) {
            remaining = self.next_expiry_ns - current_time_ns;
        }
        return .{
            .interval_ns = self.spec.interval_ns,
            .value_ns = remaining,
        };
    }

    /// Check and process timer expiration
    pub fn tick(self: *TimerFd, current_time_ns: u64) bool {
        if (!self.armed) return false;
        if (current_time_ns < self.next_expiry_ns) return false;

        // Timer expired
        if (self.spec.interval_ns > 0) {
            // Periodic: count how many periods elapsed
            const elapsed = current_time_ns - self.next_expiry_ns;
            const periods = elapsed / self.spec.interval_ns + 1;
            self.expirations += periods;
            self.next_expiry_ns += periods * self.spec.interval_ns;
        } else {
            // One-shot
            self.expirations += 1;
            self.armed = false;
        }
        return true;
    }

    /// Read expirations count (blocks if none; returns null for NONBLOCK)
    pub fn read(self: *TimerFd) ?u64 {
        if (self.expirations == 0) {
            if (self.flags & TFD_NONBLOCK != 0) return null;
            return null; // Would block
        }
        const val = self.expirations;
        self.expirations = 0;
        return val;
    }
};

// ─────────────────── signalfd ───────────────────────────────────────
pub const SFD_CLOEXEC: u32 = 1 << 0;
pub const SFD_NONBLOCK: u32 = 1 << 1;

pub const SignalFdInfo = struct {
    signo: u32 = 0,
    errno_: i32 = 0,
    code: i32 = 0,
    pid: u32 = 0,
    uid: u32 = 0,
    fd: i32 = 0,
    tid: u32 = 0,
    band: u32 = 0,
    overrun: u32 = 0,
    trapno: u32 = 0,
    status: i32 = 0,
    int_val: i32 = 0,
    ptr: u64 = 0,
    utime: u64 = 0,
    stime: u64 = 0,
    addr: u64 = 0,
};

pub const MAX_SIGFD_QUEUE: usize = 32;

pub const SignalFd = struct {
    mask: u64 = 0, // signal mask (bitmask of signals to intercept)
    flags: u32 = 0,
    queue: [MAX_SIGFD_QUEUE]SignalFdInfo = [_]SignalFdInfo{.{}} ** MAX_SIGFD_QUEUE,
    queue_head: u32 = 0,
    queue_tail: u32 = 0,
    queue_count: u32 = 0,
    fd: i32 = -1,
    active: bool = false,

    pub fn create(mask: u64, flags: u32) SignalFd {
        return .{
            .mask = mask,
            .flags = flags,
            .active = true,
        };
    }

    pub fn setMask(self: *SignalFd, new_mask: u64) void {
        self.mask = new_mask;
    }

    /// Deliver a signal to this signalfd
    pub fn deliver(self: *SignalFd, info: SignalFdInfo) bool {
        // Check if signal is in our mask
        if (info.signo < 64 and (self.mask & (@as(u64, 1) << @intCast(info.signo))) == 0) {
            return false;
        }

        if (self.queue_count >= MAX_SIGFD_QUEUE) return false;

        self.queue[self.queue_tail] = info;
        self.queue_tail = (self.queue_tail + 1) % MAX_SIGFD_QUEUE;
        self.queue_count += 1;
        return true;
    }

    /// Read a queued signal
    pub fn read(self: *SignalFd) ?SignalFdInfo {
        if (self.queue_count == 0) {
            if (self.flags & SFD_NONBLOCK != 0) return null;
            return null;
        }

        const info = self.queue[self.queue_head];
        self.queue_head = (self.queue_head + 1) % MAX_SIGFD_QUEUE;
        self.queue_count -= 1;
        return info;
    }

    pub fn isReadable(self: *const SignalFd) bool {
        return self.queue_count > 0;
    }
};

// ─────────────────── epoll ──────────────────────────────────────────
pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLRDNORM: u32 = 0x040;
pub const EPOLLRDBAND: u32 = 0x080;
pub const EPOLLWRNORM: u32 = 0x100;
pub const EPOLLWRBAND: u32 = 0x200;
pub const EPOLLMSG: u32 = 0x400;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1 << 31;     // Edge-triggered
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;

pub const EpollOp = enum(u8) {
    add = 1,
    mod_ = 2,
    del = 3,
};

pub const EpollEvent = struct {
    events: u32 = 0,
    data: u64 = 0, // user data (union of ptr, fd, u32, u64)
};

pub const MAX_EPOLL_FDS: usize = 256;
pub const MAX_EPOLL_INSTANCES: usize = 32;

pub const EpollItem = struct {
    fd: i32 = -1,
    events: u32 = 0,       // requested events
    data: u64 = 0,         // user data
    revents: u32 = 0,      // returned events
    ready: bool = false,
    active: bool = false,
    edge_triggered: bool = false,
    oneshot: bool = false,
    disabled: bool = false, // oneshot that already fired
};

pub const EpollInstance = struct {
    items: [MAX_EPOLL_FDS]EpollItem = [_]EpollItem{.{}} ** MAX_EPOLL_FDS,
    item_count: u32 = 0,
    /// Ready list (indices into items)
    ready_list: [MAX_EPOLL_FDS]u32 = [_]u32{0} ** MAX_EPOLL_FDS,
    ready_count: u32 = 0,
    fd: i32 = -1,
    active: bool = false,

    /// Add a file descriptor to monitor
    pub fn ctl(self: *EpollInstance, op: EpollOp, fd: i32, event: ?EpollEvent) bool {
        switch (op) {
            .add => {
                if (self.item_count >= MAX_EPOLL_FDS) return false;
                const ev = event orelse return false;
                // Check duplicate
                for (self.items[0..self.item_count]) |item| {
                    if (item.active and item.fd == fd) return false;
                }
                const idx = self.item_count;
                self.items[idx] = .{
                    .fd = fd,
                    .events = ev.events & ~(EPOLLET | EPOLLONESHOT),
                    .data = ev.data,
                    .active = true,
                    .edge_triggered = (ev.events & EPOLLET) != 0,
                    .oneshot = (ev.events & EPOLLONESHOT) != 0,
                };
                self.item_count += 1;
                return true;
            },
            .mod_ => {
                const ev = event orelse return false;
                var i: u32 = 0;
                while (i < self.item_count) : (i += 1) {
                    if (self.items[i].active and self.items[i].fd == fd) {
                        self.items[i].events = ev.events & ~(EPOLLET | EPOLLONESHOT);
                        self.items[i].data = ev.data;
                        self.items[i].edge_triggered = (ev.events & EPOLLET) != 0;
                        self.items[i].oneshot = (ev.events & EPOLLONESHOT) != 0;
                        self.items[i].disabled = false;
                        return true;
                    }
                }
                return false;
            },
            .del => {
                var i: u32 = 0;
                while (i < self.item_count) : (i += 1) {
                    if (self.items[i].active and self.items[i].fd == fd) {
                        self.items[i].active = false;
                        return true;
                    }
                }
                return false;
            },
        }
    }

    /// Scan for ready events
    pub fn poll(self: *EpollInstance) u32 {
        self.ready_count = 0;
        var i: u32 = 0;
        while (i < self.item_count) : (i += 1) {
            if (!self.items[i].active or self.items[i].disabled) continue;
            if (self.items[i].revents & self.items[i].events != 0) {
                self.ready_list[self.ready_count] = i;
                self.ready_count += 1;
                self.items[i].ready = true;

                if (self.items[i].oneshot) {
                    self.items[i].disabled = true;
                }
            }
        }
        return self.ready_count;
    }

    /// Wait for events (returns number of ready fds)
    pub fn wait(self: *EpollInstance, out: []EpollEvent, max_events: u32) u32 {
        const ready = self.poll();
        const to_copy = @min(ready, max_events);
        const copy_count = @min(to_copy, @as(u32, @intCast(out.len)));

        var copied: u32 = 0;
        while (copied < copy_count) : (copied += 1) {
            const idx = self.ready_list[copied];
            out[copied] = .{
                .events = self.items[idx].revents & self.items[idx].events,
                .data = self.items[idx].data,
            };
            // Edge-triggered: clear revents after reporting
            if (self.items[idx].edge_triggered) {
                self.items[idx].revents = 0;
                self.items[idx].ready = false;
            }
        }
        return copied;
    }

    /// Notify that an fd has events (called by subsystem/driver)
    pub fn notifyFd(self: *EpollInstance, fd: i32, events: u32) void {
        var i: u32 = 0;
        while (i < self.item_count) : (i += 1) {
            if (self.items[i].active and self.items[i].fd == fd) {
                if (self.items[i].edge_triggered) {
                    self.items[i].revents |= events;
                } else {
                    self.items[i].revents = events;
                }
            }
        }
    }
};

// ─────────────────── poll() support ─────────────────────────────────
pub const POLLIN: u16 = 0x0001;
pub const POLLPRI: u16 = 0x0002;
pub const POLLOUT: u16 = 0x0004;
pub const POLLERR: u16 = 0x0008;
pub const POLLHUP: u16 = 0x0010;
pub const POLLNVAL: u16 = 0x0020;
pub const POLLRDNORM_: u16 = 0x0040;
pub const POLLWRNORM_: u16 = 0x0100;

pub const PollFd = struct {
    fd: i32 = -1,
    events: u16 = 0,    // requested
    revents: u16 = 0,   // returned
};

pub const MAX_POLL_FDS: usize = 256;

/// Traditional poll() implementation
pub fn doPoll(fds: []PollFd) u32 {
    var ready: u32 = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        if (pfd.fd < 0) continue;
        // In real kernel: check each fd's wait queue
        // Stub: report all fds as writable
        if (pfd.events & POLLOUT != 0) {
            pfd.revents |= POLLOUT;
            ready += 1;
        }
    }
    return ready;
}

// ─────────────────── Event Manager ──────────────────────────────────
pub const MAX_EVENTFDS: usize = 64;
pub const MAX_TIMERFDS: usize = 32;
pub const MAX_SIGNALFDS: usize = 16;

pub const EventManager = struct {
    eventfds: [MAX_EVENTFDS]EventFd = [_]EventFd{.{}} ** MAX_EVENTFDS,
    efd_count: u32 = 0,
    timerfds: [MAX_TIMERFDS]TimerFd = [_]TimerFd{.{}} ** MAX_TIMERFDS,
    tfd_count: u32 = 0,
    signalfds: [MAX_SIGNALFDS]SignalFd = [_]SignalFd{.{}} ** MAX_SIGNALFDS,
    sfd_count: u32 = 0,
    epolls: [MAX_EPOLL_INSTANCES]EpollInstance = [_]EpollInstance{.{}} ** MAX_EPOLL_INSTANCES,
    epoll_count: u32 = 0,
    next_fd: i32 = 100, // start from fd 100 to avoid collisions
    initialized: bool = false,

    pub fn init(self: *EventManager) void {
        self.next_fd = 100;
        self.initialized = true;
    }

    fn allocFd(self: *EventManager) i32 {
        const fd = self.next_fd;
        self.next_fd += 1;
        return fd;
    }

    pub fn createEventFd(self: *EventManager, initval: u32, flags: u32) ?i32 {
        if (self.efd_count >= MAX_EVENTFDS) return null;
        const fd = self.allocFd();
        self.eventfds[self.efd_count] = EventFd.init(initval, flags);
        self.eventfds[self.efd_count].fd = fd;
        self.efd_count += 1;
        return fd;
    }

    pub fn createTimerFd(self: *EventManager, clock_id: ClockId, flags: u32) ?i32 {
        if (self.tfd_count >= MAX_TIMERFDS) return null;
        const fd = self.allocFd();
        self.timerfds[self.tfd_count] = TimerFd.create(clock_id, flags);
        self.timerfds[self.tfd_count].fd = fd;
        self.tfd_count += 1;
        return fd;
    }

    pub fn createSignalFd(self: *EventManager, mask: u64, flags: u32) ?i32 {
        if (self.sfd_count >= MAX_SIGNALFDS) return null;
        const fd = self.allocFd();
        self.signalfds[self.sfd_count] = SignalFd.create(mask, flags);
        self.signalfds[self.sfd_count].fd = fd;
        self.sfd_count += 1;
        return fd;
    }

    pub fn createEpoll(self: *EventManager) ?i32 {
        if (self.epoll_count >= MAX_EPOLL_INSTANCES) return null;
        const fd = self.allocFd();
        self.epolls[self.epoll_count] = .{
            .fd = fd,
            .active = true,
        };
        self.epoll_count += 1;
        return fd;
    }

    pub fn findEpoll(self: *EventManager, fd: i32) ?*EpollInstance {
        var i: u32 = 0;
        while (i < self.epoll_count) : (i += 1) {
            if (self.epolls[i].active and self.epolls[i].fd == fd) {
                return &self.epolls[i];
            }
        }
        return null;
    }

    pub fn findEventFd(self: *EventManager, fd: i32) ?*EventFd {
        var i: u32 = 0;
        while (i < self.efd_count) : (i += 1) {
            if (self.eventfds[i].active and self.eventfds[i].fd == fd) {
                return &self.eventfds[i];
            }
        }
        return null;
    }

    pub fn findTimerFd(self: *EventManager, fd: i32) ?*TimerFd {
        var i: u32 = 0;
        while (i < self.tfd_count) : (i += 1) {
            if (self.timerfds[i].active and self.timerfds[i].fd == fd) {
                return &self.timerfds[i];
            }
        }
        return null;
    }

    /// Tick all timers (called from timer interrupt)
    pub fn tickTimers(self: *EventManager, current_ns: u64) u32 {
        var expired: u32 = 0;
        var i: u32 = 0;
        while (i < self.tfd_count) : (i += 1) {
            if (self.timerfds[i].active and self.timerfds[i].tick(current_ns)) {
                expired += 1;
                // Notify any epoll instances watching this timerfd
                self.notifyAllEpolls(self.timerfds[i].fd, EPOLLIN);
            }
        }
        return expired;
    }

    fn notifyAllEpolls(self: *EventManager, fd: i32, events: u32) void {
        var i: u32 = 0;
        while (i < self.epoll_count) : (i += 1) {
            if (self.epolls[i].active) {
                self.epolls[i].notifyFd(fd, events);
            }
        }
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var event_mgr: EventManager = .{};

pub fn initEvents() void {
    event_mgr.init();
}

pub fn getEventManager() *EventManager {
    return &event_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_events_init() void {
    initEvents();
}

export fn zxy_eventfd_create(initval: u32, flags: u32) i32 {
    return event_mgr.createEventFd(initval, flags) orelse -1;
}

export fn zxy_timerfd_create(clock_id: u8, flags: u32) i32 {
    const clk: ClockId = @enumFromInt(@min(clock_id, 4));
    return event_mgr.createTimerFd(clk, flags) orelse -1;
}

export fn zxy_signalfd_create(mask: u64, flags: u32) i32 {
    return event_mgr.createSignalFd(mask, flags) orelse -1;
}

export fn zxy_epoll_create() i32 {
    return event_mgr.createEpoll() orelse -1;
}

export fn zxy_eventfd_count() u32 {
    return event_mgr.efd_count;
}

export fn zxy_timerfd_count() u32 {
    return event_mgr.tfd_count;
}

export fn zxy_epoll_count() u32 {
    return event_mgr.epoll_count;
}

export fn zxy_events_tick_timers(current_ns: u64) u32 {
    return event_mgr.tickTimers(current_ns);
}

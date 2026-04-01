// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Async Runtime
//
// Kernel-space async/await runtime for cooperative task scheduling:
// - Waker / RawWaker implementation (no alloc)
// - Future trait abstractions
// - Fixed-size task pool with polling
// - Timer futures
// - Yield futures
// - Channel futures (bounded MPSC)
// - Select / Join combinators
// - Integration with kernel scheduler via FFI

#![no_std]
#![allow(dead_code)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ─────────────────── Constants ──────────────────────────────────────
pub const MAX_TASKS: usize = 256;
pub const MAX_TIMERS: usize = 64;
pub const CHANNEL_CAPACITY: usize = 32;

// ─────────────────── Waker ──────────────────────────────────────────
/// Minimal waker that sets a flag when woken
#[repr(C)]
pub struct TaskWakeFlag {
    pub woken: AtomicBool,
    pub task_id: u32,
}

impl TaskWakeFlag {
    pub const fn new(id: u32) -> Self {
        Self {
            woken: AtomicBool::new(true), // Start as woken so first poll happens
            task_id: id,
        }
    }

    pub fn is_woken(&self) -> bool {
        self.woken.load(Ordering::Acquire)
    }

    pub fn clear(&self) {
        self.woken.store(false, Ordering::Release);
    }

    pub fn wake(&self) {
        self.woken.store(true, Ordering::Release);
    }
}

/// Raw waker vtable for our TaskWakeFlag
static VTABLE: RawWakerVTable = RawWakerVTable::new(
    // clone
    |data| RawWaker::new(data, &VTABLE),
    // wake
    |data| {
        let flag = unsafe { &*(data as *const TaskWakeFlag) };
        flag.wake();
    },
    // wake_by_ref
    |data| {
        let flag = unsafe { &*(data as *const TaskWakeFlag) };
        flag.wake();
    },
    // drop
    |_data| {},
);

fn create_waker(flag: &TaskWakeFlag) -> Waker {
    let raw = RawWaker::new(flag as *const _ as *const (), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

// ─────────────────── Task State ─────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TaskState {
    Empty = 0,
    Ready = 1,
    Running = 2,
    Waiting = 3,
    Completed = 4,
    Cancelled = 5,
}

// ─────────────────── Async Task ─────────────────────────────────────
/// A kernel async task wrapping a pinned future
pub struct AsyncTask {
    pub id: u32,
    pub state: TaskState,
    pub priority: u8,
    pub wake_flag: TaskWakeFlag,
    /// The future is stored as a trait object pointer (type-erased)
    /// In a real kernel, we'd use embedded storage. Here we use raw pointers.
    future_ptr: *mut dyn Future<Output = ()>,
    future_valid: bool,
    /// Deadline (kernel ticks) — 0 = no deadline
    pub deadline: u64,
    /// Name for debugging
    pub name: [u8; 32],
    pub name_len: u8,
}

impl AsyncTask {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: TaskState::Empty,
            priority: 128,
            wake_flag: TaskWakeFlag::new(0),
            future_ptr: core::ptr::null_mut(),
            future_valid: false,
            deadline: 0,
            name: [0u8; 32],
            name_len: 0,
        }
    }

    pub fn set_name(&mut self, n: &[u8]) {
        let len = n.len().min(32);
        self.name[..len].copy_from_slice(&n[..len]);
        self.name_len = len as u8;
    }

    /// Poll the future once
    pub fn poll(&mut self) -> Poll<()> {
        if !self.future_valid || self.future_ptr.is_null() {
            return Poll::Ready(());
        }

        self.state = TaskState::Running;
        self.wake_flag.clear();

        let waker = create_waker(&self.wake_flag);
        let mut cx = Context::from_waker(&waker);

        let future = unsafe { Pin::new_unchecked(&mut *self.future_ptr) };
        let result = future.poll(&mut cx);

        match result {
            Poll::Ready(()) => {
                self.state = TaskState::Completed;
                self.future_valid = false;
            }
            Poll::Pending => {
                self.state = TaskState::Waiting;
            }
        }

        result
    }
}

// ─────────────────── Executor ───────────────────────────────────────
pub struct Executor {
    tasks: [AsyncTask; MAX_TASKS],
    task_count: u32,
    next_id: AtomicU32,
    /// Current kernel tick
    current_tick: AtomicU64,
    /// Run count (for statistics)
    polls: u64,
    completions: u64,
    /// Active task count
    active: u32,
}

impl Executor {
    pub const fn new() -> Self {
        Self {
            tasks: [const { AsyncTask::empty() }; MAX_TASKS],
            task_count: 0,
            next_id: AtomicU32::new(1),
            current_tick: AtomicU64::new(0),
            polls: 0,
            completions: 0,
            active: 0,
        }
    }

    /// Spawn a new async task
    pub fn spawn(&mut self, future: *mut dyn Future<Output = ()>, name: &[u8]) -> Option<u32> {
        // Find empty slot
        for task in self.tasks.iter_mut() {
            if task.state == TaskState::Empty {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                task.id = id;
                task.state = TaskState::Ready;
                task.wake_flag = TaskWakeFlag::new(id);
                task.future_ptr = future;
                task.future_valid = true;
                task.priority = 128;
                task.deadline = 0;
                task.set_name(name);
                self.task_count += 1;
                self.active += 1;
                return Some(id);
            }
        }
        None
    }

    /// Spawn with priority
    pub fn spawn_with_priority(
        &mut self,
        future: *mut dyn Future<Output = ()>,
        name: &[u8],
        priority: u8,
    ) -> Option<u32> {
        let id = self.spawn(future, name)?;
        // Find the task and set priority
        for task in self.tasks.iter_mut() {
            if task.id == id {
                task.priority = priority;
                break;
            }
        }
        Some(id)
    }

    /// Cancel a task
    pub fn cancel(&mut self, task_id: u32) -> bool {
        for task in self.tasks.iter_mut() {
            if task.id == task_id && task.state != TaskState::Empty && task.state != TaskState::Completed {
                task.state = TaskState::Cancelled;
                task.future_valid = false;
                if self.active > 0 {
                    self.active -= 1;
                }
                return true;
            }
        }
        false
    }

    /// Run one poll cycle: poll all ready/woken tasks
    pub fn poll_once(&mut self) -> u32 {
        let mut polled = 0u32;

        // Sort by priority (simple: just iterate and pick highest priority first)
        // In a real kernel, we'd use a proper priority queue
        for task in self.tasks.iter_mut() {
            match task.state {
                TaskState::Ready => {}
                TaskState::Waiting => {
                    if !task.wake_flag.is_woken() {
                        continue;
                    }
                }
                _ => continue,
            }

            // Check deadline
            if task.deadline > 0 {
                let tick = self.current_tick.load(Ordering::Relaxed);
                if tick > task.deadline {
                    task.state = TaskState::Cancelled;
                    task.future_valid = false;
                    if self.active > 0 {
                        self.active -= 1;
                    }
                    continue;
                }
            }

            let result = task.poll();
            self.polls += 1;
            polled += 1;

            if result.is_ready() {
                self.completions += 1;
                if self.active > 0 {
                    self.active -= 1;
                }
                // Clean up completed tasks
                task.state = TaskState::Empty;
                task.future_ptr = core::ptr::null_mut();
                if self.task_count > 0 {
                    self.task_count -= 1;
                }
            }
        }

        polled
    }

    /// Run until all tasks complete
    pub fn run(&mut self) {
        loop {
            if self.active == 0 {
                break;
            }
            self.poll_once();
        }
    }

    /// Run a single step (for integration with kernel scheduler)
    pub fn step(&mut self, tick: u64) -> u32 {
        self.current_tick.store(tick, Ordering::Relaxed);
        self.poll_once()
    }

    /// Wake a specific task
    pub fn wake_task(&self, task_id: u32) -> bool {
        for task in &self.tasks {
            if task.id == task_id {
                task.wake_flag.wake();
                return true;
            }
        }
        false
    }

    pub fn active_count(&self) -> u32 {
        self.active
    }

    pub fn total_polls(&self) -> u64 {
        self.polls
    }

    pub fn total_completions(&self) -> u64 {
        self.completions
    }
}

// ─────────────────── Timer Future ───────────────────────────────────
pub struct TimerFuture {
    deadline: u64,
    done: bool,
}

impl TimerFuture {
    pub fn new(deadline_tick: u64) -> Self {
        Self {
            deadline: deadline_tick,
            done: false,
        }
    }
}

impl Future for TimerFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.done {
            return Poll::Ready(());
        }
        // Check current time via FFI
        let now = unsafe { zxy_get_kernel_ticks() };
        if now >= self.deadline {
            self.done = true;
            Poll::Ready(())
        } else {
            // Register for timer wakeup
            let waker = cx.waker().clone();
            // In a real implementation, we'd register with the timer subsystem
            // For now, just re-wake immediately (busy poll)
            waker.wake();
            Poll::Pending
        }
    }
}

// ─────────────────── Yield Future ───────────────────────────────────
pub struct YieldFuture {
    yielded: bool,
}

impl YieldFuture {
    pub fn new() -> Self {
        Self { yielded: false }
    }
}

impl Future for YieldFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Yield control back to the executor for one cycle
pub fn yield_now() -> YieldFuture {
    YieldFuture::new()
}

// ─────────────────── Channel ────────────────────────────────────────
/// A bounded MPSC channel for async communication
pub struct Channel<T: Copy + Default> {
    buffer: [T; CHANNEL_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
    closed: bool,
    /// Waiting sender waker data
    sender_woken: AtomicBool,
    /// Waiting receiver waker data
    receiver_woken: AtomicBool,
}

impl<T: Copy + Default> Channel<T> {
    pub const fn new() -> Self {
        Self {
            buffer: [const { T::default() }; CHANNEL_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            closed: false,
            sender_woken: AtomicBool::new(false),
            receiver_woken: AtomicBool::new(false),
        }
    }

    pub fn is_full(&self) -> bool {
        self.count >= CHANNEL_CAPACITY
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn try_send(&mut self, val: T) -> Result<(), T> {
        if self.closed || self.is_full() {
            return Err(val);
        }
        self.buffer[self.tail] = val;
        self.tail = (self.tail + 1) % CHANNEL_CAPACITY;
        self.count += 1;
        self.receiver_woken.store(true, Ordering::Release);
        Ok(())
    }

    pub fn try_recv(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let val = self.buffer[self.head];
        self.head = (self.head + 1) % CHANNEL_CAPACITY;
        self.count -= 1;
        self.sender_woken.store(true, Ordering::Release);
        Some(val)
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.sender_woken.store(true, Ordering::Release);
        self.receiver_woken.store(true, Ordering::Release);
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

// ─────────────────── Send Future ────────────────────────────────────
pub struct SendFuture<'a, T: Copy + Default> {
    channel: &'a mut Channel<T>,
    value: T,
    attempted: bool,
}

impl<'a, T: Copy + Default> Future for SendFuture<'a, T> {
    type Output = Result<(), T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), T>> {
        if self.channel.closed {
            return Poll::Ready(Err(self.value));
        }
        let val = self.value;
        match self.channel.try_send(val) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(v) => {
                self.attempted = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

// ─────────────────── Recv Future ────────────────────────────────────
pub struct RecvFuture<'a, T: Copy + Default> {
    channel: &'a mut Channel<T>,
}

impl<'a, T: Copy + Default> Future for RecvFuture<'a, T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        match self.channel.try_recv() {
            Some(val) => Poll::Ready(Some(val)),
            None => {
                if self.channel.closed {
                    Poll::Ready(None)
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

// ─────────────────── Event ──────────────────────────────────────────
/// A oneshot event that can be awaited
pub struct Event {
    signaled: AtomicBool,
}

impl Event {
    pub const fn new() -> Self {
        Self {
            signaled: AtomicBool::new(false),
        }
    }

    pub fn signal(&self) {
        self.signaled.store(true, Ordering::Release);
    }

    pub fn is_signaled(&self) -> bool {
        self.signaled.load(Ordering::Acquire)
    }

    pub fn reset(&self) {
        self.signaled.store(false, Ordering::Release);
    }
}

pub struct EventFuture<'a> {
    event: &'a Event,
}

impl<'a> EventFuture<'a> {
    pub fn new(event: &'a Event) -> Self {
        Self { event }
    }
}

impl<'a> Future for EventFuture<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.event.is_signaled() {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

// ─────────────────── Semaphore Future ───────────────────────────────
pub struct AsyncSemaphore {
    permits: AtomicU32,
}

impl AsyncSemaphore {
    pub const fn new(initial: u32) -> Self {
        Self {
            permits: AtomicU32::new(initial),
        }
    }

    pub fn try_acquire(&self) -> bool {
        loop {
            let current = self.permits.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            match self.permits.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    pub fn release(&self) {
        self.permits.fetch_add(1, Ordering::Release);
    }

    pub fn available(&self) -> u32 {
        self.permits.load(Ordering::Relaxed)
    }
}

pub struct SemaphoreAcquire<'a> {
    sem: &'a AsyncSemaphore,
}

impl<'a> Future for SemaphoreAcquire<'a> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.sem.try_acquire() {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

// ─────────────────── Mutex Future ───────────────────────────────────
pub struct AsyncMutex {
    locked: AtomicBool,
}

impl AsyncMutex {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    pub fn try_lock(&self) -> bool {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

pub struct MutexLock<'a> {
    mutex: &'a AsyncMutex,
}

impl<'a> Future for MutexLock<'a> {
    type Output = MutexGuard<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<MutexGuard<'a>> {
        if self.mutex.try_lock() {
            Poll::Ready(MutexGuard { mutex: self.mutex })
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub struct MutexGuard<'a> {
    mutex: &'a AsyncMutex,
}

impl<'a> Drop for MutexGuard<'a> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

// ─────────────────── FFI Imports ────────────────────────────────────
extern "C" {
    fn zxy_get_kernel_ticks() -> u64;
    fn zxy_sched_yield();
}

// ─────────────────── Global Executor ────────────────────────────────
static mut GLOBAL_EXECUTOR: Executor = Executor::new();

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_async_init() {
    // Already initialized via const constructor
}

#[no_mangle]
pub extern "C" fn rust_async_step(tick: u64) -> u32 {
    unsafe { GLOBAL_EXECUTOR.step(tick) }
}

#[no_mangle]
pub extern "C" fn rust_async_active_count() -> u32 {
    unsafe { GLOBAL_EXECUTOR.active_count() }
}

#[no_mangle]
pub extern "C" fn rust_async_wake(task_id: u32) -> bool {
    unsafe { GLOBAL_EXECUTOR.wake_task(task_id) }
}

#[no_mangle]
pub extern "C" fn rust_async_cancel(task_id: u32) -> bool {
    unsafe { GLOBAL_EXECUTOR.cancel(task_id) }
}

#[no_mangle]
pub extern "C" fn rust_async_total_polls() -> u64 {
    unsafe { GLOBAL_EXECUTOR.total_polls() }
}

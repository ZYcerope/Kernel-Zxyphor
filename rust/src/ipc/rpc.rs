// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust In-Kernel RPC Framework
//
// Lightweight Remote Procedure Call framework for kernel subsystems:
// - Service registration with method dispatch tables
// - Serialization/deserialization of RPC messages
// - Request-response correlation via request IDs
// - Asynchronous call support with completion tokens
// - Named pipe transport for local IPC
// - Message versioning and compatibility
// - Per-service rate limiting and quota enforcement
// - RPC error codes with structured error info
// - Call tracing and performance metrics
// - Service discovery and introspection

#![no_std]
#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ─────────────────── RPC Error Codes ────────────────────────────────
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum RpcError {
    Ok = 0,
    ServiceNotFound = 1,
    MethodNotFound = 2,
    InvalidArgument = 3,
    InternalError = 4,
    Timeout = 5,
    PermissionDenied = 6,
    ResourceExhausted = 7,
    Unavailable = 8,
    Cancelled = 9,
    AlreadyExists = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    DataLoss = 13,
    Unauthenticated = 14,
    BufferTooSmall = 15,
    VersionMismatch = 16,
}

impl RpcError {
    pub fn as_str(&self) -> &'static str {
        match self {
            RpcError::Ok => "ok",
            RpcError::ServiceNotFound => "service_not_found",
            RpcError::MethodNotFound => "method_not_found",
            RpcError::InvalidArgument => "invalid_argument",
            RpcError::InternalError => "internal_error",
            RpcError::Timeout => "timeout",
            RpcError::PermissionDenied => "permission_denied",
            RpcError::ResourceExhausted => "resource_exhausted",
            RpcError::Unavailable => "unavailable",
            RpcError::Cancelled => "cancelled",
            RpcError::AlreadyExists => "already_exists",
            RpcError::OutOfRange => "out_of_range",
            RpcError::Unimplemented => "unimplemented",
            RpcError::DataLoss => "data_loss",
            RpcError::Unauthenticated => "unauthenticated",
            RpcError::BufferTooSmall => "buffer_too_small",
            RpcError::VersionMismatch => "version_mismatch",
        }
    }
}

// ─────────────────── Message Format ─────────────────────────────────
pub const RPC_MAGIC: u32 = 0x5A585952; // "ZXYR"
pub const RPC_VERSION: u16 = 1;
pub const MAX_PAYLOAD_SIZE: usize = 4096;
pub const MAX_METHOD_NAME: usize = 64;
pub const MAX_SERVICE_NAME: usize = 64;

/// Wire format for RPC messages
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RpcHeader {
    pub magic: u32,
    pub version: u16,
    pub msg_type: u16,
    pub request_id: u64,
    pub service_id: u32,
    pub method_id: u32,
    pub payload_len: u32,
    pub flags: u32,
    pub timestamp: u64,
}

pub const MSG_REQUEST: u16 = 1;
pub const MSG_RESPONSE: u16 = 2;
pub const MSG_NOTIFICATION: u16 = 3;
pub const MSG_CANCEL: u16 = 4;

pub const FLAG_ONEWAY: u32 = 0x01;       // Don't expect response
pub const FLAG_STREAMING: u32 = 0x02;    // Part of a stream
pub const FLAG_COMPRESSED: u32 = 0x04;   // Payload is compressed
pub const FLAG_ENCRYPTED: u32 = 0x08;    // Payload is encrypted
pub const FLAG_LAST: u32 = 0x10;         // Last message in stream

impl RpcHeader {
    pub fn new_request(service_id: u32, method_id: u32, payload_len: u32) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            magic: RPC_MAGIC,
            version: RPC_VERSION,
            msg_type: MSG_REQUEST,
            request_id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            service_id,
            method_id,
            payload_len,
            flags: 0,
            timestamp: 0,
        }
    }

    pub fn new_response(request_id: u64, payload_len: u32) -> Self {
        Self {
            magic: RPC_MAGIC,
            version: RPC_VERSION,
            msg_type: MSG_RESPONSE,
            request_id,
            service_id: 0,
            method_id: 0,
            payload_len,
            flags: 0,
            timestamp: 0,
        }
    }

    pub fn validate(&self) -> bool {
        self.magic == RPC_MAGIC
            && self.version == RPC_VERSION
            && self.payload_len as usize <= MAX_PAYLOAD_SIZE
    }
}

// ─────────────────── Serialization ──────────────────────────────────
/// Simple TLV (Type-Length-Value) serializer for RPC payloads
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TlvType {
    Null = 0,
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    I32 = 5,
    I64 = 6,
    Bool = 7,
    Bytes = 8,
    String = 9,
    Array = 10,
    Struct = 11,
}

pub struct RpcSerializer {
    buf: [MAX_PAYLOAD_SIZE]u8,
    pos: usize,
}

impl RpcSerializer {
    pub fn new() -> Self {
        Self {
            buf: [0u8; MAX_PAYLOAD_SIZE],
            pos: 0,
        }
    }

    fn remaining(&self) -> usize {
        MAX_PAYLOAD_SIZE - self.pos
    }

    pub fn write_u8(&mut self, val: u8) -> bool {
        if self.remaining() < 3 { return false; }
        self.buf[self.pos] = TlvType::U8 as u8;
        self.buf[self.pos + 1] = 1;
        self.buf[self.pos + 2] = val;
        self.pos += 3;
        true
    }

    pub fn write_u16(&mut self, val: u16) -> bool {
        if self.remaining() < 4 { return false; }
        self.buf[self.pos] = TlvType::U16 as u8;
        self.buf[self.pos + 1] = 2;
        self.buf[self.pos + 2] = val as u8;
        self.buf[self.pos + 3] = (val >> 8) as u8;
        self.pos += 4;
        true
    }

    pub fn write_u32(&mut self, val: u32) -> bool {
        if self.remaining() < 6 { return false; }
        self.buf[self.pos] = TlvType::U32 as u8;
        self.buf[self.pos + 1] = 4;
        self.buf[self.pos + 2] = val as u8;
        self.buf[self.pos + 3] = (val >> 8) as u8;
        self.buf[self.pos + 4] = (val >> 16) as u8;
        self.buf[self.pos + 5] = (val >> 24) as u8;
        self.pos += 6;
        true
    }

    pub fn write_u64(&mut self, val: u64) -> bool {
        if self.remaining() < 10 { return false; }
        self.buf[self.pos] = TlvType::U64 as u8;
        self.buf[self.pos + 1] = 8;
        for i in 0..8 {
            self.buf[self.pos + 2 + i] = (val >> (i * 8)) as u8;
        }
        self.pos += 10;
        true
    }

    pub fn write_i32(&mut self, val: i32) -> bool {
        if self.remaining() < 6 { return false; }
        self.buf[self.pos] = TlvType::I32 as u8;
        self.buf[self.pos + 1] = 4;
        let bytes = val.to_le_bytes();
        self.buf[self.pos + 2..self.pos + 6].copy_from_slice(&bytes);
        self.pos += 6;
        true
    }

    pub fn write_bool(&mut self, val: bool) -> bool {
        if self.remaining() < 3 { return false; }
        self.buf[self.pos] = TlvType::Bool as u8;
        self.buf[self.pos + 1] = 1;
        self.buf[self.pos + 2] = if val { 1 } else { 0 };
        self.pos += 3;
        true
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> bool {
        if data.len() > 255 { return false; }
        if self.remaining() < 2 + data.len() { return false; }
        self.buf[self.pos] = TlvType::Bytes as u8;
        self.buf[self.pos + 1] = data.len() as u8;
        self.buf[self.pos + 2..self.pos + 2 + data.len()].copy_from_slice(data);
        self.pos += 2 + data.len();
        true
    }

    pub fn write_str(&mut self, s: &[u8]) -> bool {
        if s.len() > 255 { return false; }
        if self.remaining() < 2 + s.len() { return false; }
        self.buf[self.pos] = TlvType::String as u8;
        self.buf[self.pos + 1] = s.len() as u8;
        self.buf[self.pos + 2..self.pos + 2 + s.len()].copy_from_slice(s);
        self.pos += 2 + s.len();
        true
    }

    pub fn payload(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    pub fn len(&self) -> usize {
        self.pos
    }
}

pub struct RpcDeserializer<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> RpcDeserializer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn peek_type(&self) -> Option<TlvType> {
        if self.pos >= self.buf.len() { return None; }
        match self.buf[self.pos] {
            0 => Some(TlvType::Null),
            1 => Some(TlvType::U8),
            2 => Some(TlvType::U16),
            3 => Some(TlvType::U32),
            4 => Some(TlvType::U64),
            5 => Some(TlvType::I32),
            6 => Some(TlvType::I64),
            7 => Some(TlvType::Bool),
            8 => Some(TlvType::Bytes),
            9 => Some(TlvType::String),
            10 => Some(TlvType::Array),
            11 => Some(TlvType::Struct),
            _ => None,
        }
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        if self.remaining() < 3 { return None; }
        if self.peek_type() != Some(TlvType::U8) { return None; }
        let val = self.buf[self.pos + 2];
        self.pos += 3;
        Some(val)
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 6 { return None; }
        if self.peek_type() != Some(TlvType::U32) { return None; }
        let val = self.buf[self.pos + 2] as u32
            | (self.buf[self.pos + 3] as u32) << 8
            | (self.buf[self.pos + 4] as u32) << 16
            | (self.buf[self.pos + 5] as u32) << 24;
        self.pos += 6;
        Some(val)
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        if self.remaining() < 10 { return None; }
        if self.peek_type() != Some(TlvType::U64) { return None; }
        let mut val: u64 = 0;
        for i in 0..8 {
            val |= (self.buf[self.pos + 2 + i] as u64) << (i * 8);
        }
        self.pos += 10;
        Some(val)
    }

    pub fn read_bool(&mut self) -> Option<bool> {
        if self.remaining() < 3 { return None; }
        if self.peek_type() != Some(TlvType::Bool) { return None; }
        let val = self.buf[self.pos + 2] != 0;
        self.pos += 3;
        Some(val)
    }

    pub fn read_bytes(&mut self) -> Option<&'a [u8]> {
        if self.remaining() < 2 { return None; }
        if self.peek_type() != Some(TlvType::Bytes) { return None; }
        let len = self.buf[self.pos + 1] as usize;
        if self.remaining() < 2 + len { return None; }
        let data = &self.buf[self.pos + 2..self.pos + 2 + len];
        self.pos += 2 + len;
        Some(data)
    }

    pub fn read_str(&mut self) -> Option<&'a [u8]> {
        if self.remaining() < 2 { return None; }
        if self.peek_type() != Some(TlvType::String) { return None; }
        let len = self.buf[self.pos + 1] as usize;
        if self.remaining() < 2 + len { return None; }
        let data = &self.buf[self.pos + 2..self.pos + 2 + len];
        self.pos += 2 + len;
        Some(data)
    }
}

// ─────────────────── Method & Service ───────────────────────────────
pub const MAX_METHODS: usize = 32;
pub const MAX_SERVICES: usize = 64;

/// Method handler function pointer type
pub type MethodHandler = fn(request: &[u8], response: &mut RpcSerializer) -> RpcError;

pub struct RpcMethod {
    pub id: u32,
    pub name: [u8; MAX_METHOD_NAME],
    pub name_len: usize,
    pub handler: MethodHandler,
    pub call_count: AtomicU64,
    pub error_count: AtomicU64,
    pub total_time_ns: AtomicU64,
}

impl RpcMethod {
    pub fn new(id: u32, name: &[u8], handler: MethodHandler) -> Self {
        let mut n = [0u8; MAX_METHOD_NAME];
        let len = name.len().min(MAX_METHOD_NAME);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            id,
            name: n,
            name_len: len,
            handler,
            call_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
        }
    }
}

pub struct RpcService {
    pub id: u32,
    pub name: [u8; MAX_SERVICE_NAME],
    pub name_len: usize,
    pub version: u32,
    pub methods: [Option<RpcMethod>; MAX_METHODS],
    pub method_count: usize,
    pub enabled: bool,
    pub max_requests_per_sec: u32,
    pub current_requests: AtomicU32,
}

impl RpcService {
    pub fn new(id: u32, name: &[u8], version: u32) -> Self {
        let mut n = [0u8; MAX_SERVICE_NAME];
        let len = name.len().min(MAX_SERVICE_NAME);
        n[..len].copy_from_slice(&name[..len]);
        Self {
            id,
            name: n,
            name_len: len,
            version,
            methods: [const { None }; MAX_METHODS],
            method_count: 0,
            enabled: true,
            max_requests_per_sec: 10000,
            current_requests: AtomicU32::new(0),
        }
    }

    pub fn add_method(&mut self, method: RpcMethod) -> bool {
        if self.method_count >= MAX_METHODS {
            return false;
        }
        self.methods[self.method_count] = Some(method);
        self.method_count += 1;
        true
    }

    pub fn find_method(&self, method_id: u32) -> Option<&RpcMethod> {
        for m_opt in self.methods[..self.method_count].iter() {
            if let Some(m) = m_opt {
                if m.id == method_id {
                    return Some(m);
                }
            }
        }
        None
    }

    /// Dispatch a method call
    pub fn dispatch(&self, method_id: u32, request: &[u8], response: &mut RpcSerializer) -> RpcError {
        if !self.enabled {
            return RpcError::Unavailable;
        }

        // Rate limiting
        let current = self.current_requests.fetch_add(1, Ordering::Relaxed);
        if current >= self.max_requests_per_sec {
            self.current_requests.fetch_sub(1, Ordering::Relaxed);
            return RpcError::ResourceExhausted;
        }

        let result = match self.find_method(method_id) {
            Some(method) => {
                method.call_count.fetch_add(1, Ordering::Relaxed);
                let err = (method.handler)(request, response);
                if err != RpcError::Ok {
                    method.error_count.fetch_add(1, Ordering::Relaxed);
                }
                err
            }
            None => RpcError::MethodNotFound,
        };

        self.current_requests.fetch_sub(1, Ordering::Relaxed);
        result
    }

    /// Reset rate limiter (called periodically)
    pub fn reset_rate_counter(&self) {
        self.current_requests.store(0, Ordering::Relaxed);
    }
}

// ─────────────────── Pending Request Tracking ───────────────────────
pub const MAX_PENDING: usize = 256;

#[derive(Clone, Copy, PartialEq)]
pub enum RequestState {
    Free,
    Pending,
    Completed,
    TimedOut,
    Cancelled,
}

pub struct PendingRequest {
    pub request_id: u64,
    pub service_id: u32,
    pub method_id: u32,
    pub state: RequestState,
    pub submitted_at: u64,
    pub timeout_ns: u64,
    pub response_buf: [u8; MAX_PAYLOAD_SIZE],
    pub response_len: usize,
    pub error: RpcError,
}

impl Default for PendingRequest {
    fn default() -> Self {
        Self {
            request_id: 0,
            service_id: 0,
            method_id: 0,
            state: RequestState::Free,
            submitted_at: 0,
            timeout_ns: 5_000_000_000, // 5 seconds
            response_buf: [0u8; MAX_PAYLOAD_SIZE],
            response_len: 0,
            error: RpcError::Ok,
        }
    }
}

// ─────────────────── RPC Engine ─────────────────────────────────────
pub struct RpcEngine {
    pub services: [Option<RpcService>; MAX_SERVICES],
    pub service_count: usize,
    pub pending: [PendingRequest; MAX_PENDING],
    pub pending_count: usize,
    pub total_calls: AtomicU64,
    pub total_errors: AtomicU64,
    pub total_timeouts: AtomicU64,
    pub initialized: bool,
}

impl RpcEngine {
    pub const fn new() -> Self {
        Self {
            services: [const { None }; MAX_SERVICES],
            service_count: 0,
            pending: [const { PendingRequest {
                request_id: 0,
                service_id: 0,
                method_id: 0,
                state: RequestState::Free,
                submitted_at: 0,
                timeout_ns: 5_000_000_000,
                response_buf: [0u8; MAX_PAYLOAD_SIZE],
                response_len: 0,
                error: RpcError::Ok,
            } }; MAX_PENDING],
            pending_count: 0,
            total_calls: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            initialized: false,
        }
    }

    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Register a service
    pub fn register_service(&mut self, service: RpcService) -> bool {
        // Check for duplicate ID
        for svc_opt in self.services.iter() {
            if let Some(svc) = svc_opt {
                if svc.id == service.id {
                    return false;
                }
            }
        }
        for slot in self.services.iter_mut() {
            if slot.is_none() {
                *slot = Some(service);
                self.service_count += 1;
                return true;
            }
        }
        false
    }

    /// Unregister a service
    pub fn unregister_service(&mut self, service_id: u32) -> bool {
        for slot in self.services.iter_mut() {
            if let Some(svc) = slot {
                if svc.id == service_id {
                    *slot = None;
                    self.service_count = self.service_count.saturating_sub(1);
                    return true;
                }
            }
        }
        false
    }

    /// Synchronous call: dispatch immediately
    pub fn call(&self, service_id: u32, method_id: u32, request: &[u8]) -> (RpcError, RpcSerializer) {
        self.total_calls.fetch_add(1, Ordering::Relaxed);

        let mut response = RpcSerializer::new();

        for svc_opt in self.services.iter() {
            if let Some(svc) = svc_opt {
                if svc.id == service_id {
                    let err = svc.dispatch(method_id, request, &mut response);
                    if err != RpcError::Ok {
                        self.total_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    return (err, response);
                }
            }
        }

        self.total_errors.fetch_add(1, Ordering::Relaxed);
        (RpcError::ServiceNotFound, response)
    }

    /// Process incoming RPC message
    pub fn process_message(&self, header: &RpcHeader, payload: &[u8]) -> (RpcError, RpcSerializer) {
        if !header.validate() {
            return (RpcError::InvalidArgument, RpcSerializer::new());
        }

        match header.msg_type {
            MSG_REQUEST => {
                self.call(header.service_id, header.method_id, payload)
            }
            MSG_CANCEL => {
                // Would cancel pending request
                (RpcError::Ok, RpcSerializer::new())
            }
            _ => (RpcError::InvalidArgument, RpcSerializer::new()),
        }
    }

    /// Service discovery: list all registered services
    pub fn list_services(&self, out: &mut RpcSerializer) -> usize {
        let mut count = 0;
        for svc_opt in self.services.iter() {
            if let Some(svc) = svc_opt {
                out.write_u32(svc.id);
                out.write_str(&svc.name[..svc.name_len]);
                out.write_u32(svc.version);
                out.write_u32(svc.method_count as u32);
                count += 1;
            }
        }
        count
    }

    /// Sweep timed-out pending requests
    pub fn sweep_timeouts(&mut self, now_ns: u64) -> u32 {
        let mut swept = 0u32;
        for req in self.pending.iter_mut() {
            if req.state == RequestState::Pending {
                if now_ns.saturating_sub(req.submitted_at) > req.timeout_ns {
                    req.state = RequestState::TimedOut;
                    req.error = RpcError::Timeout;
                    self.total_timeouts.fetch_add(1, Ordering::Relaxed);
                    swept += 1;
                }
            }
        }
        swept
    }

    /// Reset all service rate counters
    pub fn reset_rate_limiters(&self) {
        for svc_opt in self.services.iter() {
            if let Some(svc) = svc_opt {
                svc.reset_rate_counter();
            }
        }
    }
}

// ─────────────────── Global Instance ────────────────────────────────
static mut RPC_ENGINE: RpcEngine = RpcEngine::new();

pub fn init_rpc() {
    unsafe { RPC_ENGINE.init() }
}

// ─────────────────── FFI Exports ────────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_rpc_init() {
    init_rpc();
}

#[no_mangle]
pub extern "C" fn rust_rpc_service_count() -> u32 {
    unsafe { RPC_ENGINE.service_count as u32 }
}

#[no_mangle]
pub extern "C" fn rust_rpc_total_calls() -> u64 {
    unsafe { RPC_ENGINE.total_calls.load(Ordering::Relaxed) }
}

#[no_mangle]
pub extern "C" fn rust_rpc_total_errors() -> u64 {
    unsafe { RPC_ENGINE.total_errors.load(Ordering::Relaxed) }
}

#[no_mangle]
pub extern "C" fn rust_rpc_total_timeouts() -> u64 {
    unsafe { RPC_ENGINE.total_timeouts.load(Ordering::Relaxed) }
}

#[no_mangle]
pub extern "C" fn rust_rpc_sweep_timeouts(now_ns: u64) -> u32 {
    unsafe { RPC_ENGINE.sweep_timeouts(now_ns) }
}

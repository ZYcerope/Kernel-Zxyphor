// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust Networking: HTTP/1.1 Protocol Engine
//
// Full HTTP/1.1 implementation for kernel-space web services:
// - Request parser (method, path, headers, body)
// - Response builder (status codes, headers, chunked transfer)
// - Connection keep-alive and pipelining
// - URL percent-decoding
// - Header field parsing (Content-Length, Transfer-Encoding, Host)
// - Cookie parsing
// - Basic authentication support
// - WebSocket upgrade detection

#![no_std]
#![allow(dead_code)]

// ─────────────────── HTTP Method ────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpMethod {
    Get = 0,
    Head = 1,
    Post = 2,
    Put = 3,
    Delete = 4,
    Patch = 5,
    Options = 6,
    Trace = 7,
    Connect = 8,
}

impl HttpMethod {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"GET" => Some(Self::Get),
            b"HEAD" => Some(Self::Head),
            b"POST" => Some(Self::Post),
            b"PUT" => Some(Self::Put),
            b"DELETE" => Some(Self::Delete),
            b"PATCH" => Some(Self::Patch),
            b"OPTIONS" => Some(Self::Options),
            b"TRACE" => Some(Self::Trace),
            b"CONNECT" => Some(Self::Connect),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }

    pub fn has_body(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

// ─────────────────── HTTP Status ────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HttpStatus {
    // 1xx Informational
    Continue = 100,
    SwitchingProtocols = 101,
    // 2xx Success
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    // 3xx Redirection
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    // 4xx Client Error
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PayloadTooLarge = 413,
    UriTooLong = 414,
    UnsupportedMediaType = 415,
    TooManyRequests = 429,
    // 5xx Server Error
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
}

impl HttpStatus {
    pub fn reason_phrase(&self) -> &'static str {
        match self {
            Self::Continue => "Continue",
            Self::SwitchingProtocols => "Switching Protocols",
            Self::Ok => "OK",
            Self::Created => "Created",
            Self::Accepted => "Accepted",
            Self::NoContent => "No Content",
            Self::ResetContent => "Reset Content",
            Self::PartialContent => "Partial Content",
            Self::MovedPermanently => "Moved Permanently",
            Self::Found => "Found",
            Self::SeeOther => "See Other",
            Self::NotModified => "Not Modified",
            Self::TemporaryRedirect => "Temporary Redirect",
            Self::PermanentRedirect => "Permanent Redirect",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::RequestTimeout => "Request Timeout",
            Self::Conflict => "Conflict",
            Self::Gone => "Gone",
            Self::LengthRequired => "Length Required",
            Self::PayloadTooLarge => "Payload Too Large",
            Self::UriTooLong => "URI Too Long",
            Self::UnsupportedMediaType => "Unsupported Media Type",
            Self::TooManyRequests => "Too Many Requests",
            Self::InternalServerError => "Internal Server Error",
            Self::NotImplemented => "Not Implemented",
            Self::BadGateway => "Bad Gateway",
            Self::ServiceUnavailable => "Service Unavailable",
            Self::GatewayTimeout => "Gateway Timeout",
            Self::HttpVersionNotSupported => "HTTP Version Not Supported",
        }
    }

    pub fn code(&self) -> u16 {
        *self as u16
    }

    pub fn is_informational(&self) -> bool {
        self.code() >= 100 && self.code() < 200
    }

    pub fn is_success(&self) -> bool {
        self.code() >= 200 && self.code() < 300
    }

    pub fn is_redirect(&self) -> bool {
        self.code() >= 300 && self.code() < 400
    }

    pub fn is_client_error(&self) -> bool {
        self.code() >= 400 && self.code() < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.code() >= 500 && self.code() < 600
    }
}

// ─────────────────── HTTP Version ───────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            b"HTTP/1.0" => Some(Self::Http10),
            b"HTTP/1.1" => Some(Self::Http11),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

// ─────────────────── Header ─────────────────────────────────────────
pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADER_NAME: usize = 64;
pub const MAX_HEADER_VALUE: usize = 512;
pub const MAX_PATH: usize = 2048;
pub const MAX_BODY: usize = 65536;
pub const MAX_QUERY_PARAMS: usize = 32;
pub const MAX_COOKIES: usize = 16;

#[derive(Clone)]
pub struct HttpHeader {
    pub name: [u8; MAX_HEADER_NAME],
    pub name_len: usize,
    pub value: [u8; MAX_HEADER_VALUE],
    pub value_len: usize,
}

impl HttpHeader {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_HEADER_NAME],
            name_len: 0,
            value: [0u8; MAX_HEADER_VALUE],
            value_len: 0,
        }
    }

    pub fn set(&mut self, name: &[u8], value: &[u8]) {
        let nlen = name.len().min(MAX_HEADER_NAME);
        self.name[..nlen].copy_from_slice(&name[..nlen]);
        self.name_len = nlen;

        let vlen = value.len().min(MAX_HEADER_VALUE);
        self.value[..vlen].copy_from_slice(&value[..vlen]);
        self.value_len = vlen;
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value[..self.value_len]
    }

    pub fn name_eq_ci(&self, s: &[u8]) -> bool {
        if self.name_len != s.len() {
            return false;
        }
        for i in 0..self.name_len {
            if to_lower(self.name[i]) != to_lower(s[i]) {
                return false;
            }
        }
        true
    }
}

fn to_lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

// ─────────────────── Query Parameter ────────────────────────────────
pub struct QueryParam {
    pub key: [u8; 64],
    pub key_len: usize,
    pub value: [u8; 256],
    pub value_len: usize,
}

impl QueryParam {
    pub const fn new() -> Self {
        Self {
            key: [0u8; 64],
            key_len: 0,
            value: [0u8; 256],
            value_len: 0,
        }
    }
}

// ─────────────────── Cookie ─────────────────────────────────────────
pub struct HttpCookie {
    pub name: [u8; 64],
    pub name_len: usize,
    pub value: [u8; 256],
    pub value_len: usize,
}

impl HttpCookie {
    pub const fn new() -> Self {
        Self {
            name: [0u8; 64],
            name_len: 0,
            value: [0u8; 256],
            value_len: 0,
        }
    }
}

// ─────────────────── HTTP Request ───────────────────────────────────
pub struct HttpRequest {
    pub method: HttpMethod,
    pub version: HttpVersion,
    pub path: [u8; MAX_PATH],
    pub path_len: usize,
    pub query: [u8; MAX_PATH],
    pub query_len: usize,
    pub headers: [HttpHeader; MAX_HEADERS],
    pub header_count: usize,
    pub body: [u8; MAX_BODY],
    pub body_len: usize,
    pub content_length: usize,
    pub keep_alive: bool,
    pub chunked: bool,
    pub host: [u8; 256],
    pub host_len: usize,
    pub params: [QueryParam; MAX_QUERY_PARAMS],
    pub param_count: usize,
    pub cookies: [HttpCookie; MAX_COOKIES],
    pub cookie_count: usize,
    pub is_websocket_upgrade: bool,
}

impl HttpRequest {
    pub const fn new() -> Self {
        Self {
            method: HttpMethod::Get,
            version: HttpVersion::Http11,
            path: [0u8; MAX_PATH],
            path_len: 0,
            query: [0u8; MAX_PATH],
            query_len: 0,
            headers: [const { HttpHeader::new() }; MAX_HEADERS],
            header_count: 0,
            body: [0u8; MAX_BODY],
            body_len: 0,
            content_length: 0,
            keep_alive: true,
            chunked: false,
            host: [0u8; 256],
            host_len: 0,
            params: [const { QueryParam::new() }; MAX_QUERY_PARAMS],
            param_count: 0,
            cookies: [const { HttpCookie::new() }; MAX_COOKIES],
            cookie_count: 0,
            is_websocket_upgrade: false,
        }
    }

    /// Parse a raw HTTP request from bytes. Returns bytes consumed or 0 on error.
    pub fn parse(&mut self, data: &[u8]) -> usize {
        let mut pos = 0;

        // Parse request line: METHOD SP URI SP VERSION CRLF
        let method_end = match find_byte(data, pos, b' ') {
            Some(i) => i,
            None => return 0,
        };
        self.method = match HttpMethod::from_bytes(&data[pos..method_end]) {
            Some(m) => m,
            None => return 0,
        };
        pos = method_end + 1;

        // Parse URI (path + optional query)
        let uri_end = match find_byte(data, pos, b' ') {
            Some(i) => i,
            None => return 0,
        };
        let uri = &data[pos..uri_end];
        self.parse_uri(uri);
        pos = uri_end + 1;

        // Parse version
        let ver_end = match find_crlf(data, pos) {
            Some(i) => i,
            None => return 0,
        };
        self.version = match HttpVersion::from_bytes(&data[pos..ver_end]) {
            Some(v) => v,
            None => return 0,
        };
        pos = ver_end + 2; // Skip CRLF

        // Default keep-alive behavior per version
        self.keep_alive = self.version == HttpVersion::Http11;

        // Parse headers
        self.header_count = 0;
        loop {
            if pos + 1 >= data.len() {
                break;
            }
            // Empty line = end of headers
            if data[pos] == b'\r' && data.get(pos + 1) == Some(&b'\n') {
                pos += 2;
                break;
            }

            let line_end = match find_crlf(data, pos) {
                Some(i) => i,
                None => break,
            };

            // Parse header: Name: Value
            if let Some(colon) = find_byte(data, pos, b':') {
                if colon < line_end && self.header_count < MAX_HEADERS {
                    let name = &data[pos..colon];
                    let mut val_start = colon + 1;
                    // Skip optional whitespace
                    while val_start < line_end && data[val_start] == b' ' {
                        val_start += 1;
                    }
                    let value = &data[val_start..line_end];
                    self.headers[self.header_count].set(name, value);

                    // Process special headers
                    self.process_header(&self.headers[self.header_count].clone());
                    self.header_count += 1;
                }
            }

            pos = line_end + 2;
        }

        // Parse query parameters
        self.parse_query_params();

        // Parse cookies
        self.parse_cookies();

        // Read body if Content-Length present
        if self.content_length > 0 {
            let avail = data.len().saturating_sub(pos);
            let to_read = self.content_length.min(avail).min(MAX_BODY);
            self.body[..to_read].copy_from_slice(&data[pos..pos + to_read]);
            self.body_len = to_read;
            pos += to_read;
        }

        pos
    }

    fn parse_uri(&mut self, uri: &[u8]) {
        // Split on '?'
        let (path, query) = match memchr(uri, b'?') {
            Some(i) => (&uri[..i], &uri[i + 1..]),
            None => (uri, &[] as &[u8]),
        };

        // Percent-decode path
        let decoded_len = percent_decode(path, &mut self.path);
        self.path_len = decoded_len;

        let qlen = query.len().min(MAX_PATH);
        self.query[..qlen].copy_from_slice(&query[..qlen]);
        self.query_len = qlen;
    }

    fn process_header(&mut self, header: &HttpHeader) {
        if header.name_eq_ci(b"Content-Length") {
            self.content_length = parse_usize(header.value_bytes());
        } else if header.name_eq_ci(b"Transfer-Encoding") {
            if bytes_contains_ci(header.value_bytes(), b"chunked") {
                self.chunked = true;
            }
        } else if header.name_eq_ci(b"Connection") {
            if bytes_contains_ci(header.value_bytes(), b"close") {
                self.keep_alive = false;
            } else if bytes_contains_ci(header.value_bytes(), b"keep-alive") {
                self.keep_alive = true;
            }
        } else if header.name_eq_ci(b"Host") {
            let len = header.value_len.min(256);
            self.host[..len].copy_from_slice(&header.value_bytes()[..len]);
            self.host_len = len;
        } else if header.name_eq_ci(b"Upgrade") {
            if bytes_contains_ci(header.value_bytes(), b"websocket") {
                self.is_websocket_upgrade = true;
            }
        }
    }

    fn parse_query_params(&mut self) {
        self.param_count = 0;
        let query = &self.query[..self.query_len];
        let mut start = 0;

        while start < query.len() && self.param_count < MAX_QUERY_PARAMS {
            let end = match memchr(&query[start..], b'&') {
                Some(i) => start + i,
                None => query.len(),
            };

            let pair = &query[start..end];
            if let Some(eq) = memchr(pair, b'=') {
                let key = &pair[..eq];
                let val = &pair[eq + 1..];
                let param = &mut self.params[self.param_count];

                let klen = key.len().min(64);
                param.key[..klen].copy_from_slice(&key[..klen]);
                param.key_len = klen;

                let vlen = percent_decode(val, &mut param.value);
                param.value_len = vlen;

                self.param_count += 1;
            }

            start = end + 1;
        }
    }

    fn parse_cookies(&mut self) {
        self.cookie_count = 0;
        // Find Cookie header
        for i in 0..self.header_count {
            if self.headers[i].name_eq_ci(b"Cookie") {
                let val = &self.headers[i].value[..self.headers[i].value_len];
                let mut start = 0;
                while start < val.len() && self.cookie_count < MAX_COOKIES {
                    // Skip whitespace
                    while start < val.len() && val[start] == b' ' {
                        start += 1;
                    }
                    let end = match memchr(&val[start..], b';') {
                        Some(i) => start + i,
                        None => val.len(),
                    };
                    let pair = &val[start..end];
                    if let Some(eq) = memchr(pair, b'=') {
                        let cookie = &mut self.cookies[self.cookie_count];
                        let nlen = eq.min(64);
                        cookie.name[..nlen].copy_from_slice(&pair[..nlen]);
                        cookie.name_len = nlen;
                        let vlen = (pair.len() - eq - 1).min(256);
                        cookie.value[..vlen].copy_from_slice(&pair[eq + 1..eq + 1 + vlen]);
                        cookie.value_len = vlen;
                        self.cookie_count += 1;
                    }
                    start = end + 1;
                }
                break;
            }
        }
    }

    /// Get a header value by name (case-insensitive)
    pub fn get_header(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.header_count {
            if self.headers[i].name_eq_ci(name) {
                return Some(self.headers[i].value_bytes());
            }
        }
        None
    }

    /// Get a query parameter by key
    pub fn get_param(&self, key: &[u8]) -> Option<&[u8]> {
        for i in 0..self.param_count {
            if &self.params[i].key[..self.params[i].key_len] == key {
                return Some(&self.params[i].value[..self.params[i].value_len]);
            }
        }
        None
    }

    /// Get a cookie by name
    pub fn get_cookie(&self, name: &[u8]) -> Option<&[u8]> {
        for i in 0..self.cookie_count {
            if &self.cookies[i].name[..self.cookies[i].name_len] == name {
                return Some(&self.cookies[i].value[..self.cookies[i].value_len]);
            }
        }
        None
    }

    /// Check if this is a WebSocket upgrade request
    pub fn is_websocket(&self) -> bool {
        self.is_websocket_upgrade
            && self.method == HttpMethod::Get
            && self.get_header(b"Sec-WebSocket-Key").is_some()
    }

    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

// ─────────────────── HTTP Response Builder ──────────────────────────
pub struct HttpResponse {
    pub status: HttpStatus,
    pub version: HttpVersion,
    pub headers: [HttpHeader; MAX_HEADERS],
    pub header_count: usize,
    pub body: [u8; MAX_BODY],
    pub body_len: usize,
    pub chunked: bool,
}

impl HttpResponse {
    pub const fn new() -> Self {
        Self {
            status: HttpStatus::Ok,
            version: HttpVersion::Http11,
            headers: [const { HttpHeader::new() }; MAX_HEADERS],
            header_count: 0,
            body: [0u8; MAX_BODY],
            body_len: 0,
            chunked: false,
        }
    }

    pub fn set_status(&mut self, status: HttpStatus) -> &mut Self {
        self.status = status;
        self
    }

    pub fn add_header(&mut self, name: &[u8], value: &[u8]) -> &mut Self {
        if self.header_count < MAX_HEADERS {
            self.headers[self.header_count].set(name, value);
            self.header_count += 1;
        }
        self
    }

    pub fn set_body(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len().min(MAX_BODY);
        self.body[..len].copy_from_slice(&data[..len]);
        self.body_len = len;
        self
    }

    pub fn set_content_type(&mut self, ct: &[u8]) -> &mut Self {
        self.add_header(b"Content-Type", ct)
    }

    pub fn set_json_body(&mut self, data: &[u8]) -> &mut Self {
        self.set_content_type(b"application/json");
        self.set_body(data)
    }

    pub fn set_html_body(&mut self, data: &[u8]) -> &mut Self {
        self.set_content_type(b"text/html; charset=utf-8");
        self.set_body(data)
    }

    pub fn set_text_body(&mut self, data: &[u8]) -> &mut Self {
        self.set_content_type(b"text/plain; charset=utf-8");
        self.set_body(data)
    }

    /// Enable chunked transfer encoding
    pub fn enable_chunked(&mut self) -> &mut Self {
        self.chunked = true;
        self.add_header(b"Transfer-Encoding", b"chunked")
    }

    /// Set a cookie in the response
    pub fn set_cookie(&mut self, name: &[u8], value: &[u8], path: &[u8], max_age: u32) -> &mut Self {
        let mut buf = [0u8; MAX_HEADER_VALUE];
        let mut pos = 0;

        // name=value
        pos = copy_bytes(&mut buf, pos, name);
        pos = copy_bytes(&mut buf, pos, b"=");
        pos = copy_bytes(&mut buf, pos, value);
        pos = copy_bytes(&mut buf, pos, b"; Path=");
        pos = copy_bytes(&mut buf, pos, path);
        pos = copy_bytes(&mut buf, pos, b"; Max-Age=");
        let age_str = format_u32(max_age);
        pos = copy_bytes(&mut buf, pos, &age_str.0[..age_str.1]);
        pos = copy_bytes(&mut buf, pos, b"; HttpOnly; SameSite=Strict");

        self.add_header(b"Set-Cookie", &buf[..pos])
    }

    /// Redirect to a different URL
    pub fn redirect(&mut self, location: &[u8], permanent: bool) -> &mut Self {
        self.status = if permanent {
            HttpStatus::MovedPermanently
        } else {
            HttpStatus::Found
        };
        self.add_header(b"Location", location)
    }

    /// Serialize the response to bytes. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        // Status line
        pos = copy_bytes(buf, pos, self.version.as_str().as_bytes());
        pos = copy_bytes(buf, pos, b" ");
        let code_str = format_u16(self.status.code());
        pos = copy_bytes(buf, pos, &code_str.0[..code_str.1]);
        pos = copy_bytes(buf, pos, b" ");
        pos = copy_bytes(buf, pos, self.status.reason_phrase().as_bytes());
        pos = copy_bytes(buf, pos, b"\r\n");

        // Headers
        for i in 0..self.header_count {
            pos = copy_bytes(buf, pos, self.headers[i].name_bytes());
            pos = copy_bytes(buf, pos, b": ");
            pos = copy_bytes(buf, pos, self.headers[i].value_bytes());
            pos = copy_bytes(buf, pos, b"\r\n");
        }

        // Content-Length (if not chunked)
        if !self.chunked && self.body_len > 0 {
            pos = copy_bytes(buf, pos, b"Content-Length: ");
            let cl_str = format_usize(self.body_len);
            pos = copy_bytes(buf, pos, &cl_str.0[..cl_str.1]);
            pos = copy_bytes(buf, pos, b"\r\n");
        }

        // End of headers
        pos = copy_bytes(buf, pos, b"\r\n");

        // Body
        if self.body_len > 0 {
            if self.chunked {
                // Write body as a single chunk
                let chunk_size = format_hex_usize(self.body_len);
                pos = copy_bytes(buf, pos, &chunk_size.0[..chunk_size.1]);
                pos = copy_bytes(buf, pos, b"\r\n");
                pos = copy_bytes(buf, pos, &self.body[..self.body_len]);
                pos = copy_bytes(buf, pos, b"\r\n");
                // Terminal chunk
                pos = copy_bytes(buf, pos, b"0\r\n\r\n");
            } else {
                pos = copy_bytes(buf, pos, &self.body[..self.body_len]);
            }
        }

        pos
    }

    /// Quick error response
    pub fn error(status: HttpStatus) -> Self {
        let mut resp = Self::new();
        resp.set_status(status);
        let body = status.reason_phrase().as_bytes();
        resp.set_text_body(body);
        resp
    }
}

// ─────────────────── HTTP Connection State ──────────────────────────
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnState {
    ReadingRequest,
    ProcessingRequest,
    SendingResponse,
    KeepAlive,
    Closing,
}

pub struct HttpConnection {
    pub state: ConnState,
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub requests_served: u32,
    pub max_requests: u32,
    pub idle_timeout_ms: u64,
    pub last_activity_ms: u64,
    /// Receive buffer
    rx_buf: [u8; 8192],
    rx_len: usize,
    /// Transmit buffer
    tx_buf: [u8; MAX_BODY + 4096],
    tx_len: usize,
    tx_sent: usize,
}

impl HttpConnection {
    pub const fn new() -> Self {
        Self {
            state: ConnState::ReadingRequest,
            request: HttpRequest::new(),
            response: HttpResponse::new(),
            requests_served: 0,
            max_requests: 100,
            idle_timeout_ms: 30000,
            last_activity_ms: 0,
            rx_buf: [0u8; 8192],
            rx_len: 0,
            tx_buf: [0u8; MAX_BODY + 4096],
            tx_len: 0,
            tx_sent: 0,
        }
    }

    /// Feed received data into the connection
    pub fn feed_data(&mut self, data: &[u8]) -> bool {
        let space = 8192 - self.rx_len;
        let copy = data.len().min(space);
        self.rx_buf[self.rx_len..self.rx_len + copy].copy_from_slice(&data[..copy]);
        self.rx_len += copy;

        // Try to parse request
        if self.state == ConnState::ReadingRequest || self.state == ConnState::KeepAlive {
            self.request = HttpRequest::new();
            let consumed = self.request.parse(&self.rx_buf[..self.rx_len]);
            if consumed > 0 {
                // Shift remaining data
                let remaining = self.rx_len - consumed;
                if remaining > 0 {
                    self.rx_buf.copy_within(consumed..self.rx_len, 0);
                }
                self.rx_len = remaining;
                self.state = ConnState::ProcessingRequest;
                return true;
            }
        }
        false
    }

    /// Prepare response for sending
    pub fn send_response(&mut self) {
        // Add standard headers
        self.response.add_header(b"Server", b"Zxyphor/1.0");

        if self.request.keep_alive && self.requests_served < self.max_requests {
            self.response.add_header(b"Connection", b"keep-alive");
        } else {
            self.response.add_header(b"Connection", b"close");
        }

        // Serialize
        self.tx_len = self.response.serialize(&mut self.tx_buf);
        self.tx_sent = 0;
        self.state = ConnState::SendingResponse;
    }

    /// Get bytes to transmit. Returns empty slice when done.
    pub fn get_tx_data(&self) -> &[u8] {
        &self.tx_buf[self.tx_sent..self.tx_len]
    }

    /// Acknowledge bytes that were sent
    pub fn ack_tx(&mut self, bytes: usize) {
        self.tx_sent += bytes;
        if self.tx_sent >= self.tx_len {
            self.requests_served += 1;
            if self.request.keep_alive && self.requests_served < self.max_requests {
                self.state = ConnState::KeepAlive;
            } else {
                self.state = ConnState::Closing;
            }
        }
    }

    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        if self.last_activity_ms == 0 {
            return false;
        }
        now_ms.saturating_sub(self.last_activity_ms) > self.idle_timeout_ms
    }

    pub fn update_activity(&mut self, now_ms: u64) {
        self.last_activity_ms = now_ms;
    }
}

// ─────────────────── Simple Router ──────────────────────────────────
pub const MAX_ROUTES: usize = 64;

#[derive(Clone, Copy)]
pub struct Route {
    pub method: HttpMethod,
    pub path: [u8; 128],
    pub path_len: usize,
    pub handler_id: u16,
}

impl Route {
    pub const fn new() -> Self {
        Self {
            method: HttpMethod::Get,
            path: [0u8; 128],
            path_len: 0,
            handler_id: 0,
        }
    }

    pub fn matches(&self, method: HttpMethod, path: &[u8]) -> bool {
        if self.method != method {
            return false;
        }
        let rpath = &self.path[..self.path_len];

        // Exact match
        if rpath == path {
            return true;
        }

        // Wildcard match (route ending with /*)
        if self.path_len >= 2 && rpath[self.path_len - 2] == b'/' && rpath[self.path_len - 1] == b'*' {
            let prefix = &rpath[..self.path_len - 1];
            return path.len() >= prefix.len() && &path[..prefix.len()] == prefix;
        }

        false
    }
}

pub struct HttpRouter {
    routes: [Route; MAX_ROUTES],
    route_count: usize,
}

impl HttpRouter {
    pub const fn new() -> Self {
        Self {
            routes: [const { Route::new() }; MAX_ROUTES],
            route_count: 0,
        }
    }

    pub fn add_route(&mut self, method: HttpMethod, path: &[u8], handler_id: u16) -> bool {
        if self.route_count >= MAX_ROUTES {
            return false;
        }
        let r = &mut self.routes[self.route_count];
        r.method = method;
        let len = path.len().min(128);
        r.path[..len].copy_from_slice(&path[..len]);
        r.path_len = len;
        r.handler_id = handler_id;
        self.route_count += 1;
        true
    }

    pub fn find_route(&self, method: HttpMethod, path: &[u8]) -> Option<u16> {
        for i in 0..self.route_count {
            if self.routes[i].matches(method, path) {
                return Some(self.routes[i].handler_id);
            }
        }
        None
    }

    pub fn get(&mut self, path: &[u8], handler_id: u16) -> bool {
        self.add_route(HttpMethod::Get, path, handler_id)
    }

    pub fn post(&mut self, path: &[u8], handler_id: u16) -> bool {
        self.add_route(HttpMethod::Post, path, handler_id)
    }

    pub fn put(&mut self, path: &[u8], handler_id: u16) -> bool {
        self.add_route(HttpMethod::Put, path, handler_id)
    }

    pub fn delete(&mut self, path: &[u8], handler_id: u16) -> bool {
        self.add_route(HttpMethod::Delete, path, handler_id)
    }
}

// ─────────────────── Utility Functions ──────────────────────────────
fn find_byte(data: &[u8], start: usize, byte: u8) -> Option<usize> {
    for i in start..data.len() {
        if data[i] == byte {
            return Some(i);
        }
    }
    None
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in start..data.len() - 1 {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

fn memchr(data: &[u8], byte: u8) -> Option<usize> {
    for i in 0..data.len() {
        if data[i] == byte {
            return Some(i);
        }
    }
    None
}

fn parse_usize(data: &[u8]) -> usize {
    let mut result: usize = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            result = result.wrapping_mul(10).wrapping_add((b - b'0') as usize);
        } else {
            break;
        }
    }
    result
}

fn percent_decode(input: &[u8], output: &mut [u8]) -> usize {
    let mut i = 0;
    let mut o = 0;
    while i < input.len() && o < output.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hi = hex_digit(input[i + 1]);
            let lo = hex_digit(input[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                output[o] = (h << 4) | l;
                o += 1;
                i += 3;
                continue;
            }
        } else if input[i] == b'+' {
            output[o] = b' ';
            o += 1;
            i += 1;
            continue;
        }
        output[o] = input[i];
        o += 1;
        i += 1;
    }
    o
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn bytes_contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    'outer: for i in 0..=haystack.len() - needle.len() {
        for j in 0..needle.len() {
            if to_lower(haystack[i + j]) != to_lower(needle[j]) {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

fn copy_bytes(dst: &mut [u8], pos: usize, src: &[u8]) -> usize {
    let avail = dst.len().saturating_sub(pos);
    let len = src.len().min(avail);
    dst[pos..pos + len].copy_from_slice(&src[..len]);
    pos + len
}

fn format_u16(val: u16) -> ([u8; 5], usize) {
    let mut buf = [0u8; 5];
    let mut n = val;
    let mut i = 4;
    if n == 0 {
        buf[4] = b'0';
        return (buf, 1);
    }
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let start = i + if val > 0 { 1 } else { 0 };
    let len = 5 - start;
    // Shift to beginning
    let mut out = [0u8; 5];
    out[..len].copy_from_slice(&buf[start..5]);
    (out, len)
}

fn format_u32(val: u32) -> ([u8; 10], usize) {
    let mut buf = [0u8; 10];
    let mut n = val;
    let mut pos = 9;
    if n == 0 {
        buf[0] = b'0';
        return (buf, 1);
    }
    while n > 0 {
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if pos == 0 {
            break;
        }
        pos -= 1;
    }
    let start = pos + 1;
    let len = 10 - start;
    let mut out = [0u8; 10];
    out[..len].copy_from_slice(&buf[start..10]);
    (out, len)
}

fn format_usize(val: usize) -> ([u8; 20], usize) {
    let mut buf = [0u8; 20];
    let mut n = val;
    let mut pos = 19;
    if n == 0 {
        buf[0] = b'0';
        return (buf, 1);
    }
    while n > 0 {
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if pos == 0 {
            break;
        }
        pos -= 1;
    }
    let start = pos + 1;
    let len = 20 - start;
    let mut out = [0u8; 20];
    out[..len].copy_from_slice(&buf[start..20]);
    (out, len)
}

fn format_hex_usize(val: usize) -> ([u8; 16], usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    let mut n = val;
    let mut pos = 15;
    if n == 0 {
        buf[0] = b'0';
        return (buf, 1);
    }
    while n > 0 {
        buf[pos] = HEX[n & 0xF];
        n >>= 4;
        if pos == 0 {
            break;
        }
        pos -= 1;
    }
    let start = pos + 1;
    let len = 16 - start;
    let mut out = [0u8; 16];
    out[..len].copy_from_slice(&buf[start..16]);
    (out, len)
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_http_parse_request(
    data_ptr: *const u8,
    data_len: u32,
    method_out: *mut u8,
    path_out: *mut u8,
    path_len_out: *mut u32,
) -> u32 {
    if data_ptr.is_null() || method_out.is_null() || path_out.is_null() || path_len_out.is_null() {
        return 0;
    }
    let data = unsafe { core::slice::from_raw_parts(data_ptr, data_len as usize) };
    let mut req = HttpRequest::new();
    let consumed = req.parse(data);
    if consumed > 0 {
        unsafe {
            *method_out = req.method as u8;
            let plen = req.path_len.min(2048);
            core::ptr::copy_nonoverlapping(req.path.as_ptr(), path_out, plen);
            *path_len_out = plen as u32;
        }
    }
    consumed as u32
}

#[no_mangle]
pub extern "C" fn rust_http_build_response(
    status_code: u16,
    body_ptr: *const u8,
    body_len: u32,
    out_ptr: *mut u8,
    out_max: u32,
) -> u32 {
    let status = match status_code {
        200 => HttpStatus::Ok,
        201 => HttpStatus::Created,
        204 => HttpStatus::NoContent,
        301 => HttpStatus::MovedPermanently,
        302 => HttpStatus::Found,
        400 => HttpStatus::BadRequest,
        401 => HttpStatus::Unauthorized,
        403 => HttpStatus::Forbidden,
        404 => HttpStatus::NotFound,
        405 => HttpStatus::MethodNotAllowed,
        500 => HttpStatus::InternalServerError,
        503 => HttpStatus::ServiceUnavailable,
        _ => HttpStatus::InternalServerError,
    };

    let mut resp = HttpResponse::new();
    resp.set_status(status);

    if !body_ptr.is_null() && body_len > 0 {
        let body = unsafe { core::slice::from_raw_parts(body_ptr, body_len as usize) };
        resp.set_text_body(body);
    }

    let out = unsafe { core::slice::from_raw_parts_mut(out_ptr, out_max as usize) };
    resp.serialize(out) as u32
}

// SPDX-License-Identifier: MIT
// Zxyphor Kernel — TTY / Line Discipline Subsystem (Rust)
//
// Full TTY layer: terminal devices, line disciplines (N_TTY canonical/raw),
// PTY master/slave pairs, session/process group management, job control signals,
// termios settings, input/output processing, echo, special character handling,
// flow control (XON/XOFF), baud rate management, and console binding.

#![no_std]
#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

pub const MAX_TTY_DEVICES: usize = 64;
pub const MAX_LINE_DISCS: usize = 16;
pub const MAX_PTY_PAIRS: usize = 32;
pub const TTY_BUF_SIZE: usize = 4096;
pub const TTY_NAME_LEN: usize = 32;
pub const CANON_BUF_SIZE: usize = 256;

// TTY major numbers
pub const TTY_MAJOR: u32 = 4;
pub const TTYAUX_MAJOR: u32 = 5;
pub const PTY_MASTER_MAJOR: u32 = 2;
pub const PTY_SLAVE_MAJOR: u32 = 3;
pub const CONSOLE_MAJOR: u32 = 4;

// Line discipline numbers
pub const N_TTY: u8 = 0;
pub const N_SLIP: u8 = 1;
pub const N_PPP: u8 = 3;
pub const N_RAW: u8 = 15;

// TTY ioctl commands
pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;
pub const TIOCGWINSZ: u32 = 0x5413;
pub const TIOCSWINSZ: u32 = 0x5414;
pub const TIOCGPGRP: u32 = 0x540F;
pub const TIOCSPGRP: u32 = 0x5410;
pub const TIOCGSID: u32 = 0x5429;
pub const TIOCSCTTY: u32 = 0x540E;
pub const TIOCNOTTY: u32 = 0x5422;
pub const TIOCOUTQ: u32 = 0x5411;
pub const FIONREAD: u32 = 0x541B;

// Special characters
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const NCCS: usize = 19;

// Input mode flags (c_iflag)
pub const IGNBRK: u32 = 0o000001;
pub const BRKINT: u32 = 0o000002;
pub const IGNPAR: u32 = 0o000004;
pub const PARMRK: u32 = 0o000010;
pub const INPCK: u32 = 0o000020;
pub const ISTRIP: u32 = 0o000040;
pub const INLCR: u32 = 0o000100;
pub const IGNCR: u32 = 0o000200;
pub const ICRNL: u32 = 0o000400;
pub const IXON: u32 = 0o002000;
pub const IXOFF: u32 = 0o010000;
pub const IXANY: u32 = 0o020000;
pub const IMAXBEL: u32 = 0o020000;
pub const IUTF8: u32 = 0o040000;

// Output mode flags (c_oflag)
pub const OPOST: u32 = 0o000001;
pub const ONLCR: u32 = 0o000004;
pub const OCRNL: u32 = 0o000010;
pub const ONOCR: u32 = 0o000020;
pub const ONLRET: u32 = 0o000040;
pub const TABDLY: u32 = 0o014000;

// Control mode flags (c_cflag)
pub const CSIZE: u32 = 0o000060;
pub const CS5: u32 = 0o000000;
pub const CS6: u32 = 0o000020;
pub const CS7: u32 = 0o000040;
pub const CS8: u32 = 0o000060;
pub const CSTOPB: u32 = 0o000100;
pub const CREAD: u32 = 0o000200;
pub const PARENB: u32 = 0o000400;
pub const PARODD: u32 = 0o001000;
pub const HUPCL: u32 = 0o002000;
pub const CLOCAL: u32 = 0o004000;

// Local mode flags (c_lflag)
pub const ISIG: u32 = 0o000001;
pub const ICANON: u32 = 0o000002;
pub const ECHO: u32 = 0o000010;
pub const ECHOE: u32 = 0o000020;
pub const ECHOK: u32 = 0o000040;
pub const ECHONL: u32 = 0o000100;
pub const NOFLSH: u32 = 0o000200;
pub const TOSTOP: u32 = 0o000400;
pub const ECHOCTL: u32 = 0o001000;
pub const ECHOPRT: u32 = 0o002000;
pub const ECHOKE: u32 = 0o004000;
pub const IEXTEN: u32 = 0o100000;

// Baud rates
pub const B0: u32 = 0;
pub const B50: u32 = 1;
pub const B75: u32 = 2;
pub const B110: u32 = 3;
pub const B134: u32 = 4;
pub const B150: u32 = 5;
pub const B200: u32 = 6;
pub const B300: u32 = 7;
pub const B600: u32 = 8;
pub const B1200: u32 = 9;
pub const B2400: u32 = 11;
pub const B4800: u32 = 12;
pub const B9600: u32 = 13;
pub const B19200: u32 = 14;
pub const B38400: u32 = 15;
pub const B57600: u32 = 4097;
pub const B115200: u32 = 4098;
pub const B230400: u32 = 4099;
pub const B460800: u32 = 4100;

// ============================================================================
// Termios
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    pub const fn default_cooked() -> Self {
        let mut cc = [0u8; NCCS];
        cc[VINTR] = 3;    // ^C
        cc[VQUIT] = 28;   // ^\   
        cc[VERASE] = 127;  // DEL
        cc[VKILL] = 21;   // ^U
        cc[VEOF] = 4;     // ^D
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[VSTART] = 17;  // ^Q
        cc[VSTOP] = 19;   // ^S
        cc[VSUSP] = 26;   // ^Z
        cc[VEOL] = 0;
        cc[VREPRINT] = 18; // ^R
        cc[VDISCARD] = 15; // ^O
        cc[VWERASE] = 23;  // ^W
        cc[VLNEXT] = 22;   // ^V

        Self {
            c_iflag: ICRNL | IXON | IXOFF | IUTF8,
            c_oflag: OPOST | ONLCR,
            c_cflag: CS8 | CREAD | HUPCL,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            c_line: N_TTY,
            c_cc: cc,
            c_ispeed: B38400,
            c_ospeed: B38400,
        }
    }

    pub const fn raw() -> Self {
        let cc = [0u8; NCCS];
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: CS8 | CREAD,
            c_lflag: 0,
            c_line: N_TTY,
            c_cc: cc,
            c_ispeed: B38400,
            c_ospeed: B38400,
        }
    }

    pub fn is_canonical(&self) -> bool {
        (self.c_lflag & ICANON) != 0
    }

    pub fn is_echo(&self) -> bool {
        (self.c_lflag & ECHO) != 0
    }

    pub fn is_sig(&self) -> bool {
        (self.c_lflag & ISIG) != 0
    }

    pub fn has_opost(&self) -> bool {
        (self.c_oflag & OPOST) != 0
    }

    pub fn baud_to_rate(baud: u32) -> u32 {
        match baud {
            B0 => 0,
            B50 => 50,
            B75 => 75,
            B110 => 110,
            B150 => 150,
            B300 => 300,
            B600 => 600,
            B1200 => 1200,
            B2400 => 2400,
            B4800 => 4800,
            B9600 => 9600,
            B19200 => 19200,
            B38400 => 38400,
            B57600 => 57600,
            B115200 => 115200,
            B230400 => 230400,
            B460800 => 460800,
            _ => 9600,
        }
    }
}

// ============================================================================
// Window Size
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

impl Winsize {
    pub const fn default() -> Self {
        Self {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

// ============================================================================
// Ring buffer for TTY I/O
// ============================================================================

pub struct TtyBuffer {
    data: [u8; TTY_BUF_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl TtyBuffer {
    pub const fn new() -> Self {
        Self {
            data: [0u8; TTY_BUF_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count >= TTY_BUF_SIZE
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn space(&self) -> usize {
        TTY_BUF_SIZE - self.count
    }

    pub fn put(&mut self, byte: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.data[self.head] = byte;
        self.head = (self.head + 1) % TTY_BUF_SIZE;
        self.count += 1;
        true
    }

    pub fn get(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let byte = self.data[self.tail];
        self.tail = (self.tail + 1) % TTY_BUF_SIZE;
        self.count -= 1;
        Some(byte)
    }

    pub fn peek(&self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        Some(self.data[self.tail])
    }

    pub fn write_buf(&mut self, buf: &[u8]) -> usize {
        let mut written = 0;
        for &b in buf {
            if !self.put(b) {
                break;
            }
            written += 1;
        }
        written
    }

    pub fn read_buf(&mut self, buf: &mut [u8]) -> usize {
        let mut read = 0;
        for slot in buf.iter_mut() {
            match self.get() {
                Some(b) => {
                    *slot = b;
                    read += 1;
                }
                None => break,
            }
        }
        read
    }

    pub fn flush(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }

    /// Erase the last byte (for backspace in canonical mode)
    pub fn erase_last(&mut self) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.head == 0 {
            self.head = TTY_BUF_SIZE - 1;
        } else {
            self.head -= 1;
        }
        self.count -= 1;
        true
    }

    /// Kill (erase) the entire current line in canonical buffer
    pub fn kill_line(&mut self) -> usize {
        let killed = self.count;
        self.flush();
        killed
    }

    /// Erase the last word (for ^W in canonical mode)
    pub fn erase_word(&mut self) -> usize {
        let mut erased = 0;
        // Skip trailing spaces
        while !self.is_empty() {
            let prev = if self.head == 0 {
                TTY_BUF_SIZE - 1
            } else {
                self.head - 1
            };
            if self.data[prev] == b' ' || self.data[prev] == b'\t' {
                self.head = prev;
                self.count -= 1;
                erased += 1;
            } else {
                break;
            }
        }
        // Erase word characters
        while !self.is_empty() {
            let prev = if self.head == 0 {
                TTY_BUF_SIZE - 1
            } else {
                self.head - 1
            };
            if self.data[prev] != b' ' && self.data[prev] != b'\t' {
                self.head = prev;
                self.count -= 1;
                erased += 1;
            } else {
                break;
            }
        }
        erased
    }
}

// ============================================================================
// TTY device type
// ============================================================================

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TtyType {
    Console = 0,
    Serial = 1,
    PtyMaster = 2,
    PtySlave = 3,
    Virtual = 4,
}

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum TtyState {
    Closed = 0,
    Open = 1,
    HungUp = 2,
    Closing = 3,
}

// ============================================================================
// TTY Device
// ============================================================================

pub struct TtyDevice {
    /// Device name (e.g., "tty0", "pts/0")
    name: [u8; TTY_NAME_LEN],
    name_len: u8,
    /// Device type
    tty_type: TtyType,
    /// State
    state: TtyState,
    /// Major/minor numbers
    major: u32,
    minor: u32,
    /// Termios settings
    termios: Termios,
    /// Window size
    winsize: Winsize,
    /// Line discipline index
    ldisc: u8,
    /// Input buffer (from hardware/pty master)
    input_buf: TtyBuffer,
    /// Output buffer (to hardware/pty master) 
    output_buf: TtyBuffer,
    /// Canonical line editing buffer
    canon_buf: TtyBuffer,
    /// Session leader PID
    session: u32,
    /// Foreground process group
    pgrp: u32,
    /// Open count
    open_count: u32,
    /// PTY pair index (for pty master/slave)
    pty_pair: u16,
    /// Flow control state
    stopped: bool,      // Output stopped (XOFF received or flow control)
    hw_stopped: bool,   // Hardware flow control stopped
    /// Flags
    exclusive: bool,    // Exclusive open
    no_carrier: bool,   // No carrier detect
    /// Stats
    rx_bytes: u64,
    tx_bytes: u64,
    rx_chars: u64,
    tx_chars: u64,
    overrun_count: u32,
    break_count: u32,
}

impl TtyDevice {
    pub const fn new() -> Self {
        Self {
            name: [0u8; TTY_NAME_LEN],
            name_len: 0,
            tty_type: TtyType::Console,
            state: TtyState::Closed,
            major: 0,
            minor: 0,
            termios: Termios::default_cooked(),
            winsize: Winsize::default(),
            ldisc: N_TTY,
            input_buf: TtyBuffer::new(),
            output_buf: TtyBuffer::new(),
            canon_buf: TtyBuffer::new(),
            session: 0,
            pgrp: 0,
            open_count: 0,
            pty_pair: 0xFFFF,
            stopped: false,
            hw_stopped: false,
            exclusive: false,
            no_carrier: false,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_chars: 0,
            tx_chars: 0,
            overrun_count: 0,
            break_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = if name.len() > TTY_NAME_LEN { TTY_NAME_LEN } else { name.len() };
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn open(&mut self) -> bool {
        if self.state == TtyState::HungUp {
            return false;
        }
        if self.exclusive && self.open_count > 0 {
            return false;
        }
        self.state = TtyState::Open;
        self.open_count += 1;
        true
    }

    pub fn close(&mut self) {
        if self.open_count > 0 {
            self.open_count -= 1;
        }
        if self.open_count == 0 {
            self.state = TtyState::Closed;
            self.session = 0;
            self.pgrp = 0;
        }
    }

    pub fn hangup(&mut self) {
        self.state = TtyState::HungUp;
        self.input_buf.flush();
        self.output_buf.flush();
        self.canon_buf.flush();
        // Signal SIGHUP to foreground process group
        if self.pgrp != 0 {
            extern "C" {
                fn rust_tty_signal_pgrp(pgrp: u32, sig: i32);
            }
            unsafe { rust_tty_signal_pgrp(self.pgrp, 1); } // SIGHUP=1
        }
        self.session = 0;
        self.pgrp = 0;
    }

    /// Process input through line discipline (N_TTY)
    pub fn receive_char(&mut self, ch: u8) {
        self.rx_bytes += 1;
        self.rx_chars += 1;

        let termios = &self.termios;
        let mut c = ch;

        // Input processing (c_iflag)
        if (termios.c_iflag & ISTRIP) != 0 {
            c &= 0x7F; // Strip 8th bit
        }

        if (termios.c_iflag & INLCR) != 0 && c == b'\n' {
            c = b'\r';
        } else if (termios.c_iflag & IGNCR) != 0 && c == b'\r' {
            return; // Ignore CR
        } else if (termios.c_iflag & ICRNL) != 0 && c == b'\r' {
            c = b'\n';
        }

        // Flow control (XON/XOFF)
        if (termios.c_iflag & IXON) != 0 {
            if c == termios.c_cc[VSTOP] {
                self.stopped = true;
                return;
            }
            if c == termios.c_cc[VSTART] || ((termios.c_iflag & IXANY) != 0 && self.stopped) {
                self.stopped = false;
                if c == termios.c_cc[VSTART] {
                    return;
                }
            }
        }

        // Signal characters (c_lflag & ISIG)
        if termios.is_sig() {
            if c == termios.c_cc[VINTR] {
                self.signal_char(2); // SIGINT
                if (termios.c_lflag & NOFLSH) == 0 {
                    self.input_buf.flush();
                    self.canon_buf.flush();
                }
                if termios.is_echo() {
                    self.echo_char(b'^');
                    self.echo_char(b'C');
                    self.echo_char(b'\n');
                }
                return;
            }
            if c == termios.c_cc[VQUIT] {
                self.signal_char(3); // SIGQUIT
                if (termios.c_lflag & NOFLSH) == 0 {
                    self.input_buf.flush();
                    self.canon_buf.flush();
                }
                if termios.is_echo() {
                    self.echo_char(b'^');
                    self.echo_char(b'\\');
                    self.echo_char(b'\n');
                }
                return;
            }
            if c == termios.c_cc[VSUSP] {
                self.signal_char(20); // SIGTSTP
                if termios.is_echo() {
                    self.echo_char(b'^');
                    self.echo_char(b'Z');
                    self.echo_char(b'\n');
                }
                return;
            }
        }

        // Canonical mode processing
        if termios.is_canonical() {
            if c == termios.c_cc[VERASE] {
                // Backspace — erase one character
                if self.canon_buf.erase_last() && termios.is_echo() {
                    if (termios.c_lflag & ECHOE) != 0 {
                        self.echo_char(8);   // BS
                        self.echo_char(b' ');
                        self.echo_char(8);   // BS
                    }
                }
                return;
            }
            if c == termios.c_cc[VKILL] {
                // Kill line
                let killed = self.canon_buf.kill_line();
                if termios.is_echo() {
                    if (termios.c_lflag & ECHOKE) != 0 {
                        for _ in 0..killed {
                            self.echo_char(8);
                            self.echo_char(b' ');
                            self.echo_char(8);
                        }
                    } else if (termios.c_lflag & ECHOK) != 0 {
                        self.echo_char(b'\n');
                    }
                }
                return;
            }
            if c == termios.c_cc[VWERASE] && (termios.c_lflag & IEXTEN) != 0 {
                let erased = self.canon_buf.erase_word();
                if termios.is_echo() {
                    for _ in 0..erased {
                        self.echo_char(8);
                        self.echo_char(b' ');
                        self.echo_char(8);
                    }
                }
                return;
            }
            if c == termios.c_cc[VREPRINT] && (termios.c_lflag & IEXTEN) != 0 {
                // Reprint current line
                self.echo_char(b'^');
                self.echo_char(b'R');
                self.echo_char(b'\n');
                // Re-echo canon buffer contents
                let saved_tail = self.canon_buf.tail;
                let saved_count = self.canon_buf.count;
                let mut pos = self.canon_buf.tail;
                for _ in 0..self.canon_buf.count {
                    self.echo_char(self.canon_buf.data[pos]);
                    pos = (pos + 1) % TTY_BUF_SIZE;
                }
                // Restore (peek-only iteration, don't consume)
                let _ = saved_tail;
                let _ = saved_count;
                return;
            }

            // Check for line completion (EOL / EOF / NL)
            let is_eol = c == b'\n' || c == termios.c_cc[VEOF] || c == termios.c_cc[VEOL];

            if !is_eol {
                // Buffer the character
                if !self.canon_buf.put(c) {
                    // Buffer full — ring bell if IMAXBEL
                    if (termios.c_iflag & IMAXBEL) != 0 {
                        self.echo_char(7); // BEL
                    }
                    return;
                }
                if termios.is_echo() {
                    if c < 32 && c != b'\t' && (termios.c_lflag & ECHOCTL) != 0 {
                        self.echo_char(b'^');
                        self.echo_char(c + 64);
                    } else {
                        self.echo_char(c);
                    }
                }
            } else {
                // Line complete — copy canon buffer to input buffer
                if c != termios.c_cc[VEOF] {
                    self.canon_buf.put(c);
                }
                // Flush canon -> input
                while let Some(b) = self.canon_buf.get() {
                    self.input_buf.put(b);
                }
                if termios.is_echo() {
                    if c == b'\n' {
                        self.echo_char(b'\n');
                    } else if (termios.c_lflag & ECHONL) != 0 {
                        self.echo_char(b'\n');
                    }
                }
            }
        } else {
            // Raw / non-canonical mode — put directly into input buffer
            self.input_buf.put(c);
            if termios.is_echo() {
                self.echo_char(c);
            }
        }
    }

    /// Write output through line discipline
    pub fn write_char(&mut self, ch: u8) -> bool {
        let mut c = ch;

        // Output processing (c_oflag)
        if self.termios.has_opost() {
            if (self.termios.c_oflag & ONLCR) != 0 && c == b'\n' {
                // NL -> CR NL
                if !self.output_buf.put(b'\r') {
                    return false;
                }
                self.tx_bytes += 1;
            }
            if (self.termios.c_oflag & OCRNL) != 0 && c == b'\r' {
                c = b'\n';
            }
            if (self.termios.c_oflag & ONOCR) != 0 && c == b'\r' {
                // Don't output CR at column 0 (simplified: always output)
            }
            if (self.termios.c_oflag & ONLRET) != 0 && c == b'\n' {
                // NL performs CR function (simplified)
            }
        }

        if self.stopped {
            return false; // Output stopped via flow control
        }

        if self.output_buf.put(c) {
            self.tx_bytes += 1;
            self.tx_chars += 1;
            true
        } else {
            false
        }
    }

    pub fn write_buf(&mut self, data: &[u8]) -> usize {
        let mut written = 0;
        for &b in data {
            if !self.write_char(b) {
                break;
            }
            written += 1;
        }
        written
    }

    /// Read from input buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if self.state == TtyState::HungUp {
            return 0;
        }

        if self.termios.is_canonical() {
            // In canonical mode, only return complete lines
            // Check if there's a complete line in input_buf
            self.input_buf.read_buf(buf)
        } else {
            // Non-canonical: return up to VMIN chars, with VTIME timeout
            let vmin = self.termios.c_cc[VMIN] as usize;
            let max_read = if vmin > 0 && vmin < buf.len() { vmin } else { buf.len() };
            let available = self.input_buf.len();
            let to_read = if available < max_read { available } else { max_read };
            self.input_buf.read_buf(&mut buf[..to_read])
        }
    }

    fn echo_char(&mut self, c: u8) {
        self.output_buf.put(c);
        self.tx_bytes += 1;
    }

    fn signal_char(&self, sig: i32) {
        if self.pgrp != 0 {
            extern "C" {
                fn rust_tty_signal_pgrp(pgrp: u32, sig: i32);
            }
            unsafe { rust_tty_signal_pgrp(self.pgrp, sig); }
        }
    }

    /// ioctl dispatch
    pub fn ioctl(&mut self, cmd: u32, arg: u64) -> i64 {
        match cmd {
            TIOCGWINSZ => {
                // Return winsize encoding: row << 48 | col << 32 | xpixel << 16 | ypixel
                let val = ((self.winsize.ws_row as u64) << 48)
                    | ((self.winsize.ws_col as u64) << 32)
                    | ((self.winsize.ws_xpixel as u64) << 16)
                    | (self.winsize.ws_ypixel as u64);
                val as i64
            }
            TIOCSWINSZ => {
                self.winsize.ws_row = ((arg >> 48) & 0xFFFF) as u16;
                self.winsize.ws_col = ((arg >> 32) & 0xFFFF) as u16;
                self.winsize.ws_xpixel = ((arg >> 16) & 0xFFFF) as u16;
                self.winsize.ws_ypixel = (arg & 0xFFFF) as u16;
                // Signal SIGWINCH to foreground pgid
                if self.pgrp != 0 {
                    self.signal_char(28); // SIGWINCH
                }
                0
            }
            TIOCGPGRP => self.pgrp as i64,
            TIOCSPGRP => {
                self.pgrp = arg as u32;
                0
            }
            TIOCGSID => self.session as i64,
            TIOCSCTTY => {
                self.session = arg as u32;
                0
            }
            TIOCOUTQ => self.output_buf.len() as i64,
            FIONREAD => self.input_buf.len() as i64,
            _ => -22, // EINVAL
        }
    }
}

// ============================================================================
// PTY pair (master + slave)
// ============================================================================

pub struct PtyPair {
    master_idx: u16,
    slave_idx: u16,
    active: bool,
    pts_number: u16, // /dev/pts/N
}

impl PtyPair {
    pub const fn new() -> Self {
        Self {
            master_idx: 0xFFFF,
            slave_idx: 0xFFFF,
            active: false,
            pts_number: 0,
        }
    }
}

// ============================================================================
// TTY Manager
// ============================================================================

pub struct TtyManager {
    devices: [TtyDevice; MAX_TTY_DEVICES],
    device_count: u32,

    pty_pairs: [PtyPair; MAX_PTY_PAIRS],
    pty_count: u32,
    next_pts: u16,

    /// Stats
    total_opens: u64,
    total_closes: u64,
    total_hangups: u64,
    total_rx: u64,
    total_tx: u64,
}

impl TtyManager {
    pub const fn new() -> Self {
        Self {
            devices: [const { TtyDevice::new() }; MAX_TTY_DEVICES],
            device_count: 0,
            pty_pairs: [const { PtyPair::new() }; MAX_PTY_PAIRS],
            pty_count: 0,
            next_pts: 0,
            total_opens: 0,
            total_closes: 0,
            total_hangups: 0,
            total_rx: 0,
            total_tx: 0,
        }
    }

    /// Register a new TTY device
    pub fn register_tty(&mut self, name: &[u8], tty_type: TtyType, major: u32, minor: u32) -> Option<u16> {
        if self.device_count as usize >= MAX_TTY_DEVICES {
            return None;
        }
        let idx = self.device_count as usize;
        self.devices[idx].set_name(name);
        self.devices[idx].tty_type = tty_type;
        self.devices[idx].major = major;
        self.devices[idx].minor = minor;
        self.device_count += 1;
        Some(idx as u16)
    }

    /// Register console TTY devices (tty0..ttyN)
    pub fn register_consoles(&mut self, count: u8) -> u8 {
        let mut registered = 0;
        for i in 0..count {
            let mut name = [0u8; 8];
            name[0] = b't';
            name[1] = b't';
            name[2] = b'y';
            if i < 10 {
                name[3] = b'0' + i;
            } else {
                name[3] = b'0' + (i / 10);
                name[4] = b'0' + (i % 10);
            }
            if self.register_tty(&name[..if i < 10 { 4 } else { 5 }],
                                 TtyType::Console, CONSOLE_MAJOR, i as u32).is_some() {
                registered += 1;
            }
        }
        registered
    }

    /// Register serial TTY devices (ttyS0..ttySN)
    pub fn register_serial(&mut self, count: u8) -> u8 {
        let mut registered = 0;
        for i in 0..count {
            let mut name = [0u8; 8];
            name[0] = b't';
            name[1] = b't';
            name[2] = b'y';
            name[3] = b'S';
            name[4] = b'0' + i;
            if self.register_tty(&name[..5], TtyType::Serial, TTY_MAJOR, 64 + i as u32).is_some() {
                registered += 1;
            }
        }
        registered
    }

    /// Allocate a PTY master/slave pair
    pub fn alloc_pty(&mut self) -> Option<(u16, u16)> {
        if self.pty_count as usize >= MAX_PTY_PAIRS {
            return None;
        }
        let pts_num = self.next_pts;
        self.next_pts += 1;

        // Allocate master
        let master_idx = self.register_tty(b"ptmx", TtyType::PtyMaster,
                                            PTY_MASTER_MAJOR, pts_num as u32)?;

        // Allocate slave — name "pts/N"
        let mut slave_name = [0u8; 12];
        slave_name[0] = b'p';
        slave_name[1] = b't';
        slave_name[2] = b's';
        slave_name[3] = b'/';
        let nlen = format_u16(pts_num, &mut slave_name[4..]);
        let slave_idx = self.register_tty(&slave_name[..4 + nlen],
                                           TtyType::PtySlave, PTY_SLAVE_MAJOR, pts_num as u32)?;

        // Link them
        self.devices[master_idx as usize].pty_pair = self.pty_count as u16;
        self.devices[slave_idx as usize].pty_pair = self.pty_count as u16;

        let pair_idx = self.pty_count as usize;
        self.pty_pairs[pair_idx] = PtyPair {
            master_idx,
            slave_idx,
            active: true,
            pts_number: pts_num,
        };
        self.pty_count += 1;

        Some((master_idx, slave_idx))
    }

    /// Open a TTY device
    pub fn open(&mut self, idx: u16) -> bool {
        if idx as usize >= self.device_count as usize {
            return false;
        }
        let result = self.devices[idx as usize].open();
        if result {
            self.total_opens += 1;
        }
        result
    }

    /// Close a TTY device
    pub fn close(&mut self, idx: u16) {
        if idx as usize >= self.device_count as usize {
            return;
        }
        self.devices[idx as usize].close();
        self.total_closes += 1;

        // If PTY and last close, close the pair
        let dev = &self.devices[idx as usize];
        if dev.open_count == 0 && dev.pty_pair != 0xFFFF {
            let pair = &self.pty_pairs[dev.pty_pair as usize];
            if pair.active {
                // Hangup the other end
                let other = if idx == pair.master_idx {
                    pair.slave_idx
                } else {
                    pair.master_idx
                };
                if self.devices[other as usize].state == TtyState::Open {
                    self.devices[other as usize].hangup();
                    self.total_hangups += 1;
                }
            }
        }
    }

    /// Receive data from hardware into a TTY
    pub fn receive_buf(&mut self, idx: u16, data: &[u8]) -> usize {
        if idx as usize >= self.device_count as usize {
            return 0;
        }
        let mut processed = 0;
        for &b in data {
            self.devices[idx as usize].receive_char(b);
            processed += 1;
        }
        self.total_rx += processed as u64;

        // For PTY: mirror input to master's output / slave's input
        let dev = &self.devices[idx as usize];
        if dev.pty_pair != 0xFFFF {
            let pair_idx = dev.pty_pair as usize;
            if pair_idx < self.pty_count as usize && self.pty_pairs[pair_idx].active {
                let other = if idx == self.pty_pairs[pair_idx].master_idx {
                    self.pty_pairs[pair_idx].slave_idx
                } else {
                    self.pty_pairs[pair_idx].master_idx
                };
                // Forward output buffer to the other end's input
                // (done during flush_output)
            }
        }

        processed
    }

    /// Write data to a TTY's output
    pub fn write(&mut self, idx: u16, data: &[u8]) -> usize {
        if idx as usize >= self.device_count as usize {
            return 0;
        }
        let written = self.devices[idx as usize].write_buf(data);
        self.total_tx += written as u64;
        written
    }

    /// Read from a TTY
    pub fn read(&mut self, idx: u16, buf: &mut [u8]) -> usize {
        if idx as usize >= self.device_count as usize {
            return 0;
        }
        self.devices[idx as usize].read(buf)
    }

    /// Flush output buffer — transfer to hardware or PTY peer
    pub fn flush_output(&mut self, idx: u16) -> usize {
        if idx as usize >= self.device_count as usize {
            return 0;
        }

        let mut flushed = 0;
        let dev_type = self.devices[idx as usize].tty_type;
        let pty_pair = self.devices[idx as usize].pty_pair;

        // Read all from output buffer
        let mut tmp = [0u8; 256];
        let n = self.devices[idx as usize].output_buf.read_buf(&mut tmp);
        if n == 0 {
            return 0;
        }

        match dev_type {
            TtyType::Console | TtyType::Virtual => {
                // Send to console driver
                extern "C" {
                    fn rust_tty_console_write(data: *const u8, len: usize);
                }
                unsafe { rust_tty_console_write(tmp.as_ptr(), n); }
                flushed = n;
            }
            TtyType::Serial => {
                // Send to UART
                extern "C" {
                    fn rust_tty_serial_write(minor: u32, data: *const u8, len: usize);
                }
                let minor = self.devices[idx as usize].minor;
                unsafe { rust_tty_serial_write(minor, tmp.as_ptr(), n); }
                flushed = n;
            }
            TtyType::PtyMaster | TtyType::PtySlave => {
                // Forward to peer's input buffer
                if pty_pair != 0xFFFF && (pty_pair as usize) < self.pty_count as usize {
                    let pair = &self.pty_pairs[pty_pair as usize];
                    if pair.active {
                        let peer = if idx == pair.master_idx {
                            pair.slave_idx
                        } else {
                            pair.master_idx
                        };
                        flushed = self.devices[peer as usize].input_buf.write_buf(&tmp[..n]);
                    }
                }
            }
        }

        flushed
    }

    /// Set termios on a TTY
    pub fn set_termios(&mut self, idx: u16, termios: &Termios) {
        if idx as usize >= self.device_count as usize {
            return;
        }
        self.devices[idx as usize].termios = *termios;
    }

    /// Get termios from a TTY
    pub fn get_termios(&self, idx: u16) -> Option<&Termios> {
        if idx as usize >= self.device_count as usize {
            return None;
        }
        Some(&self.devices[idx as usize].termios)
    }

    /// Set to raw mode
    pub fn set_raw(&mut self, idx: u16) {
        if idx as usize >= self.device_count as usize {
            return;
        }
        self.devices[idx as usize].termios = Termios::raw();
    }

    /// ioctl dispatch
    pub fn ioctl(&mut self, idx: u16, cmd: u32, arg: u64) -> i64 {
        if idx as usize >= self.device_count as usize {
            return -9; // EBADF
        }
        self.devices[idx as usize].ioctl(cmd, arg)
    }

    /// Set controlling terminal for session
    pub fn set_ctty(&mut self, idx: u16, session: u32, pgrp: u32) {
        if idx as usize >= self.device_count as usize {
            return;
        }
        self.devices[idx as usize].session = session;
        self.devices[idx as usize].pgrp = pgrp;
    }

    /// Hangup a TTY 
    pub fn hangup(&mut self, idx: u16) {
        if idx as usize >= self.device_count as usize {
            return;
        }
        self.devices[idx as usize].hangup();
        self.total_hangups += 1;
    }

    /// Periodic tick — flush outputs, check timeouts
    pub fn tick(&mut self) {
        for i in 0..self.device_count as usize {
            if self.devices[i].state == TtyState::Open {
                if self.devices[i].output_buf.len() > 0 {
                    self.flush_output(i as u16);
                }
            }
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn format_u16(val: u16, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut n = val;
    let mut digits = [0u8; 5];
    let mut len = 0;
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let write_len = if len > buf.len() { buf.len() } else { len };
    for i in 0..write_len {
        buf[i] = digits[len - 1 - i];
    }
    write_len
}

// ============================================================================
// Global Instance
// ============================================================================

static mut TTY_MANAGER: TtyManager = TtyManager::new();

fn mgr() -> &'static mut TtyManager {
    unsafe { &mut TTY_MANAGER }
}

// ============================================================================
// FFI Exports
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_tty_init() {
    let m = mgr();
    *m = TtyManager::new();
    // Register default console and serial TTYs
    m.register_consoles(6); // tty0..tty5
    m.register_serial(4);   // ttyS0..ttyS3
}

#[no_mangle]
pub extern "C" fn rust_tty_alloc_pty() -> i32 {
    match mgr().alloc_pty() {
        Some((master, _slave)) => master as i32,
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn rust_tty_open(idx: u16) -> i32 {
    if mgr().open(idx) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn rust_tty_close(idx: u16) {
    mgr().close(idx);
}

#[no_mangle]
pub extern "C" fn rust_tty_write(idx: u16, data: *const u8, len: usize) -> usize {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    mgr().write(idx, slice)
}

#[no_mangle]
pub extern "C" fn rust_tty_read(idx: u16, buf: *mut u8, len: usize) -> usize {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    mgr().read(idx, slice)
}

#[no_mangle]
pub extern "C" fn rust_tty_receive(idx: u16, data: *const u8, len: usize) -> usize {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, len) };
    mgr().receive_buf(idx, slice)
}

#[no_mangle]
pub extern "C" fn rust_tty_ioctl(idx: u16, cmd: u32, arg: u64) -> i64 {
    mgr().ioctl(idx, cmd, arg)
}

#[no_mangle]
pub extern "C" fn rust_tty_set_ctty(idx: u16, session: u32, pgrp: u32) {
    mgr().set_ctty(idx, session, pgrp);
}

#[no_mangle]
pub extern "C" fn rust_tty_set_raw(idx: u16) {
    mgr().set_raw(idx);
}

#[no_mangle]
pub extern "C" fn rust_tty_hangup(idx: u16) {
    mgr().hangup(idx);
}

#[no_mangle]
pub extern "C" fn rust_tty_flush(idx: u16) -> usize {
    mgr().flush_output(idx)
}

#[no_mangle]
pub extern "C" fn rust_tty_tick() {
    mgr().tick();
}

#[no_mangle]
pub extern "C" fn rust_tty_device_count() -> u32 {
    mgr().device_count
}

#[no_mangle]
pub extern "C" fn rust_tty_pty_count() -> u32 {
    mgr().pty_count
}

#[no_mangle]
pub extern "C" fn rust_tty_total_rx() -> u64 {
    mgr().total_rx
}

#[no_mangle]
pub extern "C" fn rust_tty_total_tx() -> u64 {
    mgr().total_tx
}

#[no_mangle]
pub extern "C" fn rust_tty_total_opens() -> u64 {
    mgr().total_opens
}

#[no_mangle]
pub extern "C" fn rust_tty_total_hangups() -> u64 {
    mgr().total_hangups
}

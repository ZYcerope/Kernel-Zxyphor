// SPDX-License-Identifier: MIT
// Zxyphor Kernel — PS/2 Controller Driver (Zig)
//
// Intel 8042 PS/2 controller with keyboard and mouse support:
// - Port I/O: data port 0x60, command/status port 0x64
// - Command protocol: write commands, read ACK, timeout handling
// - Scan code set 2 (default) + set 1 translation
// - Full keymap: letters, digits, F-keys, modifier tracking
// - Mouse: standard 3-byte protocol, intellimouse 4-byte (scroll)
// - IRQ1 (keyboard) and IRQ12 (mouse) handlers
// - Key repeat with typematic delay/rate
// - LED control: caps/num/scroll lock

const std = @import("std");

// ─────────── I/O Ports ──────────────────────────────────────────────

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_COMMAND: u16 = 0x64;

// ─────────── Status Register ────────────────────────────────────────

const STATUS_OUTPUT_FULL: u8 = 0x01;
const STATUS_INPUT_FULL: u8 = 0x02;
const STATUS_SYSTEM_FLAG: u8 = 0x04;
const STATUS_CMD_DATA: u8 = 0x08;
const STATUS_TIMEOUT: u8 = 0x40;
const STATUS_PARITY: u8 = 0x80;

// ─────────── Controller Commands ────────────────────────────────────

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_TEST_PORT2: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_TEST_PORT1: u8 = 0xAB;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;
const CMD_WRITE_PORT2: u8 = 0xD4;

// ─────────── Device Commands ────────────────────────────────────────

const DEV_RESET: u8 = 0xFF;
const DEV_ENABLE_SCANNING: u8 = 0xF4;
const DEV_DISABLE_SCANNING: u8 = 0xF5;
const DEV_SET_DEFAULTS: u8 = 0xF6;
const DEV_SET_LEDS: u8 = 0xED;
const DEV_SET_SCANCODE_SET: u8 = 0xF0;
const DEV_SET_TYPEMATIC: u8 = 0xF3;
const DEV_IDENTIFY: u8 = 0xF2;
const DEV_SET_SAMPLE_RATE: u8 = 0xF3;

const DEV_ACK: u8 = 0xFA;
const DEV_RESEND: u8 = 0xFE;
const DEV_TEST_PASSED: u8 = 0xAA;
const SELF_TEST_PASSED: u8 = 0x55;

// ─────────── Key Codes ──────────────────────────────────────────────

pub const KEY_NONE: u8 = 0;
pub const KEY_ESCAPE: u8 = 1;
pub const KEY_1: u8 = 2;
pub const KEY_2: u8 = 3;
pub const KEY_3: u8 = 4;
pub const KEY_4: u8 = 5;
pub const KEY_5: u8 = 6;
pub const KEY_6: u8 = 7;
pub const KEY_7: u8 = 8;
pub const KEY_8: u8 = 9;
pub const KEY_9: u8 = 10;
pub const KEY_0: u8 = 11;
pub const KEY_MINUS: u8 = 12;
pub const KEY_EQUAL: u8 = 13;
pub const KEY_BACKSPACE: u8 = 14;
pub const KEY_TAB: u8 = 15;
pub const KEY_Q: u8 = 16;
pub const KEY_W: u8 = 17;
pub const KEY_E: u8 = 18;
pub const KEY_R: u8 = 19;
pub const KEY_T: u8 = 20;
pub const KEY_Y: u8 = 21;
pub const KEY_U: u8 = 22;
pub const KEY_I: u8 = 23;
pub const KEY_O: u8 = 24;
pub const KEY_P: u8 = 25;
pub const KEY_LBRACKET: u8 = 26;
pub const KEY_RBRACKET: u8 = 27;
pub const KEY_ENTER: u8 = 28;
pub const KEY_LCTRL: u8 = 29;
pub const KEY_A: u8 = 30;
pub const KEY_S: u8 = 31;
pub const KEY_D: u8 = 32;
pub const KEY_F: u8 = 33;
pub const KEY_G: u8 = 34;
pub const KEY_H: u8 = 35;
pub const KEY_J: u8 = 36;
pub const KEY_K: u8 = 37;
pub const KEY_L: u8 = 38;
pub const KEY_SEMICOLON: u8 = 39;
pub const KEY_APOSTROPHE: u8 = 40;
pub const KEY_BACKTICK: u8 = 41;
pub const KEY_LSHIFT: u8 = 42;
pub const KEY_BACKSLASH: u8 = 43;
pub const KEY_Z: u8 = 44;
pub const KEY_X: u8 = 45;
pub const KEY_C: u8 = 46;
pub const KEY_V: u8 = 47;
pub const KEY_B: u8 = 48;
pub const KEY_N: u8 = 49;
pub const KEY_M: u8 = 50;
pub const KEY_COMMA: u8 = 51;
pub const KEY_DOT: u8 = 52;
pub const KEY_SLASH: u8 = 53;
pub const KEY_RSHIFT: u8 = 54;
pub const KEY_KP_STAR: u8 = 55;
pub const KEY_LALT: u8 = 56;
pub const KEY_SPACE: u8 = 57;
pub const KEY_CAPSLOCK: u8 = 58;
pub const KEY_F1: u8 = 59;
pub const KEY_F2: u8 = 60;
pub const KEY_F3: u8 = 61;
pub const KEY_F4: u8 = 62;
pub const KEY_F5: u8 = 63;
pub const KEY_F6: u8 = 64;
pub const KEY_F7: u8 = 65;
pub const KEY_F8: u8 = 66;
pub const KEY_F9: u8 = 67;
pub const KEY_F10: u8 = 68;
pub const KEY_NUMLOCK: u8 = 69;
pub const KEY_SCROLLLOCK: u8 = 70;
pub const KEY_F11: u8 = 71;
pub const KEY_F12: u8 = 72;
pub const KEY_UP: u8 = 73;
pub const KEY_DOWN: u8 = 74;
pub const KEY_LEFT: u8 = 75;
pub const KEY_RIGHT: u8 = 76;
pub const KEY_HOME: u8 = 77;
pub const KEY_END: u8 = 78;
pub const KEY_PGUP: u8 = 79;
pub const KEY_PGDN: u8 = 80;
pub const KEY_INSERT: u8 = 81;
pub const KEY_DELETE: u8 = 82;

// ─────────── Modifier State ─────────────────────────────────────────

pub const ModState = packed struct(u8) {
    lshift: bool = false,
    rshift: bool = false,
    lctrl: bool = false,
    rctrl: bool = false,
    lalt: bool = false,
    ralt: bool = false,
    capslock: bool = false,
    numlock: bool = false,
};

// ─────────── Key Event ──────────────────────────────────────────────

pub const KeyEvent = struct {
    keycode: u8,
    ascii: u8,
    pressed: bool,
    modifiers: ModState,
    timestamp: u64,
};

// ─────────── Mouse Packet ───────────────────────────────────────────

pub const MouseButton = packed struct(u8) {
    left: bool = false,
    right: bool = false,
    middle: bool = false,
    _pad: u5 = 0,
};

pub const MouseEvent = struct {
    dx: i16,
    dy: i16,
    dz: i8,          // Scroll wheel
    buttons: MouseButton,
    timestamp: u64,
};

// ─────────── Keyboard Ring Buffer ───────────────────────────────────

const KEY_BUFFER_SIZE: u16 = 128;

const KeyBuffer = struct {
    events: [KEY_BUFFER_SIZE]KeyEvent,
    head: u16 = 0,
    tail: u16 = 0,
    count: u16 = 0,

    fn push(self: *KeyBuffer, ev: KeyEvent) void {
        if (self.count >= KEY_BUFFER_SIZE) return;
        self.events[self.head] = ev;
        self.head = (self.head + 1) % KEY_BUFFER_SIZE;
        self.count += 1;
    }

    fn pop(self: *KeyBuffer) ?KeyEvent {
        if (self.count == 0) return null;
        const ev = self.events[self.tail];
        self.tail = (self.tail + 1) % KEY_BUFFER_SIZE;
        self.count -= 1;
        return ev;
    }
};

// ─────────── Mouse Ring Buffer ──────────────────────────────────────

const MOUSE_BUFFER_SIZE: u16 = 64;

const MouseBuffer = struct {
    events: [MOUSE_BUFFER_SIZE]MouseEvent,
    head: u16 = 0,
    tail: u16 = 0,
    count: u16 = 0,

    fn push(self: *MouseBuffer, ev: MouseEvent) void {
        if (self.count >= MOUSE_BUFFER_SIZE) return;
        self.events[self.head] = ev;
        self.head = (self.head + 1) % MOUSE_BUFFER_SIZE;
        self.count += 1;
    }

    fn pop(self: *MouseBuffer) ?MouseEvent {
        if (self.count == 0) return null;
        const ev = self.events[self.tail];
        self.tail = (self.tail + 1) % MOUSE_BUFFER_SIZE;
        self.count -= 1;
        return ev;
    }
};

// ─────────── Scan Code Set 1 to Keycode Table ──────────────────────

const SCANCODE_SET1_MAP: [128]u8 = blk: {
    var map = [_]u8{KEY_NONE} ** 128;
    map[0x01] = KEY_ESCAPE;
    map[0x02] = KEY_1;
    map[0x03] = KEY_2;
    map[0x04] = KEY_3;
    map[0x05] = KEY_4;
    map[0x06] = KEY_5;
    map[0x07] = KEY_6;
    map[0x08] = KEY_7;
    map[0x09] = KEY_8;
    map[0x0A] = KEY_9;
    map[0x0B] = KEY_0;
    map[0x0C] = KEY_MINUS;
    map[0x0D] = KEY_EQUAL;
    map[0x0E] = KEY_BACKSPACE;
    map[0x0F] = KEY_TAB;
    map[0x10] = KEY_Q;
    map[0x11] = KEY_W;
    map[0x12] = KEY_E;
    map[0x13] = KEY_R;
    map[0x14] = KEY_T;
    map[0x15] = KEY_Y;
    map[0x16] = KEY_U;
    map[0x17] = KEY_I;
    map[0x18] = KEY_O;
    map[0x19] = KEY_P;
    map[0x1A] = KEY_LBRACKET;
    map[0x1B] = KEY_RBRACKET;
    map[0x1C] = KEY_ENTER;
    map[0x1D] = KEY_LCTRL;
    map[0x1E] = KEY_A;
    map[0x1F] = KEY_S;
    map[0x20] = KEY_D;
    map[0x21] = KEY_F;
    map[0x22] = KEY_G;
    map[0x23] = KEY_H;
    map[0x24] = KEY_J;
    map[0x25] = KEY_K;
    map[0x26] = KEY_L;
    map[0x27] = KEY_SEMICOLON;
    map[0x28] = KEY_APOSTROPHE;
    map[0x29] = KEY_BACKTICK;
    map[0x2A] = KEY_LSHIFT;
    map[0x2B] = KEY_BACKSLASH;
    map[0x2C] = KEY_Z;
    map[0x2D] = KEY_X;
    map[0x2E] = KEY_C;
    map[0x2F] = KEY_V;
    map[0x30] = KEY_B;
    map[0x31] = KEY_N;
    map[0x32] = KEY_M;
    map[0x33] = KEY_COMMA;
    map[0x34] = KEY_DOT;
    map[0x35] = KEY_SLASH;
    map[0x36] = KEY_RSHIFT;
    map[0x37] = KEY_KP_STAR;
    map[0x38] = KEY_LALT;
    map[0x39] = KEY_SPACE;
    map[0x3A] = KEY_CAPSLOCK;
    map[0x3B] = KEY_F1;
    map[0x3C] = KEY_F2;
    map[0x3D] = KEY_F3;
    map[0x3E] = KEY_F4;
    map[0x3F] = KEY_F5;
    map[0x40] = KEY_F6;
    map[0x41] = KEY_F7;
    map[0x42] = KEY_F8;
    map[0x43] = KEY_F9;
    map[0x44] = KEY_F10;
    map[0x45] = KEY_NUMLOCK;
    map[0x46] = KEY_SCROLLLOCK;
    map[0x57] = KEY_F11;
    map[0x58] = KEY_F12;
    break :blk map;
};

// ─────────── Keycode to ASCII ───────────────────────────────────────

const KEYCODE_ASCII: [83]u8 = blk: {
    var map = [_]u8{0} ** 83;
    map[KEY_1] = '1';
    map[KEY_2] = '2';
    map[KEY_3] = '3';
    map[KEY_4] = '4';
    map[KEY_5] = '5';
    map[KEY_6] = '6';
    map[KEY_7] = '7';
    map[KEY_8] = '8';
    map[KEY_9] = '9';
    map[KEY_0] = '0';
    map[KEY_MINUS] = '-';
    map[KEY_EQUAL] = '=';
    map[KEY_TAB] = '\t';
    map[KEY_Q] = 'q';
    map[KEY_W] = 'w';
    map[KEY_E] = 'e';
    map[KEY_R] = 'r';
    map[KEY_T] = 't';
    map[KEY_Y] = 'y';
    map[KEY_U] = 'u';
    map[KEY_I] = 'i';
    map[KEY_O] = 'o';
    map[KEY_P] = 'p';
    map[KEY_LBRACKET] = '[';
    map[KEY_RBRACKET] = ']';
    map[KEY_ENTER] = '\n';
    map[KEY_A] = 'a';
    map[KEY_S] = 's';
    map[KEY_D] = 'd';
    map[KEY_F] = 'f';
    map[KEY_G] = 'g';
    map[KEY_H] = 'h';
    map[KEY_J] = 'j';
    map[KEY_K] = 'k';
    map[KEY_L] = 'l';
    map[KEY_SEMICOLON] = ';';
    map[KEY_APOSTROPHE] = '\'';
    map[KEY_BACKTICK] = '`';
    map[KEY_BACKSLASH] = '\\';
    map[KEY_Z] = 'z';
    map[KEY_X] = 'x';
    map[KEY_C] = 'c';
    map[KEY_V] = 'v';
    map[KEY_B] = 'b';
    map[KEY_N] = 'n';
    map[KEY_M] = 'm';
    map[KEY_COMMA] = ',';
    map[KEY_DOT] = '.';
    map[KEY_SLASH] = '/';
    map[KEY_SPACE] = ' ';
    break :blk map;
};

const KEYCODE_ASCII_SHIFTED: [83]u8 = blk: {
    var map = [_]u8{0} ** 83;
    map[KEY_1] = '!';
    map[KEY_2] = '@';
    map[KEY_3] = '#';
    map[KEY_4] = '$';
    map[KEY_5] = '%';
    map[KEY_6] = '^';
    map[KEY_7] = '&';
    map[KEY_8] = '*';
    map[KEY_9] = '(';
    map[KEY_0] = ')';
    map[KEY_MINUS] = '_';
    map[KEY_EQUAL] = '+';
    map[KEY_TAB] = '\t';
    map[KEY_Q] = 'Q';
    map[KEY_W] = 'W';
    map[KEY_E] = 'E';
    map[KEY_R] = 'R';
    map[KEY_T] = 'T';
    map[KEY_Y] = 'Y';
    map[KEY_U] = 'U';
    map[KEY_I] = 'I';
    map[KEY_O] = 'O';
    map[KEY_P] = 'P';
    map[KEY_LBRACKET] = '{';
    map[KEY_RBRACKET] = '}';
    map[KEY_ENTER] = '\n';
    map[KEY_A] = 'A';
    map[KEY_S] = 'S';
    map[KEY_D] = 'D';
    map[KEY_F] = 'F';
    map[KEY_G] = 'G';
    map[KEY_H] = 'H';
    map[KEY_J] = 'J';
    map[KEY_K] = 'K';
    map[KEY_L] = 'L';
    map[KEY_SEMICOLON] = ':';
    map[KEY_APOSTROPHE] = '"';
    map[KEY_BACKTICK] = '~';
    map[KEY_BACKSLASH] = '|';
    map[KEY_Z] = 'Z';
    map[KEY_X] = 'X';
    map[KEY_C] = 'C';
    map[KEY_V] = 'V';
    map[KEY_B] = 'B';
    map[KEY_N] = 'N';
    map[KEY_M] = 'M';
    map[KEY_COMMA] = '<';
    map[KEY_DOT] = '>';
    map[KEY_SLASH] = '?';
    map[KEY_SPACE] = ' ';
    break :blk map;
};

// ─────────── Port I/O (x86_64) ─────────────────────────────────────

inline fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (port),
    );
}

inline fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "N{dx}" (port),
    );
}

fn io_wait() void {
    outb(0x80, 0); // POST code port for delay
}

// ─────────── Controller Helpers ─────────────────────────────────────

fn wait_write_ready() bool {
    var timeout: u32 = 100000;
    while (timeout > 0) {
        if ((inb(PS2_STATUS) & STATUS_INPUT_FULL) == 0) return true;
        timeout -= 1;
    }
    return false;
}

fn wait_read_ready() bool {
    var timeout: u32 = 100000;
    while (timeout > 0) {
        if ((inb(PS2_STATUS) & STATUS_OUTPUT_FULL) != 0) return true;
        timeout -= 1;
    }
    return false;
}

fn send_command(cmd: u8) void {
    _ = wait_write_ready();
    outb(PS2_COMMAND, cmd);
}

fn send_data(data: u8) void {
    _ = wait_write_ready();
    outb(PS2_DATA, data);
}

fn read_data() ?u8 {
    if (wait_read_ready()) {
        return inb(PS2_DATA);
    }
    return null;
}

fn send_device_cmd(port2: bool, cmd: u8) ?u8 {
    if (port2) {
        send_command(CMD_WRITE_PORT2);
    }
    send_data(cmd);
    return read_data();
}

// ─────────── PS/2 Controller State ──────────────────────────────────

const PS2DeviceType = enum(u8) {
    none = 0,
    keyboard_at = 1,
    keyboard_mf2 = 2,
    mouse_standard = 3,
    mouse_scroll = 4,
    mouse_5button = 5,
};

const PS2State = struct {
    // Controller
    initialized: bool = false,
    dual_channel: bool = false,
    config_byte: u8 = 0,

    // Port 1 (keyboard)
    port1_present: bool = false,
    port1_type: PS2DeviceType = .none,

    // Port 2 (mouse)
    port2_present: bool = false,
    port2_type: PS2DeviceType = .none,

    // Keyboard state
    modifiers: ModState = .{},
    scrolllock: bool = false,
    extended_key: bool = false,
    key_buffer: KeyBuffer = .{ .events = undefined },
    key_state: [128]bool = [_]bool{false} ** 128,

    // Typematic repeat
    repeat_keycode: u8 = 0,
    repeat_delay: u16 = 500,      // ms before repeat starts
    repeat_rate: u16 = 30,        // repeats per second
    repeat_tick: u64 = 0,
    repeat_active: bool = false,

    // Mouse state
    mouse_buffer: MouseBuffer = .{ .events = undefined },
    mouse_byte_idx: u8 = 0,
    mouse_bytes: [4]u8 = [_]u8{0} ** 4,
    mouse_has_scroll: bool = false,

    // LED state
    led_capslock: bool = false,
    led_numlock: bool = false,
    led_scrolllock: bool = false,

    // Stats
    total_keystrokes: u64 = 0,
    total_mouse_events: u64 = 0,
    total_errors: u64 = 0,
    tick: u64 = 0,
};

var g_ps2: PS2State = .{};

// ─────────── Controller Initialization ──────────────────────────────

pub fn init() bool {
    // Step 1: Disable both ports
    send_command(CMD_DISABLE_PORT1);
    send_command(CMD_DISABLE_PORT2);

    // Flush output buffer
    _ = inb(PS2_DATA);

    // Step 2: Read config, disable IRQs and translation
    send_command(CMD_READ_CONFIG);
    const cfg = read_data() orelse return false;
    const new_cfg = cfg & ~@as(u8, 0x43); // Clear IRQ1, IRQ12, translation
    send_command(CMD_WRITE_CONFIG);
    send_data(new_cfg);
    g_ps2.config_byte = new_cfg;

    // Step 3: Self-test
    send_command(CMD_SELF_TEST);
    const test_result = read_data() orelse return false;
    if (test_result != SELF_TEST_PASSED) {
        g_ps2.total_errors += 1;
        return false;
    }

    // Restore config after self-test (some controllers reset it)
    send_command(CMD_WRITE_CONFIG);
    send_data(new_cfg);

    // Step 4: Check for dual channel
    send_command(CMD_ENABLE_PORT2);
    send_command(CMD_READ_CONFIG);
    const cfg2 = read_data() orelse return false;
    g_ps2.dual_channel = (cfg2 & 0x20) == 0; // Bit 5 clear = port 2 exists
    if (g_ps2.dual_channel) {
        send_command(CMD_DISABLE_PORT2);
    }

    // Step 5: Test ports
    send_command(CMD_TEST_PORT1);
    if (read_data()) |result| {
        g_ps2.port1_present = (result == 0);
    }

    if (g_ps2.dual_channel) {
        send_command(CMD_TEST_PORT2);
        if (read_data()) |result| {
            g_ps2.port2_present = (result == 0);
        }
    }

    // Step 6: Enable ports and IRQs
    if (g_ps2.port1_present) {
        send_command(CMD_ENABLE_PORT1);
        init_keyboard();
    }
    if (g_ps2.port2_present) {
        send_command(CMD_ENABLE_PORT2);
        init_mouse();
    }

    // Enable IRQs in config
    var final_cfg = new_cfg;
    if (g_ps2.port1_present) final_cfg |= 0x01; // IRQ1
    if (g_ps2.port2_present) final_cfg |= 0x02; // IRQ12
    if (g_ps2.port1_present) final_cfg |= 0x40; // Translation
    send_command(CMD_WRITE_CONFIG);
    send_data(final_cfg);
    g_ps2.config_byte = final_cfg;

    g_ps2.initialized = true;
    return true;
}

fn init_keyboard() void {
    // Reset
    const ack = send_device_cmd(false, DEV_RESET);
    if (ack) |a| {
        if (a == DEV_ACK) {
            _ = read_data(); // BAT result
        }
    }

    // Set scan code set 2
    _ = send_device_cmd(false, DEV_SET_SCANCODE_SET);
    _ = send_device_cmd(false, 2);

    // Set typematic: 500ms delay, 30 cps
    _ = send_device_cmd(false, DEV_SET_TYPEMATIC);
    _ = send_device_cmd(false, 0x00); // Fastest repeat, shortest delay

    // Enable scanning
    _ = send_device_cmd(false, DEV_ENABLE_SCANNING);

    g_ps2.port1_type = .keyboard_mf2;
}

fn init_mouse() void {
    // Reset
    const ack = send_device_cmd(true, DEV_RESET);
    if (ack) |a| {
        if (a == DEV_ACK) {
            _ = read_data(); // BAT
            _ = read_data(); // Device ID
        }
    }

    // Try to enable scroll wheel (Intellimouse)
    _ = send_device_cmd(true, DEV_SET_SAMPLE_RATE);
    _ = send_device_cmd(true, 200);
    _ = send_device_cmd(true, DEV_SET_SAMPLE_RATE);
    _ = send_device_cmd(true, 100);
    _ = send_device_cmd(true, DEV_SET_SAMPLE_RATE);
    _ = send_device_cmd(true, 80);

    // Read device ID
    _ = send_device_cmd(true, DEV_IDENTIFY);
    if (read_data()) |id| {
        if (id == 3) {
            g_ps2.mouse_has_scroll = true;
            g_ps2.port2_type = .mouse_scroll;
        } else {
            g_ps2.port2_type = .mouse_standard;
        }
    } else {
        g_ps2.port2_type = .mouse_standard;
    }

    // Set sample rate 100
    _ = send_device_cmd(true, DEV_SET_SAMPLE_RATE);
    _ = send_device_cmd(true, 100);

    // Enable data reporting
    _ = send_device_cmd(true, DEV_ENABLE_SCANNING);
}

// ─────────── LED Control ────────────────────────────────────────────

fn update_leds() void {
    var led_byte: u8 = 0;
    if (g_ps2.led_scrolllock) led_byte |= 0x01;
    if (g_ps2.led_numlock) led_byte |= 0x02;
    if (g_ps2.led_capslock) led_byte |= 0x04;
    _ = send_device_cmd(false, DEV_SET_LEDS);
    _ = send_device_cmd(false, led_byte);
}

// ─────────── Keyboard IRQ Handler ───────────────────────────────────

pub fn keyboard_irq_handler() void {
    if (!g_ps2.initialized) return;
    const scancode = inb(PS2_DATA);
    process_scancode(scancode);
}

fn process_scancode(raw: u8) void {
    // Extended scancode prefix
    if (raw == 0xE0) {
        g_ps2.extended_key = true;
        return;
    }
    if (raw == 0xE1) {
        // Pause/Break sequence — ignore for now
        g_ps2.extended_key = false;
        return;
    }

    const released = (raw & 0x80) != 0;
    const code = raw & 0x7F;

    var keycode: u8 = KEY_NONE;

    if (g_ps2.extended_key) {
        g_ps2.extended_key = false;
        // Map extended codes
        keycode = switch (code) {
            0x48 => KEY_UP,
            0x50 => KEY_DOWN,
            0x4B => KEY_LEFT,
            0x4D => KEY_RIGHT,
            0x47 => KEY_HOME,
            0x4F => KEY_END,
            0x49 => KEY_PGUP,
            0x51 => KEY_PGDN,
            0x52 => KEY_INSERT,
            0x53 => KEY_DELETE,
            0x1D => KEY_LCTRL, // Right Ctrl
            0x38 => KEY_LALT,  // Right Alt
            else => KEY_NONE,
        };
    } else {
        if (code < 128) {
            keycode = SCANCODE_SET1_MAP[code];
        }
    }

    if (keycode == KEY_NONE) return;

    const pressed = !released;

    // Track key state
    if (keycode < 128) {
        g_ps2.key_state[keycode] = pressed;
    }

    // Update modifiers
    update_modifiers(keycode, pressed);

    // Handle typematic repeat
    if (pressed) {
        g_ps2.repeat_keycode = keycode;
        g_ps2.repeat_tick = g_ps2.tick + g_ps2.repeat_delay;
        g_ps2.repeat_active = false;
    } else if (keycode == g_ps2.repeat_keycode) {
        g_ps2.repeat_keycode = 0;
        g_ps2.repeat_active = false;
    }

    // Convert to ASCII
    const ascii = keycode_to_ascii(keycode, g_ps2.modifiers);

    const ev = KeyEvent{
        .keycode = keycode,
        .ascii = ascii,
        .pressed = pressed,
        .modifiers = g_ps2.modifiers,
        .timestamp = g_ps2.tick,
    };
    g_ps2.key_buffer.push(ev);

    if (pressed) {
        g_ps2.total_keystrokes += 1;
    }
}

fn update_modifiers(keycode: u8, pressed: bool) void {
    switch (keycode) {
        KEY_LSHIFT => g_ps2.modifiers.lshift = pressed,
        KEY_RSHIFT => g_ps2.modifiers.rshift = pressed,
        KEY_LCTRL => g_ps2.modifiers.lctrl = pressed,
        KEY_LALT => g_ps2.modifiers.lalt = pressed,
        KEY_CAPSLOCK => {
            if (pressed) {
                g_ps2.modifiers.capslock = !g_ps2.modifiers.capslock;
                g_ps2.led_capslock = g_ps2.modifiers.capslock;
                update_leds();
            }
        },
        KEY_NUMLOCK => {
            if (pressed) {
                g_ps2.modifiers.numlock = !g_ps2.modifiers.numlock;
                g_ps2.led_numlock = g_ps2.modifiers.numlock;
                update_leds();
            }
        },
        KEY_SCROLLLOCK => {
            if (pressed) {
                g_ps2.scrolllock = !g_ps2.scrolllock;
                g_ps2.led_scrolllock = g_ps2.scrolllock;
                update_leds();
            }
        },
        else => {},
    }
}

fn keycode_to_ascii(keycode: u8, mods: ModState) u8 {
    if (keycode >= 83) return 0;
    const shifted = mods.lshift or mods.rshift;
    const caps = mods.capslock;

    var ascii: u8 = undefined;
    if (shifted) {
        ascii = KEYCODE_ASCII_SHIFTED[keycode];
    } else {
        ascii = KEYCODE_ASCII[keycode];
    }

    // Capslock affects letters only
    if (caps and !shifted) {
        if (ascii >= 'a' and ascii <= 'z') {
            ascii -= 32;
        }
    } else if (caps and shifted) {
        if (ascii >= 'A' and ascii <= 'Z') {
            ascii += 32;
        }
    }

    return ascii;
}

// ─────────── Mouse IRQ Handler ──────────────────────────────────────

pub fn mouse_irq_handler() void {
    if (!g_ps2.initialized or !g_ps2.port2_present) return;
    const byte = inb(PS2_DATA);
    process_mouse_byte(byte);
}

fn process_mouse_byte(byte: u8) void {
    const expected_bytes: u8 = if (g_ps2.mouse_has_scroll) 4 else 3;

    // Validate first byte (bit 3 should always be set)
    if (g_ps2.mouse_byte_idx == 0) {
        if ((byte & 0x08) == 0) {
            // Out of sync — skip
            g_ps2.total_errors += 1;
            return;
        }
    }

    g_ps2.mouse_bytes[g_ps2.mouse_byte_idx] = byte;
    g_ps2.mouse_byte_idx += 1;

    if (g_ps2.mouse_byte_idx >= expected_bytes) {
        g_ps2.mouse_byte_idx = 0;

        const b0 = g_ps2.mouse_bytes[0];
        const raw_dx: i16 = @as(i16, g_ps2.mouse_bytes[1]);
        const raw_dy: i16 = @as(i16, g_ps2.mouse_bytes[2]);

        // Sign extend using bits 4 and 5 of byte 0
        var dx: i16 = raw_dx;
        var dy: i16 = raw_dy;
        if ((b0 & 0x10) != 0) dx = dx - 256; // X sign
        if ((b0 & 0x20) != 0) dy = dy - 256; // Y sign
        dy = -dy; // Invert Y (PS/2 is bottom-up)

        var dz: i8 = 0;
        if (g_ps2.mouse_has_scroll) {
            const raw_dz: i8 = @bitCast(g_ps2.mouse_bytes[3] & 0x0F);
            if ((g_ps2.mouse_bytes[3] & 0x08) != 0) {
                dz = raw_dz | @as(i8, @bitCast(@as(u8, 0xF0)));
            } else {
                dz = raw_dz;
            }
        }

        const buttons = MouseButton{
            .left = (b0 & 0x01) != 0,
            .right = (b0 & 0x02) != 0,
            .middle = (b0 & 0x04) != 0,
        };

        const ev = MouseEvent{
            .dx = dx,
            .dy = dy,
            .dz = dz,
            .buttons = buttons,
            .timestamp = g_ps2.tick,
        };
        g_ps2.mouse_buffer.push(ev);
        g_ps2.total_mouse_events += 1;
    }
}

// ─────────── Tick / Polling ─────────────────────────────────────────

pub fn tick() void {
    g_ps2.tick += 1;

    // Handle typematic repeat
    if (g_ps2.repeat_keycode != 0 and g_ps2.tick >= g_ps2.repeat_tick) {
        const kc = g_ps2.repeat_keycode;
        const ascii = keycode_to_ascii(kc, g_ps2.modifiers);
        const ev = KeyEvent{
            .keycode = kc,
            .ascii = ascii,
            .pressed = true,
            .modifiers = g_ps2.modifiers,
            .timestamp = g_ps2.tick,
        };
        g_ps2.key_buffer.push(ev);
        g_ps2.total_keystrokes += 1;

        // Next repeat at rate interval (ms)
        if (g_ps2.repeat_rate > 0) {
            g_ps2.repeat_tick = g_ps2.tick + (1000 / @as(u64, g_ps2.repeat_rate));
        } else {
            g_ps2.repeat_tick = g_ps2.tick + 33;
        }
    }
}

pub fn poll_key() ?KeyEvent {
    return g_ps2.key_buffer.pop();
}

pub fn poll_mouse() ?MouseEvent {
    return g_ps2.mouse_buffer.pop();
}

pub fn is_key_pressed(keycode: u8) bool {
    if (keycode >= 128) return false;
    return g_ps2.key_state[keycode];
}

// ─────────── FFI Exports ────────────────────────────────────────────

export fn zxy_ps2_init() bool {
    return init();
}

export fn zxy_ps2_keyboard_irq() void {
    keyboard_irq_handler();
}

export fn zxy_ps2_mouse_irq() void {
    mouse_irq_handler();
}

export fn zxy_ps2_tick() void {
    tick();
}

export fn zxy_ps2_poll_key_code() u8 {
    if (poll_key()) |ev| return ev.keycode;
    return 0;
}

export fn zxy_ps2_poll_key_ascii() u8 {
    if (poll_key()) |ev| return ev.ascii;
    return 0;
}

export fn zxy_ps2_poll_mouse_dx() i16 {
    if (poll_mouse()) |ev| return ev.dx;
    return 0;
}

export fn zxy_ps2_is_pressed(keycode: u8) bool {
    return is_key_pressed(keycode);
}

export fn zxy_ps2_total_keys() u64 {
    return g_ps2.total_keystrokes;
}

export fn zxy_ps2_total_mouse() u64 {
    return g_ps2.total_mouse_events;
}

export fn zxy_ps2_has_mouse() bool {
    return g_ps2.port2_present;
}

export fn zxy_ps2_has_scroll() bool {
    return g_ps2.mouse_has_scroll;
}

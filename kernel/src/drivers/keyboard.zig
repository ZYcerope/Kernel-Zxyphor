// =============================================================================
// Kernel Zxyphor - PS/2 Keyboard Driver
// =============================================================================
// Handles the standard PS/2 keyboard controller (8042) and converts hardware
// scan codes into ASCII characters and key events.
//
// The keyboard generates IRQ1 (mapped to vector 33 after PIC remapping).
// Each key press/release sends one or more scan codes to port 0x60.
//
// This driver supports:
//   - Scan code set 1 (default on x86 PCs)
//   - Modifier keys: Shift, Ctrl, Alt, Caps Lock, Num Lock, Scroll Lock
//   - Extended keys (prefixed with 0xE0): arrows, Home, End, etc.
//   - Key repeat handling
//   - Circular input buffer for asynchronous reading
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// PS/2 controller ports
// =============================================================================
const KB_DATA_PORT: u16 = 0x60; // Read: scan code, Write: command to device
const KB_STATUS_PORT: u16 = 0x64; // Read: status, Write: command to controller
const KB_CMD_PORT: u16 = 0x64;

// Status register bits
const STATUS_OUTPUT_FULL: u8 = 0x01; // Data available to read
const STATUS_INPUT_FULL: u8 = 0x02; // Controller busy
const STATUS_SYSTEM: u8 = 0x04; // POST passed
const STATUS_COMMAND: u8 = 0x08; // Last write was to command port
const STATUS_TIMEOUT: u8 = 0x40; // Timeout error
const STATUS_PARITY: u8 = 0x80; // Parity error

// Controller commands
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_TEST_PORT2: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_TEST_PORT1: u8 = 0xAB;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;

// Keyboard device commands
const DEV_SET_LEDS: u8 = 0xED;
const DEV_SET_SCANCODE: u8 = 0xF0;
const DEV_SET_TYPEMATIC: u8 = 0xF3;
const DEV_ENABLE_SCANNING: u8 = 0xF4;
const DEV_DISABLE_SCANNING: u8 = 0xF5;
const DEV_RESET: u8 = 0xFF;
const DEV_ACK: u8 = 0xFA;

// =============================================================================
// Key event structure
// =============================================================================
pub const KeyEvent = struct {
    scancode: u8 = 0,
    ascii: u8 = 0,
    keycode: KeyCode = .unknown,
    pressed: bool = false,
    shift: bool = false,
    ctrl: bool = false,
    alt: bool = false,
    capslock: bool = false,
};

pub const KeyCode = enum(u8) {
    unknown = 0,
    escape = 1,
    num_1 = 2,
    num_2 = 3,
    num_3 = 4,
    num_4 = 5,
    num_5 = 6,
    num_6 = 7,
    num_7 = 8,
    num_8 = 9,
    num_9 = 10,
    num_0 = 11,
    minus = 12,
    equal = 13,
    backspace = 14,
    tab = 15,
    q = 16,
    w = 17,
    e = 18,
    r = 19,
    t = 20,
    y = 21,
    u = 22,
    i = 23,
    o = 24,
    p = 25,
    left_bracket = 26,
    right_bracket = 27,
    enter = 28,
    left_ctrl = 29,
    a = 30,
    s = 31,
    d = 32,
    f = 33,
    g = 34,
    h = 35,
    j = 36,
    k = 37,
    l = 38,
    semicolon = 39,
    apostrophe = 40,
    grave = 41,
    left_shift = 42,
    backslash = 43,
    z = 44,
    x = 45,
    c = 46,
    v = 47,
    b = 48,
    n = 49,
    m = 50,
    comma = 51,
    period = 52,
    slash = 53,
    right_shift = 54,
    kp_multiply = 55,
    left_alt = 56,
    space = 57,
    capslock_key = 58,
    f1 = 59,
    f2 = 60,
    f3 = 61,
    f4 = 62,
    f5 = 63,
    f6 = 64,
    f7 = 65,
    f8 = 66,
    f9 = 67,
    f10 = 68,
    numlock = 69,
    scrolllock = 70,
    f11 = 87,
    f12 = 88,
    // Extended keys (0xE0 prefix)
    up_arrow = 200,
    down_arrow = 208,
    left_arrow = 203,
    right_arrow = 205,
    home = 199,
    end = 207,
    page_up = 201,
    page_down = 209,
    insert = 210,
    delete = 211,
};

// =============================================================================
// Scan code to ASCII mapping (US keyboard layout)
// =============================================================================
const scancode_to_ascii = [128]u8{
    0,   0x1B, '1',  '2',  '3',  '4',  '5',  '6', // 0x00-0x07
    '7', '8',  '9',  '0',  '-',  '=',  0x08, '\t', // 0x08-0x0F
    'q', 'w',  'e',  'r',  't',  'y',  'u',  'i', // 0x10-0x17
    'o', 'p',  '[',  ']',  '\n', 0,    'a',  's', // 0x18-0x1F
    'd', 'f',  'g',  'h',  'j',  'k',  'l',  ';', // 0x20-0x27
    '\'', '`', 0,    '\\', 'z',  'x',  'c',  'v', // 0x28-0x2F
    'b', 'n',  'm',  ',',  '.',  '/',  0,    '*', // 0x30-0x37
    0,   ' ',  0,    0,    0,    0,    0,    0, // 0x38-0x3F
    0,   0,    0,    0,    0,    0,    0,    '7', // 0x40-0x47
    '8', '9',  '-',  '4',  '5',  '6',  '+',  '1', // 0x48-0x4F
    '2', '3',  '0',  '.',  0,    0,    0,    0, // 0x50-0x57
    0,   0,    0,    0,    0,    0,    0,    0, // 0x58-0x5F
    0,   0,    0,    0,    0,    0,    0,    0, // 0x60-0x67
    0,   0,    0,    0,    0,    0,    0,    0, // 0x68-0x6F
    0,   0,    0,    0,    0,    0,    0,    0, // 0x70-0x77
    0,   0,    0,    0,    0,    0,    0,    0, // 0x78-0x7F
};

const scancode_to_ascii_shift = [128]u8{
    0,   0x1B, '!',  '@',  '#',  '$',  '%',  '^', // 0x00-0x07
    '&', '*',  '(',  ')',  '_',  '+',  0x08, '\t', // 0x08-0x0F
    'Q', 'W',  'E',  'R',  'T',  'Y',  'U',  'I', // 0x10-0x17
    'O', 'P',  '{',  '}',  '\n', 0,    'A',  'S', // 0x18-0x1F
    'D', 'F',  'G',  'H',  'J',  'K',  'L',  ':', // 0x20-0x27
    '"', '~',  0,    '|',  'Z',  'X',  'C',  'V', // 0x28-0x2F
    'B', 'N',  'M',  '<',  '>',  '?',  0,    '*', // 0x30-0x37
    0,   ' ',  0,    0,    0,    0,    0,    0, // 0x38-0x3F
    0,   0,    0,    0,    0,    0,    0,    '7', // 0x40-0x47
    '8', '9',  '-',  '4',  '5',  '6',  '+',  '1', // 0x48-0x4F
    '2', '3',  '0',  '.',  0,    0,    0,    0, // 0x50-0x57
    0,   0,    0,    0,    0,    0,    0,    0, // 0x58-0x5F
    0,   0,    0,    0,    0,    0,    0,    0, // 0x60-0x67
    0,   0,    0,    0,    0,    0,    0,    0, // 0x68-0x6F
    0,   0,    0,    0,    0,    0,    0,    0, // 0x70-0x77
    0,   0,    0,    0,    0,    0,    0,    0, // 0x78-0x7F
};

// =============================================================================
// Input buffer (ring buffer)
// =============================================================================
const INPUT_BUFFER_SIZE: usize = 256;
var input_buffer: [INPUT_BUFFER_SIZE]u8 = [_]u8{0} ** INPUT_BUFFER_SIZE;
var input_head: usize = 0;
var input_tail: usize = 0;

var event_buffer: [64]KeyEvent = undefined;
var event_head: usize = 0;
var event_tail: usize = 0;

// =============================================================================
// Modifier state
// =============================================================================
var left_shift: bool = false;
var right_shift: bool = false;
var left_ctrl: bool = false;
var right_ctrl: bool = false;
var left_alt: bool = false;
var right_alt: bool = false;
var caps_lock: bool = false;
var num_lock: bool = false;
var scroll_lock: bool = false;

var extended_scancode: bool = false; // Waiting for extended key

// =============================================================================
// Initialize keyboard
// =============================================================================
pub fn initialize() void {
    // Wait for controller to be ready
    waitForInput();

    // Disable both PS/2 ports during setup
    main.cpu.outb(KB_CMD_PORT, CMD_DISABLE_PORT1);
    waitForInput();
    main.cpu.outb(KB_CMD_PORT, CMD_DISABLE_PORT2);
    waitForInput();

    // Flush the output buffer
    _ = main.cpu.inb(KB_DATA_PORT);

    // Read controller configuration
    main.cpu.outb(KB_CMD_PORT, CMD_READ_CONFIG);
    waitForOutput();
    var config = main.cpu.inb(KB_DATA_PORT);

    // Enable IRQ1 for port 1, disable IRQ12 for port 2
    config |= 0x01; // Enable port 1 IRQ
    config &= ~@as(u8, 0x10); // Enable port 1 clock
    config |= 0x40; // Enable port 1 translation

    // Write config back
    main.cpu.outb(KB_CMD_PORT, CMD_WRITE_CONFIG);
    waitForInput();
    main.cpu.outb(KB_DATA_PORT, config);
    waitForInput();

    // Self-test the controller
    main.cpu.outb(KB_CMD_PORT, CMD_SELF_TEST);
    waitForOutput();
    const self_test = main.cpu.inb(KB_DATA_PORT);
    if (self_test != 0x55) {
        main.klog(.err, "keyboard: controller self-test failed (got 0x{X:0>2})", .{self_test});
        return;
    }

    // Enable port 1
    main.cpu.outb(KB_CMD_PORT, CMD_ENABLE_PORT1);
    waitForInput();

    // Reset the keyboard device
    main.cpu.outb(KB_DATA_PORT, DEV_RESET);
    waitForOutput();
    _ = main.cpu.inb(KB_DATA_PORT); // Should get ACK (0xFA) then 0xAA

    // Enable scanning
    main.cpu.outb(KB_DATA_PORT, DEV_ENABLE_SCANNING);
    waitForOutput();
    _ = main.cpu.inb(KB_DATA_PORT); // ACK

    // Set LED states (all off initially)
    updateLEDs();

    // Register IRQ1 handler
    main.idt.registerIrqHandler(1, irqHandler);

    main.klog(.info, "keyboard: PS/2 keyboard initialized", .{});
}

// =============================================================================
// IRQ handler — called on every key press/release
// =============================================================================
fn irqHandler() void {
    const scancode = main.cpu.inb(KB_DATA_PORT);

    // Handle extended key prefix
    if (scancode == 0xE0) {
        extended_scancode = true;
        return;
    }

    if (scancode == 0xE1) {
        // Pause/Break key — ignore for now
        return;
    }

    const is_release = (scancode & 0x80) != 0;
    const code = scancode & 0x7F;

    var event = KeyEvent{
        .scancode = code,
        .pressed = !is_release,
    };

    if (extended_scancode) {
        extended_scancode = false;
        handleExtendedKey(code, is_release, &event);
    } else {
        handleNormalKey(code, is_release, &event);
    }

    // Store the event
    if (event.pressed and event.ascii != 0) {
        // Add to ASCII input buffer
        const next = (input_head + 1) % INPUT_BUFFER_SIZE;
        if (next != input_tail) {
            input_buffer[input_head] = event.ascii;
            input_head = next;
        }
    }

    // Store full key event
    const next_event = (event_head + 1) % event_buffer.len;
    if (next_event != event_tail) {
        event_buffer[event_head] = event;
        event_head = next_event;
    }
}

fn handleNormalKey(code: u8, is_release: bool, event: *KeyEvent) void {
    // Update modifier state
    switch (code) {
        0x2A => {
            left_shift = !is_release;
            return;
        },
        0x36 => {
            right_shift = !is_release;
            return;
        },
        0x1D => {
            left_ctrl = !is_release;
            return;
        },
        0x38 => {
            left_alt = !is_release;
            return;
        },
        0x3A => {
            if (!is_release) {
                caps_lock = !caps_lock;
                updateLEDs();
            }
            return;
        },
        0x45 => {
            if (!is_release) {
                num_lock = !num_lock;
                updateLEDs();
            }
            return;
        },
        0x46 => {
            if (!is_release) {
                scroll_lock = !scroll_lock;
                updateLEDs();
            }
            return;
        },
        else => {},
    }

    if (code >= 128) return;

    event.shift = left_shift or right_shift;
    event.ctrl = left_ctrl or right_ctrl;
    event.alt = left_alt or right_alt;
    event.capslock = caps_lock;

    // Determine ASCII character
    const shift_active = event.shift != caps_lock; // XOR for caps lock behavior
    if (shift_active) {
        event.ascii = scancode_to_ascii_shift[code];
    } else {
        event.ascii = scancode_to_ascii[code];
    }

    // Handle Ctrl+letter (produce control characters)
    if (event.ctrl and event.ascii >= 'a' and event.ascii <= 'z') {
        event.ascii = event.ascii - 'a' + 1; // Ctrl+A = 0x01, etc.
    }

    // Map to keycode
    if (code < 89) {
        event.keycode = @enumFromInt(code);
    }
}

fn handleExtendedKey(code: u8, is_release: bool, event: *KeyEvent) void {
    _ = is_release;

    event.shift = left_shift or right_shift;
    event.ctrl = left_ctrl or right_ctrl;
    event.alt = left_alt or right_alt;

    switch (code) {
        0x48 => {
            event.keycode = .up_arrow;
            event.ascii = 0;
        },
        0x50 => {
            event.keycode = .down_arrow;
            event.ascii = 0;
        },
        0x4B => {
            event.keycode = .left_arrow;
            event.ascii = 0;
        },
        0x4D => {
            event.keycode = .right_arrow;
            event.ascii = 0;
        },
        0x47 => {
            event.keycode = .home;
            event.ascii = 0;
        },
        0x4F => {
            event.keycode = .end;
            event.ascii = 0;
        },
        0x49 => {
            event.keycode = .page_up;
            event.ascii = 0;
        },
        0x51 => {
            event.keycode = .page_down;
            event.ascii = 0;
        },
        0x52 => {
            event.keycode = .insert;
            event.ascii = 0;
        },
        0x53 => {
            event.keycode = .delete;
            event.ascii = 0x7F;
        },
        0x1D => {
            right_ctrl = event.pressed;
        },
        0x38 => {
            right_alt = event.pressed;
        },
        else => {},
    }
}

// =============================================================================
// LED control
// =============================================================================
fn updateLEDs() void {
    var leds: u8 = 0;
    if (scroll_lock) leds |= 0x01;
    if (num_lock) leds |= 0x02;
    if (caps_lock) leds |= 0x04;

    waitForInput();
    main.cpu.outb(KB_DATA_PORT, DEV_SET_LEDS);
    waitForInput();
    main.cpu.outb(KB_DATA_PORT, leds);
}

// =============================================================================
// Reading input
// =============================================================================

/// Read a single ASCII character from the keyboard buffer (non-blocking)
pub fn readChar() ?u8 {
    if (input_tail == input_head) return null;
    const ch = input_buffer[input_tail];
    input_tail = (input_tail + 1) % INPUT_BUFFER_SIZE;
    return ch;
}

/// Read a full key event (non-blocking)
pub fn readEvent() ?KeyEvent {
    if (event_tail == event_head) return null;
    const event = event_buffer[event_tail];
    event_tail = (event_tail + 1) % event_buffer.len;
    return event;
}

/// Check if there's any input available
pub fn hasInput() bool {
    return input_tail != input_head;
}

/// Wait for a keypress (blocking)
pub fn waitForKey() u8 {
    while (true) {
        if (readChar()) |ch| return ch;
        main.cpu.halt(); // Sleep until next interrupt
    }
}

// =============================================================================
// Controller I/O helpers
// =============================================================================
fn waitForInput() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((main.cpu.inb(KB_STATUS_PORT) & STATUS_INPUT_FULL) == 0) return;
    }
}

fn waitForOutput() void {
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if ((main.cpu.inb(KB_STATUS_PORT) & STATUS_OUTPUT_FULL) != 0) return;
    }
}

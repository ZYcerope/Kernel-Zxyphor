// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced Input Subsystem
// evdev, HID report parser, multi-touch protocol, force feedback, gamepad support

const std = @import("std");

// ============================================================================
// Event Types (Linux evdev compatible)
// ============================================================================

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;
pub const EV_SW: u16 = 0x05;
pub const EV_LED: u16 = 0x11;
pub const EV_SND: u16 = 0x12;
pub const EV_REP: u16 = 0x14;
pub const EV_FF: u16 = 0x15;
pub const EV_PWR: u16 = 0x16;
pub const EV_FF_STATUS: u16 = 0x17;

// Synchronization events
pub const SYN_REPORT: u16 = 0;
pub const SYN_CONFIG: u16 = 1;
pub const SYN_MT_REPORT: u16 = 2;
pub const SYN_DROPPED: u16 = 3;

// Key codes (subset - Linux compatible)
pub const KEY_RESERVED: u16 = 0;
pub const KEY_ESC: u16 = 1;
pub const KEY_1: u16 = 2;
pub const KEY_2: u16 = 3;
pub const KEY_3: u16 = 4;
pub const KEY_4: u16 = 5;
pub const KEY_5: u16 = 6;
pub const KEY_6: u16 = 7;
pub const KEY_7: u16 = 8;
pub const KEY_8: u16 = 9;
pub const KEY_9: u16 = 10;
pub const KEY_0: u16 = 11;
pub const KEY_MINUS: u16 = 12;
pub const KEY_EQUAL: u16 = 13;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_Q: u16 = 16;
pub const KEY_W: u16 = 17;
pub const KEY_E: u16 = 18;
pub const KEY_R: u16 = 19;
pub const KEY_T: u16 = 20;
pub const KEY_Y: u16 = 21;
pub const KEY_U: u16 = 22;
pub const KEY_I: u16 = 23;
pub const KEY_O: u16 = 24;
pub const KEY_P: u16 = 25;
pub const KEY_LEFTBRACE: u16 = 26;
pub const KEY_RIGHTBRACE: u16 = 27;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_A: u16 = 30;
pub const KEY_S: u16 = 31;
pub const KEY_D: u16 = 32;
pub const KEY_F: u16 = 33;
pub const KEY_G: u16 = 34;
pub const KEY_H: u16 = 35;
pub const KEY_J: u16 = 36;
pub const KEY_K: u16 = 37;
pub const KEY_L: u16 = 38;
pub const KEY_SEMICOLON: u16 = 39;
pub const KEY_APOSTROPHE: u16 = 40;
pub const KEY_GRAVE: u16 = 41;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_BACKSLASH: u16 = 43;
pub const KEY_Z: u16 = 44;
pub const KEY_X: u16 = 45;
pub const KEY_C: u16 = 46;
pub const KEY_V: u16 = 47;
pub const KEY_B: u16 = 48;
pub const KEY_N: u16 = 49;
pub const KEY_M: u16 = 50;
pub const KEY_COMMA: u16 = 51;
pub const KEY_DOT: u16 = 52;
pub const KEY_SLASH: u16 = 53;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_KPASTERISK: u16 = 55;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_F1: u16 = 59;
pub const KEY_F2: u16 = 60;
pub const KEY_F3: u16 = 61;
pub const KEY_F4: u16 = 62;
pub const KEY_F5: u16 = 63;
pub const KEY_F6: u16 = 64;
pub const KEY_F7: u16 = 65;
pub const KEY_F8: u16 = 66;
pub const KEY_F9: u16 = 67;
pub const KEY_F10: u16 = 68;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_HOME: u16 = 102;
pub const KEY_UP: u16 = 103;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_END: u16 = 107;
pub const KEY_DOWN: u16 = 108;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_INSERT: u16 = 110;
pub const KEY_DELETE: u16 = 111;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;
pub const KEY_COMPOSE: u16 = 127;
pub const KEY_POWER: u16 = 116;
pub const KEY_SLEEP: u16 = 142;
pub const KEY_WAKEUP: u16 = 143;

// Button codes
pub const BTN_MISC: u16 = 0x100;
pub const BTN_0: u16 = 0x100;
pub const BTN_1: u16 = 0x101;
pub const BTN_MOUSE: u16 = 0x110;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_SIDE: u16 = 0x113;
pub const BTN_EXTRA: u16 = 0x114;
pub const BTN_FORWARD: u16 = 0x115;
pub const BTN_BACK: u16 = 0x116;
pub const BTN_TASK: u16 = 0x117;
// Gamepad
pub const BTN_GAMEPAD: u16 = 0x130;
pub const BTN_SOUTH: u16 = 0x130;
pub const BTN_EAST: u16 = 0x131;
pub const BTN_C: u16 = 0x132;
pub const BTN_NORTH: u16 = 0x133;
pub const BTN_WEST: u16 = 0x134;
pub const BTN_Z: u16 = 0x135;
pub const BTN_TL: u16 = 0x136;
pub const BTN_TR: u16 = 0x137;
pub const BTN_TL2: u16 = 0x138;
pub const BTN_TR2: u16 = 0x139;
pub const BTN_SELECT: u16 = 0x13A;
pub const BTN_START: u16 = 0x13B;
pub const BTN_MODE: u16 = 0x13C;
pub const BTN_THUMBL: u16 = 0x13D;
pub const BTN_THUMBR: u16 = 0x13E;
// Touchscreen
pub const BTN_TOUCH: u16 = 0x14A;
pub const BTN_STYLUS: u16 = 0x14B;
pub const BTN_STYLUS2: u16 = 0x14C;
pub const BTN_TOOL_DOUBLETAP: u16 = 0x14D;
pub const BTN_TOOL_TRIPLETAP: u16 = 0x14E;
pub const BTN_TOOL_FINGER: u16 = 0x145;
pub const BTN_TOOL_PEN: u16 = 0x140;
pub const BTN_TOOL_RUBBER: u16 = 0x141;

// Relative axes
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_Z: u16 = 0x02;
pub const REL_RX: u16 = 0x03;
pub const REL_RY: u16 = 0x04;
pub const REL_RZ: u16 = 0x05;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_DIAL: u16 = 0x07;
pub const REL_WHEEL: u16 = 0x08;
pub const REL_MISC: u16 = 0x09;
pub const REL_WHEEL_HI_RES: u16 = 0x0B;
pub const REL_HWHEEL_HI_RES: u16 = 0x0C;

// Absolute axes
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_Z: u16 = 0x02;
pub const ABS_RX: u16 = 0x03;
pub const ABS_RY: u16 = 0x04;
pub const ABS_RZ: u16 = 0x05;
pub const ABS_THROTTLE: u16 = 0x06;
pub const ABS_RUDDER: u16 = 0x07;
pub const ABS_WHEEL: u16 = 0x08;
pub const ABS_GAS: u16 = 0x09;
pub const ABS_BRAKE: u16 = 0x0A;
pub const ABS_HAT0X: u16 = 0x10;
pub const ABS_HAT0Y: u16 = 0x11;
pub const ABS_HAT1X: u16 = 0x12;
pub const ABS_HAT1Y: u16 = 0x13;
pub const ABS_HAT2X: u16 = 0x14;
pub const ABS_HAT2Y: u16 = 0x15;
pub const ABS_HAT3X: u16 = 0x16;
pub const ABS_HAT3Y: u16 = 0x17;
pub const ABS_PRESSURE: u16 = 0x18;
pub const ABS_DISTANCE: u16 = 0x19;
pub const ABS_TILT_X: u16 = 0x1A;
pub const ABS_TILT_Y: u16 = 0x1B;
pub const ABS_TOOL_WIDTH: u16 = 0x1C;
pub const ABS_VOLUME: u16 = 0x20;
pub const ABS_MISC: u16 = 0x28;
// Multi-touch
pub const ABS_MT_SLOT: u16 = 0x2F;
pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
pub const ABS_MT_TOUCH_MINOR: u16 = 0x31;
pub const ABS_MT_WIDTH_MAJOR: u16 = 0x32;
pub const ABS_MT_WIDTH_MINOR: u16 = 0x33;
pub const ABS_MT_ORIENTATION: u16 = 0x34;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TOOL_TYPE: u16 = 0x37;
pub const ABS_MT_BLOB_ID: u16 = 0x38;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;
pub const ABS_MT_PRESSURE: u16 = 0x3A;
pub const ABS_MT_DISTANCE: u16 = 0x3B;
pub const ABS_MT_TOOL_X: u16 = 0x3C;
pub const ABS_MT_TOOL_Y: u16 = 0x3D;

pub const ABS_MAX: u16 = 0x3F;

// Switch events
pub const SW_LID: u16 = 0x00;
pub const SW_TABLET_MODE: u16 = 0x01;
pub const SW_HEADPHONE_INSERT: u16 = 0x02;
pub const SW_RFKILL_ALL: u16 = 0x03;
pub const SW_MICROPHONE_INSERT: u16 = 0x04;
pub const SW_DOCK: u16 = 0x05;
pub const SW_LINEOUT_INSERT: u16 = 0x06;
pub const SW_JACK_PHYSICAL_INSERT: u16 = 0x07;
pub const SW_VIDEOOUT_INSERT: u16 = 0x08;
pub const SW_CAMERA_LENS_COVER: u16 = 0x09;
pub const SW_KEYPAD_SLIDE: u16 = 0x0A;
pub const SW_FRONT_PROXIMITY: u16 = 0x0B;
pub const SW_ROTATE_LOCK: u16 = 0x0C;
pub const SW_LINEIN_INSERT: u16 = 0x0D;
pub const SW_MUTE_DEVICE: u16 = 0x0E;
pub const SW_PEN_INSERTED: u16 = 0x0F;

// LED events
pub const LED_NUML: u16 = 0x00;
pub const LED_CAPSL: u16 = 0x01;
pub const LED_SCROLLL: u16 = 0x02;
pub const LED_COMPOSE: u16 = 0x03;
pub const LED_KANA: u16 = 0x04;

// Force feedback effect types
pub const FF_RUMBLE: u16 = 0x50;
pub const FF_PERIODIC: u16 = 0x51;
pub const FF_CONSTANT: u16 = 0x52;
pub const FF_SPRING: u16 = 0x53;
pub const FF_FRICTION: u16 = 0x54;
pub const FF_DAMPER: u16 = 0x55;
pub const FF_INERTIA: u16 = 0x56;
pub const FF_RAMP: u16 = 0x57;
pub const FF_SQUARE: u16 = 0x58;
pub const FF_TRIANGLE: u16 = 0x59;
pub const FF_SINE: u16 = 0x5A;
pub const FF_SAW_UP: u16 = 0x5B;
pub const FF_SAW_DOWN: u16 = 0x5C;
pub const FF_CUSTOM: u16 = 0x5D;
pub const FF_GAIN: u16 = 0x60;
pub const FF_AUTOCENTER: u16 = 0x61;

// ============================================================================
// Input Event (evdev compatible, 24 bytes)
// ============================================================================

pub const InputEvent = packed struct {
    time_sec: u64,
    time_usec: u32,
    event_type: u16,
    code: u16,
    value: i32,
};

// ============================================================================
// Absolute Axis Info
// ============================================================================

pub const AbsInfo = struct {
    value: i32,
    minimum: i32,
    maximum: i32,
    fuzz: i32,
    flat: i32,
    resolution: i32,
};

// ============================================================================
// Input Device
// ============================================================================

pub const MAX_INPUT_DEVICES = 64;
pub const INPUT_PROP_POINTER: u32 = 0x00;
pub const INPUT_PROP_DIRECT: u32 = 0x01;
pub const INPUT_PROP_BUTTONPAD: u32 = 0x02;
pub const INPUT_PROP_SEMI_MT: u32 = 0x03;
pub const INPUT_PROP_TOPBUTTONPAD: u32 = 0x04;
pub const INPUT_PROP_POINTING_STICK: u32 = 0x05;
pub const INPUT_PROP_ACCELEROMETER: u32 = 0x06;

pub const InputDeviceType = enum(u8) {
    keyboard,
    mouse,
    touchpad,
    touchscreen,
    tablet,
    gamepad,
    joystick,
    accelerometer,
    gyroscope,
    other,
};

pub const InputDevice = struct {
    id: u16,
    name: [128]u8,
    name_len: u8,
    phys: [64]u8,     // Physical path
    phys_len: u8,
    uniq: [64]u8,     // Unique identifier
    uniq_len: u8,
    device_type: InputDeviceType,
    // USB/transport ID
    bus_type: u16,
    vendor: u16,
    product: u16,
    version: u16,
    // Capabilities (bitmasks)
    ev_bits: [4]u64,    // Supported event types
    key_bits: [12]u64,  // Supported keys/buttons
    rel_bits: [1]u64,   // Supported relative axes
    abs_bits: [1]u64,   // Supported absolute axes
    msc_bits: [1]u64,
    led_bits: [1]u64,
    snd_bits: [1]u64,
    ff_bits: [2]u64,    // Force feedback effects
    sw_bits: [1]u64,
    prop_bits: [1]u64,  // Device properties
    // Abs axis info
    abs_info: [64]AbsInfo,
    // State
    key_state: [12]u64, // Current key/button state
    led_state: [1]u64,
    sw_state: [1]u64,
    // Multi-touch protocol B state
    mt_slot_count: u8,
    mt_current_slot: u8,
    mt_slots: [16]MtSlot,
    // Event queue
    event_queue: [512]InputEvent,
    eq_read: u16,
    eq_write: u16,
    // Repeat
    rep_delay: u32,   // ms
    rep_period: u32,  // ms
    // Force feedback
    ff_effects_max: u16,
    ff_effects: [32]FfEffect,
    ff_effect_count: u16,
    ff_gain: u16,     // 0-65535
    // Grab
    grabbed: bool,
    grab_owner: u32,  // PID
    active: bool,

    pub fn set_ev_bit(self: *InputDevice, ev: u16) void {
        self.ev_bits[ev / 64] |= @as(u64, 1) << @intCast(ev % 64);
    }

    pub fn set_key_bit(self: *InputDevice, key: u16) void {
        self.key_bits[key / 64] |= @as(u64, 1) << @intCast(key % 64);
    }

    pub fn set_rel_bit(self: *InputDevice, rel: u16) void {
        self.rel_bits[0] |= @as(u64, 1) << @intCast(rel);
    }

    pub fn set_abs_bit(self: *InputDevice, abs: u16) void {
        self.abs_bits[0] |= @as(u64, 1) << @intCast(abs);
    }

    pub fn has_ev(self: *const InputDevice, ev: u16) bool {
        return (self.ev_bits[ev / 64] >> @intCast(ev % 64)) & 1 != 0;
    }

    pub fn has_key(self: *const InputDevice, key: u16) bool {
        return (self.key_bits[key / 64] >> @intCast(key % 64)) & 1 != 0;
    }

    /// Send an input event to the event queue
    pub fn report_event(self: *InputDevice, ev_type: u16, code: u16, value: i32, time_sec: u64, time_usec: u32) void {
        const next = (self.eq_write + 1) % @as(u16, @intCast(self.event_queue.len));
        if (next == self.eq_read) return; // Queue full, drop

        self.event_queue[self.eq_write] = InputEvent{
            .time_sec = time_sec,
            .time_usec = time_usec,
            .event_type = ev_type,
            .code = code,
            .value = value,
        };
        self.eq_write = next;

        // Update state tracking
        if (ev_type == EV_KEY) {
            const idx = code / 64;
            const bit = @as(u6, @intCast(code % 64));
            if (value != 0) {
                self.key_state[idx] |= @as(u64, 1) << bit;
            } else {
                self.key_state[idx] &= ~(@as(u64, 1) << bit);
            }
        } else if (ev_type == EV_ABS) {
            if (code <= ABS_MAX) {
                self.abs_info[code].value = value;
            }
        } else if (ev_type == EV_LED) {
            if (value != 0) {
                self.led_state[0] |= @as(u64, 1) << @intCast(code);
            } else {
                self.led_state[0] &= ~(@as(u64, 1) << @intCast(code));
            }
        }
    }

    pub fn report_sync(self: *InputDevice, time_sec: u64, time_usec: u32) void {
        self.report_event(EV_SYN, SYN_REPORT, 0, time_sec, time_usec);
    }

    pub fn read_event(self: *InputDevice) ?InputEvent {
        if (self.eq_read == self.eq_write) return null;
        const ev = self.event_queue[self.eq_read];
        self.eq_read = (self.eq_read + 1) % @as(u16, @intCast(self.event_queue.len));
        return ev;
    }
};

// ============================================================================
// Multi-Touch Protocol B
// ============================================================================

pub const MT_TRACKING_ID_NONE: i32 = -1;

pub const MtSlot = struct {
    tracking_id: i32,
    x: i32,
    y: i32,
    touch_major: i32,
    touch_minor: i32,
    width_major: i32,
    width_minor: i32,
    orientation: i32,
    pressure: i32,
    distance: i32,
    tool_type: i32,
    tool_x: i32,
    tool_y: i32,
    active: bool,
};

pub fn mt_init_slots(device: *InputDevice, slot_count: u8) void {
    device.mt_slot_count = slot_count;
    device.mt_current_slot = 0;
    for (device.mt_slots[0..slot_count]) |*slot| {
        slot.* = MtSlot{
            .tracking_id = MT_TRACKING_ID_NONE,
            .x = 0, .y = 0,
            .touch_major = 0, .touch_minor = 0,
            .width_major = 0, .width_minor = 0,
            .orientation = 0, .pressure = 0,
            .distance = 0, .tool_type = 0,
            .tool_x = 0, .tool_y = 0,
            .active = false,
        };
    }
    device.set_ev_bit(EV_ABS);
    device.set_abs_bit(ABS_MT_SLOT);
    device.set_abs_bit(ABS_MT_TRACKING_ID);
    device.set_abs_bit(ABS_MT_POSITION_X);
    device.set_abs_bit(ABS_MT_POSITION_Y);
    device.set_abs_bit(ABS_MT_PRESSURE);
}

// ============================================================================
// Force Feedback Effects
// ============================================================================

pub const FfEnvelope = struct {
    attack_length: u16,  // ms
    attack_level: u16,
    fade_length: u16,    // ms
    fade_level: u16,
};

pub const FfConstant = struct {
    level: i16,          // -32767 to 32767
    envelope: FfEnvelope,
};

pub const FfRamp = struct {
    start_level: i16,
    end_level: i16,
    envelope: FfEnvelope,
};

pub const FfPeriodic = struct {
    waveform: u16,       // FF_SQUARE, FF_SINE, etc.
    period: u16,         // ms
    magnitude: i16,
    offset: i16,
    phase: u16,
    envelope: FfEnvelope,
};

pub const FfRumble = struct {
    strong_magnitude: u16,
    weak_magnitude: u16,
};

pub const FfCondition = struct {
    right_saturation: u16,
    left_saturation: u16,
    right_coeff: i16,
    left_coeff: i16,
    deadband: u16,
    center: i16,
};

pub const FfEffect = struct {
    effect_type: u16,
    id: i16,
    direction: u16,      // 0-35999 (degrees * 100)
    trigger_button: u16,
    trigger_interval: u16,
    replay_length: u16,  // ms
    replay_delay: u16,   // ms
    // Union of effect data
    data: FfData,
    playing: bool,
    start_time: u64,
};

pub const FfData = union {
    constant: FfConstant,
    ramp: FfRamp,
    periodic: FfPeriodic,
    rumble: FfRumble,
    condition: [2]FfCondition,
};

// ============================================================================
// HID Report Descriptor Parser
// ============================================================================

pub const HidGlobalItem = enum(u8) {
    usage_page = 0x04,
    logical_minimum = 0x14,
    logical_maximum = 0x24,
    physical_minimum = 0x34,
    physical_maximum = 0x44,
    unit_exponent = 0x54,
    unit = 0x64,
    report_size = 0x74,
    report_id = 0x84,
    report_count = 0x94,
    push = 0xA4,
    pop = 0xB4,
};

pub const HidLocalItem = enum(u8) {
    usage = 0x08,
    usage_minimum = 0x18,
    usage_maximum = 0x28,
    designator_index = 0x38,
    designator_minimum = 0x48,
    designator_maximum = 0x58,
    string_index = 0x78,
    string_minimum = 0x88,
    string_maximum = 0x98,
    delimiter = 0xA8,
};

pub const HidMainItem = enum(u8) {
    input = 0x80,
    output = 0x90,
    feature = 0xB0,
    collection = 0xA0,
    end_collection = 0xC0,
};

// HID Usage Pages
pub const HID_UP_GENERIC_DESKTOP: u16 = 0x01;
pub const HID_UP_SIMULATION: u16 = 0x02;
pub const HID_UP_VR: u16 = 0x03;
pub const HID_UP_SPORT: u16 = 0x04;
pub const HID_UP_GAME: u16 = 0x05;
pub const HID_UP_KEYBOARD: u16 = 0x07;
pub const HID_UP_LED: u16 = 0x08;
pub const HID_UP_BUTTON: u16 = 0x09;
pub const HID_UP_ORDINAL: u16 = 0x0A;
pub const HID_UP_TELEPHONY: u16 = 0x0B;
pub const HID_UP_CONSUMER: u16 = 0x0C;
pub const HID_UP_DIGITIZER: u16 = 0x0D;
pub const HID_UP_PID: u16 = 0x0F;
pub const HID_UP_BATTERY: u16 = 0x85;
pub const HID_UP_VENDOR: u16 = 0xFF00;

// Generic Desktop usages
pub const HID_GD_POINTER: u16 = 0x01;
pub const HID_GD_MOUSE: u16 = 0x02;
pub const HID_GD_JOYSTICK: u16 = 0x04;
pub const HID_GD_GAMEPAD: u16 = 0x05;
pub const HID_GD_KEYBOARD: u16 = 0x06;
pub const HID_GD_KEYPAD: u16 = 0x07;
pub const HID_GD_MULTI_AXIS: u16 = 0x08;
pub const HID_GD_TABLET: u16 = 0x09;
pub const HID_GD_X: u16 = 0x30;
pub const HID_GD_Y: u16 = 0x31;
pub const HID_GD_Z: u16 = 0x32;
pub const HID_GD_RX: u16 = 0x33;
pub const HID_GD_RY: u16 = 0x34;
pub const HID_GD_RZ: u16 = 0x35;
pub const HID_GD_SLIDER: u16 = 0x36;
pub const HID_GD_DIAL: u16 = 0x37;
pub const HID_GD_WHEEL: u16 = 0x38;
pub const HID_GD_HATSWITCH: u16 = 0x39;

pub const HidField = struct {
    usage_page: u16,
    usage: u16,
    usage_min: u16,
    usage_max: u16,
    logical_min: i32,
    logical_max: i32,
    physical_min: i32,
    physical_max: i32,
    report_size: u8,      // Bits per field
    report_count: u8,     // Number of fields
    report_id: u8,
    flags: u16,           // Input/output/feature flags
};

pub const HID_FIELD_CONSTANT: u16 = 1 << 0;
pub const HID_FIELD_VARIABLE: u16 = 1 << 1;
pub const HID_FIELD_RELATIVE: u16 = 1 << 2;
pub const HID_FIELD_WRAP: u16 = 1 << 3;
pub const HID_FIELD_NONLINEAR: u16 = 1 << 4;
pub const HID_FIELD_NO_PREFERRED: u16 = 1 << 5;
pub const HID_FIELD_NULL_STATE: u16 = 1 << 6;
pub const HID_FIELD_BUFFERED: u16 = 1 << 8;

pub const HidReport = struct {
    fields: [64]HidField,
    num_fields: u8,
    total_bits: u32,

    /// Parse a raw HID report descriptor
    pub fn parse(desc: []const u8) HidReport {
        var report = HidReport{
            .fields = undefined,
            .num_fields = 0,
            .total_bits = 0,
        };

        // Global state stack
        var usage_page: u16 = 0;
        var logical_min: i32 = 0;
        var logical_max: i32 = 0;
        var physical_min: i32 = 0;
        var physical_max: i32 = 0;
        var report_size: u8 = 0;
        var report_count: u8 = 0;
        var report_id: u8 = 0;
        // Local state
        var usage: u16 = 0;
        var usage_min: u16 = 0;
        var usage_max: u16 = 0;

        var i: usize = 0;
        while (i < desc.len) {
            const prefix = desc[i];
            if (prefix == 0xFE) { i += 1; continue; } // Long item, skip

            const size: usize = switch (@as(u2, @truncate(prefix & 0x3))) {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 4,
            };
            if (i + 1 + size > desc.len) break;

            var data: i32 = 0;
            if (size >= 1) data = @as(i32, desc[i + 1]);
            if (size >= 2) data = @as(i32, desc[i + 1]) | (@as(i32, desc[i + 2]) << 8);
            if (size >= 4) data = @as(i32, desc[i + 1]) | (@as(i32, desc[i + 2]) << 8) | (@as(i32, desc[i + 3]) << 16) | (@as(i32, desc[i + 4]) << 24);

            const tag = prefix & 0xFC;

            switch (tag) {
                // Global items
                0x04 => usage_page = @truncate(@as(u32, @bitCast(data))),
                0x14 => logical_min = data,
                0x24 => logical_max = data,
                0x34 => physical_min = data,
                0x44 => physical_max = data,
                0x74 => report_size = @truncate(@as(u32, @bitCast(data))),
                0x84 => report_id = @truncate(@as(u32, @bitCast(data))),
                0x94 => report_count = @truncate(@as(u32, @bitCast(data))),
                // Local items
                0x08 => usage = @truncate(@as(u32, @bitCast(data))),
                0x18 => usage_min = @truncate(@as(u32, @bitCast(data))),
                0x28 => usage_max = @truncate(@as(u32, @bitCast(data))),
                // Main items
                0x80, 0x90, 0xB0 => { // Input/Output/Feature
                    if (report.num_fields < 64) {
                        report.fields[report.num_fields] = HidField{
                            .usage_page = usage_page,
                            .usage = usage,
                            .usage_min = usage_min,
                            .usage_max = usage_max,
                            .logical_min = logical_min,
                            .logical_max = logical_max,
                            .physical_min = physical_min,
                            .physical_max = physical_max,
                            .report_size = report_size,
                            .report_count = report_count,
                            .report_id = report_id,
                            .flags = @truncate(@as(u32, @bitCast(data))),
                        };
                        report.num_fields += 1;
                        report.total_bits += @as(u32, report_size) * @as(u32, report_count);
                    }
                    // Clear local state
                    usage = 0;
                    usage_min = 0;
                    usage_max = 0;
                },
                0xA0 => {}, // Collection
                0xC0 => {}, // End Collection
                else => {},
            }

            i += 1 + size;
        }
        return report;
    }
};

// ============================================================================
// Input Subsystem Manager
// ============================================================================

pub const InputManager = struct {
    devices: [MAX_INPUT_DEVICES]?InputDevice,
    device_count: u16,
    next_id: u16,

    pub fn init() InputManager {
        return InputManager{
            .devices = [_]?InputDevice{null} ** MAX_INPUT_DEVICES,
            .device_count = 0,
            .next_id = 0,
        };
    }

    pub fn register_device(self: *InputManager, dev: InputDevice) ?u16 {
        for (self.devices, 0..) |*slot, i| {
            if (slot.* == null) {
                var d = dev;
                d.id = self.next_id;
                d.active = true;
                self.next_id += 1;
                slot.* = d;
                self.device_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    pub fn unregister_device(self: *InputManager, idx: u16) void {
        if (idx >= MAX_INPUT_DEVICES) return;
        if (self.devices[idx] != null) {
            self.devices[idx] = null;
            self.device_count -= 1;
        }
    }

    pub fn find_by_type(self: *InputManager, dtype: InputDeviceType) ?*InputDevice {
        for (&self.devices) |*slot| {
            if (slot.*) |*dev| {
                if (dev.device_type == dtype and dev.active) return dev;
            }
        }
        return null;
    }

    /// Create a standard keyboard device
    pub fn create_keyboard(self: *InputManager) ?u16 {
        var dev: InputDevice = undefined;
        @memset(@as(*[128]u8, &dev.name), 0);
        const name = "Zxyphor Virtual Keyboard";
        @memcpy(dev.name[0..name.len], name);
        dev.name_len = name.len;
        dev.device_type = .keyboard;
        dev.bus_type = 0x11; // BUS_USB
        dev.vendor = 0;
        dev.product = 0;
        dev.version = 1;
        dev.ev_bits = [_]u64{0} ** 4;
        dev.key_bits = [_]u64{0} ** 12;
        dev.rel_bits = [_]u64{0} ** 1;
        dev.abs_bits = [_]u64{0} ** 1;
        dev.msc_bits = [_]u64{0} ** 1;
        dev.led_bits = [_]u64{0} ** 1;
        dev.snd_bits = [_]u64{0} ** 1;
        dev.ff_bits = [_]u64{0} ** 2;
        dev.sw_bits = [_]u64{0} ** 1;
        dev.prop_bits = [_]u64{0} ** 1;
        dev.key_state = [_]u64{0} ** 12;
        dev.led_state = [_]u64{0} ** 1;
        dev.sw_state = [_]u64{0} ** 1;
        dev.eq_read = 0;
        dev.eq_write = 0;
        dev.rep_delay = 250;
        dev.rep_period = 33;
        dev.grabbed = false;
        dev.active = false;

        dev.set_ev_bit(EV_KEY);
        dev.set_ev_bit(EV_LED);
        dev.set_ev_bit(EV_REP);
        dev.set_ev_bit(EV_SYN);

        // Set all standard keys
        var k: u16 = KEY_ESC;
        while (k <= KEY_F12) : (k += 1) {
            dev.set_key_bit(k);
        }

        return self.register_device(dev);
    }

    /// Create a standard mouse device
    pub fn create_mouse(self: *InputManager) ?u16 {
        var dev: InputDevice = undefined;
        @memset(@as(*[128]u8, &dev.name), 0);
        const name = "Zxyphor Virtual Mouse";
        @memcpy(dev.name[0..name.len], name);
        dev.name_len = name.len;
        dev.device_type = .mouse;
        dev.bus_type = 0x11;
        dev.ev_bits = [_]u64{0} ** 4;
        dev.key_bits = [_]u64{0} ** 12;
        dev.rel_bits = [_]u64{0} ** 1;
        dev.abs_bits = [_]u64{0} ** 1;
        dev.msc_bits = [_]u64{0} ** 1;
        dev.led_bits = [_]u64{0} ** 1;
        dev.snd_bits = [_]u64{0} ** 1;
        dev.ff_bits = [_]u64{0} ** 2;
        dev.sw_bits = [_]u64{0} ** 1;
        dev.prop_bits = [_]u64{0} ** 1;
        dev.key_state = [_]u64{0} ** 12;
        dev.led_state = [_]u64{0} ** 1;
        dev.sw_state = [_]u64{0} ** 1;
        dev.eq_read = 0;
        dev.eq_write = 0;
        dev.grabbed = false;
        dev.active = false;

        dev.set_ev_bit(EV_KEY);
        dev.set_ev_bit(EV_REL);
        dev.set_ev_bit(EV_SYN);
        dev.set_key_bit(BTN_LEFT);
        dev.set_key_bit(BTN_RIGHT);
        dev.set_key_bit(BTN_MIDDLE);
        dev.set_key_bit(BTN_SIDE);
        dev.set_key_bit(BTN_EXTRA);
        dev.set_rel_bit(REL_X);
        dev.set_rel_bit(REL_Y);
        dev.set_rel_bit(REL_WHEEL);
        dev.set_rel_bit(REL_HWHEEL);
        dev.set_rel_bit(REL_WHEEL_HI_RES);
        dev.set_rel_bit(REL_HWHEEL_HI_RES);

        return self.register_device(dev);
    }
};

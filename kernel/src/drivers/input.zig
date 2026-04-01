// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Zig Input Subsystem
//
// Linux-like input event framework:
// - Input device registration (keyboard, mouse, touchpad, gamepad)
// - Event types: EV_KEY, EV_REL, EV_ABS, EV_MSC, EV_SW, EV_LED
// - Input event dispatching to listeners
// - Key repeat auto-repeat handling
// - Input grab / exclusive access
// - Multi-touch protocol (Type B)
// - Absolute axis calibration
// - Event buffer ring for userspace

const std = @import("std");

// ─────────────────── Event Types ────────────────────────────────────
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

// Sync events
pub const SYN_REPORT: u16 = 0;
pub const SYN_CONFIG: u16 = 1;
pub const SYN_MT_REPORT: u16 = 2;
pub const SYN_DROPPED: u16 = 3;

// Key states
pub const KEY_RELEASED: i32 = 0;
pub const KEY_PRESSED: i32 = 1;
pub const KEY_REPEAT: i32 = 2;

// Relative axes
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_Z: u16 = 0x02;
pub const REL_WHEEL: u16 = 0x08;
pub const REL_HWHEEL: u16 = 0x06;

// Absolute axes
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_Z: u16 = 0x02;
pub const ABS_PRESSURE: u16 = 0x18;
pub const ABS_MT_SLOT: u16 = 0x2F;
pub const ABS_MT_TOUCH_MAJOR: u16 = 0x30;
pub const ABS_MT_TOUCH_MINOR: u16 = 0x31;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;
pub const ABS_MT_PRESSURE: u16 = 0x3A;

// Key codes (subset)
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
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_UP: u16 = 103;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_DOWN: u16 = 108;
pub const KEY_DELETE: u16 = 111;

// Button codes
pub const BTN_MOUSE: u16 = 0x110;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;
pub const BTN_TOUCH: u16 = 0x14A;

// Misc events
pub const MSC_SERIAL: u16 = 0x00;
pub const MSC_SCAN: u16 = 0x04;

// Constants
pub const MAX_INPUT_DEVICES = 32;
pub const MAX_EVENT_LISTENERS = 16;
pub const EVENT_BUFFER_SIZE = 256;
pub const MAX_ABS_AXES = 16;
pub const MAX_KEY_BITS = 768;
pub const MAX_MT_SLOTS = 10;

// ─────────────────── Input Event ────────────────────────────────────
pub const InputEvent = struct {
    timestamp: u64 = 0,
    ev_type: u16 = 0,
    code: u16 = 0,
    value: i32 = 0,

    pub fn syn_report(ts: u64) InputEvent {
        return .{
            .timestamp = ts,
            .ev_type = EV_SYN,
            .code = SYN_REPORT,
            .value = 0,
        };
    }

    pub fn key_event(ts: u64, code: u16, pressed: bool) InputEvent {
        return .{
            .timestamp = ts,
            .ev_type = EV_KEY,
            .code = code,
            .value = if (pressed) KEY_PRESSED else KEY_RELEASED,
        };
    }

    pub fn rel_event(ts: u64, axis: u16, delta: i32) InputEvent {
        return .{
            .timestamp = ts,
            .ev_type = EV_REL,
            .code = axis,
            .value = delta,
        };
    }

    pub fn abs_event(ts: u64, axis: u16, value: i32) InputEvent {
        return .{
            .timestamp = ts,
            .ev_type = EV_ABS,
            .code = axis,
            .value = value,
        };
    }
};

// ─────────────────── Absolute Axis Info ─────────────────────────────
pub const AbsAxisInfo = struct {
    minimum: i32 = 0,
    maximum: i32 = 0,
    fuzz: i32 = 0,
    flat: i32 = 0,
    resolution: i32 = 0,
    current_value: i32 = 0,

    pub fn normalize(self: *const AbsAxisInfo, value: i32) f32 {
        const range = self.maximum - self.minimum;
        if (range == 0) return 0;
        return @as(f32, @floatFromInt(value - self.minimum)) / @as(f32, @floatFromInt(range));
    }
};

// ─────────────────── Multi-Touch Slot ───────────────────────────────
pub const MtSlot = struct {
    tracking_id: i32 = -1,
    x: i32 = 0,
    y: i32 = 0,
    pressure: i32 = 0,
    touch_major: i32 = 0,
    touch_minor: i32 = 0,
    active: bool = false,
};

// ─────────────────── Device Capabilities ────────────────────────────
pub const InputDeviceType = enum(u8) {
    keyboard = 0,
    mouse = 1,
    touchpad = 2,
    touchscreen = 3,
    gamepad = 4,
    tablet = 5,
    other = 255,
};

pub const DeviceCaps = struct {
    /// Which event types this device supports (bitmask)
    ev_bits: u32 = 0,
    /// Supported key codes (bitmap)
    key_bits: [MAX_KEY_BITS / 64]u64 = [_]u64{0} ** (MAX_KEY_BITS / 64),
    /// Supported relative axes (bitmask)
    rel_bits: u32 = 0,
    /// Supported absolute axes (bitmask)
    abs_bits: u32 = 0,
    /// Absolute axis info
    abs_info: [MAX_ABS_AXES]AbsAxisInfo = [_]AbsAxisInfo{.{}} ** MAX_ABS_AXES,

    pub fn supports_ev(self: *const DeviceCaps, ev_type: u16) bool {
        return (self.ev_bits & (@as(u32, 1) << @intCast(ev_type))) != 0;
    }

    pub fn set_ev_bit(self: *DeviceCaps, ev_type: u16) void {
        self.ev_bits |= @as(u32, 1) << @intCast(ev_type);
    }

    pub fn set_key_bit(self: *DeviceCaps, code: u16) void {
        const idx = code / 64;
        const bit = code % 64;
        if (idx < self.key_bits.len) {
            self.key_bits[idx] |= @as(u64, 1) << @intCast(bit);
        }
    }

    pub fn set_rel_bit(self: *DeviceCaps, axis: u16) void {
        self.rel_bits |= @as(u32, 1) << @intCast(axis);
    }

    pub fn set_abs_bit(self: *DeviceCaps, axis: u16) void {
        self.abs_bits |= @as(u32, 1) << @intCast(axis);
    }

    pub fn set_abs_info(self: *DeviceCaps, axis: u16, info: AbsAxisInfo) void {
        if (axis < MAX_ABS_AXES) {
            self.abs_info[axis] = info;
            self.set_abs_bit(axis);
        }
    }
};

// ─────────────────── Event Buffer ───────────────────────────────────
pub const EventBuffer = struct {
    events: [EVENT_BUFFER_SIZE]InputEvent = [_]InputEvent{.{}} ** EVENT_BUFFER_SIZE,
    head: u32 = 0,
    tail: u32 = 0,
    count: u32 = 0,
    overflow: bool = false,

    pub fn push(self: *EventBuffer, event: InputEvent) bool {
        if (self.count >= EVENT_BUFFER_SIZE) {
            self.overflow = true;
            return false;
        }
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % EVENT_BUFFER_SIZE;
        self.count += 1;
        return true;
    }

    pub fn pop(self: *EventBuffer) ?InputEvent {
        if (self.count == 0) return null;
        const event = self.events[self.head];
        self.head = (self.head + 1) % EVENT_BUFFER_SIZE;
        self.count -= 1;
        return event;
    }

    pub fn is_empty(self: *const EventBuffer) bool {
        return self.count == 0;
    }

    pub fn clear(self: *EventBuffer) void {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
        self.overflow = false;
    }
};

// ─────────────────── Input Device ───────────────────────────────────
pub const InputDevice = struct {
    id: u16 = 0,
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: u8 = 0,
    dev_type: InputDeviceType = .other,
    caps: DeviceCaps = .{},
    /// Key state bitmap (pressed keys)
    key_state: [MAX_KEY_BITS / 64]u64 = [_]u64{0} ** (MAX_KEY_BITS / 64),
    /// Multi-touch slots
    mt_slots: [MAX_MT_SLOTS]MtSlot = [_]MtSlot{.{}} ** MAX_MT_SLOTS,
    current_mt_slot: u8 = 0,
    /// Auto-repeat settings
    repeat_delay: u32 = 250, // ms
    repeat_rate: u32 = 33,   // ms per repeat
    repeat_key: u16 = 0,
    repeat_timestamp: u64 = 0,
    repeat_active: bool = false,
    /// Event buffer for this device
    event_buf: EventBuffer = .{},
    /// Grabbed by a listener?
    grabbed: bool = false,
    grab_listener: u16 = 0,
    /// Active flag
    active: bool = false,

    pub fn set_name(self: *InputDevice, n: []const u8) void {
        const len = @min(n.len, 64);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn is_key_pressed(self: *const InputDevice, code: u16) bool {
        const idx = code / 64;
        const bit = code % 64;
        if (idx >= self.key_state.len) return false;
        return (self.key_state[idx] & (@as(u64, 1) << @intCast(bit))) != 0;
    }

    fn set_key_state(self: *InputDevice, code: u16, pressed: bool) void {
        const idx = code / 64;
        const bit = code % 64;
        if (idx < self.key_state.len) {
            if (pressed) {
                self.key_state[idx] |= @as(u64, 1) << @intCast(bit);
            } else {
                self.key_state[idx] &= ~(@as(u64, 1) << @intCast(bit));
            }
        }
    }

    /// Report a key event
    pub fn report_key(self: *InputDevice, timestamp: u64, code: u16, value: i32) void {
        if (value == KEY_PRESSED) {
            self.set_key_state(code, true);
            self.repeat_key = code;
            self.repeat_timestamp = timestamp;
            self.repeat_active = true;
        } else if (value == KEY_RELEASED) {
            self.set_key_state(code, false);
            if (self.repeat_key == code) {
                self.repeat_active = false;
            }
        }
        const event = InputEvent{
            .timestamp = timestamp,
            .ev_type = EV_KEY,
            .code = code,
            .value = value,
        };
        _ = self.event_buf.push(event);
    }

    /// Report a relative axis event
    pub fn report_rel(self: *InputDevice, timestamp: u64, axis: u16, delta: i32) void {
        const event = InputEvent.rel_event(timestamp, axis, delta);
        _ = self.event_buf.push(event);
    }

    /// Report an absolute axis event
    pub fn report_abs(self: *InputDevice, timestamp: u64, axis: u16, value: i32) void {
        if (axis < MAX_ABS_AXES) {
            self.caps.abs_info[axis].current_value = value;
        }
        // Handle MT slot protocol
        if (axis == ABS_MT_SLOT) {
            if (value >= 0 and value < MAX_MT_SLOTS) {
                self.current_mt_slot = @intCast(value);
            }
        } else if (axis == ABS_MT_TRACKING_ID) {
            const slot = self.current_mt_slot;
            if (slot < MAX_MT_SLOTS) {
                self.mt_slots[slot].tracking_id = value;
                self.mt_slots[slot].active = value >= 0;
            }
        } else if (axis == ABS_MT_POSITION_X) {
            const slot = self.current_mt_slot;
            if (slot < MAX_MT_SLOTS) self.mt_slots[slot].x = value;
        } else if (axis == ABS_MT_POSITION_Y) {
            const slot = self.current_mt_slot;
            if (slot < MAX_MT_SLOTS) self.mt_slots[slot].y = value;
        } else if (axis == ABS_MT_PRESSURE) {
            const slot = self.current_mt_slot;
            if (slot < MAX_MT_SLOTS) self.mt_slots[slot].pressure = value;
        }
        const event = InputEvent.abs_event(timestamp, axis, value);
        _ = self.event_buf.push(event);
    }

    /// Report a sync event (frame boundary)
    pub fn report_sync(self: *InputDevice, timestamp: u64) void {
        const event = InputEvent.syn_report(timestamp);
        _ = self.event_buf.push(event);
    }

    /// Check and generate auto-repeat
    pub fn tick_repeat(self: *InputDevice, timestamp: u64) void {
        if (!self.repeat_active) return;

        const elapsed = timestamp - self.repeat_timestamp;
        const delay_ticks = self.repeat_delay;

        if (elapsed >= delay_ticks) {
            const since_delay = elapsed - delay_ticks;
            const repeats = since_delay / self.repeat_rate;
            _ = repeats;
            // Emit repeat event
            const event = InputEvent{
                .timestamp = timestamp,
                .ev_type = EV_KEY,
                .code = self.repeat_key,
                .value = KEY_REPEAT,
            };
            _ = self.event_buf.push(event);
        }
    }
};

// ─────────────────── Event Listener ─────────────────────────────────
pub const EventListener = struct {
    id: u16 = 0,
    buffer: EventBuffer = .{},
    active: bool = false,
    /// Filter: which event types to receive (0 = all)
    ev_filter: u32 = 0,
    /// Filter: which device (0xFFFF = all)
    device_filter: u16 = 0xFFFF,
};

// ─────────────────── Input Manager ──────────────────────────────────
pub const InputManager = struct {
    devices: [MAX_INPUT_DEVICES]?InputDevice = [_]?InputDevice{null} ** MAX_INPUT_DEVICES,
    device_count: u16 = 0,
    listeners: [MAX_EVENT_LISTENERS]?EventListener = [_]?EventListener{null} ** MAX_EVENT_LISTENERS,
    listener_count: u16 = 0,
    current_tick: u64 = 0,
    initialized: bool = false,

    pub fn init(self: *InputManager) void {
        self.initialized = true;
    }

    /// Register a new input device
    pub fn register_device(self: *InputManager, name: []const u8, dev_type: InputDeviceType) ?u16 {
        if (self.device_count >= MAX_INPUT_DEVICES) return null;

        for (self.devices, 0..) |*slot, i| {
            if (slot.* == null) {
                var dev = InputDevice{};
                dev.id = @intCast(i);
                dev.set_name(name);
                dev.dev_type = dev_type;
                dev.active = true;
                slot.* = dev;
                self.device_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Unregister a device
    pub fn unregister_device(self: *InputManager, dev_id: u16) void {
        if (dev_id < MAX_INPUT_DEVICES) {
            if (self.devices[dev_id]) |_| {
                self.devices[dev_id] = null;
                if (self.device_count > 0) self.device_count -= 1;
            }
        }
    }

    /// Get a mutable reference to a device
    pub fn get_device(self: *InputManager, dev_id: u16) ?*InputDevice {
        if (dev_id < MAX_INPUT_DEVICES) {
            if (self.devices[dev_id]) |*dev| return dev;
        }
        return null;
    }

    /// Register an event listener
    pub fn add_listener(self: *InputManager) ?u16 {
        if (self.listener_count >= MAX_EVENT_LISTENERS) return null;

        for (self.listeners, 0..) |*slot, i| {
            if (slot.* == null) {
                var listener = EventListener{};
                listener.id = @intCast(i);
                listener.active = true;
                slot.* = listener;
                self.listener_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Remove a listener
    pub fn remove_listener(self: *InputManager, listener_id: u16) void {
        if (listener_id < MAX_EVENT_LISTENERS) {
            self.listeners[listener_id] = null;
            if (self.listener_count > 0) self.listener_count -= 1;
        }
    }

    /// Dispatch events from all devices to all listeners
    pub fn dispatch_events(self: *InputManager) void {
        for (&self.devices) |*maybe_dev| {
            if (maybe_dev.*) |*dev| {
                while (dev.event_buf.pop()) |event| {
                    self.dispatch_single_event(dev.id, &event);
                }
            }
        }
    }

    fn dispatch_single_event(self: *InputManager, dev_id: u16, event: *const InputEvent) void {
        for (&self.listeners) |*maybe_listener| {
            if (maybe_listener.*) |*listener| {
                if (!listener.active) continue;
                // Device filter
                if (listener.device_filter != 0xFFFF and listener.device_filter != dev_id) continue;
                // Event type filter
                if (listener.ev_filter != 0) {
                    if ((listener.ev_filter & (@as(u32, 1) << @intCast(event.ev_type))) == 0) continue;
                }
                _ = listener.buffer.push(event.*);
            }
        }
    }

    /// Grab a device exclusively for a listener
    pub fn grab_device(self: *InputManager, dev_id: u16, listener_id: u16) bool {
        if (dev_id < MAX_INPUT_DEVICES) {
            if (self.devices[dev_id]) |*dev| {
                if (dev.grabbed) return false;
                dev.grabbed = true;
                dev.grab_listener = listener_id;
                return true;
            }
        }
        return false;
    }

    /// Release a device grab
    pub fn ungrab_device(self: *InputManager, dev_id: u16) void {
        if (dev_id < MAX_INPUT_DEVICES) {
            if (self.devices[dev_id]) |*dev| {
                dev.grabbed = false;
            }
        }
    }

    /// Tick: handle auto-repeat for all devices
    pub fn tick(self: *InputManager, timestamp: u64) void {
        self.current_tick = timestamp;
        for (&self.devices) |*maybe_dev| {
            if (maybe_dev.*) |*dev| {
                dev.tick_repeat(timestamp);
            }
        }
        self.dispatch_events();
    }

    /// Read events from a listener's buffer
    pub fn read_events(self: *InputManager, listener_id: u16, out: []InputEvent) u32 {
        if (listener_id >= MAX_EVENT_LISTENERS) return 0;
        if (self.listeners[listener_id]) |*listener| {
            var count: u32 = 0;
            while (count < out.len) {
                if (listener.buffer.pop()) |event| {
                    out[count] = event;
                    count += 1;
                } else break;
            }
            return count;
        }
        return 0;
    }
};

// ─────────────────── Keyboard Layout Mapping ────────────────────────
pub const KeyboardLayout = struct {
    /// Scancode to keycode mapping (PS/2 set 1)
    scancode_map: [256]u16 = init_default_scancode_map(),
    /// Keycode to ASCII (unshifted)
    ascii_map: [128]u8 = init_default_ascii_map(),
    /// Keycode to ASCII (shifted)
    ascii_shift_map: [128]u8 = init_default_ascii_shift_map(),

    pub fn scancode_to_keycode(self: *const KeyboardLayout, scancode: u8) u16 {
        return self.scancode_map[scancode];
    }

    pub fn keycode_to_ascii(self: *const KeyboardLayout, keycode: u16, shifted: bool) u8 {
        if (keycode >= 128) return 0;
        if (shifted) return self.ascii_shift_map[keycode];
        return self.ascii_map[keycode];
    }
};

fn init_default_scancode_map() [256]u16 {
    var map = [_]u16{0} ** 256;
    map[0x01] = KEY_ESC;
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
    map[0x1A] = KEY_LEFTBRACE;
    map[0x1B] = KEY_RIGHTBRACE;
    map[0x1C] = KEY_ENTER;
    map[0x1D] = KEY_LEFTCTRL;
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
    map[0x29] = KEY_GRAVE;
    map[0x2A] = KEY_LEFTSHIFT;
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
    map[0x36] = KEY_RIGHTSHIFT;
    map[0x38] = KEY_LEFTALT;
    map[0x39] = KEY_SPACE;
    map[0x3A] = KEY_CAPSLOCK;
    return map;
}

fn init_default_ascii_map() [128]u8 {
    var map = [_]u8{0} ** 128;
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
    map[KEY_LEFTBRACE] = '[';
    map[KEY_RIGHTBRACE] = ']';
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
    map[KEY_GRAVE] = '`';
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
    return map;
}

fn init_default_ascii_shift_map() [128]u8 {
    var map = [_]u8{0} ** 128;
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
    map[KEY_LEFTBRACE] = '{';
    map[KEY_RIGHTBRACE] = '}';
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
    map[KEY_GRAVE] = '~';
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
    return map;
}

// ─────────────────── Global Instance ────────────────────────────────
var input_mgr: InputManager = .{};
var keyboard_layout: KeyboardLayout = .{};

pub fn initInput() void {
    input_mgr.init();
}

pub fn getInputManager() *InputManager {
    return &input_mgr;
}

pub fn getKeyboardLayout() *KeyboardLayout {
    return &keyboard_layout;
}

// ─────────────────── C FFI Exports ──────────────────────────────────
export fn zxy_input_init() void {
    initInput();
}

export fn zxy_input_register_device(name_ptr: [*]const u8, name_len: u32, dev_type: u8) i32 {
    const name = name_ptr[0..name_len];
    const dt: InputDeviceType = @enumFromInt(dev_type);
    if (input_mgr.register_device(name, dt)) |id| {
        return @intCast(id);
    }
    return -1;
}

export fn zxy_input_report_key(dev_id: u16, timestamp: u64, code: u16, value: i32) void {
    if (input_mgr.get_device(dev_id)) |dev| {
        dev.report_key(timestamp, code, value);
    }
}

export fn zxy_input_report_rel(dev_id: u16, timestamp: u64, axis: u16, delta: i32) void {
    if (input_mgr.get_device(dev_id)) |dev| {
        dev.report_rel(timestamp, axis, delta);
    }
}

export fn zxy_input_report_abs(dev_id: u16, timestamp: u64, axis: u16, value: i32) void {
    if (input_mgr.get_device(dev_id)) |dev| {
        dev.report_abs(timestamp, axis, value);
    }
}

export fn zxy_input_report_sync(dev_id: u16, timestamp: u64) void {
    if (input_mgr.get_device(dev_id)) |dev| {
        dev.report_sync(timestamp);
    }
}

export fn zxy_input_tick(timestamp: u64) void {
    input_mgr.tick(timestamp);
}

export fn zxy_input_add_listener() i32 {
    if (input_mgr.add_listener()) |id| {
        return @intCast(id);
    }
    return -1;
}

export fn zxy_input_device_count() u16 {
    return input_mgr.device_count;
}

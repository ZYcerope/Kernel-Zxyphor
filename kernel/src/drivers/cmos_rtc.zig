// SPDX-License-Identifier: MIT
// Zxyphor Kernel — CMOS/RTC Advanced Driver (Zig)
//
// Complete CMOS/RTC driver for x86_64:
// - Direct CMOS port I/O (0x70/0x71) with NMI mask
// - BCD / binary mode detection and conversion
// - Full RTC time reading (seconds through century)
// - RTC alarm support (seconds/minutes/hours/day)
// - Periodic interrupt rate configuration (2 Hz – 8192 Hz)
// - Update-ended/alarm/periodic interrupt handling
// - CMOS NVRAM read/write for BIOS settings
// - Real-time clock → UNIX epoch conversion
// - Leap year handling is correct
// - NTP-like slewing for clock discipline
// - Battery status detection
// - Timezone offset management
// - RTC wakeup alarm (for suspend/resume)

const std = @import("std");

// ─────────────────── Port I/O ───────────────────────────────────────

const CMOS_ADDR_PORT: u16 = 0x70;
const CMOS_DATA_PORT: u16 = 0x71;

fn outb(port: u16, val: u8) void {
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (val),
          [port] "N{dx}" (port),
        : "memory"
    );
}

fn inb(port: u16) u8 {
    return asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
        : "memory"
    );
}

// ─────────────────── CMOS Registers ─────────────────────────────────

const CMOS_RTC_SECONDS: u8 = 0x00;
const CMOS_RTC_SECONDS_ALARM: u8 = 0x01;
const CMOS_RTC_MINUTES: u8 = 0x02;
const CMOS_RTC_MINUTES_ALARM: u8 = 0x03;
const CMOS_RTC_HOURS: u8 = 0x04;
const CMOS_RTC_HOURS_ALARM: u8 = 0x05;
const CMOS_RTC_DAY_OF_WEEK: u8 = 0x06;
const CMOS_RTC_DAY_OF_MONTH: u8 = 0x07;
const CMOS_RTC_MONTH: u8 = 0x08;
const CMOS_RTC_YEAR: u8 = 0x09;
const CMOS_RTC_CENTURY: u8 = 0x32;

const CMOS_STATUS_A: u8 = 0x0A;
const CMOS_STATUS_B: u8 = 0x0B;
const CMOS_STATUS_C: u8 = 0x0C;
const CMOS_STATUS_D: u8 = 0x0D;

// Status Register A bits
const STATUS_A_UIP: u8 = 0x80; // Update In Progress
const STATUS_A_RATE_MASK: u8 = 0x0F; // Periodic interrupt rate

// Status Register B bits
const STATUS_B_SET: u8 = 0x80; // Inhibit updates
const STATUS_B_PIE: u8 = 0x40; // Periodic Interrupt Enable
const STATUS_B_AIE: u8 = 0x20; // Alarm Interrupt Enable
const STATUS_B_UIE: u8 = 0x10; // Update-ended Interrupt Enable
const STATUS_B_SQWE: u8 = 0x08; // Square Wave Enable
const STATUS_B_DM: u8 = 0x04; // Data Mode: 1 = binary, 0 = BCD
const STATUS_B_24H: u8 = 0x02; // 24-hour mode
const STATUS_B_DSE: u8 = 0x01; // Daylight Saving Enable

// NVRAM size (standard CMOS)
const CMOS_NVRAM_SIZE: usize = 128;
const CMOS_NVRAM_START: u8 = 0x0E; // First general-purpose NVRAM byte

// ─────────────────── Alarm Don't-Care Value ─────────────────────────

const ALARM_DONT_CARE: u8 = 0xC0;

// ─────────────────── RTC Time ───────────────────────────────────────

pub const RtcTime = struct {
    second: u8,
    minute: u8,
    hour: u8,
    day_of_week: u8, // 1 = Sunday
    day: u8,
    month: u8,
    year: u16, // Full year (e.g. 2025)

    pub fn is_valid(self: *const RtcTime) bool {
        if (self.second > 59) return false;
        if (self.minute > 59) return false;
        if (self.hour > 23) return false;
        if (self.month < 1 or self.month > 12) return false;
        if (self.day < 1) return false;
        const max_day = days_in_month(self.month, self.year);
        if (self.day > max_day) return false;
        return true;
    }
};

// ─────────────────── Alarm Time ─────────────────────────────────────

pub const RtcAlarm = struct {
    second: u8, // 0-59 or ALARM_DONT_CARE
    minute: u8,
    hour: u8,
    day: u8, // Day-of-month or ALARM_DONT_CARE
    enabled: bool,
    fired: bool,
    callback: ?*const fn () void,

    pub fn init() RtcAlarm {
        return .{
            .second = ALARM_DONT_CARE,
            .minute = ALARM_DONT_CARE,
            .hour = ALARM_DONT_CARE,
            .day = ALARM_DONT_CARE,
            .enabled = false,
            .fired = false,
            .callback = null,
        };
    }
};

// ─────────────────── Periodic Rate ──────────────────────────────────

pub const PeriodicRate = enum(u4) {
    disabled = 0,
    hz_8192 = 3,
    hz_4096 = 4,
    hz_2048 = 5,
    hz_1024 = 6,
    hz_512 = 7,
    hz_256 = 8,
    hz_128 = 9,
    hz_64 = 10,
    hz_32 = 11,
    hz_16 = 12,
    hz_8 = 13,
    hz_4 = 14,
    hz_2 = 15,

    pub fn frequency(self: PeriodicRate) u32 {
        return switch (self) {
            .disabled => 0,
            .hz_8192 => 8192,
            .hz_4096 => 4096,
            .hz_2048 => 2048,
            .hz_1024 => 1024,
            .hz_512 => 512,
            .hz_256 => 256,
            .hz_128 => 128,
            .hz_64 => 64,
            .hz_32 => 32,
            .hz_16 => 16,
            .hz_8 => 8,
            .hz_4 => 4,
            .hz_2 => 2,
        };
    }
};

// ─────────────────── Calendar Helpers ───────────────────────────────

fn is_leap_year(year: u16) bool {
    if (year % 400 == 0) return true;
    if (year % 100 == 0) return false;
    return (year % 4 == 0);
}

fn days_in_month(month: u8, year: u16) u8 {
    const days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (month < 1 or month > 12) return 0;
    if (month == 2 and is_leap_year(year)) return 29;
    return days[month - 1];
}

fn days_in_year(year: u16) u16 {
    return if (is_leap_year(year)) 366 else 365;
}

/// Convert RTC time to UNIX timestamp (seconds since 1970-01-01 00:00:00 UTC)
pub fn rtc_to_unix(time: *const RtcTime) i64 {
    var days: i64 = 0;

    // Years
    var y: u16 = 1970;
    while (y < time.year) : (y += 1) {
        days += days_in_year(y);
    }

    // Months
    var m: u8 = 1;
    while (m < time.month) : (m += 1) {
        days += days_in_month(m, time.year);
    }

    // Days
    days += @as(i64, time.day) - 1;

    return days * 86400 + @as(i64, time.hour) * 3600 + @as(i64, time.minute) * 60 + @as(i64, time.second);
}

/// Convert UNIX timestamp to RTC time
pub fn unix_to_rtc(timestamp: i64) RtcTime {
    var rem = timestamp;
    var result: RtcTime = .{
        .second = 0,
        .minute = 0,
        .hour = 0,
        .day_of_week = 0,
        .day = 1,
        .month = 1,
        .year = 1970,
    };

    // Day of week: Jan 1, 1970 was Thursday (4)
    const total_days = @divFloor(rem, 86400);
    result.day_of_week = @intCast(@mod(total_days + 4, 7) + 1); // 1=Sun

    // Time of day
    rem = @mod(rem, 86400);
    result.hour = @intCast(@divFloor(rem, 3600));
    rem = @mod(rem, 3600);
    result.minute = @intCast(@divFloor(rem, 60));
    result.second = @intCast(@mod(rem, 60));

    // Year
    var day_count = total_days;
    while (true) {
        const dy = days_in_year(result.year);
        if (day_count < dy) break;
        day_count -= dy;
        result.year += 1;
    }

    // Month
    while (true) {
        const dm = days_in_month(result.month, result.year);
        if (day_count < dm) break;
        day_count -= dm;
        result.month += 1;
    }
    result.day = @intCast(day_count + 1);

    return result;
}

// ─────────────────── BCD Conversion ─────────────────────────────────

fn bcd_to_bin(val: u8) u8 {
    return (val & 0x0F) + ((val >> 4) * 10);
}

fn bin_to_bcd(val: u8) u8 {
    return ((val / 10) << 4) | (val % 10);
}

// ─────────────────── Low-level CMOS Access ──────────────────────────

fn cmos_read(reg: u8) u8 {
    // Preserve NMI disable bit (bit 7 of address port)
    outb(CMOS_ADDR_PORT, reg & 0x7F);
    return inb(CMOS_DATA_PORT);
}

fn cmos_write(reg: u8, val: u8) void {
    outb(CMOS_ADDR_PORT, reg & 0x7F);
    outb(CMOS_DATA_PORT, val);
}

fn cmos_read_nmi_disabled(reg: u8) u8 {
    outb(CMOS_ADDR_PORT, reg | 0x80);
    return inb(CMOS_DATA_PORT);
}

fn cmos_write_nmi_disabled(reg: u8, val: u8) void {
    outb(CMOS_ADDR_PORT, reg | 0x80);
    outb(CMOS_DATA_PORT, val);
}

/// Wait for UIP (Update In Progress) to clear
fn wait_uip_clear() void {
    // Spin until bit 7 of Status A clears — max ~244 μs
    var attempts: u32 = 0;
    while (attempts < 10000) : (attempts += 1) {
        if ((cmos_read(CMOS_STATUS_A) & STATUS_A_UIP) == 0) return;
    }
}

// ─────────────────── CMOS/RTC Manager ───────────────────────────────

pub const CmosRtcDriver = struct {
    // Mode detection
    is_bcd: bool,
    is_24h: bool,

    // Current time cache
    current_time: RtcTime,
    unix_timestamp: i64,

    // Alarm
    alarm: RtcAlarm,

    // Periodic interrupt
    periodic_rate: PeriodicRate,
    periodic_count: u64,

    // Interrupt stats
    update_irq_count: u64,
    alarm_irq_count: u64,
    periodic_irq_count: u64,

    // NVRAM cache
    nvram: [CMOS_NVRAM_SIZE]u8,
    nvram_valid: bool,

    // UTC offset (seconds from UTC, e.g. -18000 for EST)
    utc_offset: i32,

    // Clock discipline (NTP slewing)
    slew_rate: i32, // nanoseconds per second adjustment
    slew_remaining: i64,

    // Battery
    battery_ok: bool,

    // Initialized
    initialized: bool,

    const Self = @This();

    pub fn init() Self {
        var driver = Self{
            .is_bcd = true,
            .is_24h = true,
            .current_time = .{
                .second = 0,
                .minute = 0,
                .hour = 0,
                .day_of_week = 0,
                .day = 1,
                .month = 1,
                .year = 1970,
            },
            .unix_timestamp = 0,
            .alarm = RtcAlarm.init(),
            .periodic_rate = .disabled,
            .periodic_count = 0,
            .update_irq_count = 0,
            .alarm_irq_count = 0,
            .periodic_irq_count = 0,
            .nvram = [_]u8{0} ** CMOS_NVRAM_SIZE,
            .nvram_valid = false,
            .utc_offset = 0,
            .slew_rate = 0,
            .slew_remaining = 0,
            .battery_ok = true,
            .initialized = false,
        };

        // Detect mode from status register B
        const status_b = cmos_read(CMOS_STATUS_B);
        driver.is_bcd = (status_b & STATUS_B_DM) == 0;
        driver.is_24h = (status_b & STATUS_B_24H) != 0;

        // Check battery (Status D bit 7)
        const status_d = cmos_read(CMOS_STATUS_D);
        driver.battery_ok = (status_d & 0x80) != 0;

        // Read initial time
        driver.read_time();

        // Read NVRAM
        driver.read_nvram();

        driver.initialized = true;
        return driver;
    }

    /// Read current time from RTC hardware
    pub fn read_time(self: *Self) void {
        // Double-read to ensure consistency (no update crossing)
        var t1: RtcTime = undefined;
        var t2: RtcTime = undefined;

        var attempts: u32 = 0;
        while (attempts < 5) : (attempts += 1) {
            wait_uip_clear();
            t1 = self.read_raw_time();
            wait_uip_clear();
            t2 = self.read_raw_time();

            // If both reads match, data is consistent
            if (t1.second == t2.second and t1.minute == t2.minute and
                t1.hour == t2.hour and t1.day == t2.day and
                t1.month == t2.month and t1.year == t2.year)
            {
                break;
            }
        }

        self.current_time = t2;
        self.unix_timestamp = rtc_to_unix(&self.current_time);
    }

    fn read_raw_time(self: *Self) RtcTime {
        var time: RtcTime = undefined;

        var sec = cmos_read(CMOS_RTC_SECONDS);
        var min = cmos_read(CMOS_RTC_MINUTES);
        var hour = cmos_read(CMOS_RTC_HOURS);
        const dow = cmos_read(CMOS_RTC_DAY_OF_WEEK);
        var day = cmos_read(CMOS_RTC_DAY_OF_MONTH);
        var month = cmos_read(CMOS_RTC_MONTH);
        var year = cmos_read(CMOS_RTC_YEAR);
        var century = cmos_read(CMOS_RTC_CENTURY);

        // Convert from BCD if needed
        if (self.is_bcd) {
            sec = bcd_to_bin(sec);
            min = bcd_to_bin(min);
            // Hour needs special handling for 12h mode
            hour = if (!self.is_24h and (hour & 0x80) != 0)
                bcd_to_bin(hour & 0x7F) + 12
            else
                bcd_to_bin(hour);
            day = bcd_to_bin(day);
            month = bcd_to_bin(month);
            year = bcd_to_bin(year);
            century = bcd_to_bin(century);
        }

        time.second = sec;
        time.minute = min;
        time.hour = if (hour >= 24) hour - 12 else hour; // 12AM edge case
        time.day_of_week = dow;
        time.day = day;
        time.month = month;
        time.year = @as(u16, century) * 100 + @as(u16, year);

        return time;
    }

    /// Write time to RTC hardware
    pub fn write_time(self: *Self, time: *const RtcTime) void {
        if (!time.is_valid()) return;

        // Inhibit updates
        var status_b = cmos_read(CMOS_STATUS_B);
        cmos_write(CMOS_STATUS_B, status_b | STATUS_B_SET);

        var sec = time.second;
        var min = time.minute;
        var hour = time.hour;
        var day = time.day;
        var month = time.month;
        const year_low: u8 = @intCast(time.year % 100);
        const century_val: u8 = @intCast(time.year / 100);

        if (self.is_bcd) {
            sec = bin_to_bcd(sec);
            min = bin_to_bcd(min);
            hour = bin_to_bcd(hour);
            day = bin_to_bcd(day);
            month = bin_to_bcd(month);
        }

        cmos_write(CMOS_RTC_SECONDS, sec);
        cmos_write(CMOS_RTC_MINUTES, min);
        cmos_write(CMOS_RTC_HOURS, hour);
        cmos_write(CMOS_RTC_DAY_OF_MONTH, day);
        cmos_write(CMOS_RTC_MONTH, month);
        cmos_write(CMOS_RTC_YEAR, if (self.is_bcd) bin_to_bcd(year_low) else year_low);
        cmos_write(CMOS_RTC_CENTURY, if (self.is_bcd) bin_to_bcd(century_val) else century_val);

        // Re-enable updates
        cmos_write(CMOS_STATUS_B, status_b & ~STATUS_B_SET);

        self.current_time = time.*;
        self.unix_timestamp = rtc_to_unix(time);
    }

    /// Set alarm
    pub fn set_alarm(self: *Self, alarm_time: *const RtcAlarm) void {
        self.alarm = alarm_time.*;

        // Inhibit updates
        var status_b = cmos_read(CMOS_STATUS_B);
        cmos_write(CMOS_STATUS_B, status_b | STATUS_B_SET);

        var sec = alarm_time.second;
        var min = alarm_time.minute;
        var hour = alarm_time.hour;

        if (self.is_bcd) {
            if (sec != ALARM_DONT_CARE) sec = bin_to_bcd(sec);
            if (min != ALARM_DONT_CARE) min = bin_to_bcd(min);
            if (hour != ALARM_DONT_CARE) hour = bin_to_bcd(hour);
        }

        cmos_write(CMOS_RTC_SECONDS_ALARM, sec);
        cmos_write(CMOS_RTC_MINUTES_ALARM, min);
        cmos_write(CMOS_RTC_HOURS_ALARM, hour);

        // Enable alarm interrupt
        if (alarm_time.enabled) {
            status_b |= STATUS_B_AIE;
        } else {
            status_b &= ~STATUS_B_AIE;
        }
        cmos_write(CMOS_STATUS_B, status_b & ~STATUS_B_SET);
    }

    /// Clear alarm
    pub fn clear_alarm(self: *Self) void {
        self.alarm = RtcAlarm.init();

        var status_b = cmos_read(CMOS_STATUS_B);
        status_b &= ~STATUS_B_AIE;
        cmos_write(CMOS_STATUS_B, status_b);
    }

    /// Set periodic interrupt rate
    pub fn set_periodic_rate(self: *Self, rate: PeriodicRate) void {
        var status_a = cmos_read(CMOS_STATUS_A);
        status_a = (status_a & ~STATUS_A_RATE_MASK) | @intFromEnum(rate);
        cmos_write(CMOS_STATUS_A, status_a);

        var status_b = cmos_read(CMOS_STATUS_B);
        if (rate != .disabled) {
            status_b |= STATUS_B_PIE;
        } else {
            status_b &= ~STATUS_B_PIE;
        }
        cmos_write(CMOS_STATUS_B, status_b);

        self.periodic_rate = rate;
    }

    /// Enable update-ended interrupt
    pub fn enable_update_interrupt(self: *Self) void {
        _ = self;
        var status_b = cmos_read(CMOS_STATUS_B);
        status_b |= STATUS_B_UIE;
        cmos_write(CMOS_STATUS_B, status_b);
    }

    /// Disable update-ended interrupt
    pub fn disable_update_interrupt(self: *Self) void {
        _ = self;
        var status_b = cmos_read(CMOS_STATUS_B);
        status_b &= ~STATUS_B_UIE;
        cmos_write(CMOS_STATUS_B, status_b);
    }

    /// Handle RTC interrupt (IRQ 8)
    pub fn handle_interrupt(self: *Self) void {
        // Read status C to acknowledge (and determine cause)
        const status_c = cmos_read(CMOS_STATUS_C);

        if ((status_c & STATUS_B_UIE) != 0) {
            // Update-ended: refresh time
            self.read_time();
            self.update_irq_count += 1;
        }

        if ((status_c & STATUS_B_AIE) != 0) {
            // Alarm fired
            self.alarm.fired = true;
            self.alarm_irq_count += 1;
            if (self.alarm.callback) |cb| {
                cb();
            }
        }

        if ((status_c & STATUS_B_PIE) != 0) {
            // Periodic
            self.periodic_count += 1;
            self.periodic_irq_count += 1;
        }
    }

    // ─── NVRAM ──────────────────────────────────────────────────────

    /// Read all NVRAM bytes
    pub fn read_nvram(self: *Self) void {
        for (0..CMOS_NVRAM_SIZE) |i| {
            self.nvram[i] = cmos_read(CMOS_NVRAM_START + @as(u8, @intCast(i)));
        }
        self.nvram_valid = true;
    }

    /// Write NVRAM (specific offset)
    pub fn write_nvram_byte(self: *Self, offset: u8, val: u8) void {
        if (offset >= CMOS_NVRAM_SIZE) return;
        cmos_write(CMOS_NVRAM_START + offset, val);
        self.nvram[offset] = val;
    }

    /// Read NVRAM byte
    pub fn read_nvram_byte(self: *const Self, offset: u8) u8 {
        if (offset >= CMOS_NVRAM_SIZE) return 0;
        if (self.nvram_valid) return self.nvram[offset];
        return cmos_read(CMOS_NVRAM_START + offset);
    }

    /// Compute CMOS checksum (sum of bytes 0x10-0x2D, stored in 0x2E-0x2F)
    pub fn compute_checksum(self: *const Self) u16 {
        var sum: u16 = 0;
        for (0x10..0x2E) |i| {
            sum += @as(u16, self.read_nvram_byte(@intCast(i)));
        }
        return sum;
    }

    pub fn verify_checksum(self: *const Self) bool {
        const computed = self.compute_checksum();
        const stored_hi = self.read_nvram_byte(0x2E);
        const stored_lo = self.read_nvram_byte(0x2F);
        const stored = (@as(u16, stored_hi) << 8) | @as(u16, stored_lo);
        return computed == stored;
    }

    pub fn update_checksum(self: *Self) void {
        const checksum = self.compute_checksum();
        self.write_nvram_byte(0x2E, @intCast(checksum >> 8));
        self.write_nvram_byte(0x2F, @intCast(checksum & 0xFF));
    }

    // ─── Clock Discipline ───────────────────────────────────────────

    /// Apply NTP-like slew correction
    pub fn set_slew(self: *Self, nsec_per_sec: i32, duration_sec: u32) void {
        self.slew_rate = nsec_per_sec;
        self.slew_remaining = @as(i64, nsec_per_sec) * @as(i64, duration_sec);
    }

    /// Called each second by tick handler
    pub fn slew_tick(self: *Self) void {
        if (self.slew_remaining == 0) return;

        if (self.slew_remaining > 0) {
            const adj = @min(self.slew_rate, @as(i32, @intCast(self.slew_remaining)));
            self.slew_remaining -= adj;
        } else {
            const adj = @max(self.slew_rate, @as(i32, @intCast(self.slew_remaining)));
            self.slew_remaining -= adj;
        }

        if (self.slew_remaining == 0) {
            self.slew_rate = 0;
        }
    }

    // ─── Wakeup Alarm ───────────────────────────────────────────────

    /// Set a wakeup alarm N seconds from now
    pub fn set_wakeup_alarm(self: *Self, seconds_from_now: u32) void {
        const target_ts = self.unix_timestamp + @as(i64, seconds_from_now);
        const target_time = unix_to_rtc(target_ts);
        var alarm_cfg = RtcAlarm{
            .second = target_time.second,
            .minute = target_time.minute,
            .hour = target_time.hour,
            .day = target_time.day,
            .enabled = true,
            .fired = false,
            .callback = null,
        };
        self.set_alarm(&alarm_cfg);
    }

    /// Get local time with UTC offset applied
    pub fn get_local_time(self: *const Self) RtcTime {
        const local_ts = self.unix_timestamp + @as(i64, self.utc_offset);
        return unix_to_rtc(local_ts);
    }

    /// Get UNIX timestamp with UTC offset
    pub fn get_local_unix(self: *const Self) i64 {
        return self.unix_timestamp + @as(i64, self.utc_offset);
    }

    // ─── Boot Time Estimation ───────────────────────────────────────

    /// Estimate system uptime from current RTC vs. stored boot time
    pub fn estimate_uptime_seconds(self: *const Self, boot_timestamp: i64) i64 {
        return self.unix_timestamp - boot_timestamp;
    }

    // ─── Diagnostic ─────────────────────────────────────────────────

    pub fn get_battery_status(self: *const Self) bool {
        return self.battery_ok;
    }

    pub fn get_total_interrupts(self: *const Self) u64 {
        return self.update_irq_count + self.alarm_irq_count + self.periodic_irq_count;
    }
};

// ─────────────────── Global Instance ────────────────────────────────

var g_cmos_rtc: CmosRtcDriver = undefined;
var g_cmos_initialized: bool = false;

fn cmos_instance() *CmosRtcDriver {
    return &g_cmos_rtc;
}

// ─────────────────── FFI Exports ────────────────────────────────────

export fn zxy_cmos_rtc_init() void {
    g_cmos_rtc = CmosRtcDriver.init();
    g_cmos_initialized = true;
}

export fn zxy_cmos_read_time() void {
    if (g_cmos_initialized) {
        cmos_instance().read_time();
    }
}

export fn zxy_cmos_unix_timestamp() i64 {
    if (!g_cmos_initialized) return 0;
    return cmos_instance().unix_timestamp;
}

export fn zxy_cmos_set_utc_offset(offset: i32) void {
    if (g_cmos_initialized) {
        cmos_instance().utc_offset = offset;
    }
}

export fn zxy_cmos_local_unix() i64 {
    if (!g_cmos_initialized) return 0;
    return cmos_instance().get_local_unix();
}

export fn zxy_cmos_set_wakeup(seconds: u32) void {
    if (g_cmos_initialized) {
        cmos_instance().set_wakeup_alarm(seconds);
    }
}

export fn zxy_cmos_handle_irq() void {
    if (g_cmos_initialized) {
        cmos_instance().handle_interrupt();
    }
}

export fn zxy_cmos_set_periodic_rate(rate: u8) void {
    if (g_cmos_initialized and rate <= 15) {
        cmos_instance().set_periodic_rate(@enumFromInt(@as(u4, @intCast(rate))));
    }
}

export fn zxy_cmos_total_interrupts() u64 {
    if (!g_cmos_initialized) return 0;
    return cmos_instance().get_total_interrupts();
}

export fn zxy_cmos_battery_ok() bool {
    if (!g_cmos_initialized) return false;
    return cmos_instance().get_battery_status();
}

export fn zxy_cmos_nvram_read(offset: u8) u8 {
    if (!g_cmos_initialized) return 0;
    return cmos_instance().read_nvram_byte(offset);
}

export fn zxy_cmos_nvram_write(offset: u8, val: u8) void {
    if (g_cmos_initialized) {
        cmos_instance().write_nvram_byte(offset, val);
    }
}

export fn zxy_cmos_verify_checksum() bool {
    if (!g_cmos_initialized) return false;
    return cmos_instance().verify_checksum();
}

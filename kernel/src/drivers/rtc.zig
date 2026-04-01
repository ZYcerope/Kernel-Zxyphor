// =============================================================================
// Kernel Zxyphor - Real-Time Clock (RTC) Driver
// =============================================================================
// The RTC (CMOS Real-Time Clock) is a battery-backed clock that maintains
// date and time even when the computer is powered off. It's accessed via
// I/O ports 0x70 (index/address) and 0x71 (data).
//
// The RTC also provides:
//   - Periodic interrupts (IRQ 8)
//   - Alarm functionality
//   - Century register (if available)
//
// CMOS memory layout (first 128 bytes):
//   0x00: Seconds
//   0x02: Minutes
//   0x04: Hours
//   0x06: Day of week (1=Sunday)
//   0x07: Day of month
//   0x08: Month
//   0x09: Year (0-99)
//   0x0A: Status Register A
//   0x0B: Status Register B
//   0x0C: Status Register C
//   0x0D: Status Register D
//   0x32: Century (if supported)
// =============================================================================

const main = @import("../main.zig");

// =============================================================================
// I/O Ports
// =============================================================================
const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// =============================================================================
// CMOS Register addresses
// =============================================================================
const RTC_SECONDS: u8 = 0x00;
const RTC_SECONDS_ALARM: u8 = 0x01;
const RTC_MINUTES: u8 = 0x02;
const RTC_MINUTES_ALARM: u8 = 0x03;
const RTC_HOURS: u8 = 0x04;
const RTC_HOURS_ALARM: u8 = 0x05;
const RTC_DAY_OF_WEEK: u8 = 0x06;
const RTC_DAY_OF_MONTH: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_STATUS_A: u8 = 0x0A;
const RTC_STATUS_B: u8 = 0x0B;
const RTC_STATUS_C: u8 = 0x0C;
const RTC_STATUS_D: u8 = 0x0D;
const RTC_CENTURY: u8 = 0x32;

// Status Register A bits
const SRA_UIP: u8 = 0x80; // Update in Progress

// Status Register B bits
const SRB_DSE: u8 = 0x01; // Daylight Saving Enable
const SRB_24HR: u8 = 0x02; // 24-hour format (vs 12-hour)
const SRB_DM: u8 = 0x04; // Binary mode (vs BCD)
const SRB_SQWE: u8 = 0x08; // Square wave output enable
const SRB_UIE: u8 = 0x10; // Update-ended interrupt enable
const SRB_AIE: u8 = 0x20; // Alarm interrupt enable
const SRB_PIE: u8 = 0x40; // Periodic interrupt enable
const SRB_SET: u8 = 0x80; // Abort update / set mode

// =============================================================================
// DateTime structure
// =============================================================================
pub const DateTime = struct {
    year: u16 = 2025,
    month: u8 = 1,
    day: u8 = 1,
    hour: u8 = 0,
    minute: u8 = 0,
    second: u8 = 0,
    day_of_week: u8 = 0,

    /// Convert to Unix timestamp (simplified, doesn't handle leap seconds)
    pub fn toUnixTimestamp(self: *const DateTime) u64 {
        // Days per month (non-leap year)
        const days_per_month = [12]u16{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

        var days: u64 = 0;

        // Years since 1970
        var y: u16 = 1970;
        while (y < self.year) : (y += 1) {
            if (isLeapYear(y)) {
                days += 366;
            } else {
                days += 365;
            }
        }

        // Months
        var m: u8 = 1;
        while (m < self.month) : (m += 1) {
            days += days_per_month[m - 1];
            if (m == 2 and isLeapYear(self.year)) {
                days += 1;
            }
        }

        // Days
        days += self.day - 1;

        return days * 86400 + @as(u64, self.hour) * 3600 +
            @as(u64, self.minute) * 60 + @as(u64, self.second);
    }

    fn isLeapYear(year: u16) bool {
        return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
    }
};

// =============================================================================
// State
// =============================================================================
var is_binary_mode: bool = false;
var is_24hour: bool = false;
var has_century: bool = false;
var last_read: DateTime = .{};

// =============================================================================
// Initialize RTC
// =============================================================================
pub fn initialize() void {
    // Read status register B to learn the RTC format
    const status_b = readCmos(RTC_STATUS_B);
    is_binary_mode = (status_b & SRB_DM) != 0;
    is_24hour = (status_b & SRB_24HR) != 0;

    // Try to detect century register
    has_century = true; // Assume century register exists at 0x32

    // Read initial time
    last_read = readDateTime();

    main.klog(.info, "RTC: {d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} (binary={s}, 24h={s})", .{
        last_read.year,
        last_read.month,
        last_read.day,
        last_read.hour,
        last_read.minute,
        last_read.second,
        if (is_binary_mode) "yes" else "no",
        if (is_24hour) "yes" else "no",
    });
}

// =============================================================================
// Read date/time from RTC
// =============================================================================
pub fn readDateTime() DateTime {
    // Wait until the RTC is not updating
    waitForUpdate();

    var dt = DateTime{};

    // Read raw values
    var second = readCmos(RTC_SECONDS);
    var minute = readCmos(RTC_MINUTES);
    var hour = readCmos(RTC_HOURS);
    var day = readCmos(RTC_DAY_OF_MONTH);
    var month = readCmos(RTC_MONTH);
    var year = readCmos(RTC_YEAR);
    var century: u8 = 0;
    if (has_century) {
        century = readCmos(RTC_CENTURY);
    }
    const dow = readCmos(RTC_DAY_OF_WEEK);

    // Read a second time to ensure values are consistent
    // (RTC might have updated between reads)
    waitForUpdate();
    const second2 = readCmos(RTC_SECONDS);
    const minute2 = readCmos(RTC_MINUTES);
    const hour2 = readCmos(RTC_HOURS);
    const day2 = readCmos(RTC_DAY_OF_MONTH);
    const month2 = readCmos(RTC_MONTH);
    const year2 = readCmos(RTC_YEAR);

    // If values differ, read again
    if (second != second2 or minute != minute2 or hour != hour2 or
        day != day2 or month != month2 or year != year2)
    {
        second = readCmos(RTC_SECONDS);
        minute = readCmos(RTC_MINUTES);
        hour = readCmos(RTC_HOURS);
        day = readCmos(RTC_DAY_OF_MONTH);
        month = readCmos(RTC_MONTH);
        year = readCmos(RTC_YEAR);
        if (has_century) century = readCmos(RTC_CENTURY);
    }

    // Convert from BCD if needed
    if (!is_binary_mode) {
        second = bcdToDecimal(second);
        minute = bcdToDecimal(minute);
        hour = bcdToDecimal(hour & 0x7F); // Mask PM bit if 12-hour
        day = bcdToDecimal(day);
        month = bcdToDecimal(month);
        year = bcdToDecimal(year);
        century = bcdToDecimal(century);
    }

    // Handle 12-hour format
    if (!is_24hour and (hour & 0x80) != 0) {
        hour = ((hour & 0x7F) % 12) + 12; // Convert PM to 24-hour
    }

    // Calculate full year
    if (has_century and century > 0) {
        dt.year = @as(u16, century) * 100 + year;
    } else {
        dt.year = if (year >= 70) @as(u16, 1900) + year else @as(u16, 2000) + year;
    }

    dt.month = month;
    dt.day = day;
    dt.hour = hour;
    dt.minute = minute;
    dt.second = second;
    dt.day_of_week = dow;

    last_read = dt;
    return dt;
}

// =============================================================================
// Set date/time
// =============================================================================
pub fn setDateTime(dt: *const DateTime) void {
    var second = @as(u8, dt.second);
    var minute = @as(u8, dt.minute);
    var hour = @as(u8, dt.hour);
    var day = @as(u8, dt.day);
    var month = @as(u8, dt.month);
    var year = @as(u8, @truncate(dt.year % 100));
    var century = @as(u8, @truncate(dt.year / 100));

    // Convert to BCD if needed
    if (!is_binary_mode) {
        second = decimalToBcd(second);
        minute = decimalToBcd(minute);
        hour = decimalToBcd(hour);
        day = decimalToBcd(day);
        month = decimalToBcd(month);
        year = decimalToBcd(year);
        century = decimalToBcd(century);
    }

    // Set the "SET" bit to halt updates during write
    var status_b = readCmos(RTC_STATUS_B);
    writeCmos(RTC_STATUS_B, status_b | SRB_SET);

    writeCmos(RTC_SECONDS, second);
    writeCmos(RTC_MINUTES, minute);
    writeCmos(RTC_HOURS, hour);
    writeCmos(RTC_DAY_OF_MONTH, day);
    writeCmos(RTC_MONTH, month);
    writeCmos(RTC_YEAR, year);
    if (has_century) writeCmos(RTC_CENTURY, century);

    // Clear the "SET" bit to resume updates
    status_b = readCmos(RTC_STATUS_B);
    writeCmos(RTC_STATUS_B, status_b & ~SRB_SET);
}

// =============================================================================
// Enable periodic interrupt
// =============================================================================
pub fn enablePeriodicInterrupt(rate: u8) void {
    // Rate must be between 3 (8192 Hz) and 15 (2 Hz)
    // Frequency = 32768 >> (rate - 1)
    if (rate < 3 or rate > 15) return;

    const flags = main.cpu.disableInterrupts();
    defer main.cpu.restoreInterrupts(flags);

    // Set rate in Status Register A
    var status_a = readCmos(RTC_STATUS_A);
    status_a = (status_a & 0xF0) | rate;
    writeCmos(RTC_STATUS_A, status_a);

    // Enable periodic interrupt in Status Register B
    var status_b = readCmos(RTC_STATUS_B);
    status_b |= SRB_PIE;
    writeCmos(RTC_STATUS_B, status_b);

    // Must read Status Register C to re-enable interrupts
    _ = readCmos(RTC_STATUS_C);
}

/// Disable periodic interrupt
pub fn disablePeriodicInterrupt() void {
    var status_b = readCmos(RTC_STATUS_B);
    status_b &= ~SRB_PIE;
    writeCmos(RTC_STATUS_B, status_b);
}

// =============================================================================
// CMOS access (low-level)
// =============================================================================
fn readCmos(reg: u8) u8 {
    // Bit 7 = NMI disable (keep it 0 to not mask NMI)
    main.cpu.outb(CMOS_ADDR, reg & 0x7F);
    return main.cpu.inb(CMOS_DATA);
}

fn writeCmos(reg: u8, value: u8) void {
    main.cpu.outb(CMOS_ADDR, reg & 0x7F);
    main.cpu.outb(CMOS_DATA, value);
}

fn waitForUpdate() void {
    // Wait until the Update-In-Progress bit clears
    var timeout: u32 = 10000;
    while (timeout > 0) : (timeout -= 1) {
        if ((readCmos(RTC_STATUS_A) & SRA_UIP) == 0) return;
    }
}

// =============================================================================
// BCD conversion
// =============================================================================
fn bcdToDecimal(bcd: u8) u8 {
    return (bcd >> 4) * 10 + (bcd & 0x0F);
}

fn decimalToBcd(dec: u8) u8 {
    return ((dec / 10) << 4) | (dec % 10);
}

/// Get the last-read time (cached, doesn't re-read hardware)
pub fn getLastRead() DateTime {
    return last_read;
}

/// Get the current Unix timestamp
pub fn getUnixTimestamp() u64 {
    const dt = readDateTime();
    return dt.toUnixTimestamp();
}

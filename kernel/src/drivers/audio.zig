// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Audio Subsystem (ALSA-like Sound Core)
//
// Hardware-independent audio framework:
// - PCM (Pulse Code Modulation) buffer management
// - Audio codec abstraction (AC'97, HDA, USB Audio)
// - Sample format conversion (S16LE, S24LE, S32LE, Float32)
// - Sample rate conversion (SRC) with linear interpolation
// - Ring buffer for DMA transfers
// - Volume control with dB mapping
// - Mixer channels with routing
// - MIDI sequencer stub
// - Audio topology/graph routing
// - Timer-driven periodic callbacks
// - Latency tracking

const std = @import("std");

// ─────────────────── Sample Formats ─────────────────────────────────
pub const SampleFormat = enum(u8) {
    s8 = 0,
    u8_ = 1,
    s16_le = 2,
    s16_be = 3,
    u16_le = 4,
    s24_le = 5,    // packed 3 bytes
    s24_3le = 6,   // in 4 bytes
    s32_le = 7,
    s32_be = 8,
    float32_le = 9,
    float64_le = 10,
    mu_law = 11,
    a_law = 12,
    ima_adpcm = 13,

    pub fn bytesPerSample(self: SampleFormat) u8 {
        return switch (self) {
            .s8, .u8_, .mu_law, .a_law => 1,
            .s16_le, .s16_be, .u16_le, .ima_adpcm => 2,
            .s24_le => 3,
            .s24_3le, .s32_le, .s32_be, .float32_le => 4,
            .float64_le => 8,
        };
    }

    pub fn bitsPerSample(self: SampleFormat) u8 {
        return switch (self) {
            .s8, .u8_, .mu_law, .a_law => 8,
            .s16_le, .s16_be, .u16_le, .ima_adpcm => 16,
            .s24_le, .s24_3le => 24,
            .s32_le, .s32_be, .float32_le => 32,
            .float64_le => 64,
        };
    }

    pub fn isSigned(self: SampleFormat) bool {
        return switch (self) {
            .u8_, .u16_le => false,
            else => true,
        };
    }
};

// ─────────────────── PCM Parameters ─────────────────────────────────
pub const PcmDirection = enum(u8) {
    playback = 0,
    capture = 1,
};

pub const PcmState = enum(u8) {
    open,
    setup,
    prepared,
    running,
    xrun,
    draining,
    paused,
    suspended,
    disconnected,
};

pub const PcmHwParams = struct {
    format: SampleFormat = .s16_le,
    channels: u8 = 2,
    rate: u32 = 44100,
    period_size: u32 = 1024,    // frames per period
    periods: u32 = 4,           // number of periods in buffer
    buffer_size: u32 = 4096,    // total buffer size in frames

    pub fn frameBytes(self: *const PcmHwParams) u32 {
        return @as(u32, self.channels) * self.format.bytesPerSample();
    }

    pub fn periodBytes(self: *const PcmHwParams) u32 {
        return self.period_size * self.frameBytes();
    }

    pub fn bufferBytes(self: *const PcmHwParams) u32 {
        return self.buffer_size * self.frameBytes();
    }

    pub fn periodTimeUs(self: *const PcmHwParams) u64 {
        if (self.rate == 0) return 0;
        return (@as(u64, self.period_size) * 1000000) / self.rate;
    }

    pub fn bufferTimeUs(self: *const PcmHwParams) u64 {
        if (self.rate == 0) return 0;
        return (@as(u64, self.buffer_size) * 1000000) / self.rate;
    }

    pub fn latencyFrames(self: *const PcmHwParams) u32 {
        return self.buffer_size;
    }
};

// ─────────────────── PCM Ring Buffer ────────────────────────────────
pub const PCM_RING_SIZE: usize = 65536; // 64KB DMA-capable ring

pub const PcmRingBuffer = struct {
    buffer: [PCM_RING_SIZE]u8 = [_]u8{0} ** PCM_RING_SIZE,
    hw_ptr: u32 = 0,     // hardware pointer (DMA position)
    appl_ptr: u32 = 0,   // application pointer
    buf_size: u32 = 0,   // configured buffer size in bytes
    period_bytes: u32 = 0,
    boundary: u32 = 0,   // wrap-around boundary

    pub fn init(self: *PcmRingBuffer, buf_size: u32, period_bytes: u32) void {
        self.buf_size = @min(buf_size, PCM_RING_SIZE);
        self.period_bytes = period_bytes;
        self.hw_ptr = 0;
        self.appl_ptr = 0;
        // Boundary = lcm-like value much larger than buf_size
        self.boundary = self.buf_size;
        while (self.boundary * 2 <= 0x7FFFFFFF) {
            self.boundary *= 2;
        }
    }

    /// Available space for writing (playback)
    pub fn availPlayback(self: *const PcmRingBuffer) u32 {
        var avail = self.hw_ptr +% self.buf_size -% self.appl_ptr;
        if (avail >= self.boundary) avail -= self.boundary;
        return avail;
    }

    /// Available data for reading (capture)
    pub fn availCapture(self: *const PcmRingBuffer) u32 {
        var avail = self.hw_ptr -% self.appl_ptr;
        if (avail >= self.boundary) avail += self.boundary;
        return avail;
    }

    /// Write data into ring buffer (playback: app → buffer → HW)
    pub fn write(self: *PcmRingBuffer, data: []const u8) u32 {
        const avail = self.availPlayback();
        const to_write = @min(@as(u32, @intCast(data.len)), avail);

        var offset = self.appl_ptr % self.buf_size;
        var remain = to_write;
        var src_pos: usize = 0;

        while (remain > 0) {
            const chunk = @min(remain, self.buf_size - offset);
            @memcpy(
                self.buffer[offset..offset + chunk],
                data[src_pos..src_pos + chunk],
            );
            remain -= chunk;
            src_pos += chunk;
            offset = 0; // wrapped
        }

        self.appl_ptr += to_write;
        if (self.appl_ptr >= self.boundary) self.appl_ptr -= self.boundary;
        return to_write;
    }

    /// Read data from ring buffer (capture: HW → buffer → app)
    pub fn read(self: *PcmRingBuffer, out: []u8) u32 {
        const avail = self.availCapture();
        const to_read = @min(@as(u32, @intCast(out.len)), avail);

        var offset = self.appl_ptr % self.buf_size;
        var remain = to_read;
        var dst_pos: usize = 0;

        while (remain > 0) {
            const chunk = @min(remain, self.buf_size - offset);
            @memcpy(
                out[dst_pos..dst_pos + chunk],
                self.buffer[offset..offset + chunk],
            );
            remain -= chunk;
            dst_pos += chunk;
            offset = 0;
        }

        self.appl_ptr += to_read;
        if (self.appl_ptr >= self.boundary) self.appl_ptr -= self.boundary;
        return to_read;
    }

    /// Advance hardware pointer (called from DMA interrupt)
    pub fn advanceHw(self: *PcmRingBuffer, frames_bytes: u32) void {
        self.hw_ptr += frames_bytes;
        if (self.hw_ptr >= self.boundary) self.hw_ptr -= self.boundary;
    }

    /// Check for buffer underrun (playback) or overrun (capture)
    pub fn xrunCheck(self: *const PcmRingBuffer, direction: PcmDirection) bool {
        return switch (direction) {
            .playback => self.availPlayback() >= self.buf_size,
            .capture => self.availCapture() >= self.buf_size,
        };
    }
};

// ─────────────────── Volume Control ─────────────────────────────────
pub const VOLUME_MIN_DB: i32 = -6400;  // -64.00 dB (in centi-dB)
pub const VOLUME_MAX_DB: i32 = 0;      //   0.00 dB
pub const VOLUME_MUTE_DB: i32 = -9999; // mute threshold

pub const VolumeControl = struct {
    value: i32 = 0,       // centi-dB (-6400 to 0)
    muted: bool = false,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    min_db: i32 = VOLUME_MIN_DB,
    max_db: i32 = VOLUME_MAX_DB,

    pub fn setName(self: *VolumeControl, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn setDb(self: *VolumeControl, centi_db: i32) void {
        self.value = @max(self.min_db, @min(centi_db, self.max_db));
    }

    pub fn getLinear(self: *const VolumeControl) u16 {
        if (self.muted or self.value <= VOLUME_MUTE_DB) return 0;
        // Convert centi-dB to linear 0-65535
        // Approximation: 10^(dB/20) scaled to u16
        // dB = centi_db / 100
        // For simplicity, linear mapping: (value - min) / (max - min) * 65535
        const range = self.max_db - self.min_db;
        if (range <= 0) return 0;
        const offset = self.value - self.min_db;
        return @intCast(@min(65535, @as(u32, @intCast(offset)) * 65535 / @as(u32, @intCast(range))));
    }

    /// Apply volume to S16LE samples in-place
    pub fn applySamples(self: *const VolumeControl, samples: []u8) void {
        if (self.muted) {
            @memset(samples, 0);
            return;
        }
        const linear = self.getLinear();
        if (linear == 65535) return; // No change needed

        var i: usize = 0;
        while (i + 1 < samples.len) : (i += 2) {
            const raw: i16 = @bitCast([2]u8{ samples[i], samples[i + 1] });
            const scaled = @as(i32, raw) * @as(i32, linear) / 65535;
            const clamped: i16 = @intCast(@max(-32768, @min(32767, scaled)));
            const bytes: [2]u8 = @bitCast(clamped);
            samples[i] = bytes[0];
            samples[i + 1] = bytes[1];
        }
    }
};

// ─────────────────── Mixer Channel ──────────────────────────────────
pub const MAX_MIXER_CHANNELS: usize = 32;

pub const MixerChannelType = enum(u8) {
    master,
    pcm,
    mic,
    line_in,
    cd,
    speaker,
    headphone,
    bass,
    treble,
    monitor,
    aux,
};

pub const MixerChannel = struct {
    channel_type: MixerChannelType = .pcm,
    volume_left: VolumeControl = .{},
    volume_right: VolumeControl = .{},
    stereo: bool = true,
    active: bool = false,

    pub fn setVolume(self: *MixerChannel, left_db: i32, right_db: i32) void {
        self.volume_left.setDb(left_db);
        if (self.stereo) {
            self.volume_right.setDb(right_db);
        } else {
            self.volume_right.setDb(left_db);
        }
    }

    pub fn setMute(self: *MixerChannel, muted: bool) void {
        self.volume_left.muted = muted;
        self.volume_right.muted = muted;
    }
};

// ─────────────────── Sample Rate Converter ──────────────────────────
pub const SrcState = struct {
    src_rate: u32 = 44100,
    dst_rate: u32 = 48000,
    channels: u8 = 2,
    // Fixed-point accumulator for fractional sample position
    frac_pos: u64 = 0,
    frac_step: u64 = 0,
    // Previous sample for interpolation
    prev_sample: [8]i32 = [_]i32{0} ** 8, // max 8 channels

    pub fn init(self: *SrcState, src_rate: u32, dst_rate: u32, channels: u8) void {
        self.src_rate = src_rate;
        self.dst_rate = dst_rate;
        self.channels = @min(channels, 8);
        self.frac_pos = 0;
        // Fixed-point step: src_rate / dst_rate in 32.32 format
        self.frac_step = (@as(u64, src_rate) << 32) / dst_rate;
    }

    /// Convert S16LE samples with linear interpolation
    pub fn convert(self: *SrcState, input: []const u8, output: []u8) usize {
        const ch = @as(usize, self.channels);
        const src_frame_bytes = ch * 2; // S16LE
        const dst_frame_bytes = ch * 2;
        const src_frames = input.len / src_frame_bytes;
        const max_dst_frames = output.len / dst_frame_bytes;

        var dst_frame: usize = 0;
        while (dst_frame < max_dst_frames) {
            const int_pos = @as(usize, @intCast(self.frac_pos >> 32));
            if (int_pos + 1 >= src_frames) break;

            const frac = @as(u32, @intCast(self.frac_pos & 0xFFFFFFFF));

            for (0..ch) |c| {
                const src_off_a = (int_pos * ch + c) * 2;
                const src_off_b = ((int_pos + 1) * ch + c) * 2;
                const dst_off = (dst_frame * ch + c) * 2;

                if (src_off_a + 1 >= input.len or src_off_b + 1 >= input.len) break;
                if (dst_off + 1 >= output.len) break;

                const a: i32 = @as(i16, @bitCast([2]u8{ input[src_off_a], input[src_off_a + 1] }));
                const b: i32 = @as(i16, @bitCast([2]u8{ input[src_off_b], input[src_off_b + 1] }));

                // Linear interpolation
                const interp = a + @as(i32, @intCast((@as(i64, b - a) * frac) >> 32));
                const sample: i16 = @intCast(@max(-32768, @min(32767, interp)));
                const bytes: [2]u8 = @bitCast(sample);
                output[dst_off] = bytes[0];
                output[dst_off + 1] = bytes[1];
            }

            self.frac_pos += self.frac_step;
            dst_frame += 1;
        }

        // Retune fractional position relative to consumed input
        const consumed = @as(u64, @intCast(self.frac_pos >> 32));
        self.frac_pos -= consumed << 32;

        return dst_frame * dst_frame_bytes;
    }
};

// ─────────────────── Audio Codec Interface ──────────────────────────
pub const CodecType = enum(u8) {
    ac97,
    hda,
    usb_audio,
    i2s,
    spdif,
    bluetooth,
};

pub const AudioCodec = struct {
    codec_type: CodecType = .hda,
    name: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    vendor_id: u32 = 0,
    subsystem_id: u32 = 0,
    min_rate: u32 = 8000,
    max_rate: u32 = 192000,
    supported_formats: u16 = 0, // bitmask of SampleFormat
    max_channels: u8 = 2,
    hw_volume: bool = false,
    initialized: bool = false,

    pub fn setName(self: *AudioCodec, n: []const u8) void {
        const len = @min(n.len, 31);
        @memcpy(self.name[0..len], n[0..len]);
        self.name_len = @intCast(len);
    }

    pub fn supportsRate(self: *const AudioCodec, rate: u32) bool {
        return rate >= self.min_rate and rate <= self.max_rate;
    }

    pub fn supportsFormat(self: *const AudioCodec, fmt: SampleFormat) bool {
        return (self.supported_formats & (@as(u16, 1) << @intFromEnum(fmt))) != 0;
    }
};

// ─────────────────── PCM Substream ──────────────────────────────────
pub const MAX_PCM_STREAMS: usize = 16;

pub const PcmSubstream = struct {
    direction: PcmDirection = .playback,
    state: PcmState = .open,
    hw_params: PcmHwParams = .{},
    ring: PcmRingBuffer = .{},
    xrun_count: u32 = 0,
    frames_played: u64 = 0,
    frames_captured: u64 = 0,
    src: ?SrcState = null,
    active: bool = false,

    pub fn prepare(self: *PcmSubstream) void {
        self.ring.init(
            self.hw_params.bufferBytes(),
            self.hw_params.periodBytes(),
        );
        self.state = .prepared;
    }

    pub fn start(self: *PcmSubstream) void {
        if (self.state == .prepared or self.state == .paused) {
            self.state = .running;
        }
    }

    pub fn stop(self: *PcmSubstream) void {
        self.state = .setup;
    }

    pub fn pause(self: *PcmSubstream) void {
        if (self.state == .running) self.state = .paused;
    }

    /// Called from timer/DMA interrupt
    pub fn handlePeriodElapsed(self: *PcmSubstream) void {
        if (self.state != .running) return;

        self.ring.advanceHw(self.hw_params.periodBytes());

        if (self.ring.xrunCheck(self.direction)) {
            self.state = .xrun;
            self.xrun_count += 1;
        }

        switch (self.direction) {
            .playback => self.frames_played += self.hw_params.period_size,
            .capture => self.frames_captured += self.hw_params.period_size,
        }
    }
};

// ─────────────────── MIDI (stub) ────────────────────────────────────
pub const MidiMsg = struct {
    status: u8 = 0,
    data1: u8 = 0,
    data2: u8 = 0,
    timestamp: u64 = 0,

    pub fn noteOn(channel: u4, note: u7, velocity: u7) MidiMsg {
        return .{
            .status = 0x90 | @as(u8, channel),
            .data1 = note,
            .data2 = velocity,
        };
    }

    pub fn noteOff(channel: u4, note: u7) MidiMsg {
        return .{
            .status = 0x80 | @as(u8, channel),
            .data1 = note,
            .data2 = 0,
        };
    }

    pub fn controlChange(channel: u4, cc: u7, value: u7) MidiMsg {
        return .{
            .status = 0xB0 | @as(u8, channel),
            .data1 = cc,
            .data2 = value,
        };
    }

    pub fn isNoteOn(self: *const MidiMsg) bool {
        return (self.status & 0xF0) == 0x90 and self.data2 > 0;
    }

    pub fn isNoteOff(self: *const MidiMsg) bool {
        return (self.status & 0xF0) == 0x80 or
            ((self.status & 0xF0) == 0x90 and self.data2 == 0);
    }
};

// ─────────────────── Audio Manager ──────────────────────────────────
pub const AudioManager = struct {
    streams: [MAX_PCM_STREAMS]PcmSubstream = [_]PcmSubstream{.{}} ** MAX_PCM_STREAMS,
    stream_count: u8 = 0,
    mixer: [MAX_MIXER_CHANNELS]MixerChannel = [_]MixerChannel{.{}} ** MAX_MIXER_CHANNELS,
    mixer_count: u8 = 0,
    codecs: [4]AudioCodec = [_]AudioCodec{.{}} ** 4,
    codec_count: u8 = 0,
    master_volume: VolumeControl = .{},
    initialized: bool = false,

    pub fn init(self: *AudioManager) void {
        self.master_volume.setName("Master");
        self.master_volume.setDb(0); // 0 dB

        // Create default mixer channels
        self.addMixerChannel(.master, "Master");
        self.addMixerChannel(.pcm, "PCM");
        self.addMixerChannel(.mic, "Mic");
        self.addMixerChannel(.headphone, "Headphone");

        self.initialized = true;
    }

    fn addMixerChannel(self: *AudioManager, ch_type: MixerChannelType, name: []const u8) void {
        if (self.mixer_count >= MAX_MIXER_CHANNELS) return;
        self.mixer[self.mixer_count] = .{
            .channel_type = ch_type,
            .active = true,
        };
        self.mixer[self.mixer_count].volume_left.setName(name);
        self.mixer[self.mixer_count].volume_right.setName(name);
        self.mixer_count += 1;
    }

    pub fn openStream(self: *AudioManager, direction: PcmDirection) ?u8 {
        if (self.stream_count >= MAX_PCM_STREAMS) return null;
        const idx = self.stream_count;
        self.streams[idx] = .{
            .direction = direction,
            .state = .open,
            .active = true,
        };
        self.stream_count += 1;
        return idx;
    }

    pub fn configureStream(self: *AudioManager, idx: u8, params: PcmHwParams) bool {
        if (idx >= self.stream_count) return false;
        self.streams[idx].hw_params = params;
        self.streams[idx].state = .setup;
        return true;
    }

    pub fn registerCodec(self: *AudioManager, codec: AudioCodec) bool {
        if (self.codec_count >= 4) return false;
        self.codecs[self.codec_count] = codec;
        self.codecs[self.codec_count].initialized = true;
        self.codec_count += 1;
        return true;
    }
};

// ─────────────────── Global Instance ────────────────────────────────
var audio_mgr: AudioManager = .{};

pub fn initAudio() void {
    audio_mgr.init();
}

pub fn getAudioManager() *AudioManager {
    return &audio_mgr;
}

// ─────────────────── FFI Exports ────────────────────────────────────
export fn zxy_audio_init() void {
    initAudio();
}

export fn zxy_audio_open_stream(direction: u8) i32 {
    const dir: PcmDirection = if (direction == 0) .playback else .capture;
    if (audio_mgr.openStream(dir)) |idx| {
        return @intCast(idx);
    }
    return -1;
}

export fn zxy_audio_stream_count() u8 {
    return audio_mgr.stream_count;
}

export fn zxy_audio_mixer_count() u8 {
    return audio_mgr.mixer_count;
}

export fn zxy_audio_codec_count() u8 {
    return audio_mgr.codec_count;
}

export fn zxy_audio_master_volume(centi_db: i32) void {
    audio_mgr.master_volume.setDb(centi_db);
}

export fn zxy_audio_master_mute(mute: bool) void {
    audio_mgr.master_volume.muted = mute;
}

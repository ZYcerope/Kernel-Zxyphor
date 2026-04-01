// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Advanced ALSA-compatible Sound Subsystem
// HDA codec, PCM streams, mixer, MIDI, software volume, resampling

const std = @import("std");

// ============================================================================
// Sound Card Framework
// ============================================================================

pub const MAX_SOUND_CARDS = 32;
pub const MAX_PCM_DEVICES = 16;
pub const MAX_PCM_SUBSTREAMS = 32;
pub const MAX_MIXER_ELEMENTS = 256;
pub const MAX_CODECS = 16;
pub const MAX_DAI_LINKS = 32;
pub const MAX_WIDGETS = 256;

pub const SndCardState = enum(u8) {
    open,
    disconnected,
    registered,
    suspended,
    free,
};

pub const SndCard = struct {
    number: u8,
    id: [64]u8,           // Card ID string
    driver: [64]u8,       // Driver name
    shortname: [64]u8,    // Short card name
    longname: [128]u8,    // Long card name  
    mixername: [128]u8,
    components: [256]u8,
    state: SndCardState,
    pcm_devices: [MAX_PCM_DEVICES]?*PcmDevice,
    num_pcm: u8,
    mixer: MixerState,
    power_state: SndPowerState,
    // HDA specific
    hda_codec_count: u8,
    hda_codecs: [MAX_CODECS]?*HdaCodec,
};

pub const SndPowerState = enum(u8) {
    d0_active = 0,
    d1 = 1,
    d2 = 2,
    d3_hot = 3,
    d3_cold = 4,
};

// ============================================================================
// PCM (Pulse Code Modulation) Subsystem
// ============================================================================

pub const PcmFormat = enum(u32) {
    s8 = 0,
    u8_ = 1,
    s16_le = 2,
    s16_be = 3,
    u16_le = 4,
    u16_be = 5,
    s24_le = 6,
    s24_be = 7,
    u24_le = 8,
    u24_be = 9,
    s32_le = 10,
    s32_be = 11,
    u32_le = 12,
    u32_be = 13,
    float_le = 14,
    float_be = 15,
    float64_le = 16,
    float64_be = 17,
    s24_3le = 32, // 3-byte formats
    s24_3be = 33,
    u24_3le = 34,
    u24_3be = 35,
    s20_3le = 36,
    s20_3be = 37,
    u20_3le = 38,
    u20_3be = 39,
    // IEC958 / DSD
    iec958_subframe_le = 18,
    iec958_subframe_be = 19,
    dsd_u8 = 48,
    dsd_u16_le = 49,
    dsd_u32_le = 50,
    dsd_u16_be = 51,
    dsd_u32_be = 52,
};

pub const PcmAccess = enum(u8) {
    mmap_interleaved = 0,
    mmap_noninterleaved = 1,
    mmap_complex = 2,
    rw_interleaved = 3,
    rw_noninterleaved = 4,
};

pub const PcmState = enum(u8) {
    open = 0,
    setup = 1,
    prepared = 2,
    running = 3,
    xrun = 4,          // Overrun/underrun
    draining = 5,
    paused = 6,
    suspended = 7,
    disconnected = 8,
};

pub const StreamDirection = enum(u1) {
    playback = 0,
    capture = 1,
};

pub const PcmHwParams = struct {
    // Ranges
    access: PcmAccess,
    format: PcmFormat,
    subformat: u8,
    channels: u32,
    rate: u32,           // Sample rate in Hz
    period_size: u32,    // Frames per period
    period_count: u32,   // Number of periods
    buffer_size: u64,    // Total buffer size in frames
    // Computed
    sample_bits: u32,    // Bits per sample
    frame_bits: u32,     // Bits per frame (sample_bits * channels)
    fifo_size: u32,      // Hardware FIFO size
    tick_time: u32,      // Timer tick in usec
};

pub const PcmSwParams = struct {
    tstamp_mode: u8,
    period_step: u32,
    sleep_min: u32,
    avail_min: u64,      // Minimum available frames for wakeup
    xfer_align: u64,     // Transfer alignment
    start_threshold: u64, // Frames to auto-start
    stop_threshold: u64,  // Frames to auto-stop
    silence_threshold: u64,
    silence_size: u64,
    boundary: u64,
    proto: u32,
    tstamp_type: u8,
};

pub const PcmPosition = struct {
    hw_ptr: u64,          // Hardware pointer (frames)
    appl_ptr: u64,        // Application pointer (frames)
    avail: u64,           // Available frames
    delay: i64,           // Current delay in frames
    tstamp_sec: u64,
    tstamp_nsec: u32,
};

pub const PcmSubstream = struct {
    number: u8,
    direction: StreamDirection,
    state: PcmState,
    hw_params: PcmHwParams,
    sw_params: PcmSwParams,
    position: PcmPosition,
    // DMA
    dma_buffer_phys: u64,
    dma_buffer_size: u64,
    dma_period_bytes: u32,
    dma_started: bool,
    // Runtime
    runtime_buffer: [65536]u8, // Mixed audio buffer
    runtime_buffer_pos: u32,
    underruns: u32,
    overruns: u32,
    xrun_count: u64,
    total_frames: u64,
    // Volume
    volume_left: u16,     // 0-65535
    volume_right: u16,
    muted: bool,
};

pub const PcmDevice = struct {
    device_id: u8,
    card: *SndCard,
    name: [64]u8,
    playback_count: u8,
    capture_count: u8,
    playback: [MAX_PCM_SUBSTREAMS]?PcmSubstream,
    capture: [MAX_PCM_SUBSTREAMS]?PcmSubstream,
    // Capabilities
    formats_mask: u64,    // Bitmask of supported formats
    rates_mask: u32,      // Bitmask of supported rates
    rate_min: u32,
    rate_max: u32,
    channels_min: u8,
    channels_max: u8,
    period_bytes_min: u32,
    period_bytes_max: u32,
    periods_min: u8,
    periods_max: u8,
    buffer_bytes_max: u64,
};

// Standard sample rates
pub const RATE_5512: u32 = 5512;
pub const RATE_8000: u32 = 8000;
pub const RATE_11025: u32 = 11025;
pub const RATE_16000: u32 = 16000;
pub const RATE_22050: u32 = 22050;
pub const RATE_32000: u32 = 32000;
pub const RATE_44100: u32 = 44100;
pub const RATE_48000: u32 = 48000;
pub const RATE_64000: u32 = 64000;
pub const RATE_88200: u32 = 88200;
pub const RATE_96000: u32 = 96000;
pub const RATE_176400: u32 = 176400;
pub const RATE_192000: u32 = 192000;
pub const RATE_352800: u32 = 352800;
pub const RATE_384000: u32 = 384000;

pub fn format_sample_bits(format: PcmFormat) u32 {
    return switch (format) {
        .s8, .u8_ => 8,
        .s16_le, .s16_be, .u16_le, .u16_be => 16,
        .s24_le, .s24_be, .u24_le, .u24_be => 32, // Packed in 32 bits
        .s24_3le, .s24_3be, .u24_3le, .u24_3be => 24,
        .s20_3le, .s20_3be, .u20_3le, .u20_3be => 24,
        .s32_le, .s32_be, .u32_le, .u32_be => 32,
        .float_le, .float_be => 32,
        .float64_le, .float64_be => 64,
        .dsd_u8 => 8,
        .dsd_u16_le, .dsd_u16_be => 16,
        .dsd_u32_le, .dsd_u32_be => 32,
        .iec958_subframe_le, .iec958_subframe_be => 32,
    };
}

// ============================================================================
// Mixer Subsystem
// ============================================================================

pub const MixerElementType = enum(u8) {
    volume,
    switch_,
    enum_,
    bytes,
    iec958,
};

pub const MixerElement = struct {
    id: u32,
    name: [64]u8,
    name_len: u8,
    element_type: MixerElementType,
    // Volume parameters
    volume_min: i32,
    volume_max: i32,
    volume_step: i32,
    volume_db_min: i32,   // in 0.01 dB
    volume_db_max: i32,
    // Current values (stereo)
    value_left: i32,
    value_right: i32,
    enabled: bool,
    // Capabilities
    has_playback: bool,
    has_capture: bool,
    has_switch: bool,
    has_volume: bool,
    is_enumerated: bool,
    // Enum items
    enum_items: [32][32]u8,
    num_enum_items: u8,
    enum_current: u8,
    // TLV (Type-Length-Value) data for dB scale
    tlv_data: [64]u32,
    tlv_len: u8,
};

pub const MixerState = struct {
    elements: [MAX_MIXER_ELEMENTS]MixerElement,
    num_elements: u16,
    master_volume: i32,
    master_mute: bool,

    pub fn find_by_name(self: *MixerState, name: []const u8) ?*MixerElement {
        for (self.elements[0..self.num_elements]) |*e| {
            if (std.mem.eql(u8, e.name[0..e.name_len], name)) return e;
        }
        return null;
    }

    pub fn set_volume(self: *MixerState, id: u32, left: i32, right: i32) bool {
        if (id >= self.num_elements) return false;
        var elem = &self.elements[id];
        elem.value_left = @max(elem.volume_min, @min(left, elem.volume_max));
        elem.value_right = @max(elem.volume_min, @min(right, elem.volume_max));
        return true;
    }

    /// Convert volume value to dB (0.01 dB units)
    pub fn volume_to_db(elem: *const MixerElement, value: i32) i32 {
        if (elem.volume_max == elem.volume_min) return elem.volume_db_min;
        const range = elem.volume_max - elem.volume_min;
        const db_range = elem.volume_db_max - elem.volume_db_min;
        return elem.volume_db_min + @divTrunc((value - elem.volume_min) * db_range, range);
    }
};

// ============================================================================
// HDA (High Definition Audio) Codec
// ============================================================================

// HDA Controller registers
pub const HDA_GCAP: u16 = 0x00;
pub const HDA_VMIN: u16 = 0x02;
pub const HDA_VMAJ: u16 = 0x03;
pub const HDA_OUTPAY: u16 = 0x04;
pub const HDA_INPAY: u16 = 0x06;
pub const HDA_GCTL: u16 = 0x08;
pub const HDA_WAKEEN: u16 = 0x0C;
pub const HDA_STATESTS: u16 = 0x0E;
pub const HDA_GSTS: u16 = 0x10;
pub const HDA_INTCTL: u16 = 0x20;
pub const HDA_INTSTS: u16 = 0x24;
pub const HDA_WALCLK: u16 = 0x30;
pub const HDA_SSYNC: u16 = 0x38;
pub const HDA_CORBLBASE: u16 = 0x40;
pub const HDA_CORBUBASE: u16 = 0x44;
pub const HDA_CORBWP: u16 = 0x48;
pub const HDA_CORBRP: u16 = 0x4A;
pub const HDA_CORBCTL: u16 = 0x4C;
pub const HDA_CORBSTS: u16 = 0x4D;
pub const HDA_CORBSIZE: u16 = 0x4E;
pub const HDA_RIRBLBASE: u16 = 0x50;
pub const HDA_RIRBUBASE: u16 = 0x54;
pub const HDA_RIRBWP: u16 = 0x58;
pub const HDA_RINTCNT: u16 = 0x5A;
pub const HDA_RIRBCTL: u16 = 0x5C;
pub const HDA_RIRBSTS: u16 = 0x5D;
pub const HDA_RIRBSIZE: u16 = 0x5E;
pub const HDA_DPLBASE: u16 = 0x70;
pub const HDA_DPUBASE: u16 = 0x74;

// GCTL bits
pub const HDA_GCTL_CRST: u32 = 1 << 0;
pub const HDA_GCTL_FCNTRL: u32 = 1 << 1;
pub const HDA_GCTL_UNSOL: u32 = 1 << 8;

// Stream descriptor offsets (relative to stream base)
pub const HDA_SD_CTL: u8 = 0x00;
pub const HDA_SD_STS: u8 = 0x03;
pub const HDA_SD_LPIB: u8 = 0x04;
pub const HDA_SD_CBL: u8 = 0x08;
pub const HDA_SD_LVI: u8 = 0x0C;
pub const HDA_SD_FIFOW: u8 = 0x0E;
pub const HDA_SD_FIFOSIZE: u8 = 0x10;
pub const HDA_SD_FORMAT: u8 = 0x12;
pub const HDA_SD_BDLPL: u8 = 0x18;
pub const HDA_SD_BDLPU: u8 = 0x1C;

// HDA Verbs
pub const HDA_VERB_GET_PARAMETER: u32 = 0xF0000;
pub const HDA_VERB_GET_CONN_SELECT: u32 = 0xF0100;
pub const HDA_VERB_SET_CONN_SELECT: u32 = 0x70100;
pub const HDA_VERB_GET_CONN_LIST: u32 = 0xF0200;
pub const HDA_VERB_GET_PROC_STATE: u32 = 0xF0300;
pub const HDA_VERB_SET_PROC_STATE: u32 = 0x70300;
pub const HDA_VERB_GET_AMP_GAIN: u32 = 0xB0000;
pub const HDA_VERB_SET_AMP_GAIN: u32 = 0x30000;
pub const HDA_VERB_GET_PROC_COEFF: u32 = 0xF2000;
pub const HDA_VERB_SET_PROC_COEFF: u32 = 0x72000;
pub const HDA_VERB_GET_COEFF_INDEX: u32 = 0xF2200;
pub const HDA_VERB_SET_COEFF_INDEX: u32 = 0x72200;
pub const HDA_VERB_GET_PIN_CFG_DEFAULT: u32 = 0xF1C00;
pub const HDA_VERB_SET_PIN_CFG_DEFAULT: u32 = 0x71C00;
pub const HDA_VERB_GET_PIN_WIDGET_CTL: u32 = 0xF0700;
pub const HDA_VERB_SET_PIN_WIDGET_CTL: u32 = 0x70700;
pub const HDA_VERB_GET_UNSOL_RESP: u32 = 0xF0800;
pub const HDA_VERB_SET_UNSOL_ENABLE: u32 = 0x70800;
pub const HDA_VERB_GET_PIN_SENSE: u32 = 0xF0900;
pub const HDA_VERB_EXEC_PIN_SENSE: u32 = 0x70900;
pub const HDA_VERB_GET_EAPD_BTL: u32 = 0xF0C00;
pub const HDA_VERB_SET_EAPD_BTL: u32 = 0x70C00;
pub const HDA_VERB_GET_POWER_STATE: u32 = 0xF0500;
pub const HDA_VERB_SET_POWER_STATE: u32 = 0x70500;
pub const HDA_VERB_GET_CONV: u32 = 0xF0600;
pub const HDA_VERB_SET_CONV: u32 = 0x70600;
pub const HDA_VERB_GET_VOLUME_KNOB: u32 = 0xF0F00;
pub const HDA_VERB_SET_VOLUME_KNOB: u32 = 0x70F00;
pub const HDA_VERB_GET_STRIPE_CONTROL: u32 = 0xF2400;
pub const HDA_VERB_SET_STRIPE_CONTROL: u32 = 0x72400;

// HDA Parameters
pub const HDA_PARAM_VENDOR_ID: u8 = 0x00;
pub const HDA_PARAM_REVISION_ID: u8 = 0x02;
pub const HDA_PARAM_SUBNODE_COUNT: u8 = 0x04;
pub const HDA_PARAM_FUNC_GROUP_TYPE: u8 = 0x05;
pub const HDA_PARAM_AUDIO_FG_CAP: u8 = 0x08;
pub const HDA_PARAM_AUDIO_WIDGET_CAP: u8 = 0x09;
pub const HDA_PARAM_SAMPLE_SIZE_RATE: u8 = 0x0A;
pub const HDA_PARAM_STREAM_FORMATS: u8 = 0x0B;
pub const HDA_PARAM_PIN_CAP: u8 = 0x0C;
pub const HDA_PARAM_IN_AMP_CAP: u8 = 0x0D;
pub const HDA_PARAM_OUT_AMP_CAP: u8 = 0x12;
pub const HDA_PARAM_CONN_LIST_LEN: u8 = 0x0E;
pub const HDA_PARAM_POWER_STATE: u8 = 0x0F;
pub const HDA_PARAM_PROC_CAP: u8 = 0x10;
pub const HDA_PARAM_GPIO_COUNT: u8 = 0x11;
pub const HDA_PARAM_VOLUME_KNOB: u8 = 0x13;

// Widget types
pub const HDA_WIDGET_AUDIO_OUTPUT: u8 = 0x0;
pub const HDA_WIDGET_AUDIO_INPUT: u8 = 0x1;
pub const HDA_WIDGET_AUDIO_MIXER: u8 = 0x2;
pub const HDA_WIDGET_AUDIO_SELECTOR: u8 = 0x3;
pub const HDA_WIDGET_PIN_COMPLEX: u8 = 0x4;
pub const HDA_WIDGET_POWER_WIDGET: u8 = 0x5;
pub const HDA_WIDGET_VOLUME_KNOB: u8 = 0x6;
pub const HDA_WIDGET_BEEP_GENERATOR: u8 = 0x7;
pub const HDA_WIDGET_VENDOR_DEFINED: u8 = 0xF;

// Pin default config: connectivity
pub const PIN_CFG_CONN_JACK: u8 = 0;
pub const PIN_CFG_CONN_NONE: u8 = 1;
pub const PIN_CFG_CONN_FIXED: u8 = 2;
pub const PIN_CFG_CONN_BOTH: u8 = 3;

// Pin default config: location
pub const PIN_CFG_LOC_EXTERNAL: u8 = 0;
pub const PIN_CFG_LOC_INTERNAL: u8 = 1;
pub const PIN_CFG_LOC_SEPARATE: u8 = 2;
pub const PIN_CFG_LOC_OTHER: u8 = 3;

// Pin default config: device
pub const PIN_CFG_DEV_LINE_OUT: u8 = 0;
pub const PIN_CFG_DEV_SPEAKER: u8 = 1;
pub const PIN_CFG_DEV_HP_OUT: u8 = 2;
pub const PIN_CFG_DEV_CD: u8 = 3;
pub const PIN_CFG_DEV_SPDIF_OUT: u8 = 4;
pub const PIN_CFG_DEV_DIGITAL_OUT: u8 = 5;
pub const PIN_CFG_DEV_MODEM_LINE: u8 = 6;
pub const PIN_CFG_DEV_MODEM_HAND: u8 = 7;
pub const PIN_CFG_DEV_LINE_IN: u8 = 8;
pub const PIN_CFG_DEV_AUX: u8 = 9;
pub const PIN_CFG_DEV_MIC_IN: u8 = 10;
pub const PIN_CFG_DEV_TELEPHONY: u8 = 11;
pub const PIN_CFG_DEV_SPDIF_IN: u8 = 12;
pub const PIN_CFG_DEV_DIGITAL_IN: u8 = 13;
pub const PIN_CFG_DEV_OTHER: u8 = 15;

pub const HdaWidget = struct {
    nid: u16,                 // Node ID
    widget_type: u8,
    capabilities: u32,
    pin_config: u32,          // Default configuration
    pin_control: u8,          // Pin widget control
    conn_list: [16]u16,       // Connection list
    conn_list_len: u8,
    conn_select: u8,          // Selected connection
    amp_in_caps: u32,
    amp_out_caps: u32,
    amp_in_val: [16]u16,      // Gain values per connection
    amp_out_val: u16,
    power_state: u8,
    // Computed
    is_output: bool,
    is_input: bool,
    is_mixer: bool,
    is_pin: bool,
    has_amp_in: bool,
    has_amp_out: bool,
    has_connection: bool,
    unsol_capable: bool,
};

pub const HdaCodec = struct {
    address: u8,              // Codec address (0-14)
    vendor_id: u32,
    subsystem_id: u32,
    revision_id: u32,
    afg_nid: u16,             // Audio Function Group NID
    mfg_nid: u16,             // Modem Function Group NID
    // Widgets
    widgets: [MAX_WIDGETS]HdaWidget,
    num_widgets: u16,
    start_nid: u16,
    end_nid: u16,
    // Capabilities
    supported_formats: u32,
    supported_rates: u32,
    amp_in_caps: u32,
    amp_out_caps: u32,
    // Pin configurations (parsed)
    num_speaker_pins: u8,
    num_hp_pins: u8,
    num_line_out_pins: u8,
    num_mic_pins: u8,
    num_line_in_pins: u8,
    speaker_pins: [4]u16,
    hp_pins: [4]u16,
    line_out_pins: [4]u16,
    mic_pins: [4]u16,
    line_in_pins: [4]u16,
    // Power
    power_state: SndPowerState,
    power_filter: bool,
    beep_nid: u16,

    pub fn find_widget(self: *HdaCodec, nid: u16) ?*HdaWidget {
        for (self.widgets[0..self.num_widgets]) |*w| {
            if (w.nid == nid) return w;
        }
        return null;
    }

    /// Build CORB command
    pub fn make_verb(codec_addr: u8, nid: u16, verb: u32) u32 {
        return (@as(u32, codec_addr) << 28) | (@as(u32, nid) << 20) | verb;
    }

    /// Parse pin default config
    pub fn parse_pin_config(config: u32) PinConfig {
        return PinConfig{
            .sequence = @truncate(config & 0xF),
            .association = @truncate((config >> 4) & 0xF),
            .misc = @truncate((config >> 8) & 0xF),
            .color = @truncate((config >> 12) & 0xF),
            .connection_type = @truncate((config >> 16) & 0xF),
            .device = @truncate((config >> 20) & 0xF),
            .location = @truncate((config >> 24) & 0x3F),
            .connectivity = @truncate((config >> 30) & 0x3),
        };
    }
};

pub const PinConfig = struct {
    sequence: u4,
    association: u4,
    misc: u4,
    color: u4,
    connection_type: u4,
    device: u4,
    location: u6,
    connectivity: u2,
};

// ============================================================================
// HDA Controller
// ============================================================================

pub const HdaBdlEntry = packed struct {
    address: u64,
    length: u32,
    ioc: u32,           // bit 0 = Interrupt On Completion
};

pub const MAX_BDL_ENTRIES = 256;
pub const CORB_SIZE = 256;
pub const RIRB_SIZE = 256;

pub const HdaStream = struct {
    index: u8,
    direction: StreamDirection,
    tag: u8,
    format: u16,           // HDA stream format register value
    running: bool,
    // BDL (Buffer Descriptor List)
    bdl: [MAX_BDL_ENTRIES]HdaBdlEntry,
    bdl_count: u16,
    bdl_phys: u64,
    // DMA buffer
    buffer_phys: u64,
    buffer_size: u32,
    period_bytes: u32,
    // Position
    current_pos: u32,
    periods_elapsed: u64,
    // Linked PCM substream
    pcm_substream: ?*PcmSubstream,
};

pub const HdaController = struct {
    mmio_base: u64,
    // Capabilities
    num_iss: u8,           // Input streams
    num_oss: u8,           // Output streams
    num_bss: u8,           // Bidirectional streams
    num_sdo: u8,           // Serial Data Out signals
    is_64bit: bool,
    // CORB/RIRB
    corb: [CORB_SIZE]u32,
    corb_phys: u64,
    corb_wp: u16,
    rirb: [RIRB_SIZE]u64,
    rirb_phys: u64,
    rirb_rp: u16,
    // Streams
    streams: [30]HdaStream,  // Max 30 streams
    num_streams: u8,
    // Codecs
    codecs: [15]?HdaCodec,
    codec_mask: u16,          // Bitmask of detected codecs
    // State
    running: bool,
    irq: u8,
    wall_clock: u64,
    position_fix: u8,        // 0=auto, 1=LPIB, 2=POSBUF, 3=VIACOMBO

    pub fn read32(self: *const HdaController, offset: u16) u32 {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    pub fn write32(self: *const HdaController, offset: u16, value: u32) void {
        const ptr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = value;
    }

    pub fn read16(self: *const HdaController, offset: u16) u16 {
        const ptr: *volatile u16 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    pub fn write16(self: *const HdaController, offset: u16, value: u16) void {
        const ptr: *volatile u16 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = value;
    }

    pub fn read8(self: *const HdaController, offset: u16) u8 {
        const ptr: *volatile u8 = @ptrFromInt(self.mmio_base + offset);
        return ptr.*;
    }

    pub fn write8(self: *const HdaController, offset: u16, value: u8) void {
        const ptr: *volatile u8 = @ptrFromInt(self.mmio_base + offset);
        ptr.* = value;
    }

    /// Reset the HDA controller
    pub fn reset(self: *HdaController) bool {
        // Enter reset
        self.write32(HDA_GCTL, 0);
        var timeout: u32 = 100;
        while (timeout > 0) : (timeout -= 1) {
            if (self.read32(HDA_GCTL) & HDA_GCTL_CRST == 0) break;
        }
        if (timeout == 0) return false;

        // Exit reset
        self.write32(HDA_GCTL, HDA_GCTL_CRST);
        timeout = 100;
        while (timeout > 0) : (timeout -= 1) {
            if (self.read32(HDA_GCTL) & HDA_GCTL_CRST != 0) break;
        }
        return timeout > 0;
    }

    /// Send a verb via CORB
    pub fn send_verb(self: *HdaController, verb: u32) void {
        self.corb_wp = (self.corb_wp + 1) % CORB_SIZE;
        self.corb[self.corb_wp] = verb;
        self.write16(HDA_CORBWP, self.corb_wp);
    }

    /// Receive response from RIRB
    pub fn recv_response(self: *HdaController) ?u64 {
        const wp = self.read16(HDA_RIRBWP);
        if (wp == self.rirb_rp) return null;
        self.rirb_rp = (self.rirb_rp + 1) % RIRB_SIZE;
        return self.rirb[self.rirb_rp];
    }

    /// Enable unsolicited responses
    pub fn enable_unsol(self: *HdaController) void {
        var gctl = self.read32(HDA_GCTL);
        gctl |= HDA_GCTL_UNSOL;
        self.write32(HDA_GCTL, gctl);
    }

    /// Get stream descriptor offset
    pub fn stream_offset(self: *const HdaController, stream_idx: u8) u16 {
        _ = self;
        return 0x80 + @as(u16, stream_idx) * 0x20;
    }

    /// Configure a stream's format register
    pub fn encode_stream_format(channels: u8, bits: u8, rate_hz: u32) u16 {
        var fmt: u16 = 0;

        // Sample rate base + multiplier + divisor
        // This is simplified; real implementation needs exact divider selection
        if (rate_hz >= 176400) {
            fmt |= (1 << 14); // Base = 44.1 kHz
            fmt |= (3 << 11); // Mult = 4x
        } else if (rate_hz >= 96000) {
            fmt |= (0 << 14); // Base = 48 kHz
            fmt |= (1 << 11); // Mult = 2x
        } else if (rate_hz >= 88200) {
            fmt |= (1 << 14); // Base = 44.1 kHz
            fmt |= (1 << 11); // Mult = 2x
        } else if (rate_hz >= 48000) {
            fmt |= (0 << 14); // Base = 48 kHz
        } else if (rate_hz >= 44100) {
            fmt |= (1 << 14); // Base = 44.1 kHz
        } else {
            fmt |= (0 << 14);
            // Sub-48kHz rates need divisors
        }

        // Channels
        if (channels > 0) {
            fmt |= @as(u16, channels - 1);
        }

        // Bits per sample
        switch (bits) {
            8 => fmt |= (0 << 4),
            16 => fmt |= (1 << 4),
            20 => fmt |= (2 << 4),
            24 => fmt |= (3 << 4),
            32 => fmt |= (4 << 4),
            else => fmt |= (1 << 4),
        }

        return fmt;
    }
};

// ============================================================================
// Software Audio Processing
// ============================================================================

/// Software mixer for combining multiple PCM streams
pub const SoftMixer = struct {
    mix_buffer: [8192]i32,   // 32-bit accumulator
    output_buffer: [8192]i16,
    buffer_frames: u32,
    channels: u8,
    sample_rate: u32,

    /// Mix a 16-bit PCM source into the mix buffer
    pub fn mix_pcm16(self: *SoftMixer, src: []const i16, volume: u16) void {
        const vol = @as(i32, volume);
        const len = @min(src.len, self.mix_buffer.len);
        for (0..len) |i| {
            const sample = @as(i32, src[i]) * vol >> 16;
            self.mix_buffer[i] += sample;
        }
    }

    /// Convert mix buffer to 16-bit output with clipping
    pub fn render_output(self: *SoftMixer, frames: u32) []const i16 {
        const samples = frames * self.channels;
        const len = @min(samples, @as(u32, @intCast(self.output_buffer.len)));
        for (0..len) |i| {
            const val = self.mix_buffer[i];
            self.output_buffer[i] = if (val > 32767) 32767 else if (val < -32768) -32768 else @truncate(val);
        }
        // Clear mix buffer
        @memset(&self.mix_buffer, 0);
        return self.output_buffer[0..len];
    }
};

/// Simple linear resampler
pub const Resampler = struct {
    src_rate: u32,
    dst_rate: u32,
    channels: u8,
    phase: u64,          // Current fractional position (32.32 fixed point)
    phase_step: u64,
    last_sample: [8]i16, // Last sample per channel

    pub fn init(src_rate: u32, dst_rate: u32, channels: u8) Resampler {
        return Resampler{
            .src_rate = src_rate,
            .dst_rate = dst_rate,
            .channels = channels,
            .phase = 0,
            .phase_step = (@as(u64, src_rate) << 32) / @as(u64, dst_rate),
            .last_sample = [_]i16{0} ** 8,
        };
    }

    /// Resample src into dst, returns number of output frames written
    pub fn process(self: *Resampler, src: []const i16, dst: []i16) u32 {
        var out_frames: u32 = 0;
        const src_frames = @as(u32, @intCast(src.len / self.channels));
        const max_out = @as(u32, @intCast(dst.len / self.channels));

        while (out_frames < max_out) {
            const int_pos = @as(u32, @truncate(self.phase >> 32));
            if (int_pos >= src_frames) break;

            const frac = @as(u32, @truncate(self.phase & 0xFFFFFFFF));
            const next_pos = if (int_pos + 1 < src_frames) int_pos + 1 else int_pos;

            for (0..self.channels) |ch| {
                const s0 = @as(i32, src[int_pos * self.channels + ch]);
                const s1 = @as(i32, src[next_pos * self.channels + ch]);
                const interp = s0 + @as(i32, @intCast(((@as(i64, s1 - s0) * @as(i64, frac)) >> 32)));
                dst[out_frames * self.channels + ch] = @truncate(interp);
            }

            out_frames += 1;
            self.phase += self.phase_step;
        }

        // Adjust phase
        const consumed = @as(u64, @as(u32, @truncate(self.phase >> 32)));
        self.phase -= consumed << 32;

        return out_frames;
    }
};

// ============================================================================
// MIDI Subsystem
// ============================================================================

pub const MidiEventType = enum(u4) {
    note_off = 0x8,
    note_on = 0x9,
    poly_aftertouch = 0xA,
    control_change = 0xB,
    program_change = 0xC,
    channel_aftertouch = 0xD,
    pitch_bend = 0xE,
    system = 0xF,
};

pub const MidiEvent = struct {
    event_type: MidiEventType,
    channel: u4,
    data1: u8,
    data2: u8,
    timestamp_ns: u64,
};

pub const MidiPort = struct {
    name: [64]u8,
    name_len: u8,
    is_input: bool,
    is_output: bool,
    active: bool,
    // Ring buffer for events
    events: [256]MidiEvent,
    read_idx: u8,
    write_idx: u8,

    pub fn enqueue(self: *MidiPort, event: MidiEvent) bool {
        const next = self.write_idx +% 1;
        if (next == self.read_idx) return false;
        self.events[self.write_idx] = event;
        self.write_idx = next;
        return true;
    }

    pub fn dequeue(self: *MidiPort) ?MidiEvent {
        if (self.read_idx == self.write_idx) return null;
        const evt = self.events[self.read_idx];
        self.read_idx +%= 1;
        return evt;
    }
};

// Common MIDI CC numbers
pub const MIDI_CC_BANK_SELECT: u8 = 0;
pub const MIDI_CC_MOD_WHEEL: u8 = 1;
pub const MIDI_CC_BREATH: u8 = 2;
pub const MIDI_CC_FOOT: u8 = 4;
pub const MIDI_CC_PORTAMENTO_TIME: u8 = 5;
pub const MIDI_CC_DATA_ENTRY: u8 = 6;
pub const MIDI_CC_VOLUME: u8 = 7;
pub const MIDI_CC_BALANCE: u8 = 8;
pub const MIDI_CC_PAN: u8 = 10;
pub const MIDI_CC_EXPRESSION: u8 = 11;
pub const MIDI_CC_SUSTAIN: u8 = 64;
pub const MIDI_CC_PORTAMENTO: u8 = 65;
pub const MIDI_CC_SOSTENUTO: u8 = 66;
pub const MIDI_CC_SOFT: u8 = 67;
pub const MIDI_CC_LEGATO: u8 = 68;
pub const MIDI_CC_ALL_SOUND_OFF: u8 = 120;
pub const MIDI_CC_RESET_ALL_CTRL: u8 = 121;
pub const MIDI_CC_ALL_NOTES_OFF: u8 = 123;

// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - ALSA Sound Subsystem Detail
// Complete ALSA core: PCM, Control, MIDI, Sequencer, Timer,
// Mixer, Codec, HDA widgets, Jack detection, DPCM, ASoC

const std = @import("std");

// ============================================================================
// ALSA Card
// ============================================================================

pub const SNDRV_CARDS = 32;

pub const SndCardState = enum(u8) {
    Init = 0,
    Registered = 1,
    Disconnected = 2,
    Released = 3,
};

pub const SndCard = struct {
    number: i32,
    id: [16]u8,
    driver: [16]u8,
    shortname: [32]u8,
    longname: [80]u8,
    mixername: [80]u8,
    components: [128]u8,
    dev: u64,
    state: SndCardState,
    private_data: u64,
    private_free: ?*const fn (u64) void,
    shutdown: bool,
    registered: bool,
    files_list: u64,
    power_state: SndPowerState,
};

pub const SndPowerState = enum(u8) {
    Running = 0,
    D3hot = 3,
    D3cold = 4,
};

// ============================================================================
// PCM (Pulse Code Modulation)
// ============================================================================

pub const SndPcmStream = enum(u1) {
    Playback = 0,
    Capture = 1,
};

pub const SndPcmState = enum(u8) {
    Open = 0,
    Setup = 1,
    Prepared = 2,
    Running = 3,
    XRun = 4,
    Draining = 5,
    Paused = 6,
    Suspended = 7,
    Disconnected = 8,
};

pub const SndPcmFormat = enum(i32) {
    Unknown = -1,
    S8 = 0,
    U8 = 1,
    S16LE = 2,
    S16BE = 3,
    U16LE = 4,
    U16BE = 5,
    S24LE = 6,
    S24BE = 7,
    U24LE = 8,
    U24BE = 9,
    S32LE = 10,
    S32BE = 11,
    U32LE = 12,
    U32BE = 13,
    FloatLE = 14,
    FloatBE = 15,
    Float64LE = 16,
    Float64BE = 17,
    IEC958SubframeLE = 18,
    IEC958SubframeBE = 19,
    MuLaw = 20,
    ALaw = 21,
    ImaAdpcm = 22,
    Mpeg = 23,
    Gsm = 24,
    S20LE = 25,
    S20BE = 26,
    U20LE = 27,
    U20BE = 28,
    Special = 31,
    S243LE = 32,
    S243BE = 33,
    U243LE = 34,
    U243BE = 35,
    S203LE = 36,
    S203BE = 37,
    U203LE = 38,
    U203BE = 39,
    S183LE = 40,
    S183BE = 41,
    U183LE = 42,
    U183BE = 43,
    DsdU8 = 48,
    DsdU16LE = 49,
    DsdU32LE = 50,
    DsdU16BE = 51,
    DsdU32BE = 52,
};

pub const SndPcmAccess = enum(u8) {
    MmapInterleaved = 0,
    MmapNonInterleaved = 1,
    MmapComplex = 2,
    RwInterleaved = 3,
    RwNonInterleaved = 4,
};

pub const SndPcmHwParams = struct {
    flags: u32,
    masks: [3]SndMask,         // access, format, subformat
    intervals: [12]SndInterval, // sample_bits, frame_bits, channels, rate, period_time, period_size, period_bytes, periods, buffer_time, buffer_size, buffer_bytes, tick_time
    rmask: u32,
    cmask: u32,
    info: u32,
    msbits: u32,
    rate_num: u32,
    rate_den: u32,
    fifo_size: u64,
};

pub const SndMask = struct {
    bits: [8]u32,
};

pub const SndInterval = struct {
    min: u32,
    max: u32,
    openmin: bool,
    openmax: bool,
    integer: bool,
    empty: bool,
};

pub const SndPcmSwParams = struct {
    tstamp_mode: i32,
    period_step: u32,
    sleep_min: u32,
    avail_min: u64,
    xfer_align: u64,
    start_threshold: u64,
    stop_threshold: u64,
    silence_threshold: u64,
    silence_size: u64,
    boundary: u64,
    proto: u32,
    tstamp_type: u32,
};

pub const SndPcmStatus = struct {
    state: SndPcmState,
    trigger_tstamp: u64,
    tstamp: u64,
    appl_ptr: u64,
    hw_ptr: u64,
    delay: i64,
    avail: u64,
    avail_max: u64,
    overrange: u64,
    suspended_state: SndPcmState,
    audio_tstamp_data: u32,
    audio_tstamp: u64,
    driver_tstamp: u64,
    audio_tstamp_accuracy: u32,
};

pub const SndPcmOps = struct {
    open: ?*const fn (*SndPcmSubstream) i32,
    close: ?*const fn (*SndPcmSubstream) i32,
    hw_params: ?*const fn (*SndPcmSubstream, *SndPcmHwParams) i32,
    hw_free: ?*const fn (*SndPcmSubstream) i32,
    prepare: ?*const fn (*SndPcmSubstream) i32,
    trigger: ?*const fn (*SndPcmSubstream, i32) i32,
    sync_stop: ?*const fn (*SndPcmSubstream) i32,
    pointer: ?*const fn (*SndPcmSubstream) u64,
    get_time_info: ?*const fn (*SndPcmSubstream, *u64, *u64, *u64) i32,
    fill_silence: ?*const fn (*SndPcmSubstream, i32, u64, u64) i32,
    copy: ?*const fn (*SndPcmSubstream, i32, u64, [*]u8, u64) i32,
    page: ?*const fn (*SndPcmSubstream, u64) u64,
    mmap: ?*const fn (*SndPcmSubstream, u64) i32,
    ack: ?*const fn (*SndPcmSubstream) i32,
};

pub const SndPcmSubstream = struct {
    pcm: u64,
    pstr: u64,
    number: i32,
    name: [32]u8,
    stream: SndPcmStream,
    buffer_bytes_max: u64,
    dma_buffer: SndDmaBuffer,
    dma_max: u64,
    runtime: ?*SndPcmRuntime,
    ops: ?*const SndPcmOps,
    timer: u64,
    group: u64,
    ref_count: u32,
    managed_buffer_alloc: bool,
};

pub const SndPcmRuntime = struct {
    status: ?*SndPcmStatus,
    control: u64,
    trigger_master: u64,
    info: u32,
    rate: u32,
    channels: u32,
    period_size: u64,
    periods: u32,
    buffer_size: u64,
    min_align: u64,
    byte_align: u64,
    frame_bits: u32,
    sample_bits: u32,
    format: SndPcmFormat,
    access: SndPcmAccess,
    silence_threshold: u64,
    silence_size: u64,
    boundary: u64,
    silence_start: u64,
    silence_filled: u64,
    hw: SndPcmHardware,
    hw_constraints: u64,
    dma_area: u64,
    dma_addr: u64,
    dma_bytes: u64,
};

pub const SndPcmHardware = struct {
    info: u32,
    formats: u64,
    rates: u32,
    rate_min: u32,
    rate_max: u32,
    channels_min: u32,
    channels_max: u32,
    buffer_bytes_max: u64,
    period_bytes_min: u64,
    period_bytes_max: u64,
    periods_min: u32,
    periods_max: u32,
    fifo_size: u64,
};

pub const SndDmaBuffer = struct {
    area: u64,
    addr: u64,
    bytes: u64,
    private_data: u64,
    dev_type: SndDmaType,
};

pub const SndDmaType = enum(u8) {
    Unknown = 0,
    Continuous = 1,
    DevNonContiguous = 2,
    DevSg = 3,
    DevWcSg = 4,
    DevVmalloc = 5,
    Noncontig = 6,
    Noncoherent = 7,
};

// ============================================================================
// ALSA Control Interface
// ============================================================================

pub const SndCtlElemType = enum(u8) {
    None = 0,
    Boolean = 1,
    Integer = 2,
    Enumerated = 3,
    Bytes = 4,
    Iec958 = 5,
    Integer64 = 6,
};

pub const SndCtlElemIface = enum(u8) {
    Card = 0,
    Hwdep = 1,
    Mixer = 2,
    Pcm = 3,
    Rawmidi = 4,
    Timer = 5,
    Sequencer = 6,
};

pub const SndCtlElemId = struct {
    numid: u32,
    iface: SndCtlElemIface,
    device: u32,
    subdevice: u32,
    name: [44]u8,
    index: u32,
};

pub const SndCtlElemInfo = struct {
    id: SndCtlElemId,
    elem_type: SndCtlElemType,
    access: SndCtlElemAccess,
    count: u32,
    owner: i32,
    value: union {
        integer: struct { min: i64, max: i64, step: i64 },
        integer64: struct { min: i64, max: i64, step: i64 },
        enumerated: struct { items: u32, item: u32, name: [64]u8 },
    },
    dimens: [4]u16,
};

pub const SndCtlElemAccess = packed struct(u32) {
    read: bool = false,
    write: bool = false,
    volatile_: bool = false,
    timestamp: bool = false,
    tlv_read: bool = false,
    tlv_write: bool = false,
    tlv_command: bool = false,
    inactive: bool = false,
    lock: bool = false,
    owner: bool = false,
    tlv_callback: bool = false,
    _reserved: u21 = 0,
};

pub const SndCtlElemValue = struct {
    id: SndCtlElemId,
    indirect: bool,
    value: union {
        integer: [128]i32,
        integer64: [64]i64,
        enumerated: [128]u32,
        bytes: [512]u8,
        iec958: SndAesIec958,
    },
    tstamp: u64,
};

pub const SndAesIec958 = struct {
    status: [24]u8,
    subcode: [147]u8,
    pad: u8,
    dig_subframe: [4]u8,
};

// ============================================================================
// HDA (High Definition Audio) Codec
// ============================================================================

pub const HdaCodecType = enum(u8) {
    Audio = 0,
    Modem = 1,
    Unknown = 255,
};

pub const HdaWidgetType = enum(u4) {
    AudioOutput = 0,
    AudioInput = 1,
    AudioMixer = 2,
    AudioSelector = 3,
    PinComplex = 4,
    Power = 5,
    VolumeKnob = 6,
    BeepGenerator = 7,
    VendorDefined = 15,
};

pub const HdaPinConfig = packed struct(u32) {
    sequence: u4,
    default_assoc: u4,
    misc: u4,
    color: u4,
    conn_type: u4,
    device: u4,
    location: u6,
    port_connectivity: u2,
};

pub const HdaPinDevice = enum(u4) {
    LineOut = 0,
    Speaker = 1,
    HpOut = 2,
    Cd = 3,
    Spdif = 4,
    DigitalOther = 5,
    ModemHandset = 6,
    ModemLine = 7,
    LineIn = 8,
    Aux = 9,
    MicIn = 10,
    Telephony = 11,
    SpdifIn = 12,
    Other = 15,
};

pub const HdaWidgetCaps = packed struct(u32) {
    num_steps_override: bool,
    amp_param_override: bool,
    amp_override: bool,
    format_override: bool,
    stripe: bool,
    proc_widget: bool,
    unsol_capable: bool,
    conn_list: bool,
    digital: bool,
    power_cntrl: bool,
    lr_swap: bool,
    cp_caps: bool,
    chan_cnt_ext: u3,
    delay: u4,
    widget_type: HdaWidgetType,
    _reserved: u4,
    stereo: bool,
    in_amp: bool,
    out_amp: bool,
};

pub const HdaAmpCaps = packed struct(u32) {
    offset: u7,
    num_steps: u7,
    step_size: u7,
    _reserved: u7,
    mute: bool,
    _pad: u3,
};

pub const HdaVerb = enum(u12) {
    GetConvControl = 0xf06,
    SetConvControl = 0x706,
    GetAmpGainMute = 0xb00,
    SetAmpGainMute = 0x300,
    GetConnSelect = 0xf01,
    SetConnSelect = 0x701,
    GetConnList = 0xf02,
    GetPinControl = 0xf07,
    SetPinControl = 0x707,
    GetPinSense = 0xf09,
    ExecutePinSense = 0x709,
    GetEapdBtlEnable = 0xf0c,
    SetEapdBtlEnable = 0x70c,
    GetPowerState = 0xf05,
    SetPowerState = 0x705,
    GetStreamFormat = 0xa00,
    SetStreamFormat = 0x200,
    GetConfigDefault = 0xf1c,
    GetSubsystemId = 0xf20,
    GetParameter = 0xf00,
};

// ============================================================================
// ASoC (ALSA System on Chip)
// ============================================================================

pub const SndSocDaiFormat = enum(u8) {
    I2s = 1,
    RightJ = 2,
    LeftJ = 3,
    DspA = 4,
    DspB = 5,
    Ac97 = 6,
    Pdm = 7,
};

pub const SndSocDaiDir = enum(u1) {
    Playback = 0,
    Capture = 1,
};

pub const SndSocDaiLink = struct {
    name: [64]u8,
    stream_name: [64]u8,
    cpus: u64,
    codecs: u64,
    platforms: u64,
    num_cpus: u32,
    num_codecs: u32,
    num_platforms: u32,
    id: u32,
    dai_fmt: SndSocDaiFormat,
    init: ?*const fn (u64) i32,
    ops: ?*const SndSocOps,
    symmetric_rate: bool,
    symmetric_channels: bool,
    symmetric_sample_bits: bool,
    no_pcm: bool,
    dynamic: bool,
    dpcm_playback: bool,
    dpcm_capture: bool,
    dpcm_merged_format: bool,
    dpcm_merged_chan: bool,
    dpcm_merged_rate: bool,
    trigger: [2]i32,
};

pub const SndSocOps = struct {
    startup: ?*const fn (*SndPcmSubstream) i32,
    shutdown: ?*const fn (*SndPcmSubstream) void,
    hw_params: ?*const fn (*SndPcmSubstream, *SndPcmHwParams) i32,
    hw_free: ?*const fn (*SndPcmSubstream) i32,
    prepare: ?*const fn (*SndPcmSubstream) i32,
    trigger: ?*const fn (*SndPcmSubstream, i32) i32,
};

pub const SndSocDaiOps = struct {
    set_sysclk: ?*const fn (u64, i32, u32, i32) i32,
    set_pll: ?*const fn (u64, i32, i32, u32, u32) i32,
    set_clkdiv: ?*const fn (u64, i32, i32) i32,
    set_bclk_ratio: ?*const fn (u64, u32) i32,
    set_fmt: ?*const fn (u64, u32) i32,
    set_tdm_slot: ?*const fn (u64, u32, u32, i32, i32) i32,
    set_channel_map: ?*const fn (u64, u32, [*]const u32, u32, [*]const u32) i32,
    set_tristate: ?*const fn (u64, i32) i32,
    digital_mute: ?*const fn (u64, i32, i32) i32,
    startup: ?*const fn (*SndPcmSubstream, u64) i32,
    shutdown: ?*const fn (*SndPcmSubstream, u64) void,
    hw_params: ?*const fn (*SndPcmSubstream, *SndPcmHwParams, u64) i32,
    hw_free: ?*const fn (*SndPcmSubstream, u64) i32,
    prepare: ?*const fn (*SndPcmSubstream, u64) i32,
    trigger: ?*const fn (*SndPcmSubstream, i32, u64) i32,
};

// ============================================================================
// Jack Detection
// ============================================================================

pub const SndJackType = packed struct(u32) {
    headphone: bool = false,
    microphone: bool = false,
    headset: bool = false,
    lineout: bool = false,
    mechanical: bool = false,
    videoout: bool = false,
    linein: bool = false,
    btn_0: bool = false,
    btn_1: bool = false,
    btn_2: bool = false,
    btn_3: bool = false,
    btn_4: bool = false,
    btn_5: bool = false,
    _reserved: u19 = 0,
};

pub const SndJack = struct {
    jack_type: SndJackType,
    status: u32,
    id: [64]u8,
    hw_status_cache: u32,
    input_dev: u64,
};

// ============================================================================
// MIDI / Sequencer
// ============================================================================

pub const SndRawmidiStreamDir = enum(u1) {
    Output = 0,
    Input = 1,
};

pub const SndRawmidiInfo = struct {
    device: u32,
    subdevice: u32,
    stream: SndRawmidiStreamDir,
    card: i32,
    flags: u32,
    id: [64]u8,
    name: [80]u8,
    subname: [32]u8,
    subdevices_count: u32,
    subdevices_avail: u32,
};

pub const SndSeqEventType = enum(u8) {
    System = 0,
    Result = 1,
    Note = 5,
    NoteOn = 6,
    NoteOff = 7,
    KeyPress = 8,
    Controller = 10,
    PgmChange = 11,
    ChanPress = 12,
    PitchBend = 13,
    Control14 = 14,
    NonRegParam = 15,
    RegParam = 16,
    SongPos = 20,
    SongSel = 21,
    QFrame = 22,
    TimeSign = 23,
    KeySign = 24,
    Start = 30,
    Continue = 31,
    Stop = 32,
    SetPosTime = 33,
    Clock = 36,
    Tick = 37,
    TuneRequest = 40,
    Reset = 41,
    Sensing = 42,
    Echo = 50,
    Oss = 51,
    ClientStart = 60,
    ClientExit = 61,
    ClientChange = 62,
    PortStart = 63,
    PortExit = 64,
    PortChange = 65,
    PortSubscribed = 66,
    PortUnsubscribed = 67,
    Usr0 = 90,
    Sysex = 130,
    Bounce = 131,
    UsrVar0 = 135,
    None = 255,
};

// ============================================================================
// ALSA Timer
// ============================================================================

pub const SndTimerClass = enum(i32) {
    None = -1,
    Slave = 0,
    Global = 1,
    Card = 2,
    Pcm = 3,
};

pub const SndTimerSlaveClass = enum(u8) {
    None = 0,
    Application = 1,
    Sequencer = 2,
};

pub const SndTimerGlobal = enum(u8) {
    System = 0,
    RTC = 1,
    Hpet = 2,
    HRTimer = 3,
};

pub const SndTimerInfo = struct {
    flags: u32,
    card: i32,
    id: [64]u8,
    name: [80]u8,
    resolution: u64,
};

// ============================================================================
// Audio Manager
// ============================================================================

pub const AlsaManager = struct {
    cards: [SNDRV_CARDS]?*SndCard,
    num_cards: u32,
    total_pcm_streams: u32,
    total_controls: u32,
    total_midi_devs: u32,
    total_timer_devs: u32,
    total_seq_clients: u32,
    total_jack_devs: u32,
    initialized: bool,

    pub fn init() AlsaManager {
        return .{
            .cards = [_]?*SndCard{null} ** SNDRV_CARDS,
            .num_cards = 0,
            .total_pcm_streams = 0,
            .total_controls = 0,
            .total_midi_devs = 0,
            .total_timer_devs = 0,
            .total_seq_clients = 0,
            .total_jack_devs = 0,
            .initialized = true,
        };
    }
};

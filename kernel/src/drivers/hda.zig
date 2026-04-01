// =============================================================================
// Kernel Zxyphor — Intel HD Audio (HDA) Driver
// =============================================================================
// Full HDA controller and codec driver:
//   - HDA controller BAR0 registers
//   - CORB/RIRB command transport
//   - Codec discovery and initialization
//   - Widget parsing (audio output/input, mixer, pin complex)
//   - Pin configuration and connectivity
//   - Stream management (input and output)
//   - Buffer Descriptor List (BDL) for DMA
//   - PCM format configuration
//   - Volume/mute control
//   - Multi-codec support
//   - Jack detection
// =============================================================================

// ============================================================================
// HDA Register offsets (relative to BAR0)
// ============================================================================

pub const GCAP: u32 = 0x00;        // Global Capabilities
pub const VMIN: u32 = 0x02;        // Minor Version
pub const VMAJ: u32 = 0x03;        // Major Version
pub const OUTPAY: u32 = 0x04;      // Output Payload Capability
pub const INPAY: u32 = 0x06;       // Input Payload Capability
pub const GCTL: u32 = 0x08;        // Global Control
pub const WAKEEN: u32 = 0x0C;      // Wake Enable
pub const STATESTS: u32 = 0x0E;    // State Change Status
pub const GSTS: u32 = 0x10;        // Global Status
pub const INTCTL: u32 = 0x20;      // Interrupt Control
pub const INTSTS: u32 = 0x24;      // Interrupt Status
pub const WALCLK: u32 = 0x30;      // Wall Clock Counter
pub const SSYNC: u32 = 0x38;       // Stream Synchronization
pub const CORBLBASE: u32 = 0x40;   // CORB Lower Base Address
pub const CORBUBASE: u32 = 0x44;   // CORB Upper Base Address
pub const CORBWP: u32 = 0x48;      // CORB Write Pointer
pub const CORBRP: u32 = 0x4A;      // CORB Read Pointer
pub const CORBCTL: u32 = 0x4C;     // CORB Control
pub const CORBSTS: u32 = 0x4D;     // CORB Status
pub const CORBSIZE: u32 = 0x4E;    // CORB Size
pub const RIRBLBASE: u32 = 0x50;   // RIRB Lower Base Address
pub const RIRBUBASE: u32 = 0x54;   // RIRB Upper Base Address
pub const RIRBWP: u32 = 0x58;      // RIRB Write Pointer
pub const RINTCNT: u32 = 0x5A;     // Response Interrupt Count
pub const RIRBCTL: u32 = 0x5C;     // RIRB Control
pub const RIRBSTS: u32 = 0x5D;     // RIRB Status
pub const RIRBSIZE: u32 = 0x5E;    // RIRB Size
pub const DPLBASE: u32 = 0x70;     // DMA Position Lower Base
pub const DPUBASE: u32 = 0x74;     // DMA Position Upper Base

// Stream descriptor offsets (base + 0x80 + N*0x20)
pub const SD_CTL: u32 = 0x00;      // Stream Descriptor Control
pub const SD_STS: u32 = 0x03;      // Stream Descriptor Status
pub const SD_LPIB: u32 = 0x04;     // Link Position in Buffer
pub const SD_CBL: u32 = 0x08;      // Cyclic Buffer Length
pub const SD_LVI: u32 = 0x0C;      // Last Valid Index
pub const SD_FIFOW: u32 = 0x0E;    // FIFO Watermark
pub const SD_FIFOS: u32 = 0x10;    // FIFO Size
pub const SD_FMT: u32 = 0x12;      // Format
pub const SD_BDLPL: u32 = 0x18;    // BDL Pointer Lower
pub const SD_BDLPU: u32 = 0x1C;    // BDL Pointer Upper

// GCTL bits
pub const GCTL_RESET: u32 = 0x01;
pub const GCTL_FCNTRL: u32 = 0x02;
pub const GCTL_UNSOL: u32 = 0x100;

// INTCTL bits
pub const INTCTL_GIE: u32 = 0x80000000;
pub const INTCTL_CIE: u32 = 0x40000000;

// SD_CTL bits
pub const SD_CTL_SRST: u32 = 0x01;
pub const SD_CTL_RUN: u32 = 0x02;
pub const SD_CTL_IOCE: u32 = 0x04;
pub const SD_CTL_FEIE: u32 = 0x08;
pub const SD_CTL_DEIE: u32 = 0x10;

// ============================================================================
// HDA Verb encoding
// ============================================================================

pub const MAX_CODECS: usize = 4;
pub const MAX_WIDGETS: usize = 64;
pub const MAX_CONNECTIONS: usize = 16;
pub const MAX_STREAMS: usize = 8;
pub const MAX_BDL_ENTRIES: usize = 32;

// Verb IDs (GET/SET parameter commands)
pub const VERB_GET_PARAM: u32 = 0xF0000;
pub const VERB_GET_CONN_SELECT: u32 = 0xF0100;
pub const VERB_SET_CONN_SELECT: u32 = 0x70100;
pub const VERB_GET_CONN_LIST: u32 = 0xF0200;
pub const VERB_GET_CONV_STREAM: u32 = 0xF0600;
pub const VERB_SET_CONV_STREAM: u32 = 0x70600;
pub const VERB_GET_PIN_CTRL: u32 = 0xF0700;
pub const VERB_SET_PIN_CTRL: u32 = 0x70700;
pub const VERB_GET_EAPD: u32 = 0xF0C00;
pub const VERB_SET_EAPD: u32 = 0x70C00;
pub const VERB_GET_VOLUME_KNOB: u32 = 0xF0F00;
pub const VERB_SET_VOLUME_KNOB: u32 = 0x70F00;
pub const VERB_GET_AMP_GAIN: u32 = 0xB0000;
pub const VERB_SET_AMP_GAIN: u32 = 0x30000;
pub const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C00;
pub const VERB_GET_PIN_SENSE: u32 = 0xF0900;
pub const VERB_SET_POWER_STATE: u32 = 0x70500;
pub const VERB_GET_POWER_STATE: u32 = 0xF0500;

// Parameters
pub const PARAM_VENDOR_ID: u32 = 0x00;
pub const PARAM_REV_ID: u32 = 0x02;
pub const PARAM_NODE_COUNT: u32 = 0x04;
pub const PARAM_FN_GROUP_TYPE: u32 = 0x05;
pub const PARAM_AUDIO_CAPS: u32 = 0x09;
pub const PARAM_PIN_CAPS: u32 = 0x0C;
pub const PARAM_AMP_IN_CAPS: u32 = 0x0D;
pub const PARAM_AMP_OUT_CAPS: u32 = 0x12;
pub const PARAM_CONN_LIST_LEN: u32 = 0x0E;
pub const PARAM_AUDIO_WIDGET_CAPS: u32 = 0x09;
pub const PARAM_SUPPORTED_RATES: u32 = 0x0A;
pub const PARAM_SUPPORTED_FORMATS: u32 = 0x0B;

// Pin control bits
pub const PIN_CTL_ENABLE: u8 = 0x40;
pub const PIN_CTL_HP_ENABLE: u8 = 0x80;
pub const PIN_CTL_OUT_ENABLE: u8 = 0x40;
pub const PIN_CTL_IN_ENABLE: u8 = 0x20;
pub const PIN_CTL_VREF_HIZ: u8 = 0x00;
pub const PIN_CTL_VREF_50: u8 = 0x01;
pub const PIN_CTL_VREF_GND: u8 = 0x02;
pub const PIN_CTL_VREF_80: u8 = 0x04;
pub const PIN_CTL_VREF_100: u8 = 0x05;

// ============================================================================
// Widget types
// ============================================================================

pub const WidgetType = enum(u8) {
    AudioOutput = 0,
    AudioInput = 1,
    AudioMixer = 2,
    AudioSelector = 3,
    PinComplex = 4,
    Power = 5,
    VolumeKnob = 6,
    BeepGenerator = 7,
    VendorDefined = 0x0F,
    Unknown = 0xFF,
};

// ============================================================================
// Pin connectivity
// ============================================================================

pub const PinConnectivity = enum(u2) {
    Jack = 0,       // External jack
    NoConnection = 1,
    Fixed = 2,      // Built-in (e.g., internal speaker)
    Both = 3,       // Both internal and jack
};

pub const PinLocation = enum(u4) {
    NA = 0,
    Rear = 1,
    Front = 2,
    Left = 3,
    Right = 4,
    Top = 5,
    Bottom = 6,
    Special = 7,
};

pub const PinDefaultDevice = enum(u4) {
    LineOut = 0,
    Speaker = 1,
    HpOut = 2,
    CD = 3,
    SPDIF_Out = 4,
    DigitalOther = 5,
    ModemLine = 6,
    ModemHandset = 7,
    LineIn = 8,
    Aux = 9,
    MicIn = 10,
    Telephony = 11,
    SPDIF_In = 12,
    DigitalIn = 13,
    Reserved = 14,
    Other = 15,
};

// ============================================================================
// Pin configuration
// ============================================================================

pub const PinConfig = struct {
    connectivity: PinConnectivity,
    location: PinLocation,
    default_device: PinDefaultDevice,
    connection_type: u4,
    color: u4,
    misc: u4,
    default_assoc: u4,
    sequence: u4,

    pub fn fromRaw(raw: u32) PinConfig {
        return .{
            .connectivity = @enumFromInt(@as(u2, @intCast((raw >> 30) & 0x3))),
            .location = @enumFromInt(@as(u4, @intCast((raw >> 24) & 0xF))),
            .default_device = @enumFromInt(@as(u4, @intCast((raw >> 20) & 0xF))),
            .connection_type = @intCast((raw >> 16) & 0xF),
            .color = @intCast((raw >> 12) & 0xF),
            .misc = @intCast((raw >> 8) & 0xF),
            .default_assoc = @intCast((raw >> 4) & 0xF),
            .sequence = @intCast(raw & 0xF),
        };
    }

    pub fn isOutput(self: *const PinConfig) bool {
        return switch (self.default_device) {
            .LineOut, .Speaker, .HpOut, .SPDIF_Out => true,
            else => false,
        };
    }

    pub fn isInput(self: *const PinConfig) bool {
        return switch (self.default_device) {
            .LineIn, .MicIn, .Aux, .SPDIF_In, .DigitalIn => true,
            else => false,
        };
    }

    pub fn isConnected(self: *const PinConfig) bool {
        return self.connectivity != .NoConnection;
    }
};

// ============================================================================
// Audio widget
// ============================================================================

pub const AudioWidget = struct {
    nid: u8,                    // Node ID
    widget_type: WidgetType,
    active: bool,
    capabilities: u32,
    connections: [u8; MAX_CONNECTIONS],
    connection_count: u8,
    selected_connection: u8,
    pin_config: PinConfig,
    amp_in_caps: u32,
    amp_out_caps: u32,
    amp_in_gain: u8,            // Current gain
    amp_out_gain: u8,
    amp_in_mute: bool,
    amp_out_mute: bool,
    stream_tag: u8,
    stream_channel: u8,
    format: u16,
    power_state: u8,

    pub fn init(nid: u8) AudioWidget {
        var w: AudioWidget = undefined;
        w.nid = nid;
        w.widget_type = .Unknown;
        w.active = false;
        w.capabilities = 0;
        w.connection_count = 0;
        w.selected_connection = 0;
        w.amp_in_caps = 0;
        w.amp_out_caps = 0;
        w.amp_in_gain = 0;
        w.amp_out_gain = 0;
        w.amp_in_mute = false;
        w.amp_out_mute = false;
        w.stream_tag = 0;
        w.stream_channel = 0;
        w.format = 0;
        w.power_state = 0;
        w.pin_config = PinConfig.fromRaw(0);
        for (0..MAX_CONNECTIONS) |i| w.connections[i] = 0;
        return w;
    }

    pub fn hasAmpIn(self: *const AudioWidget) bool {
        return self.amp_in_caps != 0;
    }

    pub fn hasAmpOut(self: *const AudioWidget) bool {
        return self.amp_out_caps != 0;
    }

    pub fn maxGainIn(self: *const AudioWidget) u8 {
        return @intCast(self.amp_in_caps & 0x7F);
    }

    pub fn maxGainOut(self: *const AudioWidget) u8 {
        return @intCast(self.amp_out_caps & 0x7F);
    }

    pub fn stepSizeIn(self: *const AudioWidget) u8 {
        return @intCast((self.amp_in_caps >> 16) & 0x7F);
    }

    pub fn stepSizeOut(self: *const AudioWidget) u8 {
        return @intCast((self.amp_out_caps >> 16) & 0x7F);
    }
};

// ============================================================================
// Buffer Descriptor List entry
// ============================================================================

pub const BdlEntry = extern struct {
    address_low: u32,
    address_high: u32,
    length: u32,
    ioc: u32,             // Interrupt on Completion (bit 0)
};

// ============================================================================
// PCM stream format
// ============================================================================

pub const SampleRate = enum(u16) {
    Rate8000 = 0x0000,
    Rate11025 = 0x0100,
    Rate16000 = 0x0200,
    Rate22050 = 0x0300,
    Rate32000 = 0x0600,
    Rate44100 = 0x4000,
    Rate48000 = 0x0000 | 0x0000,
    Rate88200 = 0x4000 | 0x0800,
    Rate96000 = 0x0000 | 0x0800,
    Rate176400 = 0x4000 | 0x1800,
    Rate192000 = 0x0000 | 0x1800,
};

pub const SampleBits = enum(u3) {
    Bits8 = 0,
    Bits16 = 1,
    Bits20 = 2,
    Bits24 = 3,
    Bits32 = 4,
};

pub const PcmFormat = struct {
    rate: SampleRate,
    bits: SampleBits,
    channels: u4,          // 0 = mono, 1 = stereo, etc.

    pub fn toHdaFormat(self: *const PcmFormat) u16 {
        return @as(u16, @intFromEnum(self.rate)) |
            (@as(u16, @intFromEnum(self.bits)) << 4) |
            @as(u16, self.channels);
    }
};

// ============================================================================
// Audio stream
// ============================================================================

pub const StreamDirection = enum(u1) {
    Output = 0,
    Input = 1,
};

pub const AudioStream = struct {
    stream_id: u8,
    tag: u8,
    direction: StreamDirection,
    active: bool,
    running: bool,
    format: PcmFormat,
    bdl: [MAX_BDL_ENTRIES]BdlEntry,
    bdl_count: u8,
    bdl_phys: u64,
    buffer_size: u32,
    position: u32,

    pub fn init(id: u8) AudioStream {
        var s: AudioStream = undefined;
        s.stream_id = id;
        s.tag = 0;
        s.direction = .Output;
        s.active = false;
        s.running = false;
        s.format = .{
            .rate = .Rate48000,
            .bits = .Bits16,
            .channels = 1,
        };
        s.bdl_count = 0;
        s.bdl_phys = 0;
        s.buffer_size = 0;
        s.position = 0;
        for (0..MAX_BDL_ENTRIES) |i| {
            s.bdl[i] = .{
                .address_low = 0,
                .address_high = 0,
                .length = 0,
                .ioc = 0,
            };
        }
        return s;
    }

    pub fn addBdlEntry(self: *AudioStream, phys_addr: u64, length: u32, ioc: bool) bool {
        if (self.bdl_count >= MAX_BDL_ENTRIES) return false;
        self.bdl[self.bdl_count] = .{
            .address_low = @intCast(phys_addr & 0xFFFFFFFF),
            .address_high = @intCast((phys_addr >> 32) & 0xFFFFFFFF),
            .length = length,
            .ioc = if (ioc) 1 else 0,
        };
        self.bdl_count += 1;
        self.buffer_size += length;
        return true;
    }
};

// ============================================================================
// HDA Codec
// ============================================================================

pub const HdaCodec = struct {
    codec_addr: u8,
    active: bool,
    vendor_id: u32,
    revision_id: u32,
    fg_type: u8,           // Function group type
    fg_nid: u8,            // Function group node ID
    widgets: [MAX_WIDGETS]AudioWidget,
    widget_count: u8,
    output_pin_count: u8,
    input_pin_count: u8,
    dac_count: u8,
    adc_count: u8,
    mixer_count: u8,

    pub fn init(addr: u8) HdaCodec {
        var codec: HdaCodec = undefined;
        codec.codec_addr = addr;
        codec.active = false;
        codec.vendor_id = 0;
        codec.revision_id = 0;
        codec.fg_type = 0;
        codec.fg_nid = 0;
        codec.widget_count = 0;
        codec.output_pin_count = 0;
        codec.input_pin_count = 0;
        codec.dac_count = 0;
        codec.adc_count = 0;
        codec.mixer_count = 0;
        for (0..MAX_WIDGETS) |i| {
            codec.widgets[i] = AudioWidget.init(@intCast(i));
        }
        return codec;
    }

    /// Build a HDA verb command
    pub fn makeVerb(self: *const HdaCodec, nid: u8, verb: u32) u32 {
        return (@as(u32, self.codec_addr) << 28) |
            (@as(u32, nid) << 20) |
            verb;
    }

    /// Find a widget by NID
    pub fn findWidget(self: *const HdaCodec, nid: u8) ?*const AudioWidget {
        for (0..self.widget_count) |i| {
            if (self.widgets[i].nid == nid and self.widgets[i].active) {
                return &self.widgets[i];
            }
        }
        return null;
    }

    /// Count output pins
    pub fn countOutputPins(self: *const HdaCodec) u8 {
        var count: u8 = 0;
        for (0..self.widget_count) |i| {
            if (self.widgets[i].active and
                self.widgets[i].widget_type == .PinComplex and
                self.widgets[i].pin_config.isOutput())
            {
                count += 1;
            }
        }
        return count;
    }

    /// Count input pins
    pub fn countInputPins(self: *const HdaCodec) u8 {
        var count: u8 = 0;
        for (0..self.widget_count) |i| {
            if (self.widgets[i].active and
                self.widgets[i].widget_type == .PinComplex and
                self.widgets[i].pin_config.isInput())
            {
                count += 1;
            }
        }
        return count;
    }
};

// ============================================================================
// CORB/RIRB
// ============================================================================

pub const MAX_CORB_ENTRIES: usize = 256;
pub const MAX_RIRB_ENTRIES: usize = 256;

pub const CorbRirb = struct {
    corb: [MAX_CORB_ENTRIES]u32,
    corb_write_ptr: u16,
    corb_read_ptr: u16,
    corb_phys: u64,

    rirb: [MAX_RIRB_ENTRIES]u64,    // Response + solicited bit
    rirb_write_ptr: u16,
    rirb_phys: u64,

    pub fn init() CorbRirb {
        var cr: CorbRirb = undefined;
        cr.corb_write_ptr = 0;
        cr.corb_read_ptr = 0;
        cr.corb_phys = 0;
        cr.rirb_write_ptr = 0;
        cr.rirb_phys = 0;
        for (0..MAX_CORB_ENTRIES) |i| cr.corb[i] = 0;
        for (0..MAX_RIRB_ENTRIES) |i| cr.rirb[i] = 0;
        return cr;
    }

    pub fn writeCommand(self: *CorbRirb, verb: u32) {
        self.corb_write_ptr = (self.corb_write_ptr + 1) % @as(u16, MAX_CORB_ENTRIES);
        self.corb[self.corb_write_ptr] = verb;
    }
};

// ============================================================================
// HDA Controller
// ============================================================================

pub const HdaController = struct {
    mmio_base: u64,
    active: bool,
    version_major: u8,
    version_minor: u8,
    num_output_streams: u8,
    num_input_streams: u8,
    num_bidir_streams: u8,
    codecs: [MAX_CODECS]HdaCodec,
    codec_count: u8,
    corb_rirb: CorbRirb,
    streams: [MAX_STREAMS]AudioStream,
    stream_count: u8,
    irq: u8,

    pub fn init() HdaController {
        var ctrl: HdaController = undefined;
        ctrl.mmio_base = 0;
        ctrl.active = false;
        ctrl.version_major = 0;
        ctrl.version_minor = 0;
        ctrl.num_output_streams = 0;
        ctrl.num_input_streams = 0;
        ctrl.num_bidir_streams = 0;
        ctrl.codec_count = 0;
        ctrl.corb_rirb = CorbRirb.init();
        ctrl.stream_count = 0;
        ctrl.irq = 0;
        for (0..MAX_CODECS) |i| ctrl.codecs[i] = HdaCodec.init(@intCast(i));
        for (0..MAX_STREAMS) |i| ctrl.streams[i] = AudioStream.init(@intCast(i));
        return ctrl;
    }

    fn readReg32(self: *const HdaController, offset: u32) u32 {
        const addr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        return addr.*;
    }

    fn writeReg32(self: *HdaController, offset: u32, value: u32) void {
        const addr: *volatile u32 = @ptrFromInt(self.mmio_base + offset);
        addr.* = value;
    }

    fn readReg16(self: *const HdaController, offset: u32) u16 {
        const addr: *volatile u16 = @ptrFromInt(self.mmio_base + offset);
        return addr.*;
    }

    fn writeReg16(self: *HdaController, offset: u32, value: u16) void {
        const addr: *volatile u16 = @ptrFromInt(self.mmio_base + offset);
        addr.* = value;
    }

    fn readReg8(self: *const HdaController, offset: u32) u8 {
        const addr: *volatile u8 = @ptrFromInt(self.mmio_base + offset);
        return addr.*;
    }

    pub fn detect(self: *HdaController, base_addr: u64) bool {
        self.mmio_base = base_addr;

        const gcap = self.readReg16(GCAP);
        self.num_output_streams = @intCast((gcap >> 12) & 0xF);
        self.num_input_streams = @intCast((gcap >> 8) & 0xF);
        self.num_bidir_streams = @intCast((gcap >> 3) & 0x1F);
        self.version_major = self.readReg8(VMAJ);
        self.version_minor = self.readReg8(VMIN);

        if (self.version_major == 0 and self.version_minor == 0) return false;

        self.active = true;
        return true;
    }

    pub fn reset(self: *HdaController) void {
        // Enter reset
        self.writeReg32(GCTL, self.readReg32(GCTL) & ~GCTL_RESET);
        // Wait for reset
        var i: u32 = 0;
        while (i < 1000) : (i += 1) {
            if (self.readReg32(GCTL) & GCTL_RESET == 0) break;
        }
        // Exit reset
        self.writeReg32(GCTL, self.readReg32(GCTL) | GCTL_RESET);
        i = 0;
        while (i < 1000) : (i += 1) {
            if (self.readReg32(GCTL) & GCTL_RESET != 0) break;
        }
    }

    pub fn enableInterrupts(self: *HdaController) void {
        self.writeReg32(INTCTL, INTCTL_GIE | INTCTL_CIE);
    }

    pub fn disableInterrupts(self: *HdaController) void {
        self.writeReg32(INTCTL, 0);
    }

    pub fn scanCodecs(self: *HdaController) void {
        const statests = self.readReg16(STATESTS);
        for (0..MAX_CODECS) |i| {
            if (statests & (@as(u16, 1) << @intCast(i)) != 0) {
                self.codecs[i].active = true;
                self.codecs[i].codec_addr = @intCast(i);
                self.codec_count += 1;
            }
        }
    }

    pub fn sendCommand(self: *HdaController, verb: u32) void {
        self.corb_rirb.writeCommand(verb);
        // Write CORB write pointer register
        self.writeReg16(CORBWP, self.corb_rirb.corb_write_ptr);
    }
};

// ============================================================================
// Global HDA subsystem
// ============================================================================

pub const MAX_HDA_CONTROLLERS: usize = 2;

pub const HdaSubsystem = struct {
    controllers: [MAX_HDA_CONTROLLERS]HdaController,
    controller_count: u8,

    pub fn init() HdaSubsystem {
        var sub: HdaSubsystem = undefined;
        sub.controller_count = 0;
        for (0..MAX_HDA_CONTROLLERS) |i| {
            sub.controllers[i] = HdaController.init();
        }
        return sub;
    }

    pub fn registerController(self: *HdaSubsystem, base: u64) ?u8 {
        if (self.controller_count >= MAX_HDA_CONTROLLERS) return null;
        const idx = self.controller_count;
        if (!self.controllers[idx].detect(base)) return null;
        self.controllers[idx].reset();
        self.controllers[idx].scanCodecs();
        self.controller_count += 1;
        return idx;
    }
};

var hda_subsystem: HdaSubsystem = HdaSubsystem.init();

pub fn getHdaSubsystem() *HdaSubsystem {
    return &hda_subsystem;
}

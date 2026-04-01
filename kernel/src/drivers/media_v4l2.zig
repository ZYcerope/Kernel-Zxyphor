// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Media/V4L2 Subsystem, Camera, Codec, DVB,
// Media Controller API, V4L2 Memory, CEC
// More advanced than Linux 2026 media subsystem

const std = @import("std");

// ============================================================================
// V4L2 (Video For Linux 2)
// ============================================================================

/// V4L2 device type
pub const V4l2DevType = enum(u8) {
    video_capture = 1,
    video_output = 2,
    video_overlay = 3,
    vbi_capture = 4,
    vbi_output = 5,
    sliced_vbi_capture = 6,
    sliced_vbi_output = 7,
    video_output_overlay = 8,
    video_capture_mplane = 9,
    video_output_mplane = 10,
    sdr_capture = 11,
    sdr_output = 12,
    meta_capture = 13,
    meta_output = 14,
    // Zxyphor
    zxy_ai_vision = 50,
};

/// V4L2 pixel format (fourcc codes)
pub const V4l2PixFmt = enum(u32) {
    // RGB
    rgb332 = fourcc('R', 'G', 'B', '1'),
    rgb444 = fourcc('R', '4', '4', '4'),
    argb444 = fourcc('A', 'R', '1', '2'),
    xrgb444 = fourcc('X', 'R', '1', '2'),
    rgb555 = fourcc('R', 'G', 'B', 'O'),
    argb555 = fourcc('A', 'R', '1', '5'),
    xrgb555 = fourcc('X', 'R', '1', '5'),
    rgb565 = fourcc('R', 'G', 'B', 'P'),
    rgb555x = fourcc('R', 'G', 'B', 'Q'),
    argb555x = fourcc('A', 'R', '1', 'X'),
    xrgb555x = fourcc('X', 'R', '1', 'X'),
    rgb565x = fourcc('R', 'G', 'B', 'R'),
    bgr666 = fourcc('B', 'G', 'R', 'H'),
    bgr24 = fourcc('B', 'G', 'R', '3'),
    rgb24 = fourcc('R', 'G', 'B', '3'),
    bgr32 = fourcc('B', 'G', 'R', '4'),
    abgr32 = fourcc('A', 'R', '2', '4'),
    xbgr32 = fourcc('X', 'R', '2', '4'),
    bgra32 = fourcc('R', 'A', '2', '4'),
    bgrx32 = fourcc('R', 'X', '2', '4'),
    rgb32 = fourcc('R', 'G', 'B', '4'),
    rgba32 = fourcc('A', 'B', '2', '4'),
    rgbx32 = fourcc('X', 'B', '2', '4'),
    argb32 = fourcc('B', 'A', '2', '4'),
    xrgb32 = fourcc('B', 'X', '2', '4'),
    // YUV
    grey = fourcc('G', 'R', 'E', 'Y'),
    y10 = fourcc('Y', '1', '0', ' '),
    y12 = fourcc('Y', '1', '2', ' '),
    y14 = fourcc('Y', '1', '4', ' '),
    y16 = fourcc('Y', '1', '6', ' '),
    y16_be = fourcc('Y', '1', '6', 'B'),
    yuyv = fourcc('Y', 'U', 'Y', 'V'),
    uyvy = fourcc('U', 'Y', 'V', 'Y'),
    yvyu = fourcc('Y', 'V', 'Y', 'U'),
    vyuy = fourcc('V', 'Y', 'U', 'Y'),
    nv12 = fourcc('N', 'V', '1', '2'),
    nv21 = fourcc('N', 'V', '2', '1'),
    nv16 = fourcc('N', 'V', '1', '6'),
    nv61 = fourcc('N', 'V', '6', '1'),
    nv24 = fourcc('N', 'V', '2', '4'),
    nv42 = fourcc('N', 'V', '4', '2'),
    yuv410 = fourcc('Y', 'U', 'V', '9'),
    yvu410 = fourcc('Y', 'V', 'U', '9'),
    yuv411p = fourcc('4', '1', '1', 'P'),
    yuv420 = fourcc('Y', 'U', '1', '2'),
    yvu420 = fourcc('Y', 'V', '1', '2'),
    yuv422p = fourcc('4', '2', '2', 'P'),
    // Compressed
    mjpeg = fourcc('M', 'J', 'P', 'G'),
    jpeg = fourcc('J', 'P', 'E', 'G'),
    h264 = fourcc('H', '2', '6', '4'),
    h264_no_sc = fourcc('A', 'V', 'C', '1'),
    h264_mvc = fourcc('M', '2', '6', '4'),
    h265 = fourcc('H', '2', '6', '5'),
    hevc = fourcc('H', 'E', 'V', 'C'),
    vp8 = fourcc('V', 'P', '8', '0'),
    vp9 = fourcc('V', 'P', '9', '0'),
    av1 = fourcc('A', 'V', '0', '1'),
    mpeg1 = fourcc('M', 'P', 'G', '1'),
    mpeg2 = fourcc('M', 'P', 'G', '2'),
    mpeg4 = fourcc('M', 'P', 'G', '4'),
    // Bayer
    sbggr8 = fourcc('B', 'A', '8', '1'),
    sgbrg8 = fourcc('G', 'B', 'R', 'G'),
    sgrbg8 = fourcc('G', 'R', 'B', 'G'),
    srggb8 = fourcc('R', 'G', 'G', 'B'),
    sbggr10 = fourcc('B', 'G', '1', '0'),
    sgbrg10 = fourcc('G', 'B', '1', '0'),
    sgrbg10 = fourcc('B', 'A', '1', '0'),
    srggb10 = fourcc('R', 'G', '1', '0'),
    sbggr12 = fourcc('B', 'G', '1', '2'),
    sgbrg12 = fourcc('G', 'B', '1', '2'),
    sgrbg12 = fourcc('B', 'A', '1', '2'),
    srggb12 = fourcc('R', 'G', '1', '2'),
};

fn fourcc(a: u8, b: u8, c: u8, d: u8) u32 {
    return @as(u32, a) | (@as(u32, b) << 8) | (@as(u32, c) << 16) | (@as(u32, d) << 24);
}

/// V4L2 buffer type
pub const V4l2BufType = enum(u32) {
    video_capture = 1,
    video_output = 2,
    video_overlay = 3,
    vbi_capture = 4,
    vbi_output = 5,
    sliced_vbi_capture = 6,
    sliced_vbi_output = 7,
    video_output_overlay = 8,
    video_capture_mplane = 9,
    video_output_mplane = 10,
    sdr_capture = 11,
    sdr_output = 12,
    meta_capture = 13,
    meta_output = 14,
};

/// V4L2 memory type
pub const V4l2Memory = enum(u32) {
    mmap = 1,
    userptr = 2,
    overlay = 3,
    dmabuf = 4,
};

/// V4L2 field
pub const V4l2Field = enum(u32) {
    any = 0,
    none = 1,
    top = 2,
    bottom = 3,
    interlaced = 4,
    seq_tb = 5,
    seq_bt = 6,
    alternate = 7,
    interlaced_tb = 8,
    interlaced_bt = 9,
};

/// V4L2 colorspace
pub const V4l2Colorspace = enum(u32) {
    default = 0,
    smpte170m = 1,
    smpte240m = 2,
    rec709 = 3,
    bt878 = 4,
    system_470m = 5,
    system_470bg = 6,
    jpeg = 7,
    srgb = 8,
    oprgb = 9,
    bt2020 = 10,
    raw = 11,
    dcip3 = 12,
};

/// V4L2 transfer function
pub const V4l2XferFunc = enum(u32) {
    default = 0,
    func_709 = 1,
    srgb = 2,
    oprgb = 3,
    smpte240m = 4,
    none = 5,
    dcip3 = 6,
    smpte2084 = 7,     // HDR PQ
};

/// V4L2 quantization
pub const V4l2Quantization = enum(u32) {
    default = 0,
    full_range = 1,
    lim_range = 2,
};

/// V4L2 ycbcr encoding
pub const V4l2YcbcrEncoding = enum(u32) {
    default = 0,
    enc_601 = 1,
    enc_709 = 2,
    enc_xv601 = 3,
    enc_xv709 = 4,
    enc_bt2020 = 5,
    enc_bt2020_const_lum = 6,
    enc_smpte240m = 7,
};

/// V4L2 format descriptor
pub const V4l2Format = struct {
    buf_type: V4l2BufType,
    // Pix format
    width: u32,
    height: u32,
    pixelformat: V4l2PixFmt,
    field: V4l2Field,
    bytesperline: u32,
    sizeimage: u32,
    colorspace: V4l2Colorspace,
    xfer_func: V4l2XferFunc,
    quantization: V4l2Quantization,
    ycbcr_enc: V4l2YcbcrEncoding,
    flags: u32,
    // Multiplanar
    num_planes: u8,
};

/// V4L2 buffer flags
pub const V4l2BufFlags = packed struct {
    mapped: bool = false,
    queued: bool = false,
    done: bool = false,
    keyframe: bool = false,
    pframe: bool = false,
    bframe: bool = false,
    error_flag: bool = false,
    in_request: bool = false,
    timecode: bool = false,
    m2m_hold_capture: bool = false,
    prepared: bool = false,
    no_cache_invalidate: bool = false,
    no_cache_clean: bool = false,
    timestamp_monotonic: bool = false,
    timestamp_copy: bool = false,
    tstamp_src_eof: bool = false,
    last: bool = false,
    request_fd: bool = false,
    _padding: u14 = 0,
};

/// V4L2 capability flags
pub const V4l2CapFlags = packed struct {
    video_capture: bool = false,
    video_output: bool = false,
    video_overlay: bool = false,
    vbi_capture: bool = false,
    vbi_output: bool = false,
    sliced_vbi_capture: bool = false,
    sliced_vbi_output: bool = false,
    rds_capture: bool = false,
    video_output_overlay: bool = false,
    hw_freq_seek: bool = false,
    rds_output: bool = false,
    video_capture_mplane: bool = false,
    video_output_mplane: bool = false,
    video_m2m_mplane: bool = false,
    video_m2m: bool = false,
    tuner: bool = false,
    audio: bool = false,
    radio: bool = false,
    modulator: bool = false,
    sdr_capture: bool = false,
    ext_pix_format: bool = false,
    sdr_output: bool = false,
    meta_capture: bool = false,
    readwrite: bool = false,
    streaming: bool = false,
    meta_output: bool = false,
    touch: bool = false,
    io_mc: bool = false,
    device_caps: bool = false,
    _padding: u3 = 0,
};

// ============================================================================
// V4L2 Controls
// ============================================================================

/// V4L2 control class
pub const V4l2CtrlClass = enum(u32) {
    user = 0x00980000,
    codec = 0x00990000,
    camera = 0x009A0000,
    fm_tx = 0x009B0000,
    flash = 0x009C0000,
    jpeg = 0x009D0000,
    image_source = 0x009E0000,
    image_proc = 0x009F0000,
    dv = 0x00A00000,
    fm_rx = 0x00A10000,
    rf_tuner = 0x00A20000,
    detect = 0x00A30000,
    codec_stateless = 0x00A40000,
    colorimetry = 0x00A50000,
};

/// Common V4L2 CIDs
pub const V4L2_CID_BRIGHTNESS: u32 = 0x00980900;
pub const V4L2_CID_CONTRAST: u32 = 0x00980901;
pub const V4L2_CID_SATURATION: u32 = 0x00980902;
pub const V4L2_CID_HUE: u32 = 0x00980903;
pub const V4L2_CID_AUDIO_VOLUME: u32 = 0x00980905;
pub const V4L2_CID_AUDIO_BALANCE: u32 = 0x00980906;
pub const V4L2_CID_AUDIO_BASS: u32 = 0x00980907;
pub const V4L2_CID_AUDIO_TREBLE: u32 = 0x00980908;
pub const V4L2_CID_AUDIO_MUTE: u32 = 0x00980909;
pub const V4L2_CID_HFLIP: u32 = 0x00980914;
pub const V4L2_CID_VFLIP: u32 = 0x00980915;
pub const V4L2_CID_ROTATE: u32 = 0x00980922;
pub const V4L2_CID_EXPOSURE: u32 = 0x009A0901;
pub const V4L2_CID_AUTOGAIN: u32 = 0x009A0912;
pub const V4L2_CID_GAIN: u32 = 0x009A0913;
pub const V4L2_CID_POWER_LINE_FREQUENCY: u32 = 0x009A0918;
pub const V4L2_CID_WHITE_BALANCE_TEMPERATURE: u32 = 0x009A091A;
pub const V4L2_CID_SHARPNESS: u32 = 0x009A091B;
pub const V4L2_CID_BACKLIGHT_COMPENSATION: u32 = 0x009A091C;
pub const V4L2_CID_FOCUS_AUTO: u32 = 0x009A090C;
pub const V4L2_CID_ZOOM_ABSOLUTE: u32 = 0x009A090D;
pub const V4L2_CID_PAN_ABSOLUTE: u32 = 0x009A0908;
pub const V4L2_CID_TILT_ABSOLUTE: u32 = 0x009A0909;

/// V4L2 control type
pub const V4l2CtrlType = enum(u32) {
    integer = 1,
    boolean = 2,
    menu = 3,
    button = 4,
    integer64 = 5,
    ctrl_class = 6,
    string = 7,
    bitmask = 8,
    integer_menu = 9,
    compound = 0x0100,
    u8_type = 0x0100,
    u16_type = 0x0101,
    u32_type = 0x0102,
    area = 0x0106,
    hdr10_cll = 0x0110,
    hdr10_mastering = 0x0111,
    h264_sps = 0x0200,
    h264_pps = 0x0201,
    h264_scaling_matrix = 0x0202,
    h264_slice_params = 0x0203,
    h264_decode_params = 0x0204,
    h264_pred_weights = 0x0205,
    fwht_params = 0x0220,
    vp8_frame = 0x0240,
    mpeg2_quantisation = 0x0250,
    mpeg2_sequence = 0x0251,
    mpeg2_picture = 0x0252,
    vp9_compressed_hdr = 0x0260,
    vp9_frame = 0x0261,
    hevc_sps = 0x0270,
    hevc_pps = 0x0271,
    hevc_slice_params = 0x0272,
    hevc_scaling_matrix = 0x0273,
    hevc_decode_params = 0x0274,
    av1_sequence = 0x0280,
    av1_tile_group_entry = 0x0281,
    av1_frame = 0x0282,
    av1_film_grain = 0x0283,
};

// ============================================================================
// Media Controller API
// ============================================================================

/// Media entity type
pub const MediaEntityType = enum(u32) {
    unknown = 0x00000000,
    // Base types
    base_v4l2_subdev = 0x00020000,
    // V4L2 video
    io_v4l = 0x00010001,
    io_vbi = 0x00010002,
    io_swradio = 0x00010003,
    io_dtv = 0x00010004,
    // Subdev types
    cam_sensor = 0x00020001,
    flash = 0x00020002,
    lens = 0x00020003,
    tuner = 0x00020004,
    v4l2_subdev_unknown = 0x00020000,
    // Processing
    proc_video_pixel_formatter = 0x00040001,
    proc_video_pixel_enc = 0x00040002,
    proc_video_lut = 0x00040003,
    proc_video_scaler = 0x00040004,
    proc_video_statistics = 0x00040005,
    proc_video_encoder = 0x00040006,
    proc_video_decoder = 0x00040007,
    proc_video_isp = 0x00040008,
    proc_video_composer = 0x00040009,
    // Connector
    conn_rf = 0x00060001,
    conn_svideo = 0x00060002,
    conn_composite = 0x00060003,
    conn_test = 0x00060004,
};

/// Media pad flags
pub const MediaPadFlags = packed struct {
    sink: bool = false,
    source: bool = false,
    must_connect: bool = false,
    internal: bool = false,
    _padding: u4 = 0,
};

/// Media link flags
pub const MediaLinkFlags = packed struct {
    enabled: bool = false,
    immutable: bool = false,
    dynamic: bool = false,
    data_link: bool = false,
    interface_link: bool = false,
    ancillary_link: bool = false,
    _padding: u2 = 0,
};

// ============================================================================
// DVB (Digital Video Broadcasting)
// ============================================================================

/// DVB frontend type
pub const DvbFeType = enum(u8) {
    qpsk = 0,      // DVB-S
    qam = 1,       // DVB-C
    ofdm = 2,      // DVB-T
    atsc = 3,      // ATSC
    // Multi-standard
    dvbs2 = 10,
    dvbt2 = 11,
    dvbc2 = 12,
    isdbt = 13,
    isdbs = 14,
    dtmb = 15,
};

/// DVB delivery system
pub const DvbDeliverySystem = enum(u8) {
    dvbs = 0,
    dvbs2 = 1,
    dvbt = 2,
    dvbt2 = 3,
    dss = 4,
    dvbc_annex_a = 5,
    dvbc_annex_b = 6,
    dvbc_annex_c = 7,
    dvbc2 = 8,
    atsc = 9,
    atsc_mh = 10,
    dtmb = 11,
    cmmb = 12,
    dab = 13,
    dvbh = 14,
    isdbt = 15,
    isdbs = 16,
    isdbc = 17,
};

// ============================================================================
// CEC (Consumer Electronics Control)
// ============================================================================

/// CEC log address type
pub const CecLogAddrType = enum(u8) {
    tv = 0,
    recording = 1,
    tuner = 2,
    playback = 3,
    audiosystem = 4,
    switch_dev = 5,
    videoproc = 6,
    unregistered = 7,
    specific = 8,
};

/// CEC opcode
pub const CecOpcode = enum(u8) {
    active_source = 0x82,
    image_view_on = 0x04,
    text_view_on = 0x0D,
    inactive_source = 0x9D,
    request_active_source = 0x85,
    routing_change = 0x80,
    routing_information = 0x81,
    set_stream_path = 0x86,
    standby = 0x36,
    record_off = 0x0B,
    record_on = 0x09,
    record_status = 0x0A,
    record_tv_screen = 0x0F,
    clear_analogue_timer = 0x33,
    clear_digital_timer = 0x99,
    clear_external_timer = 0xA1,
    set_analogue_timer = 0x34,
    set_digital_timer = 0x97,
    set_external_timer = 0xA2,
    set_timer_program_title = 0x67,
    timer_cleared_status = 0x43,
    timer_status = 0x35,
    cec_version = 0x9E,
    get_cec_version = 0x9F,
    give_physical_addr = 0x83,
    get_menu_language = 0x91,
    report_physical_addr = 0x84,
    set_menu_language = 0x32,
    report_features = 0xA6,
    give_features = 0xA5,
    deck_control = 0x42,
    deck_status = 0x1B,
    give_deck_status = 0x1A,
    play = 0x41,
    give_tuner_device_status = 0x08,
    select_analogue_service = 0x92,
    select_digital_service = 0x93,
    tuner_device_status = 0x07,
    tuner_step_decrement = 0x06,
    tuner_step_increment = 0x05,
    device_vendor_id = 0x87,
    give_device_vendor_id = 0x8C,
    vendor_command = 0x89,
    vendor_command_with_id = 0xA0,
    vendor_remote_button_down = 0x8A,
    vendor_remote_button_up = 0x8B,
    set_osd_string = 0x64,
    give_osd_name = 0x46,
    set_osd_name = 0x47,
    menu_request = 0x8D,
    menu_status = 0x8E,
    user_control_pressed = 0x44,
    user_control_released = 0x45,
    give_device_power_status = 0x8F,
    report_power_status = 0x90,
    feature_abort = 0x00,
    abort_msg = 0xFF,
    give_audio_status = 0x71,
    give_system_audio_mode_status = 0x7D,
    report_audio_status = 0x7A,
    report_short_audio_descriptor = 0xA3,
    request_short_audio_descriptor = 0xA4,
    set_system_audio_mode = 0x72,
    system_audio_mode_request = 0x70,
    system_audio_mode_status = 0x7E,
    set_audio_rate = 0x9A,
    initiate_arc = 0xC0,
    report_arc_initiated = 0xC1,
    report_arc_terminated = 0xC2,
    request_arc_initiation = 0xC3,
    request_arc_termination = 0xC4,
    terminate_arc = 0xC5,
    cdc_message = 0xF8,
};

// ============================================================================
// Subsystem Manager
// ============================================================================

pub const MediaSubsystem = struct {
    // Devices
    nr_video_devices: u32,
    nr_capture_devices: u32,
    nr_output_devices: u32,
    nr_m2m_devices: u32,
    nr_subdevices: u32,
    nr_dvb_devices: u32,
    nr_cec_devices: u32,
    // Media controller
    nr_entities: u32,
    nr_pads: u32,
    nr_links: u32,
    // Stats
    total_frames_captured: u64,
    total_frames_output: u64,
    total_bytes_streamed: u64,
    total_buffer_underruns: u64,
    total_buffer_overruns: u64,
    // Codecs
    nr_hw_codecs: u32,
    // Zxyphor
    zxy_ai_processing: bool,
    zxy_zero_copy_pipeline: bool,
    initialized: bool,

    pub fn init() MediaSubsystem {
        return MediaSubsystem{
            .nr_video_devices = 0,
            .nr_capture_devices = 0,
            .nr_output_devices = 0,
            .nr_m2m_devices = 0,
            .nr_subdevices = 0,
            .nr_dvb_devices = 0,
            .nr_cec_devices = 0,
            .nr_entities = 0,
            .nr_pads = 0,
            .nr_links = 0,
            .total_frames_captured = 0,
            .total_frames_output = 0,
            .total_bytes_streamed = 0,
            .total_buffer_underruns = 0,
            .total_buffer_overruns = 0,
            .nr_hw_codecs = 0,
            .zxy_ai_processing = true,
            .zxy_zero_copy_pipeline = true,
            .initialized = false,
        };
    }
};

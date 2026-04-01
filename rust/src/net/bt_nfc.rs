// SPDX-License-Identifier: MIT
// Zxyphor Kernel - Rust: Bluetooth/BLE driver model, NFC, RFID
// Classic BT profiles, BLE GATT client/server, Mesh, LE Audio,
// NFC NCI, NDEF, NFC-A/B/F/V, RFID reader abstraction
// More advanced than Linux 2026 wireless subsystem

/// Bluetooth HCI Transport types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HciBusType {
    Virtual = 0,
    Usb = 1,
    PcCard = 2,
    Uart = 3,
    Rs232 = 4,
    Pci = 5,
    Sdio = 6,
    Spi = 7,
    I2c = 8,
    Virtio = 10,
}

/// Bluetooth device type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtDevType {
    BredrOnly = 0,
    LeOnly = 1,
    DualMode = 2,
}

/// BT connection type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtLinkType {
    Acl = 0,
    Sco = 1,
    Esco = 2,
    Le = 3,
    Iso = 4,
}

/// Bluetooth version
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtVersion {
    V1_0 = 0,
    V1_1 = 1,
    V1_2 = 2,
    V2_0 = 3,
    V2_1 = 4,
    V3_0 = 5,
    V4_0 = 6,
    V4_1 = 7,
    V4_2 = 8,
    V5_0 = 9,
    V5_1 = 10,
    V5_2 = 11,
    V5_3 = 12,
    V5_4 = 13,
    // Zxyphor
    ZxyV6_0 = 20,
}

/// Bluetooth Address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdAddr {
    pub bytes: [u8; 6],
}

impl BdAddr {
    pub const ZERO: BdAddr = BdAddr { bytes: [0; 6] };

    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; 6]
    }

    pub fn addr_type(&self) -> BdAddrType {
        match self.bytes[5] & 0xC0 {
            0xC0 => BdAddrType::RandomStatic,
            0x40 => BdAddrType::RandomResolvable,
            0x00 => BdAddrType::RandomNonResolvable,
            _ => BdAddrType::Public,
        }
    }
}

/// BD Address type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BdAddrType {
    Public = 0,
    RandomStatic = 1,
    RandomResolvable = 2,
    RandomNonResolvable = 3,
}

/// HCI device state
#[derive(Debug, Clone)]
pub struct HciDeviceInfo {
    pub id: u32,
    pub name: [u8; 248],
    pub dev_type: BtDevType,
    pub bus_type: HciBusType,
    pub bdaddr: BdAddr,
    pub version: BtVersion,
    pub hci_ver: u8,
    pub hci_rev: u16,
    pub lmp_ver: u8,
    pub lmp_subver: u16,
    pub manufacturer: u16,
    // Features
    pub features: [[u8; 8]; 8],
    pub le_features: [u8; 8],
    pub commands: [u8; 64],
    // Capabilities
    pub acl_mtu: u16,
    pub acl_max_pkt: u16,
    pub sco_mtu: u16,
    pub sco_max_pkt: u16,
    pub le_mtu: u16,
    pub le_max_pkt: u16,
    pub iso_mtu: u16,
    pub iso_max_pkt: u16,
    // Class of Device
    pub dev_class: [u8; 3],
    // Power
    pub tx_power: i8,
    // LE features
    pub le_states: u64,
    pub le_accept_list_size: u8,
    pub le_resolv_list_size: u8,
    pub adv_instance_cnt: u8,
}

/// Bluetooth profile types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtProfile {
    // Classic
    A2dp = 0,
    Avrcp = 1,
    Hfp = 2,
    Hsp = 3,
    Hid = 4,
    Pan = 5,
    Pbap = 6,
    Map = 7,
    Opp = 8,
    Spp = 9,
    // LE
    Hogp = 20,
    Csip = 21,
    Vcp = 22,
    Micp = 23,
    Bap = 24,
    Cap = 25,
    Tmap = 26,
    Hap = 27,
    Gmcs = 28,
    Tbs = 29,
    Mcp = 30,
    Ccp = 31,
    // Zxyphor
    ZxyStream = 50,
}

/// GATT attribute permission
#[derive(Debug, Clone, Copy)]
pub struct GattPermission {
    pub read: bool,
    pub write: bool,
    pub read_encrypted: bool,
    pub write_encrypted: bool,
    pub read_authen: bool,
    pub write_authen: bool,
    pub prepare_write: bool,
    pub authen_signed_wr: bool,
}

/// BLE GATT Service
#[derive(Debug, Clone)]
pub struct GattServiceDef {
    pub uuid: [u8; 16],
    pub uuid_type: UuidType,
    pub is_primary: bool,
    pub start_handle: u16,
    pub end_handle: u16,
    pub nr_characteristics: u16,
    pub nr_includes: u8,
}

/// UUID type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidType {
    Uuid16 = 2,
    Uuid32 = 4,
    Uuid128 = 16,
}

/// BLE Advertising type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvType {
    AdvInd = 0x00,
    AdvDirectIndHigh = 0x01,
    AdvScanInd = 0x02,
    AdvNonconnInd = 0x03,
    AdvDirectIndLow = 0x04,
    // Extended (BT 5.0+)
    ExtAdvConnUndir = 0x10,
    ExtAdvConnDir = 0x11,
    ExtAdvScanUndir = 0x12,
    ExtAdvNonconnNonscanUndir = 0x13,
    ExtAdvScanRsp = 0x14,
}

/// BLE PHY type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LePhy {
    Phy1M = 1,
    Phy2M = 2,
    PhyCoded = 3,
}

/// LE Audio Codec Configuration
#[derive(Debug, Clone)]
pub struct Lc3Config {
    pub sampling_freq: Lc3SamplingFreq,
    pub frame_duration: Lc3FrameDuration,
    pub octets_per_frame: u16,
    pub audio_channel_allocation: u32,
    pub codec_frames_per_sdu: u8,
}

/// LC3 Sampling frequencies
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lc3SamplingFreq {
    Hz8000 = 0x01,
    Hz11025 = 0x02,
    Hz16000 = 0x03,
    Hz22050 = 0x04,
    Hz24000 = 0x05,
    Hz32000 = 0x06,
    Hz44100 = 0x07,
    Hz48000 = 0x08,
    Hz88200 = 0x09,
    Hz96000 = 0x0A,
    Hz176400 = 0x0B,
    Hz192000 = 0x0C,
    Hz384000 = 0x0D,
}

/// LC3 Frame durations
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lc3FrameDuration {
    Ms7_5 = 0x00,
    Ms10 = 0x01,
}

/// BT Mesh element
#[derive(Debug, Clone)]
pub struct MeshElement {
    pub addr: u16,
    pub location: u16,
    pub nr_sig_models: u8,
    pub nr_vendor_models: u8,
}

// ============================================================================
// NFC (Near Field Communication)
// ============================================================================

/// NFC Technology
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfcTechnology {
    NfcA = 0,      // ISO 14443-3A (TypeA)
    NfcB = 1,      // ISO 14443-3B (TypeB)
    NfcF = 2,      // JIS X 6319-4 (FeliCa)
    NfcV = 3,      // ISO 15693 (VICC)
    NfcDep = 4,    // NFC Data Exchange Protocol
    NfcBarcode = 5, // Thinfilm NFC Barcode
}

/// NFC Protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfcProtocol {
    Unknown = 0,
    T1t = 1,       // NFC Type 1 Tag (Topaz)
    T2t = 2,       // NFC Type 2 Tag (NTAG/Ultralight)
    T3t = 3,       // NFC Type 3 Tag (FeliCa)
    T4t = 4,       // NFC Type 4 Tag (ISO-DEP)
    T5t = 5,       // NFC Type 5 Tag (ISO 15693)
    IsoDep = 6,    // ISO-DEP (ISO 14443-4)
    NfcDep = 7,    // NFC-DEP (LLCP)
    Mifare = 8,    // MIFARE Classic
}

/// NFC Communication mode
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfcCommMode {
    Passive = 0,
    Active = 1,
}

/// NCI (NFC Controller Interface) State
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NciState {
    Idle = 0,
    Discovery = 1,
    WaitForAllDiscoveries = 2,
    WaitForSelectResp = 3,
    PollActive = 4,
    ListenActive = 5,
    ListenSleep = 6,
    WaitForDeactivateNtf = 7,
}

/// NCI Message type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NciMsgType {
    Data = 0x00,
    Command = 0x01,
    Response = 0x02,
    Notification = 0x03,
}

/// NCI Group ID
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NciGid {
    Core = 0x00,
    RfManagement = 0x01,
    NfceeManagement = 0x02,
    Proprietary = 0x0F,
}

/// NDEF Record Type Name Format
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdefTnf {
    Empty = 0x00,
    WellKnown = 0x01,
    MimeMedia = 0x02,
    AbsoluteUri = 0x03,
    External = 0x04,
    Unknown = 0x05,
    Unchanged = 0x06,
    Reserved = 0x07,
}

/// NDEF Record
#[derive(Debug, Clone)]
pub struct NdefRecord {
    pub tnf: NdefTnf,
    pub mb: bool,      // Message Begin
    pub me: bool,      // Message End
    pub cf: bool,      // Chunk Flag
    pub sr: bool,      // Short Record
    pub il: bool,      // ID Length present
    pub type_length: u8,
    pub payload_length: u32,
    pub id_length: u8,
    // Well-known types
    pub record_type: NdefWellKnownType,
}

/// NDEF Well-Known Record Types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdefWellKnownType {
    Text = 0,          // "T" - Text record
    Uri = 1,           // "U" - URI record
    SmartPoster = 2,   // "Sp" - Smart Poster
    HandoverRequest = 3,
    HandoverSelect = 4,
    HandoverMediation = 5,
    HandoverInitiate = 6,
    Signature = 7,     // "Sig"
    Other = 255,
}

/// NDEF URI Prefix codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdefUriPrefix {
    None = 0x00,
    HttpWww = 0x01,        // "http://www."
    HttpsWww = 0x02,       // "https://www."
    Http = 0x03,           // "http://"
    Https = 0x04,          // "https://"
    Tel = 0x05,            // "tel:"
    Mailto = 0x06,         // "mailto:"
    FtpAnon = 0x07,
    FtpFtp = 0x08,
    Ftps = 0x09,
    Sftp = 0x0A,
    Smb = 0x0B,
    Nfs = 0x0C,
    Ftp = 0x0D,
    Dav = 0x0E,
    News = 0x0F,
    Telnet = 0x10,
    Imap = 0x11,
    Rtsp = 0x12,
    Urn = 0x13,
    Pop = 0x14,
    Sip = 0x15,
    Sips = 0x16,
    Tftp = 0x17,
    Btspp = 0x18,
    Btl2cap = 0x19,
    Btgoep = 0x1A,
    TcpObex = 0x1B,
    Irdaobex = 0x1C,
    File = 0x1D,
    UrnEpcId = 0x1E,
    UrnEpcTag = 0x1F,
    UrnEpcPat = 0x20,
    UrnEpcRaw = 0x21,
    UrnEpc = 0x22,
    UrnNfc = 0x23,
}

/// NFC Target / Tag
#[derive(Debug, Clone)]
pub struct NfcTarget {
    pub idx: u32,
    pub technology: NfcTechnology,
    pub protocol: NfcProtocol,
    // Identifiers
    pub nfcid1: [u8; 10],
    pub nfcid1_len: u8,
    pub nfcid2: [u8; 8],
    pub sensb_res: [u8; 12],
    pub sensf_res: [u8; 18],
    pub sensf_res_len: u8,
    // UID
    pub uid: [u8; 10],
    pub uid_len: u8,
    // ISO 15693
    pub iso15693_dsfid: u8,
    pub iso15693_uid: [u8; 8],
    // ATR (Answer to Reset)
    pub atr_res: [u8; 64],
    pub atr_res_len: u8,
    pub atr_req: [u8; 64],
    pub atr_req_len: u8,
    // NDEF
    pub is_ndef: bool,
    pub ndef_max_size: u32,
    pub ndef_current_size: u32,
    pub ndef_readonly: bool,
}

/// NFC Device (controller)
#[derive(Debug, Clone)]
pub struct NfcDeviceInfo {
    pub idx: u32,
    pub name: [u8; 32],
    // NCI info
    pub nci_ver: u8,
    pub manufacturer_id: u8,
    pub nci_state: NciState,
    // Supported technologies
    pub supported_technologies: u32,
    pub supported_protocols: u32,
    // RF interfaces
    pub nr_rf_interfaces: u8,
    // Secure Element
    pub nr_se: u8,
    // Power
    pub powered: bool,
    // Discovery
    pub polling: bool,
    pub listening: bool,
    // Stats
    pub total_tags_discovered: u64,
    pub total_p2p_connections: u64,
    pub total_se_transactions: u64,
    pub total_ndef_reads: u64,
    pub total_ndef_writes: u64,
    pub total_errors: u64,
}

/// Secure Element type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfcSeType {
    Uicc = 0,     // SIM card
    Embedded = 1,  // eSE
    Sd = 2,       // SD card
}

// ============================================================================
// RFID Reader Abstraction
// ============================================================================

/// RFID Frequency band
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfidFrequency {
    Lf125Khz = 0,     // Low Frequency
    Lf134Khz = 1,
    Hf13Mhz = 2,      // High Frequency (same as NFC)
    Uhf860Mhz = 3,    // Ultra High Frequency (EU)
    Uhf902Mhz = 4,    // Ultra High Frequency (US)
    Uhf920Mhz = 5,    // Ultra High Frequency (China)
    Shf2_4Ghz = 6,    // Super High Frequency
}

/// RFID Protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfidProtocol {
    Iso14443A = 0,
    Iso14443B = 1,
    Iso15693 = 2,
    Iso18000_6C = 3,   // EPC Gen2 UHF
    Em4100 = 4,        // EM4100 125kHz
    HidProx = 5,       // HID Prox
    Hitag = 6,         // Hitag 1/2/S
    Felica = 7,
    LfFsk = 8,
    LfAsk = 9,
    // Zxyphor
    ZxySecure = 20,
}

/// RFID Tag info
#[derive(Debug, Clone)]
pub struct RfidTag {
    pub protocol: RfidProtocol,
    pub frequency: RfidFrequency,
    pub uid: [u8; 16],
    pub uid_len: u8,
    // EPC Gen2
    pub epc: [u8; 12],
    pub epc_len: u8,
    pub tid: [u8; 12],
    pub user_memory_size: u32,
    // Signal strength
    pub rssi: i16,
    // Last seen
    pub last_seen_ns: u64,
    pub read_count: u32,
}

// ============================================================================
// Subsystem Manager
// ============================================================================

/// Combined BT/NFC/RFID subsystem
#[derive(Debug, Clone)]
pub struct WirelessSubsystem {
    // Bluetooth
    pub nr_bt_devices: u32,
    pub nr_bt_connections: u32,
    pub bt_le_audio_support: bool,
    pub bt_mesh_support: bool,
    pub total_bt_tx_bytes: u64,
    pub total_bt_rx_bytes: u64,
    pub total_bt_pairings: u64,
    // NFC
    pub nr_nfc_devices: u32,
    pub nr_nfc_targets: u32,
    pub total_nfc_tags_read: u64,
    pub total_nfc_tags_written: u64,
    pub total_nfc_p2p: u64,
    // RFID
    pub nr_rfid_readers: u32,
    pub total_rfid_tags_read: u64,
    // Zxyphor
    pub zxy_unified_wireless: bool,
    pub initialized: bool,
}

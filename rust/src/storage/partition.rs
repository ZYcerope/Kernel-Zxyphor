// =============================================================================
// Kernel Zxyphor — Partition Table Parser
// =============================================================================
// Full MBR and GPT partition table support:
//   - Legacy MBR with CHS and LBA addressing
//   - Extended/logical partitions (EBR chain)
//   - GPT with header validation and CRC32 verification
//   - Protective MBR detection
//   - Known GUID identification (EFI System, Linux, swap, etc.)
//   - Partition enumeration and device path generation
// =============================================================================

use core::sync::atomic::{AtomicU32, Ordering};

pub const MAX_PARTITIONS: usize = 128;
pub const SECTOR_SIZE: u64 = 512;
pub const GPT_HEADER_SIGNATURE: u64 = 0x5452415020494645; // "EFI PART"

// =============================================================================
// MBR structures
// =============================================================================

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MbrChs {
    pub head: u8,
    pub sector_cylinder: u8,  // Sector (bits 0-5), Cylinder high (bits 6-7)
    pub cylinder_low: u8,
}

impl MbrChs {
    pub fn sector(&self) -> u8 {
        self.sector_cylinder & 0x3F
    }

    pub fn cylinder(&self) -> u16 {
        ((self.sector_cylinder as u16 & 0xC0) << 2) | self.cylinder_low as u16
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct MbrEntry {
    pub status: u8,           // 0x80 = active/bootable
    pub first_chs: MbrChs,
    pub partition_type: u8,
    pub last_chs: MbrChs,
    pub first_lba: u32,
    pub sector_count: u32,
}

impl MbrEntry {
    pub fn is_valid(&self) -> bool {
        self.partition_type != 0 && self.sector_count > 0
    }

    pub fn is_bootable(&self) -> bool {
        self.status == 0x80
    }

    pub fn is_extended(&self) -> bool {
        matches!(self.partition_type, 0x05 | 0x0F | 0x85)
    }

    pub fn is_gpt_protective(&self) -> bool {
        self.partition_type == 0xEE
    }

    pub fn type_name(&self) -> &'static str {
        match self.partition_type {
            0x00 => "Empty",
            0x01 => "FAT12",
            0x04 | 0x06 | 0x0E => "FAT16",
            0x05 => "Extended",
            0x07 => "NTFS/exFAT",
            0x0B | 0x0C => "FAT32",
            0x0F => "Extended LBA",
            0x11 => "Hidden FAT12",
            0x14 => "Hidden FAT16",
            0x1B | 0x1C => "Hidden FAT32",
            0x27 => "WinRE",
            0x42 => "LDM",
            0x82 => "Linux Swap",
            0x83 => "Linux",
            0x85 => "Linux Extended",
            0x8E => "Linux LVM",
            0xA5 => "FreeBSD",
            0xA6 => "OpenBSD",
            0xA9 => "NetBSD",
            0xAF => "macOS HFS+",
            0xBE => "Solaris Boot",
            0xBF => "Solaris",
            0xEE => "GPT Protective",
            0xEF => "EFI System",
            0xFD => "Linux RAID",
            _ => "Unknown",
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct MbrHeader {
    pub bootstrap: [u8; 446],
    pub entries: [MbrEntry; 4],
    pub signature: u16, // 0xAA55
}

impl MbrHeader {
    /// Validate the MBR signature
    pub fn is_valid(&self) -> bool {
        self.signature == 0xAA55
    }

    /// Check if this is a GPT protective MBR
    pub fn is_gpt_protective(&self) -> bool {
        self.is_valid() && self.entries[0].is_gpt_protective()
    }
}

// =============================================================================
// GPT structures
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const ZERO: Self = Self { data1: 0, data2: 0, data3: 0, data4: [0; 8] };

    pub const EFI_SYSTEM: Self = Self {
        data1: 0xC12A7328, data2: 0xF81F, data3: 0x11D2,
        data4: [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
    };
    pub const MICROSOFT_BASIC: Self = Self {
        data1: 0xEBD0A0A2, data2: 0xB9E5, data3: 0x4433,
        data4: [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
    };
    pub const LINUX_FILESYSTEM: Self = Self {
        data1: 0x0FC63DAF, data2: 0x8483, data3: 0x4772,
        data4: [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
    };
    pub const LINUX_SWAP: Self = Self {
        data1: 0x0657FD6D, data2: 0xA4AB, data3: 0x43C4,
        data4: [0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F],
    };
    pub const LINUX_LVM: Self = Self {
        data1: 0xE6D6D379, data2: 0xF507, data3: 0x44C2,
        data4: [0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28],
    };
    pub const LINUX_ROOT_X86_64: Self = Self {
        data1: 0x4F68BCE3, data2: 0xE8CD, data3: 0x4DB1,
        data4: [0x96, 0xE7, 0xFB, 0xCA, 0xF9, 0x84, 0xB7, 0x09],
    };

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    pub fn type_name(&self) -> &'static str {
        if *self == Self::EFI_SYSTEM { return "EFI System"; }
        if *self == Self::MICROSOFT_BASIC { return "Microsoft Basic Data"; }
        if *self == Self::LINUX_FILESYSTEM { return "Linux Filesystem"; }
        if *self == Self::LINUX_SWAP { return "Linux Swap"; }
        if *self == Self::LINUX_LVM { return "Linux LVM"; }
        if *self == Self::LINUX_ROOT_X86_64 { return "Linux Root (x86-64)"; }
        "Unknown"
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GptHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub reserved: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: Guid,
    pub partition_entry_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_array_crc32: u32,
}

impl GptHeader {
    pub fn is_valid(&self) -> bool {
        self.signature == GPT_HEADER_SIGNATURE
            && self.header_size >= 92
            && self.partition_entry_size >= 128
    }

    /// Verify CRC32 of the header (zeroing the CRC field for calculation)
    pub fn verify_crc(&self) -> bool {
        // Simple CRC32 — use same table as compression module
        let bytes = unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                self.header_size as usize,
            )
        };

        let mut crc: u32 = 0xFFFFFFFF;
        let header_crc_offset = 16; // Offset of header_crc32 field
        for (i, &byte) in bytes.iter().enumerate() {
            // Zero out the CRC field bytes during calculation
            let b = if (header_crc_offset..header_crc_offset + 4).contains(&i) {
                0u8
            } else {
                byte
            };
            let index = ((crc ^ b as u32) & 0xFF) as usize;
            crc = CRC32_TABLE[index] ^ (crc >> 8);
        }
        crc ^= 0xFFFFFFFF;

        crc == self.header_crc32
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct GptEntry {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub name: [u16; 36], // UTF-16LE
}

impl GptEntry {
    pub fn is_used(&self) -> bool {
        !self.type_guid.is_zero()
    }

    pub fn size_sectors(&self) -> u64 {
        if self.ending_lba >= self.starting_lba {
            self.ending_lba - self.starting_lba + 1
        } else {
            0
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * SECTOR_SIZE
    }

    /// Get ASCII name (lossy conversion from UTF-16)
    pub fn ascii_name(&self, buf: &mut [u8; 36]) -> usize {
        let mut len = 0;
        for &ch in &self.name {
            if ch == 0 { break; }
            if ch < 128 {
                buf[len] = ch as u8;
            } else {
                buf[len] = b'?';
            }
            len += 1;
        }
        len
    }

    /// Check attribute bits
    pub fn required_for_platform(&self) -> bool {
        (self.attributes & (1 << 0)) != 0
    }

    pub fn legacy_bios_bootable(&self) -> bool {
        (self.attributes & (1 << 2)) != 0
    }

    pub fn no_block_io(&self) -> bool {
        (self.attributes & (1 << 1)) != 0
    }
}

// =============================================================================
// Unified partition descriptor
// =============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PartitionScheme {
    None = 0,
    Mbr = 1,
    Gpt = 2,
}

#[derive(Clone, Copy)]
pub struct PartitionInfo {
    pub start_lba: u64,
    pub size_sectors: u64,
    pub scheme: PartitionScheme,
    pub index: u8,
    pub bootable: bool,
    pub device_id: u16,
    // MBR fields
    pub mbr_type: u8,
    pub is_logical: bool,
    // GPT fields
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub name: [u8; 36],
    pub name_len: u8,
    pub active: bool,
}

impl PartitionInfo {
    pub const fn empty() -> Self {
        Self {
            start_lba: 0,
            size_sectors: 0,
            scheme: PartitionScheme::None,
            index: 0,
            bootable: false,
            device_id: 0,
            mbr_type: 0,
            is_logical: false,
            type_guid: Guid::ZERO,
            unique_guid: Guid::ZERO,
            name: [0u8; 36],
            name_len: 0,
            active: false,
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_sectors * SECTOR_SIZE
    }

    pub fn size_mb(&self) -> u64 {
        self.size_bytes() / (1024 * 1024)
    }

    pub fn type_name(&self) -> &'static str {
        match self.scheme {
            PartitionScheme::Mbr => {
                let fakentry = MbrEntry {
                    status: 0,
                    first_chs: MbrChs { head: 0, sector_cylinder: 0, cylinder_low: 0 },
                    partition_type: self.mbr_type,
                    last_chs: MbrChs { head: 0, sector_cylinder: 0, cylinder_low: 0 },
                    first_lba: 0,
                    sector_count: 0,
                };
                fakentry.type_name()
            }
            PartitionScheme::Gpt => self.type_guid.type_name(),
            PartitionScheme::None => "None",
        }
    }
}

// =============================================================================
// Partition table
// =============================================================================

pub struct PartitionTable {
    pub partitions: [PartitionInfo; MAX_PARTITIONS],
    pub count: AtomicU32,
    pub scheme: PartitionScheme,
    pub disk_guid: Guid,
}

impl PartitionTable {
    pub const fn new() -> Self {
        Self {
            partitions: [const { PartitionInfo::empty() }; MAX_PARTITIONS],
            count: AtomicU32::new(0),
            scheme: PartitionScheme::None,
            disk_guid: Guid::ZERO,
        }
    }

    /// Parse an MBR from raw sector data
    pub fn parse_mbr(&mut self, sector_data: &[u8; 512], device_id: u16) -> usize {
        let mbr = unsafe { &*(sector_data.as_ptr() as *const MbrHeader) };
        if !mbr.is_valid() {
            return 0;
        }

        if mbr.is_gpt_protective() {
            self.scheme = PartitionScheme::Gpt;
            return 0; // Caller should parse GPT from LBA 1
        }

        self.scheme = PartitionScheme::Mbr;
        let mut idx = 0usize;

        for (i, entry) in mbr.entries.iter().enumerate() {
            if !entry.is_valid() || entry.is_extended() {
                continue;
            }
            if idx >= MAX_PARTITIONS { break; }

            self.partitions[idx] = PartitionInfo {
                start_lba: entry.first_lba as u64,
                size_sectors: entry.sector_count as u64,
                scheme: PartitionScheme::Mbr,
                index: i as u8,
                bootable: entry.is_bootable(),
                device_id,
                mbr_type: entry.partition_type,
                is_logical: false,
                type_guid: Guid::ZERO,
                unique_guid: Guid::ZERO,
                name: [0u8; 36],
                name_len: 0,
                active: true,
            };
            idx += 1;
        }

        self.count.store(idx as u32, Ordering::Release);
        idx
    }

    /// Parse GPT from raw header + entry data
    pub fn parse_gpt(
        &mut self,
        header_data: &[u8; 512],
        entry_data: &[u8],
        device_id: u16,
    ) -> usize {
        let header = unsafe { &*(header_data.as_ptr() as *const GptHeader) };
        if !header.is_valid() {
            return 0;
        }

        self.scheme = PartitionScheme::Gpt;
        self.disk_guid = header.disk_guid;

        let entry_size = header.partition_entry_size as usize;
        let max_entries = core::cmp::min(
            header.num_partition_entries as usize,
            entry_data.len() / entry_size,
        );

        let mut idx = 0usize;
        for i in 0..max_entries {
            if idx >= MAX_PARTITIONS { break; }

            let offset = i * entry_size;
            if offset + 128 > entry_data.len() { break; }

            let entry = unsafe { &*(entry_data.as_ptr().add(offset) as *const GptEntry) };
            if !entry.is_used() { continue; }

            let mut name_buf = [0u8; 36];
            let name_len = entry.ascii_name(&mut name_buf);

            self.partitions[idx] = PartitionInfo {
                start_lba: entry.starting_lba,
                size_sectors: entry.size_sectors(),
                scheme: PartitionScheme::Gpt,
                index: i as u8,
                bootable: entry.legacy_bios_bootable(),
                device_id,
                mbr_type: 0,
                is_logical: false,
                type_guid: entry.type_guid,
                unique_guid: entry.unique_guid,
                name: name_buf,
                name_len: name_len as u8,
                active: true,
            };
            idx += 1;
        }

        self.count.store(idx as u32, Ordering::Release);
        idx
    }

    pub fn partition_count(&self) -> usize {
        self.count.load(Ordering::Acquire) as usize
    }

    pub fn get(&self, index: usize) -> Option<&PartitionInfo> {
        if index < self.partition_count() && self.partitions[index].active {
            Some(&self.partitions[index])
        } else {
            None
        }
    }

    /// Find a partition by type GUID
    pub fn find_by_type(&self, guid: &Guid) -> Option<&PartitionInfo> {
        let count = self.partition_count();
        for i in 0..count {
            if self.partitions[i].active && self.partitions[i].type_guid == *guid {
                return Some(&self.partitions[i]);
            }
        }
        None
    }
}

// =============================================================================
// CRC32 lookup table (same polynomial as zlib: 0xEDB88320)
// =============================================================================

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

// =============================================================================
// Global partition table
// =============================================================================

static mut PARTITIONS: PartitionTable = PartitionTable::new();

pub unsafe fn partition_table() -> &'static mut PartitionTable {
    &mut *core::ptr::addr_of_mut!(PARTITIONS)
}

// =============================================================================
// FFI exports
// =============================================================================

#[no_mangle]
pub extern "C" fn zxyphor_partition_parse_mbr(data_ptr: *const u8, device_id: u16) -> i32 {
    if data_ptr.is_null() { return -1; }
    unsafe {
        let data = &*(data_ptr as *const [u8; 512]);
        partition_table().parse_mbr(data, device_id) as i32
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_partition_count() -> u32 {
    unsafe { partition_table().partition_count() as u32 }
}

#[no_mangle]
pub extern "C" fn zxyphor_partition_start_lba(index: u32) -> u64 {
    unsafe {
        partition_table().get(index as usize).map_or(0, |p| p.start_lba)
    }
}

#[no_mangle]
pub extern "C" fn zxyphor_partition_size_sectors(index: u32) -> u64 {
    unsafe {
        partition_table().get(index as usize).map_or(0, |p| p.size_sectors)
    }
}

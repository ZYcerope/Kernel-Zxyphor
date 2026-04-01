// =============================================================================
// Kernel Zxyphor — FAT32 Filesystem (Rust)
// =============================================================================
// Full FAT32 filesystem implementation with read and write support.
// Supports:
//   - FAT32 BPB (BIOS Parameter Block) parsing
//   - FAT chain traversal and allocation
//   - Directory entry parsing (8.3 short names)
//   - Long File Name (LFN) support (VFAT)
//   - File reading and writing
//   - Directory creation and file creation
//   - File deletion (marks clusters as free)
//   - Subdirectory traversal
//
// References: Microsoft FAT32 File System Specification (Dec 2000)
// =============================================================================

// =============================================================================
// On-Disk Structures
// =============================================================================

const SECTOR_SIZE: usize = 512;
const FAT32_EOC: u32 = 0x0FFFFFF8; // End of cluster chain marker
const FAT32_FREE: u32 = 0x00000000;
const FAT32_BAD: u32 = 0x0FFFFFF7;
const FAT_ENTRY_MASK: u32 = 0x0FFFFFFF;

// Directory entry attributes
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const DIR_ENTRY_SIZE: usize = 32;
const DELETED_MARKER: u8 = 0xE5;
const LAST_ENTRY: u8 = 0x00;

/// FAT32 BIOS Parameter Block (BPB) + Extended Boot Record
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32Bpb {
    pub bs_jmp_boot: [u8; 3],
    pub bs_oem_name: [u8; 8],
    pub bpb_bytes_per_sec: u16,
    pub bpb_sec_per_clus: u8,
    pub bpb_rsvd_sec_cnt: u16,
    pub bpb_num_fats: u8,
    pub bpb_root_ent_cnt: u16,    // 0 for FAT32
    pub bpb_tot_sec16: u16,       // 0 for FAT32
    pub bpb_media: u8,
    pub bpb_fat_sz16: u16,        // 0 for FAT32
    pub bpb_sec_per_trk: u16,
    pub bpb_num_heads: u16,
    pub bpb_hidd_sec: u32,
    pub bpb_tot_sec32: u32,
    // FAT32 specific
    pub bpb_fat_sz32: u32,
    pub bpb_ext_flags: u16,
    pub bpb_fs_ver: u16,
    pub bpb_root_clus: u32,
    pub bpb_fs_info: u16,
    pub bpb_bk_boot_sec: u16,
    pub bpb_reserved: [u8; 12],
    pub bs_drv_num: u8,
    pub bs_reserved1: u8,
    pub bs_boot_sig: u8,
    pub bs_vol_id: u32,
    pub bs_vol_lab: [u8; 11],
    pub bs_fil_sys_type: [u8; 8],
}

/// Short directory entry (8.3 format)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32DirEntry {
    pub dir_name: [u8; 11],       // 8.3 name
    pub dir_attr: u8,
    pub dir_nt_res: u8,
    pub dir_crt_time_tenth: u8,
    pub dir_crt_time: u16,
    pub dir_crt_date: u16,
    pub dir_lst_acc_date: u16,
    pub dir_fst_clus_hi: u16,
    pub dir_wrt_time: u16,
    pub dir_wrt_date: u16,
    pub dir_fst_clus_lo: u16,
    pub dir_file_size: u32,
}

/// Long File Name directory entry (VFAT)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32LfnEntry {
    pub ldir_ord: u8,
    pub ldir_name1: [u16; 5],     // UCS-2 characters 1-5
    pub ldir_attr: u8,            // Always ATTR_LONG_NAME
    pub ldir_type: u8,            // 0 for VFAT LFN
    pub ldir_chksum: u8,
    pub ldir_name2: [u16; 6],     // UCS-2 characters 6-11
    pub ldir_fst_clus_lo: u16,    // Always 0
    pub ldir_name3: [u16; 2],     // UCS-2 characters 12-13
}

// =============================================================================
// Filesystem State
// =============================================================================

pub type BlockReadFn = extern "C" fn(device_id: u32, sector: u64, count: u32, buffer: *mut u8) -> i32;
pub type BlockWriteFn = extern "C" fn(device_id: u32, sector: u64, count: u32, buffer: *const u8) -> i32;

/// FAT32 filesystem context
pub struct Fat32Fs {
    device_id: u32,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_sectors: u32,
    root_cluster: u32,
    total_sectors: u32,
    first_data_sector: u32,
    total_clusters: u32,
    read_sector: BlockReadFn,
    write_sector: Option<BlockWriteFn>,
}

/// Parsed directory entry with optional LFN
pub struct DirEntryInfo {
    pub short_name: [u8; 11],
    pub long_name: [u8; 256],
    pub long_name_len: usize,
    pub attr: u8,
    pub cluster: u32,
    pub size: u32,
    pub create_time: u16,
    pub create_date: u16,
    pub write_time: u16,
    pub write_date: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum Fat32Error {
    IoError,
    NotFat32,
    InvalidCluster,
    NotFound,
    NotADirectory,
    DiskFull,
    DirFull,
    ReadOnly,
    InvalidName,
    AlreadyExists,
    PathTooDeep,
}

const MAX_PATH_DEPTH: usize = 32;

impl Fat32Fs {
    /// Mount a FAT32 filesystem
    pub fn mount(
        device_id: u32,
        read_fn: BlockReadFn,
        write_fn: Option<BlockWriteFn>,
    ) -> Result<Self, Fat32Error> {
        let mut sector_buf = [0u8; SECTOR_SIZE];
        let result = read_fn(device_id, 0, 1, sector_buf.as_mut_ptr());
        if result != 0 {
            return Err(Fat32Error::IoError);
        }

        let bpb = unsafe { *(sector_buf.as_ptr() as *const Fat32Bpb) };

        // Validate: must be FAT32
        if bpb.bpb_fat_sz16 != 0 || bpb.bpb_root_ent_cnt != 0 {
            return Err(Fat32Error::NotFat32);
        }

        if bpb.bpb_bytes_per_sec == 0 || bpb.bpb_sec_per_clus == 0 {
            return Err(Fat32Error::NotFat32);
        }

        let root_dir_sectors = 0u32; // FAT32 has no fixed root dir
        let first_data_sector = bpb.bpb_rsvd_sec_cnt as u32
            + (bpb.bpb_num_fats as u32 * bpb.bpb_fat_sz32)
            + root_dir_sectors;

        let total_sectors = if bpb.bpb_tot_sec32 != 0 {
            bpb.bpb_tot_sec32
        } else {
            bpb.bpb_tot_sec16 as u32
        };

        let data_sectors = total_sectors - first_data_sector;
        let total_clusters = data_sectors / bpb.bpb_sec_per_clus as u32;

        // FAT32 requires >= 65525 clusters
        if total_clusters < 65525 {
            return Err(Fat32Error::NotFat32);
        }

        Ok(Fat32Fs {
            device_id,
            bytes_per_sector: bpb.bpb_bytes_per_sec,
            sectors_per_cluster: bpb.bpb_sec_per_clus,
            reserved_sectors: bpb.bpb_rsvd_sec_cnt,
            num_fats: bpb.bpb_num_fats,
            fat_size_sectors: bpb.bpb_fat_sz32,
            root_cluster: bpb.bpb_root_clus,
            total_sectors,
            first_data_sector,
            total_clusters,
            read_sector: read_fn,
            write_sector: write_fn,
        })
    }

    /// Convert a cluster number to its first sector
    fn cluster_to_sector(&self, cluster: u32) -> u32 {
        self.first_data_sector + (cluster - 2) * self.sectors_per_cluster as u32
    }

    /// Bytes per cluster
    fn cluster_size(&self) -> u32 {
        self.sectors_per_cluster as u32 * self.bytes_per_sector as u32
    }

    /// Read a single sector
    fn read_sector_data(&self, sector: u64, buf: &mut [u8]) -> Result<(), Fat32Error> {
        let result = (self.read_sector)(self.device_id, sector, 1, buf.as_mut_ptr());
        if result != 0 { Err(Fat32Error::IoError) } else { Ok(()) }
    }

    /// Write a single sector
    fn write_sector_data(&self, sector: u64, buf: &[u8]) -> Result<(), Fat32Error> {
        match self.write_sector {
            Some(write_fn) => {
                let result = write_fn(self.device_id, sector, 1, buf.as_ptr());
                if result != 0 { Err(Fat32Error::IoError) } else { Ok(()) }
            }
            None => Err(Fat32Error::ReadOnly),
        }
    }

    /// Read a FAT entry for a given cluster
    fn read_fat_entry(&self, cluster: u32) -> Result<u32, Fat32Error> {
        let fat_offset = cluster * 4;
        let fat_sector = self.reserved_sectors as u32 + (fat_offset / self.bytes_per_sector as u32);
        let fat_offset_in_sector = (fat_offset % self.bytes_per_sector as u32) as usize;

        let mut sector_buf = [0u8; SECTOR_SIZE];
        self.read_sector_data(fat_sector as u64, &mut sector_buf)?;

        let entry = u32::from_le_bytes([
            sector_buf[fat_offset_in_sector],
            sector_buf[fat_offset_in_sector + 1],
            sector_buf[fat_offset_in_sector + 2],
            sector_buf[fat_offset_in_sector + 3],
        ]) & FAT_ENTRY_MASK;

        Ok(entry)
    }

    /// Write a FAT entry (updates all FAT copies)
    fn write_fat_entry(&self, cluster: u32, value: u32) -> Result<(), Fat32Error> {
        let fat_offset = cluster * 4;
        let fat_sector = self.reserved_sectors as u32 + (fat_offset / self.bytes_per_sector as u32);
        let fat_offset_in_sector = (fat_offset % self.bytes_per_sector as u32) as usize;

        // Read-modify-write for each FAT copy
        for fat in 0..self.num_fats as u32 {
            let sector = fat_sector + fat * self.fat_size_sectors;
            let mut sector_buf = [0u8; SECTOR_SIZE];
            self.read_sector_data(sector as u64, &mut sector_buf)?;

            // Preserve high 4 bits
            let existing = u32::from_le_bytes([
                sector_buf[fat_offset_in_sector],
                sector_buf[fat_offset_in_sector + 1],
                sector_buf[fat_offset_in_sector + 2],
                sector_buf[fat_offset_in_sector + 3],
            ]);
            let new_entry = (existing & 0xF0000000) | (value & FAT_ENTRY_MASK);
            let bytes = new_entry.to_le_bytes();
            sector_buf[fat_offset_in_sector] = bytes[0];
            sector_buf[fat_offset_in_sector + 1] = bytes[1];
            sector_buf[fat_offset_in_sector + 2] = bytes[2];
            sector_buf[fat_offset_in_sector + 3] = bytes[3];

            self.write_sector_data(sector as u64, &sector_buf)?;
        }

        Ok(())
    }

    /// Find a free cluster in the FAT
    fn allocate_cluster(&self) -> Result<u32, Fat32Error> {
        for cluster in 2..self.total_clusters + 2 {
            let entry = self.read_fat_entry(cluster)?;
            if entry == FAT32_FREE {
                // Mark as end-of-chain
                self.write_fat_entry(cluster, FAT32_EOC)?;
                // Zero the cluster
                let sector = self.cluster_to_sector(cluster);
                let zero_buf = [0u8; SECTOR_SIZE];
                for s in 0..self.sectors_per_cluster as u32 {
                    self.write_sector_data((sector + s) as u64, &zero_buf)?;
                }
                return Ok(cluster);
            }
        }
        Err(Fat32Error::DiskFull)
    }

    /// Extend a cluster chain by appending a new cluster
    fn extend_chain(&self, last_cluster: u32) -> Result<u32, Fat32Error> {
        let new_cluster = self.allocate_cluster()?;
        self.write_fat_entry(last_cluster, new_cluster)?;
        Ok(new_cluster)
    }

    /// Follow the cluster chain and return the Nth cluster
    fn follow_chain(&self, start: u32, n: u32) -> Result<u32, Fat32Error> {
        let mut current = start;
        for _ in 0..n {
            let next = self.read_fat_entry(current)?;
            if next >= FAT32_EOC || next == FAT32_BAD {
                return Err(Fat32Error::InvalidCluster);
            }
            current = next;
        }
        Ok(current)
    }

    /// Read a full cluster into a buffer
    fn read_cluster(&self, cluster: u32, buf: &mut [u8]) -> Result<(), Fat32Error> {
        let sector = self.cluster_to_sector(cluster);
        let cluster_size = self.cluster_size() as usize;
        let mut offset = 0;

        for s in 0..self.sectors_per_cluster as u32 {
            let mut sector_buf = [0u8; SECTOR_SIZE];
            self.read_sector_data((sector + s) as u64, &mut sector_buf)?;
            let copy_len = SECTOR_SIZE.min(cluster_size - offset);
            buf[offset..offset + copy_len].copy_from_slice(&sector_buf[..copy_len]);
            offset += copy_len;
        }
        Ok(())
    }

    /// Read file data
    pub fn read_file(
        &self,
        start_cluster: u32,
        file_size: u32,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Fat32Error> {
        if start_cluster < 2 {
            return Ok(0);
        }
        if offset >= file_size as u64 {
            return Ok(0);
        }

        let cluster_size = self.cluster_size() as u64;
        let available = file_size as u64 - offset;
        let to_read = (buf.len() as u64).min(available) as usize;
        let mut bytes_read = 0;

        let start_cluster_index = (offset / cluster_size) as u32;
        let mut current_cluster = self.follow_chain(start_cluster, start_cluster_index)?;
        let mut cluster_offset = (offset % cluster_size) as usize;

        let mut cluster_buf = [0u8; 65536]; // Max cluster size (128 sectors * 512)

        while bytes_read < to_read {
            self.read_cluster(current_cluster, &mut cluster_buf[..cluster_size as usize])?;

            let chunk = (cluster_size as usize - cluster_offset).min(to_read - bytes_read);
            buf[bytes_read..bytes_read + chunk]
                .copy_from_slice(&cluster_buf[cluster_offset..cluster_offset + chunk]);
            bytes_read += chunk;
            cluster_offset = 0;

            if bytes_read < to_read {
                let next = self.read_fat_entry(current_cluster)?;
                if next >= FAT32_EOC {
                    break;
                }
                current_cluster = next;
            }
        }

        Ok(bytes_read)
    }

    /// Iterate directory entries in a cluster chain
    pub fn read_dir(
        &self,
        dir_cluster: u32,
        callback: &mut dyn FnMut(&Fat32DirEntry, &[u8], usize) -> bool,
    ) -> Result<(), Fat32Error> {
        let cluster_size = self.cluster_size() as usize;
        let mut current_cluster = dir_cluster;
        let mut cluster_buf = [0u8; 65536];

        // LFN accumulator
        let mut lfn_buf: [u8; 256] = [0; 256];
        let mut lfn_len: usize = 0;

        loop {
            self.read_cluster(current_cluster, &mut cluster_buf[..cluster_size])?;

            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;
            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let first_byte = cluster_buf[offset];

                if first_byte == LAST_ENTRY {
                    return Ok(());
                }
                if first_byte == DELETED_MARKER {
                    lfn_len = 0;
                    continue;
                }

                let attr = cluster_buf[offset + 11];

                if attr == ATTR_LONG_NAME {
                    // LFN entry
                    let lfn = unsafe {
                        *(cluster_buf[offset..].as_ptr() as *const Fat32LfnEntry)
                    };
                    let ord = lfn.ldir_ord & 0x3F;
                    let is_last = (lfn.ldir_ord & 0x40) != 0;

                    if is_last {
                        lfn_len = 0;
                        for b in lfn_buf.iter_mut() {
                            *b = 0;
                        }
                    }

                    // Extract UCS-2 characters and convert to ASCII (simplified)
                    let char_offset = ((ord as usize) - 1) * 13;
                    let chars: [u16; 13] = [
                        lfn.ldir_name1[0], lfn.ldir_name1[1], lfn.ldir_name1[2],
                        lfn.ldir_name1[3], lfn.ldir_name1[4],
                        lfn.ldir_name2[0], lfn.ldir_name2[1], lfn.ldir_name2[2],
                        lfn.ldir_name2[3], lfn.ldir_name2[4], lfn.ldir_name2[5],
                        lfn.ldir_name3[0], lfn.ldir_name3[1],
                    ];

                    for (j, &ch) in chars.iter().enumerate() {
                        if ch == 0x0000 || ch == 0xFFFF {
                            break;
                        }
                        let pos = char_offset + j;
                        if pos < 255 {
                            // Simple UCS-2 to ASCII (truncate to low byte)
                            lfn_buf[pos] = if ch < 128 { ch as u8 } else { b'?' };
                            if pos + 1 > lfn_len {
                                lfn_len = pos + 1;
                            }
                        }
                    }
                } else if (attr & ATTR_VOLUME_ID) == 0 {
                    // Short name entry (regular file or directory)
                    let entry = unsafe {
                        *(cluster_buf[offset..].as_ptr() as *const Fat32DirEntry)
                    };

                    let name = if lfn_len > 0 {
                        &lfn_buf[..lfn_len]
                    } else {
                        &entry.dir_name[..]
                    };

                    if !callback(&entry, name, lfn_len) {
                        return Ok(());
                    }

                    lfn_len = 0;
                }
            }

            // Follow FAT chain
            let next = self.read_fat_entry(current_cluster)?;
            if next >= FAT32_EOC || next == FAT32_BAD || next < 2 {
                break;
            }
            current_cluster = next;
        }

        Ok(())
    }

    /// Look up a file/directory by name in a directory cluster
    pub fn lookup(
        &self,
        dir_cluster: u32,
        name: &[u8],
    ) -> Result<(u32, u32, u8), Fat32Error> {
        let mut result: Option<(u32, u32, u8)> = None;

        self.read_dir(dir_cluster, &mut |entry, entry_name, lfn_len| {
            let matches = if lfn_len > 0 {
                // Compare with LFN (case-insensitive)
                if entry_name.len() != name.len() {
                    false
                } else {
                    let mut eq = true;
                    for i in 0..name.len() {
                        let a = to_upper(entry_name[i]);
                        let b = to_upper(name[i]);
                        if a != b {
                            eq = false;
                            break;
                        }
                    }
                    eq
                }
            } else {
                // Compare with 8.3 short name
                compare_short_name(&entry.dir_name, name)
            };

            if matches {
                let cluster = ((entry.dir_fst_clus_hi as u32) << 16) | entry.dir_fst_clus_lo as u32;
                result = Some((cluster, entry.dir_file_size, entry.dir_attr));
                return false;
            }
            true
        })?;

        result.ok_or(Fat32Error::NotFound)
    }

    /// Resolve a full path (e.g., "/DOCS/README.TXT") to (cluster, size, attr)
    pub fn resolve_path(&self, path: &[u8]) -> Result<(u32, u32, u8), Fat32Error> {
        let mut current_cluster = self.root_cluster;
        let mut current_size = 0u32;
        let mut current_attr = ATTR_DIRECTORY;
        let mut start = 0;

        while start < path.len() && path[start] == b'/' {
            start += 1;
        }

        if start >= path.len() {
            return Ok((self.root_cluster, 0, ATTR_DIRECTORY));
        }

        let mut depth = 0;

        while start < path.len() && depth < MAX_PATH_DEPTH {
            let mut end = start;
            while end < path.len() && path[end] != b'/' {
                end += 1;
            }

            if end > start {
                if (current_attr & ATTR_DIRECTORY) == 0 {
                    return Err(Fat32Error::NotADirectory);
                }

                let component = &path[start..end];
                let (cluster, size, attr) = self.lookup(current_cluster, component)?;
                current_cluster = cluster;
                current_size = size;
                current_attr = attr;
                depth += 1;
            }

            start = end + 1;
        }

        if depth >= MAX_PATH_DEPTH {
            return Err(Fat32Error::PathTooDeep);
        }

        Ok((current_cluster, current_size, current_attr))
    }

    /// Create a new file in a directory
    pub fn create_file_entry(
        &self,
        dir_cluster: u32,
        name: &[u8; 11],
        attr: u8,
    ) -> Result<u32, Fat32Error> {
        // Allocate a cluster for the new file
        let file_cluster = self.allocate_cluster()?;

        // Find a free directory entry
        let cluster_size = self.cluster_size() as usize;
        let mut current_cluster = dir_cluster;
        let mut cluster_buf = [0u8; 65536];

        loop {
            self.read_cluster(current_cluster, &mut cluster_buf[..cluster_size])?;
            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let first_byte = cluster_buf[offset];

                if first_byte == LAST_ENTRY || first_byte == DELETED_MARKER {
                    // Found a free slot — write the new entry
                    let mut entry = Fat32DirEntry {
                        dir_name: *name,
                        dir_attr: attr,
                        dir_nt_res: 0,
                        dir_crt_time_tenth: 0,
                        dir_crt_time: 0,
                        dir_crt_date: 0,
                        dir_lst_acc_date: 0,
                        dir_fst_clus_hi: (file_cluster >> 16) as u16,
                        dir_wrt_time: 0,
                        dir_wrt_date: 0,
                        dir_fst_clus_lo: file_cluster as u16,
                        dir_file_size: 0,
                    };

                    let entry_bytes = unsafe {
                        core::slice::from_raw_parts(
                            &entry as *const _ as *const u8,
                            DIR_ENTRY_SIZE,
                        )
                    };
                    cluster_buf[offset..offset + DIR_ENTRY_SIZE]
                        .copy_from_slice(entry_bytes);

                    // Mark next entry as last if we used the last marker
                    if first_byte == LAST_ENTRY && i + 1 < entries_per_cluster {
                        cluster_buf[offset + DIR_ENTRY_SIZE] = LAST_ENTRY;
                    }

                    // Write cluster back
                    let sector = self.cluster_to_sector(current_cluster);
                    let sectors = cluster_size / SECTOR_SIZE;
                    for s in 0..sectors {
                        let s_offset = s * SECTOR_SIZE;
                        self.write_sector_data(
                            (sector as u64) + s as u64,
                            &cluster_buf[s_offset..s_offset + SECTOR_SIZE],
                        )?;
                    }

                    return Ok(file_cluster);
                }
            }

            // Need another cluster for the directory
            let next = self.read_fat_entry(current_cluster)?;
            if next >= FAT32_EOC || next < 2 {
                // Extend directory
                current_cluster = self.extend_chain(current_cluster)?;
                // The newly allocated cluster is already zeroed
                return self.create_file_entry(current_cluster, name, attr);
            }
            current_cluster = next;
        }
    }

    /// Delete a file by marking its directory entry and FAT chain as free
    pub fn delete_file(&self, dir_cluster: u32, name: &[u8]) -> Result<(), Fat32Error> {
        let cluster_size = self.cluster_size() as usize;
        let mut current_cluster = dir_cluster;
        let mut cluster_buf = [0u8; 65536];

        loop {
            self.read_cluster(current_cluster, &mut cluster_buf[..cluster_size])?;
            let entries_per_cluster = cluster_size / DIR_ENTRY_SIZE;

            for i in 0..entries_per_cluster {
                let offset = i * DIR_ENTRY_SIZE;
                let first_byte = cluster_buf[offset];

                if first_byte == LAST_ENTRY {
                    return Err(Fat32Error::NotFound);
                }
                if first_byte == DELETED_MARKER {
                    continue;
                }

                let entry = unsafe {
                    *(cluster_buf[offset..].as_ptr() as *const Fat32DirEntry)
                };

                if compare_short_name(&entry.dir_name, name) {
                    // Free the cluster chain
                    let file_cluster = ((entry.dir_fst_clus_hi as u32) << 16)
                        | entry.dir_fst_clus_lo as u32;
                    if file_cluster >= 2 {
                        self.free_chain(file_cluster)?;
                    }

                    // Mark directory entry as deleted
                    cluster_buf[offset] = DELETED_MARKER;

                    let sector = self.cluster_to_sector(current_cluster);
                    let sectors = cluster_size / SECTOR_SIZE;
                    for s in 0..sectors {
                        let s_offset = s * SECTOR_SIZE;
                        self.write_sector_data(
                            (sector as u64) + s as u64,
                            &cluster_buf[s_offset..s_offset + SECTOR_SIZE],
                        )?;
                    }
                    return Ok(());
                }
            }

            let next = self.read_fat_entry(current_cluster)?;
            if next >= FAT32_EOC || next < 2 {
                break;
            }
            current_cluster = next;
        }

        Err(Fat32Error::NotFound)
    }

    /// Free an entire cluster chain
    fn free_chain(&self, start: u32) -> Result<(), Fat32Error> {
        let mut current = start;
        loop {
            let next = self.read_fat_entry(current)?;
            self.write_fat_entry(current, FAT32_FREE)?;
            if next >= FAT32_EOC || next == FAT32_BAD || next < 2 {
                break;
            }
            current = next;
        }
        Ok(())
    }

    /// Write data to a file (overwrites from beginning)
    pub fn write_file(
        &self,
        dir_cluster: u32,
        name: &[u8],
        data: &[u8],
    ) -> Result<usize, Fat32Error> {
        let (file_cluster, _, attr) = self.lookup(dir_cluster, name)?;

        if (attr & ATTR_DIRECTORY) != 0 {
            return Err(Fat32Error::NotADirectory);
        }

        let cluster_size = self.cluster_size() as usize;
        let mut written = 0;
        let mut current_cluster = file_cluster;
        let mut cluster_buf = [0u8; 65536];

        while written < data.len() {
            let chunk = (data.len() - written).min(cluster_size);

            // Zero the buffer and copy data
            for b in cluster_buf[..cluster_size].iter_mut() {
                *b = 0;
            }
            cluster_buf[..chunk].copy_from_slice(&data[written..written + chunk]);

            // Write cluster
            let sector = self.cluster_to_sector(current_cluster);
            let sectors = cluster_size / SECTOR_SIZE;
            for s in 0..sectors {
                let s_offset = s * SECTOR_SIZE;
                self.write_sector_data(
                    (sector as u64) + s as u64,
                    &cluster_buf[s_offset..s_offset + SECTOR_SIZE],
                )?;
            }

            written += chunk;

            if written < data.len() {
                let next = self.read_fat_entry(current_cluster)?;
                current_cluster = if next >= FAT32_EOC || next < 2 {
                    self.extend_chain(current_cluster)?
                } else {
                    next
                };
            }
        }

        // Update directory entry with new file size
        self.update_dir_entry_size(dir_cluster, name, data.len() as u32)?;

        Ok(written)
    }

    /// Update the file size in its directory entry
    fn update_dir_entry_size(
        &self,
        dir_cluster: u32,
        name: &[u8],
        new_size: u32,
    ) -> Result<(), Fat32Error> {
        let cluster_size = self.cluster_size() as usize;
        let mut current_cluster = dir_cluster;
        let mut cluster_buf = [0u8; 65536];

        loop {
            self.read_cluster(current_cluster, &mut cluster_buf[..cluster_size])?;
            let entries = cluster_size / DIR_ENTRY_SIZE;

            for i in 0..entries {
                let offset = i * DIR_ENTRY_SIZE;
                if cluster_buf[offset] == LAST_ENTRY {
                    return Err(Fat32Error::NotFound);
                }
                if cluster_buf[offset] == DELETED_MARKER {
                    continue;
                }

                let entry = unsafe {
                    *(cluster_buf[offset..].as_ptr() as *const Fat32DirEntry)
                };

                if compare_short_name(&entry.dir_name, name) {
                    // Update size
                    let size_bytes = new_size.to_le_bytes();
                    cluster_buf[offset + 28] = size_bytes[0];
                    cluster_buf[offset + 29] = size_bytes[1];
                    cluster_buf[offset + 30] = size_bytes[2];
                    cluster_buf[offset + 31] = size_bytes[3];

                    let sector = self.cluster_to_sector(current_cluster);
                    let sectors = cluster_size / SECTOR_SIZE;
                    for s in 0..sectors {
                        let s_offset = s * SECTOR_SIZE;
                        self.write_sector_data(
                            (sector as u64) + s as u64,
                            &cluster_buf[s_offset..s_offset + SECTOR_SIZE],
                        )?;
                    }
                    return Ok(());
                }
            }

            let next = self.read_fat_entry(current_cluster)?;
            if next >= FAT32_EOC || next < 2 {
                break;
            }
            current_cluster = next;
        }

        Err(Fat32Error::NotFound)
    }

    /// Get filesystem information
    pub fn get_info(&self) -> Fat32Info {
        Fat32Info {
            bytes_per_sector: self.bytes_per_sector,
            sectors_per_cluster: self.sectors_per_cluster,
            total_clusters: self.total_clusters,
            root_cluster: self.root_cluster,
            total_sectors: self.total_sectors,
            fat_size_sectors: self.fat_size_sectors,
            writable: self.write_sector.is_some(),
        }
    }
}

pub struct Fat32Info {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub total_clusters: u32,
    pub root_cluster: u32,
    pub total_sectors: u32,
    pub fat_size_sectors: u32,
    pub writable: bool,
}

// =============================================================================
// Helper Functions
// =============================================================================

fn to_upper(c: u8) -> u8 {
    if c >= b'a' && c <= b'z' { c - 32 } else { c }
}

/// Compare a FAT 8.3 name with a user-supplied name (case-insensitive)
fn compare_short_name(fat_name: &[u8; 11], name: &[u8]) -> bool {
    // Build the 8.3 name from user input for comparison
    let mut short = [b' '; 11];
    let mut dot_pos = None;

    for (i, &c) in name.iter().enumerate() {
        if c == b'.' {
            dot_pos = Some(i);
            break;
        }
    }

    match dot_pos {
        Some(dp) => {
            // Name part (up to 8 chars)
            for i in 0..dp.min(8) {
                short[i] = to_upper(name[i]);
            }
            // Extension part (up to 3 chars)
            let ext_start = dp + 1;
            for i in 0..(name.len() - ext_start).min(3) {
                short[8 + i] = to_upper(name[ext_start + i]);
            }
        }
        None => {
            for i in 0..name.len().min(8) {
                short[i] = to_upper(name[i]);
            }
        }
    }

    for i in 0..11 {
        if to_upper(fat_name[i]) != short[i] {
            return false;
        }
    }
    true
}

// =============================================================================
// C FFI for Zig kernel
// =============================================================================

static mut FAT32_INSTANCES: [Option<Fat32Fs>; 4] = [None, None, None, None];

/// Mount a FAT32 filesystem; returns handle (0-3) or -1
#[no_mangle]
pub extern "C" fn fat32_mount(
    device_id: u32,
    read_fn: BlockReadFn,
    write_fn: BlockWriteFn,
) -> i32 {
    let fs = match Fat32Fs::mount(device_id, read_fn, Some(write_fn)) {
        Ok(fs) => fs,
        Err(_) => return -1,
    };

    unsafe {
        for i in 0..4 {
            if FAT32_INSTANCES[i].is_none() {
                FAT32_INSTANCES[i] = Some(fs);
                return i as i32;
            }
        }
    }
    -1
}

/// Read-only mount
#[no_mangle]
pub extern "C" fn fat32_mount_ro(device_id: u32, read_fn: BlockReadFn) -> i32 {
    let fs = match Fat32Fs::mount(device_id, read_fn, None) {
        Ok(fs) => fs,
        Err(_) => return -1,
    };

    unsafe {
        for i in 0..4 {
            if FAT32_INSTANCES[i].is_none() {
                FAT32_INSTANCES[i] = Some(fs);
                return i as i32;
            }
        }
    }
    -1
}

/// Unmount
#[no_mangle]
pub extern "C" fn fat32_unmount(handle: i32) {
    if handle >= 0 && (handle as usize) < 4 {
        unsafe {
            FAT32_INSTANCES[handle as usize] = None;
        }
    }
}

/// Read file data; returns bytes read or -1
#[no_mangle]
pub extern "C" fn fat32_read(
    handle: i32,
    cluster: u32,
    file_size: u32,
    offset: u64,
    buf: *mut u8,
    buf_len: usize,
) -> i64 {
    if handle < 0 || (handle as usize) >= 4 || buf.is_null() {
        return -1;
    }
    unsafe {
        match &FAT32_INSTANCES[handle as usize] {
            Some(fs) => {
                let out = core::slice::from_raw_parts_mut(buf, buf_len);
                match fs.read_file(cluster, file_size, offset, out) {
                    Ok(n) => n as i64,
                    Err(_) => -1,
                }
            }
            None => -1,
        }
    }
}

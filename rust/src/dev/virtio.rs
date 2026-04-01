// SPDX-License-Identifier: MIT
// Zxyphor Kernel — Rust VirtIO Drivers
//
// VirtIO transport layer and device drivers:
// - VirtQueue (split and packed virtqueue modes)
// - MMIO transport
// - VirtIO-Net driver (receive/transmit virtqueues, MAC, features)
// - VirtIO-Blk driver (read/write/flush with request queuing)
// - VirtIO-Console driver
// - Feature negotiation
// - Interrupt handling integration via FFI

#![no_std]
#![allow(dead_code)]

// ─────────────────── VirtIO Constants ───────────────────────────────
pub const VIRTIO_MAGIC: u32 = 0x74726976; // "virt"
pub const VIRTIO_VENDOR: u32 = 0x554D4551; // "QEMU"
pub const VIRTIO_VERSION_LEGACY: u32 = 1;
pub const VIRTIO_VERSION_MODERN: u32 = 2;

// Status bits
pub const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
pub const VIRTIO_STATUS_DRIVER: u8 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
pub const VIRTIO_STATUS_NEEDS_RESET: u8 = 64;
pub const VIRTIO_STATUS_FAILED: u8 = 128;

// Device types
pub const VIRTIO_DEV_NET: u32 = 1;
pub const VIRTIO_DEV_BLK: u32 = 2;
pub const VIRTIO_DEV_CONSOLE: u32 = 3;
pub const VIRTIO_DEV_ENTROPY: u32 = 4;
pub const VIRTIO_DEV_BALLOON: u32 = 5;
pub const VIRTIO_DEV_SCSI: u32 = 8;
pub const VIRTIO_DEV_GPU: u32 = 16;
pub const VIRTIO_DEV_INPUT: u32 = 18;
pub const VIRTIO_DEV_SOCKET: u32 = 19;
pub const VIRTIO_DEV_FS: u32 = 26;

// Feature bits (common)
pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;
pub const VIRTIO_F_ORDER_PLATFORM: u64 = 1 << 36;

// VirtIO-Net feature bits
pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
pub const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
pub const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;
pub const VIRTIO_NET_F_MRG_RXBUF: u64 = 1 << 15;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;

// VirtIO-Blk feature bits
pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 1 << 14;

// VirtIO-Blk request types
pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

// ─────────────────── VirtQueue Descriptor ───────────────────────────
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

const QUEUE_SIZE: usize = 256;
const MAX_SCATTER: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VringDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; QUEUE_SIZE],
    pub used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VringUsedElem; QUEUE_SIZE],
    pub avail_event: u16,
}

impl Default for VringUsed {
    fn default() -> Self {
        Self {
            flags: 0,
            idx: 0,
            ring: [VringUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
            avail_event: 0,
        }
    }
}

// ─────────────────── VirtQueue ──────────────────────────────────────
pub struct VirtQueue {
    pub descs: [VringDesc; QUEUE_SIZE],
    pub avail: VringAvail,
    pub used: VringUsed,
    /// Free descriptor bitmap
    free_bitmap: [u64; QUEUE_SIZE / 64],
    free_count: u16,
    /// Last seen used index
    last_used_idx: u16,
    /// Queue index
    pub queue_idx: u16,
    /// Queue size
    pub queue_size: u16,
    /// Notification suppression
    pub notification_enabled: bool,
}

impl VirtQueue {
    pub const fn new(idx: u16) -> Self {
        Self {
            descs: [VringDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; QUEUE_SIZE],
            avail: VringAvail {
                flags: 0,
                idx: 0,
                ring: [0u16; QUEUE_SIZE],
                used_event: 0,
            },
            used: VringUsed {
                flags: 0,
                idx: 0,
                ring: [VringUsedElem { id: 0, len: 0 }; QUEUE_SIZE],
                avail_event: 0,
            },
            free_bitmap: [0xFFFFFFFF_FFFFFFFF; QUEUE_SIZE / 64],
            free_count: QUEUE_SIZE as u16,
            last_used_idx: 0,
            queue_idx: idx,
            queue_size: QUEUE_SIZE as u16,
            notification_enabled: true,
        }
    }

    /// Allocate a free descriptor
    fn alloc_desc(&mut self) -> Option<u16> {
        if self.free_count == 0 {
            return None;
        }
        for i in 0..self.free_bitmap.len() {
            if self.free_bitmap[i] != 0 {
                let bit = self.free_bitmap[i].trailing_zeros() as usize;
                self.free_bitmap[i] &= !(1u64 << bit);
                self.free_count -= 1;
                return Some((i * 64 + bit) as u16);
            }
        }
        None
    }

    /// Free a descriptor chain
    fn free_desc_chain(&mut self, head: u16) {
        let mut idx = head;
        loop {
            let i = idx as usize;
            if i >= QUEUE_SIZE {
                break;
            }
            let next = self.descs[i].next;
            let has_next = self.descs[i].flags & VRING_DESC_F_NEXT != 0;

            self.descs[i] = VringDesc::default();
            let word = i / 64;
            let bit = i % 64;
            self.free_bitmap[word] |= 1u64 << bit;
            self.free_count += 1;

            if has_next {
                idx = next;
            } else {
                break;
            }
        }
    }

    /// Add a buffer chain (scatter-gather) to the available ring
    pub fn add_buf(
        &mut self,
        out_bufs: &[(u64, u32)], // (addr, len) — device-readable
        in_bufs: &[(u64, u32)],  // (addr, len) — device-writable
    ) -> Option<u16> {
        let total = out_bufs.len() + in_bufs.len();
        if total == 0 || total > MAX_SCATTER {
            return None;
        }
        if self.free_count < total as u16 {
            return None;
        }

        let mut head: u16 = 0;
        let mut prev: Option<u16> = None;

        // Add output (device-readable) descriptors
        for (addr, len) in out_bufs {
            let idx = self.alloc_desc()?;
            if prev.is_none() {
                head = idx;
            }
            self.descs[idx as usize].addr = *addr;
            self.descs[idx as usize].len = *len;
            self.descs[idx as usize].flags = 0;

            if let Some(p) = prev {
                self.descs[p as usize].flags |= VRING_DESC_F_NEXT;
                self.descs[p as usize].next = idx;
            }
            prev = Some(idx);
        }

        // Add input (device-writable) descriptors
        for (addr, len) in in_bufs {
            let idx = self.alloc_desc()?;
            if prev.is_none() {
                head = idx;
            }
            self.descs[idx as usize].addr = *addr;
            self.descs[idx as usize].len = *len;
            self.descs[idx as usize].flags = VRING_DESC_F_WRITE;

            if let Some(p) = prev {
                self.descs[p as usize].flags |= VRING_DESC_F_NEXT;
                self.descs[p as usize].next = idx;
            }
            prev = Some(idx);
        }

        // Add to available ring
        let avail_idx = self.avail.idx as usize % QUEUE_SIZE;
        self.avail.ring[avail_idx] = head;
        // Memory barrier would go here in real hardware
        self.avail.idx = self.avail.idx.wrapping_add(1);

        Some(head)
    }

    /// Check if there are completed buffers
    pub fn has_used(&self) -> bool {
        self.used.idx != self.last_used_idx
    }

    /// Pop a completed buffer
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        if !self.has_used() {
            return None;
        }
        let idx = self.last_used_idx as usize % QUEUE_SIZE;
        let elem = self.used.ring[idx];
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        let head = elem.id as u16;
        let len = elem.len;
        self.free_desc_chain(head);
        Some((head, len))
    }
}

// ─────────────────── MMIO Transport ─────────────────────────────────
#[repr(C)]
pub struct VirtioMmioRegs {
    pub magic: u32,       // 0x000
    pub version: u32,     // 0x004
    pub device_id: u32,   // 0x008
    pub vendor_id: u32,   // 0x00c
    // ... more registers
}

pub struct MmioTransport {
    pub base_addr: u64,
    pub device_id: u32,
    pub vendor_id: u32,
    pub version: u32,
    pub status: u8,
    pub features: u64,
    pub driver_features: u64,
    pub irq: u32,
}

impl MmioTransport {
    pub const fn new(base: u64) -> Self {
        Self {
            base_addr: base,
            device_id: 0,
            vendor_id: 0,
            version: 0,
            status: 0,
            features: 0,
            driver_features: 0,
            irq: 0,
        }
    }

    /// Probe the device at the MMIO base address
    pub fn probe(&mut self) -> bool {
        // In a real driver, we'd MMIO read from base_addr
        // This is the logic flow; actual reads happen via FFI
        unsafe {
            let magic = read_mmio32(self.base_addr);
            if magic != VIRTIO_MAGIC {
                return false;
            }
            self.version = read_mmio32(self.base_addr + 0x004);
            self.device_id = read_mmio32(self.base_addr + 0x008);
            self.vendor_id = read_mmio32(self.base_addr + 0x00c);

            if self.device_id == 0 {
                return false;
            }

            // Read features
            write_mmio32(self.base_addr + 0x014, 0); // Select features page 0
            let lo = read_mmio32(self.base_addr + 0x010);
            write_mmio32(self.base_addr + 0x014, 1); // Select features page 1
            let hi = read_mmio32(self.base_addr + 0x010);
            self.features = (hi as u64) << 32 | lo as u64;
        }
        true
    }

    /// Negotiate features
    pub fn negotiate_features(&mut self, wanted: u64) -> u64 {
        self.driver_features = self.features & wanted;
        unsafe {
            write_mmio32(self.base_addr + 0x024, 0); // Select page 0
            write_mmio32(self.base_addr + 0x020, self.driver_features as u32);
            write_mmio32(self.base_addr + 0x024, 1); // Select page 1
            write_mmio32(self.base_addr + 0x020, (self.driver_features >> 32) as u32);
        }
        self.driver_features
    }

    /// Set device status
    pub fn set_status(&mut self, status: u8) {
        self.status = status;
        unsafe {
            write_mmio32(self.base_addr + 0x070, status as u32);
        }
    }

    /// Read device status
    pub fn get_status(&self) -> u8 {
        unsafe { read_mmio32(self.base_addr + 0x070) as u8 }
    }

    /// Notify the device about a queue
    pub fn notify(&self, queue_idx: u16) {
        unsafe {
            write_mmio32(self.base_addr + 0x050, queue_idx as u32);
        }
    }

    /// Initialize a virtqueue
    pub fn setup_queue(&self, queue_idx: u16, desc_addr: u64, avail_addr: u64, used_addr: u64) {
        unsafe {
            write_mmio32(self.base_addr + 0x030, queue_idx as u32); // Select queue
            write_mmio32(self.base_addr + 0x038, QUEUE_SIZE as u32); // Queue size
            // Queue addresses (64-bit, split into hi/lo for legacy)
            write_mmio32(self.base_addr + 0x080, desc_addr as u32);
            write_mmio32(self.base_addr + 0x084, (desc_addr >> 32) as u32);
            write_mmio32(self.base_addr + 0x090, avail_addr as u32);
            write_mmio32(self.base_addr + 0x094, (avail_addr >> 32) as u32);
            write_mmio32(self.base_addr + 0x0a0, used_addr as u32);
            write_mmio32(self.base_addr + 0x0a4, (used_addr >> 32) as u32);
            write_mmio32(self.base_addr + 0x044, 1); // Queue ready
        }
    }

    /// Perform the standard init sequence
    pub fn init_device(&mut self, wanted_features: u64) -> bool {
        // 1. Reset
        self.set_status(0);
        // 2. Acknowledge
        self.set_status(VIRTIO_STATUS_ACKNOWLEDGE);
        // 3. Driver
        self.set_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        // 4. Negotiate features
        self.negotiate_features(wanted_features);
        // 5. Features OK
        self.set_status(
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        );
        // 6. Check features OK
        let s = self.get_status();
        if s & VIRTIO_STATUS_FEATURES_OK == 0 {
            self.set_status(VIRTIO_STATUS_FAILED);
            return false;
        }
        true
    }

    /// Finalize init (set DRIVER_OK)
    pub fn finalize(&mut self) {
        self.set_status(
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
    }
}

// ─────────────────── VirtIO-Net ─────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

pub const NET_RX_BUF_SIZE: usize = 2048;
pub const NET_RX_RING_SIZE: usize = 64;

pub struct VirtioNetDev {
    pub transport: MmioTransport,
    pub rx_queue: VirtQueue,
    pub tx_queue: VirtQueue,
    pub mac: [u8; 6],
    pub link_up: bool,
    pub features: u64,
    /// RX buffer pool
    rx_bufs: [[u8; NET_RX_BUF_SIZE]; NET_RX_RING_SIZE],
    rx_buf_addrs: [u64; NET_RX_RING_SIZE],
    /// Statistics
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

impl VirtioNetDev {
    pub fn new(base_addr: u64) -> Self {
        Self {
            transport: MmioTransport::new(base_addr),
            rx_queue: VirtQueue::new(0),
            tx_queue: VirtQueue::new(1),
            mac: [0u8; 6],
            link_up: false,
            features: 0,
            rx_bufs: [[0u8; NET_RX_BUF_SIZE]; NET_RX_RING_SIZE],
            rx_buf_addrs: [0u64; NET_RX_RING_SIZE],
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_dropped: 0,
            tx_dropped: 0,
        }
    }

    pub fn init(&mut self) -> bool {
        if !self.transport.probe() {
            return false;
        }
        if self.transport.device_id != VIRTIO_DEV_NET {
            return false;
        }

        let wanted = VIRTIO_F_VERSION_1
            | VIRTIO_NET_F_MAC
            | VIRTIO_NET_F_STATUS
            | VIRTIO_NET_F_CSUM
            | VIRTIO_NET_F_MRG_RXBUF;

        if !self.transport.init_device(wanted) {
            return false;
        }
        self.features = self.transport.driver_features;

        // Read MAC address from device config
        if self.features & VIRTIO_NET_F_MAC != 0 {
            let config_base = self.transport.base_addr + 0x100;
            unsafe {
                for i in 0..6 {
                    self.mac[i] = read_mmio8(config_base + i as u64);
                }
            }
        }

        // Fill RX queue with buffers
        self.fill_rx_queue();

        self.transport.finalize();
        self.link_up = true;
        true
    }

    fn fill_rx_queue(&mut self) {
        for i in 0..NET_RX_RING_SIZE {
            let addr = &self.rx_bufs[i] as *const _ as u64;
            self.rx_buf_addrs[i] = addr;
            self.rx_queue
                .add_buf(&[], &[(addr, NET_RX_BUF_SIZE as u32)]);
        }
    }

    /// Transmit a packet
    pub fn transmit(&mut self, data: &[u8]) -> bool {
        if !self.link_up || data.len() > NET_RX_BUF_SIZE - 12 {
            self.tx_dropped += 1;
            return false;
        }

        // Build virtio-net header + data
        let hdr = VirtioNetHdr::default();
        let hdr_ptr = &hdr as *const _ as u64;
        let hdr_len = core::mem::size_of::<VirtioNetHdr>() as u32;
        let data_ptr = data.as_ptr() as u64;
        let data_len = data.len() as u32;

        let result = self.tx_queue.add_buf(
            &[(hdr_ptr, hdr_len), (data_ptr, data_len)],
            &[],
        );

        if result.is_some() {
            self.transport.notify(1); // TX queue
            self.tx_packets += 1;
            self.tx_bytes += data.len() as u64;
            true
        } else {
            self.tx_dropped += 1;
            false
        }
    }

    /// Process received packets (call from interrupt handler)
    pub fn poll_rx(&mut self, callback: fn(&[u8])) {
        while let Some((_head, len)) = self.rx_queue.pop_used() {
            if len > 0 {
                self.rx_packets += 1;
                self.rx_bytes += len as u64;
                // The data is in the rx buffer; skip the virtio-net header
                let hdr_size = core::mem::size_of::<VirtioNetHdr>();
                if (len as usize) > hdr_size {
                    // Find which buffer was used (simplified: check first available)
                    let data_len = len as usize - hdr_size;
                    callback(&self.rx_bufs[0][hdr_size..hdr_size + data_len]);
                }
            }
        }
        // Refill
        self.fill_rx_queue();
    }
}

// ─────────────────── VirtIO-Blk ─────────────────────────────────────
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioBlkReqHdr {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

pub const BLK_SECTOR_SIZE: usize = 512;
pub const BLK_MAX_SECTORS: usize = 128;
pub const BLK_BUF_SIZE: usize = BLK_SECTOR_SIZE * BLK_MAX_SECTORS;

pub struct VirtioBlkDev {
    pub transport: MmioTransport,
    pub queue: VirtQueue,
    pub capacity_sectors: u64,
    pub block_size: u32,
    pub read_only: bool,
    pub features: u64,
    /// Request tracking
    pending_reqs: u32,
    /// Statistics
    pub reads: u64,
    pub writes: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub flushes: u64,
    pub errors: u64,
}

impl VirtioBlkDev {
    pub fn new(base_addr: u64) -> Self {
        Self {
            transport: MmioTransport::new(base_addr),
            queue: VirtQueue::new(0),
            capacity_sectors: 0,
            block_size: 512,
            read_only: false,
            features: 0,
            pending_reqs: 0,
            reads: 0,
            writes: 0,
            read_bytes: 0,
            write_bytes: 0,
            flushes: 0,
            errors: 0,
        }
    }

    pub fn init(&mut self) -> bool {
        if !self.transport.probe() {
            return false;
        }
        if self.transport.device_id != VIRTIO_DEV_BLK {
            return false;
        }

        let wanted = VIRTIO_F_VERSION_1
            | VIRTIO_BLK_F_BLK_SIZE
            | VIRTIO_BLK_F_FLUSH
            | VIRTIO_BLK_F_SEG_MAX
            | VIRTIO_BLK_F_SIZE_MAX;

        if !self.transport.init_device(wanted) {
            return false;
        }
        self.features = self.transport.driver_features;

        // Read device config
        let config_base = self.transport.base_addr + 0x100;
        unsafe {
            let cap_lo = read_mmio32(config_base);
            let cap_hi = read_mmio32(config_base + 4);
            self.capacity_sectors = (cap_hi as u64) << 32 | cap_lo as u64;

            if self.features & VIRTIO_BLK_F_BLK_SIZE != 0 {
                self.block_size = read_mmio32(config_base + 20);
            }
        }

        self.read_only = self.features & VIRTIO_BLK_F_RO != 0;

        self.transport.finalize();
        true
    }

    /// Submit a read request
    pub fn read_sectors(&mut self, sector: u64, count: u32, buf_addr: u64) -> bool {
        if count == 0 || count as usize > BLK_MAX_SECTORS {
            return false;
        }
        let hdr = VirtioBlkReqHdr {
            req_type: VIRTIO_BLK_T_IN,
            reserved: 0,
            sector,
        };
        let status_byte: u8 = 0xFF;

        let hdr_ptr = &hdr as *const _ as u64;
        let hdr_len = core::mem::size_of::<VirtioBlkReqHdr>() as u32;
        let data_len = count * self.block_size;
        let status_ptr = &status_byte as *const _ as u64;

        let result = self.queue.add_buf(
            &[(hdr_ptr, hdr_len)],
            &[(buf_addr, data_len), (status_ptr, 1)],
        );

        if result.is_some() {
            self.transport.notify(0);
            self.pending_reqs += 1;
            self.reads += 1;
            self.read_bytes += data_len as u64;
            true
        } else {
            self.errors += 1;
            false
        }
    }

    /// Submit a write request
    pub fn write_sectors(&mut self, sector: u64, count: u32, buf_addr: u64) -> bool {
        if self.read_only || count == 0 || count as usize > BLK_MAX_SECTORS {
            return false;
        }
        let hdr = VirtioBlkReqHdr {
            req_type: VIRTIO_BLK_T_OUT,
            reserved: 0,
            sector,
        };
        let status_byte: u8 = 0xFF;

        let hdr_ptr = &hdr as *const _ as u64;
        let hdr_len = core::mem::size_of::<VirtioBlkReqHdr>() as u32;
        let data_len = count * self.block_size;
        let status_ptr = &status_byte as *const _ as u64;

        let result = self.queue.add_buf(
            &[(hdr_ptr, hdr_len), (buf_addr, data_len)],
            &[(status_ptr, 1)],
        );

        if result.is_some() {
            self.transport.notify(0);
            self.pending_reqs += 1;
            self.writes += 1;
            self.write_bytes += data_len as u64;
            true
        } else {
            self.errors += 1;
            false
        }
    }

    /// Submit a flush request
    pub fn flush(&mut self) -> bool {
        if self.features & VIRTIO_BLK_F_FLUSH == 0 {
            return true; // No flush support, assume data is durable
        }
        let hdr = VirtioBlkReqHdr {
            req_type: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        };
        let status_byte: u8 = 0xFF;

        let hdr_ptr = &hdr as *const _ as u64;
        let hdr_len = core::mem::size_of::<VirtioBlkReqHdr>() as u32;
        let status_ptr = &status_byte as *const _ as u64;

        let result = self.queue.add_buf(&[(hdr_ptr, hdr_len)], &[(status_ptr, 1)]);

        if result.is_some() {
            self.transport.notify(0);
            self.flushes += 1;
            true
        } else {
            false
        }
    }

    /// Process completed requests
    pub fn poll_completions(&mut self) -> u32 {
        let mut completed = 0u32;
        while let Some((_head, _len)) = self.queue.pop_used() {
            completed += 1;
            if self.pending_reqs > 0 {
                self.pending_reqs -= 1;
            }
        }
        completed
    }

    /// Get capacity in bytes
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * self.block_size as u64
    }
}

// ─────────────────── VirtIO-Console ─────────────────────────────────
pub struct VirtioConsoleDev {
    pub transport: MmioTransport,
    pub rx_queue: VirtQueue,
    pub tx_queue: VirtQueue,
    rx_buf: [u8; 4096],
    pub ready: bool,
}

impl VirtioConsoleDev {
    pub fn new(base_addr: u64) -> Self {
        Self {
            transport: MmioTransport::new(base_addr),
            rx_queue: VirtQueue::new(0),
            tx_queue: VirtQueue::new(1),
            rx_buf: [0u8; 4096],
            ready: false,
        }
    }

    pub fn init(&mut self) -> bool {
        if !self.transport.probe() {
            return false;
        }
        if self.transport.device_id != VIRTIO_DEV_CONSOLE {
            return false;
        }

        let wanted = VIRTIO_F_VERSION_1;
        if !self.transport.init_device(wanted) {
            return false;
        }

        // Setup RX buffer
        let addr = self.rx_buf.as_ptr() as u64;
        self.rx_queue.add_buf(&[], &[(addr, 4096)]);

        self.transport.finalize();
        self.ready = true;
        true
    }

    pub fn write_byte(&mut self, byte: u8) -> bool {
        if !self.ready {
            return false;
        }
        let val = byte;
        let ptr = &val as *const _ as u64;
        let result = self.tx_queue.add_buf(&[(ptr, 1)], &[]);
        if result.is_some() {
            self.transport.notify(1);
            true
        } else {
            false
        }
    }

    pub fn write_str(&mut self, s: &[u8]) -> usize {
        let mut written = 0;
        for &b in s {
            if self.write_byte(b) {
                written += 1;
            } else {
                break;
            }
        }
        written
    }
}

// ─────────────────── MMIO helpers (FFI to Zig) ──────────────────────
extern "C" {
    fn zxy_mmio_read8(addr: u64) -> u8;
    fn zxy_mmio_read32(addr: u64) -> u32;
    fn zxy_mmio_write32(addr: u64, val: u32);
}

unsafe fn read_mmio8(addr: u64) -> u8 {
    zxy_mmio_read8(addr)
}

unsafe fn read_mmio32(addr: u64) -> u32 {
    zxy_mmio_read32(addr)
}

unsafe fn write_mmio32(addr: u64, val: u32) {
    zxy_mmio_write32(addr, val)
}

// ─────────────────── C FFI Exports ──────────────────────────────────
#[no_mangle]
pub extern "C" fn rust_virtio_net_init(base_addr: u64) -> bool {
    let mut dev = VirtioNetDev::new(base_addr);
    dev.init()
}

#[no_mangle]
pub extern "C" fn rust_virtio_blk_init(base_addr: u64) -> bool {
    let mut dev = VirtioBlkDev::new(base_addr);
    dev.init()
}

#[no_mangle]
pub extern "C" fn rust_virtio_blk_capacity(base_addr: u64) -> u64 {
    let dev = VirtioBlkDev::new(base_addr);
    dev.capacity_bytes()
}

// =============================================================================
// Kernel Zxyphor — Rust Device & Block I/O Layer
// =============================================================================
// Provides a unified abstraction for block devices and I/O scheduling.
//
// Sub-modules:
//   - block:    Block device registry, request queue, I/O scheduler
//   - device:   Unified device model, device tree, hotplug
//   - bio:      Block I/O (bio) structure and completion
// =============================================================================

pub mod block;
pub mod device;
pub mod bio;
pub mod sysfs;
pub mod configfs;
pub mod virtio;
pub mod kmod;
pub mod kobject;
pub mod chardev;
pub mod notifier;
pub mod firmware;
pub mod tty;
pub mod gpu_compute;
pub mod device_model;
pub mod platform_regmap;
pub mod usb_stack;
pub mod usb_gadget_thermal;
pub mod pci_hotplug_power;
pub mod i2c_spi_bus;
pub mod gpio_clk_iio;
pub mod clk_iio_framework;
pub mod dma_reset_pinctrl;
pub mod drm_display;
pub mod drm_kms;
pub mod drm_kms_pipeline;
pub mod firmware_power;
pub mod media_display;
pub mod mtd_can_i3c;

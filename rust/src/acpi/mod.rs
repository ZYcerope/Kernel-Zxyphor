// =============================================================================
// Kernel Zxyphor — Rust ACPI Table Parser
// =============================================================================
// Advanced Configuration and Power Interface table parsing:
//   - RSDP (Root System Description Pointer) detection
//   - RSDT / XSDT parsing
//   - MADT (Multiple APIC Description Table)
//   - FADT (Fixed ACPI Description Table)
//   - MCFG (PCI Express Memory-mapped Configuration)
//   - HPET table
//   - DMAR (DMA Remapping) for IOMMU
//   - SRAT (System Resource Affinity Table) for NUMA
//   - DSDT/SSDT (not AML interpretation, just table location)
//   - Generic table discovery and validation
// =============================================================================

pub mod tables;
pub mod madt;
pub mod fadt;

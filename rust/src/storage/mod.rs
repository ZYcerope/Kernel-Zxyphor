// =============================================================================
// Kernel Zxyphor — Storage Driver Abstraction Layer
// =============================================================================
// Unified storage driver interface:
//   - Storage device trait abstraction
//   - Partition table parsing (MBR + GPT) with CRC32 validation
//   - I/O scheduler with deadline + CFQ policies
//   - Write-back cache with dirty page tracking
//   - TRIM/discard support
//   - S.M.A.R.T. health monitoring
//   - Performance statistics and latency tracking
//   - Multi-queue block I/O dispatch
// =============================================================================

pub mod cache;
pub mod ioqueue;
pub mod partition;
pub mod smart;
pub mod raid;
pub mod pagecache;
pub mod dm;

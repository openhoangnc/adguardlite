//! Types shared across the adguardlite crates, all chosen to match the wire
//! and on-disk representations of AdGuard Home v0.107.79.

pub mod bytesize;
pub mod duration;
pub mod gotime;
pub mod name;
pub mod perms;
pub mod reason;
pub mod schedule;

pub use bytesize::ByteSize;
pub use duration::GoDuration;
pub use reason::{Reason, STATS_RESULT_COUNT, StatsResult};

/// The configuration schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 34;

/// The AdGuard Home version string this build reports.
pub const AGH_VERSION: &str = "v0.107.79";

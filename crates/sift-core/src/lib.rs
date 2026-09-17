//! Types shared across the sift crates, all chosen to match the wire
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

/// The version this build reports, over the API and in its startup log.
///
/// It is sift's own version, not AdGuard Home's: this is a separate
/// implementation with a separate release history, and reporting a v0.107.x
/// would claim to be a release it is not.  Compatibility with AdGuard Home is
/// pinned by `SCHEMA_VERSION` and by the formats each module documents, not by
/// this string.
pub const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// The AdGuard Home release whose config, on-disk data and API this build
/// reproduces.  Reported nowhere; recorded here because every compatibility
/// claim in the tree is measured against it.
pub const AGH_COMPAT_VERSION: &str = "v0.107.79";

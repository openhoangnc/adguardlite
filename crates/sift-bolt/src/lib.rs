//! A minimal reader and writer for Go's [bbolt] database files.
//!
//! Only what AdGuard Home's `stats.db` needs is implemented: a flat set of
//! top-level buckets, each holding a single key.  That shape lets the writer
//! build a whole file from scratch on every flush rather than managing page
//! allocation incrementally, which removes most of the format's complexity
//! while still producing a file the Go implementation reads.
//!
//! [bbolt]: https://github.com/etcd-io/bbolt

#![allow(clippy::missing_errors_doc)]

pub mod page;
pub mod read;
pub mod write;

pub use read::Db;
pub use write::write_file;

/// The magic number in a bbolt meta page.
pub const MAGIC: u32 = 0xED0C_DAED;

/// The file format version this supports.
pub const VERSION: u32 = 2;

/// The page size bbolt uses by default on the platforms AdGuard Home runs on.
pub const DEFAULT_PAGE_SIZE: usize = 4096;

/// A failure reading or writing a database.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file could not be read or written.
    #[error("bolt i/o: {0}")]
    Io(#[from] std::io::Error),

    /// The file is not a bbolt database.
    #[error("not a bolt database: {0}")]
    NotBolt(String),

    /// The file is structurally invalid.
    #[error("corrupt bolt database: {0}")]
    Corrupt(String),

    /// The file uses a feature this implementation does not support.
    #[error("unsupported bolt database: {0}")]
    Unsupported(String),
}

/// The result type this crate returns.
pub type Result<T> = std::result::Result<T, Error>;

/// Computes an FNV-1a 64-bit hash, which bbolt uses for meta checksums.
pub fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut h = OFFSET;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(PRIME);
    }

    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_matches_known_vectors() {
        // The canonical FNV-1a 64 test vectors.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    }
}

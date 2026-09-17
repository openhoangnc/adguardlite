//! A focused implementation of Go's `encoding/gob` for AdGuard Home's
//! statistics unit.
//!
//! This is not a general gob library.  It encodes and decodes exactly the
//! `unitDB` struct that `internal/stats` stores in `stats.db`, which is enough
//! to read a database written by the Go implementation and to write one it
//! accepts.
//!
//! Byte-identical output is not a goal, and would not be meaningful: Go's own
//! encoder does not reproduce its own bytes for the same value, because the
//! order in which it emits type definitions depends on how the types were
//! first walked.  What matters is that each side decodes the other's output.

pub mod codec;
pub mod unit;

pub use unit::{CountPair, UnitDb, decode_unit, encode_unit};

/// A failure encoding or decoding a gob stream.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The input ended in the middle of a value.
    #[error("gob stream truncated")]
    Truncated,

    /// The stream is structurally invalid.
    #[error("invalid gob stream: {0}")]
    Invalid(String),

    /// The stream describes a type this implementation does not handle.
    #[error("unsupported gob type: {0}")]
    Unsupported(String),
}

/// The result type this crate returns.
pub type Result<T> = std::result::Result<T, Error>;

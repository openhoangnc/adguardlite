//! Reading and writing `AdGuardHome.yaml` with byte-level fidelity to the Go
//! implementation.

pub mod file;
pub mod model;
pub mod types;
pub mod yaml;

pub use file::{load, save};
pub use model::Config;

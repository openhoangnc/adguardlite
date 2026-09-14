//! Go-`yaml.v3`-compatible reading and writing of the config document.

pub mod emit;
pub mod ser;
pub mod value;

pub use ser::{to_string, to_yaml};
pub use value::Yaml;

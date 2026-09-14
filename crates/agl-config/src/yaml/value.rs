//! An order-preserving YAML value tree.
//!
//! Field order in `AdGuardHome.yaml` is meaningful — upstream warns against
//! reordering — so maps keep insertion order rather than sorting.

/// A YAML node.
#[derive(Clone, Debug, PartialEq)]
pub enum Yaml {
    /// An explicit `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer that may exceed [`i64::MAX`].
    UInt(u64),
    /// A floating-point number.
    Float(f64),
    /// A string scalar.
    Str(String),
    /// A sequence.
    Seq(Vec<Yaml>),
    /// A mapping, in insertion order.
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    /// Reports whether the node is a scalar, i.e. renders on one line.
    pub fn is_scalar(&self) -> bool {
        !matches!(self, Yaml::Seq(_) | Yaml::Map(_))
    }

    /// Reports whether the node renders as an empty collection.
    pub fn is_empty_collection(&self) -> bool {
        match self {
            Yaml::Seq(v) => v.is_empty(),
            Yaml::Map(m) => m.is_empty(),
            _ => false,
        }
    }

    /// Looks a key up in a mapping.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

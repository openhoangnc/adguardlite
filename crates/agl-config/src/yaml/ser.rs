//! A `serde::Serializer` that builds a [`Yaml`] tree, preserving struct field
//! declaration order so the emitted config keeps upstream's key ordering.

use serde::ser::{self, Serialize};

use super::value::Yaml;

/// Serialisation failure.
#[derive(Debug, thiserror::Error)]
#[error("yaml serialize: {0}")]
pub struct Error(String);

impl ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

/// Serialises `value` into a [`Yaml`] tree.
pub fn to_yaml<T: Serialize>(value: &T) -> Result<Yaml, Error> {
    value.serialize(Serializer)
}

/// Serialises `value` into a Go-`yaml.v3`-styled document.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, Error> {
    Ok(super::emit::to_string(&to_yaml(value)?))
}

/// The serializer itself; it is stateless and builds values bottom-up.
pub struct Serializer;

impl ser::Serializer for Serializer {
    type Ok = Yaml;
    type Error = Error;

    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = SeqBuilder;
    type SerializeMap = MapBuilder;
    type SerializeStruct = MapBuilder;
    type SerializeStructVariant = MapBuilder;

    fn serialize_bool(self, v: bool) -> Result<Yaml, Error> {
        Ok(Yaml::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Yaml, Error> {
        Ok(Yaml::Int(v.into()))
    }

    fn serialize_i16(self, v: i16) -> Result<Yaml, Error> {
        Ok(Yaml::Int(v.into()))
    }

    fn serialize_i32(self, v: i32) -> Result<Yaml, Error> {
        Ok(Yaml::Int(v.into()))
    }

    fn serialize_i64(self, v: i64) -> Result<Yaml, Error> {
        Ok(Yaml::Int(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Yaml, Error> {
        Ok(Yaml::Int(v as i64))
    }

    fn serialize_u8(self, v: u8) -> Result<Yaml, Error> {
        Ok(Yaml::UInt(v.into()))
    }

    fn serialize_u16(self, v: u16) -> Result<Yaml, Error> {
        Ok(Yaml::UInt(v.into()))
    }

    fn serialize_u32(self, v: u32) -> Result<Yaml, Error> {
        Ok(Yaml::UInt(v.into()))
    }

    fn serialize_u64(self, v: u64) -> Result<Yaml, Error> {
        Ok(Yaml::UInt(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Yaml, Error> {
        Ok(Yaml::UInt(v as u64))
    }

    fn serialize_f32(self, v: f32) -> Result<Yaml, Error> {
        Ok(Yaml::Float(v.into()))
    }

    fn serialize_f64(self, v: f64) -> Result<Yaml, Error> {
        Ok(Yaml::Float(v))
    }

    fn serialize_char(self, v: char) -> Result<Yaml, Error> {
        Ok(Yaml::Str(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Yaml, Error> {
        Ok(Yaml::Str(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Yaml, Error> {
        Ok(Yaml::Seq(
            v.iter().map(|b| Yaml::UInt((*b).into())).collect(),
        ))
    }

    fn serialize_none(self) -> Result<Yaml, Error> {
        Ok(Yaml::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, v: &T) -> Result<Yaml, Error> {
        v.serialize(self)
    }

    fn serialize_unit(self) -> Result<Yaml, Error> {
        Ok(Yaml::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Yaml, Error> {
        Ok(Yaml::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
    ) -> Result<Yaml, Error> {
        Ok(Yaml::Str(variant.to_string()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        v: &T,
    ) -> Result<Yaml, Error> {
        v.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        v: &T,
    ) -> Result<Yaml, Error> {
        Ok(Yaml::Map(vec![(variant.to_string(), v.serialize(self)?)]))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqBuilder, Error> {
        Ok(SeqBuilder {
            items: Vec::with_capacity(len.unwrap_or(0)),
            variant: None,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SeqBuilder, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SeqBuilder, Error> {
        Ok(SeqBuilder {
            items: Vec::with_capacity(len),
            variant: Some(variant),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapBuilder, Error> {
        Ok(MapBuilder {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            pending_key: None,
            variant: None,
        })
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<MapBuilder, Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<MapBuilder, Error> {
        Ok(MapBuilder {
            entries: Vec::with_capacity(len),
            pending_key: None,
            variant: Some(variant),
        })
    }
}

/// Accumulates sequence items.
pub struct SeqBuilder {
    items: Vec<Yaml>,
    variant: Option<&'static str>,
}

impl SeqBuilder {
    /// Wraps the finished sequence in its variant map, if any.
    fn finish(self) -> Yaml {
        let seq = Yaml::Seq(self.items);
        match self.variant {
            Some(v) => Yaml::Map(vec![(v.to_string(), seq)]),
            None => seq,
        }
    }
}

impl ser::SerializeSeq for SeqBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        self.items.push(v.serialize(Serializer)?);

        Ok(())
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

impl ser::SerializeTuple for SeqBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, v)
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

impl ser::SerializeTupleStruct for SeqBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, v)
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

impl ser::SerializeTupleVariant for SeqBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        ser::SerializeSeq::serialize_element(self, v)
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

/// Accumulates mapping entries in insertion order.
pub struct MapBuilder {
    entries: Vec<(String, Yaml)>,
    pending_key: Option<String>,
    variant: Option<&'static str>,
}

impl MapBuilder {
    /// Wraps the finished map in its variant map, if any.
    fn finish(self) -> Yaml {
        let map = Yaml::Map(self.entries);
        match self.variant {
            Some(v) => Yaml::Map(vec![(v.to_string(), map)]),
            None => map,
        }
    }
}

impl ser::SerializeMap for MapBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, k: &T) -> Result<(), Error> {
        let key = match k.serialize(Serializer)? {
            Yaml::Str(s) => s,
            Yaml::Int(i) => i.to_string(),
            Yaml::UInt(u) => u.to_string(),
            Yaml::Bool(b) => b.to_string(),
            other => return Err(Error(format!("unsupported map key: {other:?}"))),
        };
        self.pending_key = Some(key);

        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, v: &T) -> Result<(), Error> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| Error("value serialized before key".into()))?;
        self.entries.push((key, v.serialize(Serializer)?));

        Ok(())
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

impl ser::SerializeStruct for MapBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        self.entries
            .push((key.to_string(), v.serialize(Serializer)?));

        Ok(())
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

impl ser::SerializeStructVariant for MapBuilder {
    type Ok = Yaml;
    type Error = Error;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        v: &T,
    ) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(self, key, v)
    }

    fn end(self) -> Result<Yaml, Error> {
        Ok(self.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Inner {
        port: u16,
        enabled: bool,
    }

    #[derive(serde::Serialize)]
    struct Outer {
        pprof: Inner,
        routes: Vec<String>,
        address: String,
        empty: Vec<String>,
        maybe: Option<u8>,
    }

    #[test]
    fn preserves_struct_field_order() {
        let o = Outer {
            pprof: Inner {
                port: 6060,
                enabled: false,
            },
            routes: vec!["GET /dns-query".into()],
            address: "127.0.0.1:13000".into(),
            empty: vec![],
            maybe: None,
        };

        assert_eq!(
            to_string(&o).unwrap(),
            "pprof:\n  port: 6060\n  enabled: false\nroutes:\n  - GET /dns-query\n\
             address: 127.0.0.1:13000\nempty: []\nmaybe: null\n"
        );
    }

    #[test]
    fn unit_variants_become_plain_strings() {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "snake_case")]
        enum Mode {
            LoadBalance,
        }

        assert_eq!(
            to_yaml(&Mode::LoadBalance).unwrap(),
            Yaml::Str("load_balance".into())
        );
    }
}

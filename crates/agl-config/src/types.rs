//! Scalar wrappers whose YAML/JSON shape matches the Go types they replace.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A `netip.Addr` that may be the zero value.
///
/// Go renders the zero address as an empty string, which is what the reference
/// config contains for `blocking_ipv4`, `custom_ip` and friends.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OptAddr(pub Option<IpAddr>);

impl OptAddr {
    /// Returns the address, if set.
    pub const fn get(self) -> Option<IpAddr> {
        self.0
    }

    /// Reports whether the address is the zero value.
    pub const fn is_unset(self) -> bool {
        self.0.is_none()
    }
}

impl From<IpAddr> for OptAddr {
    fn from(a: IpAddr) -> Self {
        Self(Some(a))
    }
}

impl fmt::Display for OptAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(a) => write!(f, "{a}"),
            None => Ok(()),
        }
    }
}

impl Serialize for OptAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OptAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = OptString::deserialize(d)?.0;
        match s.as_deref() {
            None | Some("") => Ok(OptAddr(None)),
            Some(v) => v
                .parse::<IpAddr>()
                .map(|a| OptAddr(Some(a)))
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Helper that accepts a string or an explicit null.
#[derive(Deserialize)]
struct OptString(Option<String>);

/// An IP network prefix, rendered as `127.0.0.0/8`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Prefix {
    /// The network address.
    pub addr: IpAddr,
    /// The prefix length in bits.
    pub bits: u8,
}

impl Prefix {
    /// Reports whether `ip` falls inside the prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                mask_eq(&net.octets(), &a.octets(), self.bits)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                mask_eq(&net.octets(), &a.octets(), self.bits)
            }
            _ => false,
        }
    }
}

/// Compares the first `bits` bits of two addresses.
fn mask_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let full = (bits / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }

    let rem = bits % 8;
    if rem == 0 {
        return true;
    }

    let mask = 0xFFu8 << (8 - rem);

    (a[full] & mask) == (b[full] & mask)
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl FromStr for Prefix {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (a, b) = s
            .rsplit_once('/')
            .ok_or_else(|| format!("missing prefix length in {s:?}"))?;
        let addr: IpAddr = a.parse().map_err(|e| format!("{s:?}: {e}"))?;
        let bits: u8 = b.parse().map_err(|e| format!("{s:?}: {e}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(format!("prefix length {bits} out of range in {s:?}"));
        }

        Ok(Prefix { addr, bits })
    }
}

impl Serialize for Prefix {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Prefix {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A `netip.AddrPort`, rendered as `127.0.0.1:3000`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrPort(pub SocketAddr);

impl Default for AddrPort {
    fn default() -> Self {
        Self(SocketAddr::from(([0, 0, 0, 0], 3000)))
    }
}

impl fmt::Display for AddrPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for AddrPort {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for AddrPort {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<SocketAddr>()
            .map(AddrPort)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_address_renders_empty() {
        let y = crate::yaml::to_string(&OptAddr(None)).unwrap();
        assert_eq!(y, "\"\"\n");
    }

    #[test]
    fn set_address_renders_plain() {
        let a = OptAddr(Some("192.168.1.1".parse().unwrap()));
        assert_eq!(crate::yaml::to_string(&a).unwrap(), "192.168.1.1\n");
    }

    #[test]
    fn prefix_round_trips() {
        for s in ["127.0.0.0/8", "::1/128", "10.0.0.0/24"] {
            let p: Prefix = s.parse().unwrap();
            assert_eq!(p.to_string(), s);
        }
    }

    #[test]
    fn prefix_containment() {
        let p: Prefix = "127.0.0.0/8".parse().unwrap();
        assert!(p.contains("127.0.0.1".parse().unwrap()));
        assert!(p.contains("127.255.255.255".parse().unwrap()));
        assert!(!p.contains("128.0.0.1".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));

        let p6: Prefix = "::1/128".parse().unwrap();
        assert!(p6.contains("::1".parse().unwrap()));
        assert!(!p6.contains("::2".parse().unwrap()));

        // Non-byte-aligned prefix lengths.
        let p: Prefix = "10.0.0.0/12".parse().unwrap();
        assert!(p.contains("10.15.1.1".parse().unwrap()));
        assert!(!p.contains("10.16.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_bad_prefixes() {
        assert!("10.0.0.0".parse::<Prefix>().is_err());
        assert!("10.0.0.0/33".parse::<Prefix>().is_err());
        assert!("::1/129".parse::<Prefix>().is_err());
    }

    #[test]
    fn addr_port_round_trips() {
        let a: AddrPort = serde_yaml_ng::from_str("127.0.0.1:13000").unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:13000");
    }
}

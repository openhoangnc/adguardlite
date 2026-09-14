//! The primitive encodings Go's `encoding/gob` uses.

use crate::{Error, Result};

/// Appends an unsigned integer.
///
/// Values below 128 are a single byte; anything larger is a minimal-length
/// big-endian byte stream preceded by the negated byte count.
pub fn put_uint(out: &mut Vec<u8>, v: u64) {
    if v < 0x80 {
        out.push(v as u8);

        return;
    }

    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(7);
    let used = &bytes[first..];

    out.push((0u8).wrapping_sub(used.len() as u8));
    out.extend_from_slice(used);
}

/// Appends a signed integer, using gob's low-bit sign encoding.
pub fn put_int(out: &mut Vec<u8>, v: i64) {
    let u = if v < 0 {
        ((!(v as u64)) << 1) | 1
    } else {
        (v as u64) << 1
    };

    put_uint(out, u);
}

/// Appends a string as a length followed by its bytes.
pub fn put_string(out: &mut Vec<u8>, s: &str) {
    put_uint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Reads an unsigned integer, advancing `b`.
pub fn get_uint(b: &mut &[u8]) -> Result<u64> {
    let first = *b.first().ok_or(Error::Truncated)?;
    *b = &b[1..];

    if first < 0x80 {
        return Ok(u64::from(first));
    }

    let n = (0u8).wrapping_sub(first) as usize;
    if n == 0 || n > 8 {
        return Err(Error::Invalid(format!(
            "bad integer length byte {first:#x}"
        )));
    }
    if b.len() < n {
        return Err(Error::Truncated);
    }

    let mut v: u64 = 0;
    for &byte in &b[..n] {
        v = (v << 8) | u64::from(byte);
    }
    *b = &b[n..];

    Ok(v)
}

/// Reads a signed integer, advancing `b`.
pub fn get_int(b: &mut &[u8]) -> Result<i64> {
    let u = get_uint(b)?;

    Ok(if u & 1 != 0 {
        !((u >> 1) as i64)
    } else {
        (u >> 1) as i64
    })
}

/// Reads a length-prefixed string, advancing `b`.
pub fn get_string(b: &mut &[u8]) -> Result<String> {
    let n = get_uint(b)? as usize;
    if b.len() < n {
        return Err(Error::Truncated);
    }

    let s = String::from_utf8(b[..n].to_vec())
        .map_err(|e| Error::Invalid(format!("string is not utf-8: {e}")))?;
    *b = &b[n..];

    Ok(s)
}

/// Skips a length-prefixed byte string, advancing `b`.
pub fn skip_bytes(b: &mut &[u8]) -> Result<()> {
    let n = get_uint(b)? as usize;
    if b.len() < n {
        return Err(Error::Truncated);
    }
    *b = &b[n..];

    Ok(())
}

/// Wraps a payload as a gob message: its byte length, then the payload.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_uint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);

    out
}

/// Reads one framed message, returning its payload and advancing `b`.
pub fn unframe<'a>(b: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = get_uint(b)? as usize;
    if b.len() < n {
        return Err(Error::Truncated);
    }

    let (payload, rest) = b.split_at(n);
    *b = rest;

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_uint(v: u64) {
        let mut out = Vec::new();
        put_uint(&mut out, v);
        let mut s = out.as_slice();
        assert_eq!(get_uint(&mut s).unwrap(), v, "for {v}");
        assert!(s.is_empty(), "for {v}");
    }

    #[test]
    fn unsigned_integers_round_trip() {
        for v in [0, 1, 127, 128, 255, 256, 65_535, 1 << 32, u64::MAX] {
            roundtrip_uint(v);
        }
    }

    #[test]
    fn small_unsigned_integers_are_one_byte() {
        let mut out = Vec::new();
        put_uint(&mut out, 6);
        assert_eq!(out, vec![6]);
    }

    #[test]
    fn larger_unsigned_integers_carry_a_negated_length() {
        // This is the shape seen throughout a real stats.db.
        let mut out = Vec::new();
        put_uint(&mut out, 128);
        assert_eq!(out, vec![0xFF, 0x80]);

        let mut out = Vec::new();
        put_uint(&mut out, 0x0384);
        assert_eq!(out, vec![0xFE, 0x03, 0x84]);
    }

    #[test]
    fn signed_integers_round_trip() {
        for v in [0i64, 1, -1, 63, 64, -64, -65, i64::MAX, i64::MIN + 1] {
            let mut out = Vec::new();
            put_int(&mut out, v);
            let mut s = out.as_slice();
            assert_eq!(get_int(&mut s).unwrap(), v, "for {v}");
        }
    }

    #[test]
    fn signed_encoding_matches_the_bytes_go_writes() {
        // A type definition for id 64 is sent as the signed value -64.
        let mut out = Vec::new();
        put_int(&mut out, -64);
        assert_eq!(out, vec![0x7F]);

        // And a value message names the type as the positive 64.
        let mut out = Vec::new();
        put_int(&mut out, 64);
        assert_eq!(out, vec![0xFF, 0x80]);
    }

    #[test]
    fn strings_round_trip() {
        for s in [
            "",
            "example.com",
            "https://dns10.quad9.net:443/dns-query",
            "日本",
        ] {
            let mut out = Vec::new();
            put_string(&mut out, s);
            let mut r = out.as_slice();
            assert_eq!(get_string(&mut r).unwrap(), s);
        }
    }

    #[test]
    fn framing_round_trips() {
        let framed = frame(b"payload");
        let mut r = framed.as_slice();
        assert_eq!(unframe(&mut r).unwrap(), b"payload");
        assert!(r.is_empty());
    }

    #[test]
    fn truncated_input_is_an_error() {
        let mut r: &[u8] = &[];
        assert!(matches!(get_uint(&mut r), Err(Error::Truncated)));

        let mut r: &[u8] = &[0xFE, 0x01];
        assert!(matches!(get_uint(&mut r), Err(Error::Truncated)));

        let mut r: &[u8] = &[10, 1, 2];
        assert!(matches!(unframe(&mut r), Err(Error::Truncated)));
    }
}

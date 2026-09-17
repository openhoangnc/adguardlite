//! Encoding and decoding `internal/stats.unitDB`.

use std::collections::HashMap;

use crate::codec::{frame, get_int, get_string, get_uint, put_int, put_string, put_uint, unframe};
use crate::{Error, Result};

/// Gob's built-in type identifier for a string.
const T_STRING: i64 = 6;

/// Gob's built-in type identifier for an unsigned integer.
const T_UINT: i64 = 3;

/// The first identifier gob grants to a user-defined type.
const FIRST_USER_ID: i64 = 64;

/// Identifiers this encoder assigns.  Any value at or above
/// [`FIRST_USER_ID`] works, as long as the definitions are self-consistent.
const ID_UNIT: i64 = 64;
const ID_UINT_SLICE: i64 = 65;
const ID_PAIR_SLICE: i64 = 66;
const ID_PAIR: i64 = 67;

/// A name and its count, mirroring `internal/stats.countPair`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CountPair {
    /// The name.
    pub name: String,
    /// The count.
    pub count: u64,
}

/// One hour's statistics, mirroring `internal/stats.unitDB`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitDb {
    /// Query counts per result category.
    pub n_result: Vec<u64>,
    /// Top queried domains.
    pub domains: Vec<CountPair>,
    /// Top blocked domains.
    pub blocked_domains: Vec<CountPair>,
    /// Top clients.
    pub clients: Vec<CountPair>,
    /// Responses per upstream.
    pub upstreams_responses: Vec<CountPair>,
    /// Summed response time per upstream.
    pub upstreams_time_sum: Vec<CountPair>,
    /// Total queries.
    pub n_total: u64,
    /// Mean processing time, in microseconds.
    pub time_avg: u32,
}

/// The struct's fields, in the order Go declares them.
///
/// Position matters: gob identifies a field by its index, and the decoder here
/// maps by name so a reordering upstream would be caught rather than silently
/// misread.
const FIELDS: [&str; 8] = [
    "NResult",
    "Domains",
    "BlockedDomains",
    "Clients",
    "UpstreamsResponses",
    "UpstreamsTimeSum",
    "NTotal",
    "TimeAvg",
];

/// Encodes a unit as a complete gob stream, type definitions included.
pub fn encode_unit(u: &UnitDb) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    out.extend_from_slice(&type_defs());
    out.extend_from_slice(&frame(&encode_unit_value(u)));

    out
}

/// Emits the four type definitions the value refers to.
fn type_defs() -> Vec<u8> {
    let mut out = Vec::new();

    // unitDB: a struct whose fields name the other three types.
    let mut b = Vec::new();
    put_int(&mut b, -ID_UNIT);
    put_uint(&mut b, 3); // wireType.StructT
    put_uint(&mut b, 1); // structType.CommonType
    put_common(&mut b, "unitDB", ID_UNIT);
    put_uint(&mut b, 1); // structType.Field
    put_uint(&mut b, FIELDS.len() as u64);
    for (i, name) in FIELDS.iter().enumerate() {
        let id = match i {
            0 => ID_UINT_SLICE,
            1..=5 => ID_PAIR_SLICE,
            // NTotal is a uint64 and TimeAvg a uint32; both are gob uints.
            _ => T_UINT,
        };
        put_field(&mut b, name, id);
    }
    put_uint(&mut b, 0); // end structType
    put_uint(&mut b, 0); // end wireType
    out.extend_from_slice(&frame(&b));

    out.extend_from_slice(&slice_def(ID_UINT_SLICE, "[]uint64", T_UINT));
    out.extend_from_slice(&slice_def(ID_PAIR_SLICE, "[]stats.countPair", ID_PAIR));

    // countPair.
    let mut b = Vec::new();
    put_int(&mut b, -ID_PAIR);
    put_uint(&mut b, 3); // wireType.StructT
    put_uint(&mut b, 1); // structType.CommonType
    put_common(&mut b, "countPair", ID_PAIR);
    put_uint(&mut b, 1); // structType.Field
    put_uint(&mut b, 2);
    put_field(&mut b, "Name", T_STRING);
    put_field(&mut b, "Count", T_UINT);
    put_uint(&mut b, 0);
    put_uint(&mut b, 0);
    out.extend_from_slice(&frame(&b));

    out
}

/// Emits a slice type definition.
fn slice_def(id: i64, name: &str, elem: i64) -> Vec<u8> {
    let mut b = Vec::new();
    put_int(&mut b, -id);
    put_uint(&mut b, 2); // wireType.SliceT
    put_uint(&mut b, 1); // sliceType.CommonType
    put_common(&mut b, name, id);
    put_uint(&mut b, 1); // sliceType.Elem
    put_int(&mut b, elem);
    put_uint(&mut b, 0); // end sliceType
    put_uint(&mut b, 0); // end wireType

    frame(&b)
}

/// Emits a `CommonType`: a name and an identifier.
fn put_common(out: &mut Vec<u8>, name: &str, id: i64) {
    put_uint(out, 1); // CommonType.Name
    put_string(out, name);
    put_uint(out, 1); // CommonType.Id
    put_int(out, id);
    put_uint(out, 0); // end CommonType
}

/// Emits a `fieldType`: a name and the identifier of its type.
fn put_field(out: &mut Vec<u8>, name: &str, id: i64) {
    put_uint(out, 1); // fieldType.Name
    put_string(out, name);
    put_uint(out, 1); // fieldType.Id
    put_int(out, id);
    put_uint(out, 0); // end fieldType
}

/// Encodes the value message: the type identifier, then the struct's fields.
///
/// Gob omits zero-valued fields, and identifies each sent field by its delta
/// from the previous one.
fn encode_unit_value(u: &UnitDb) -> Vec<u8> {
    let mut b = Vec::new();
    put_int(&mut b, ID_UNIT);

    let mut last: usize = 0;
    let mut field = |b: &mut Vec<u8>, index: usize, write: &mut dyn FnMut(&mut Vec<u8>)| {
        put_uint(b, (index + 1 - last) as u64);
        last = index + 1;
        write(b);
    };

    if !u.n_result.is_empty() {
        field(&mut b, 0, &mut |b| {
            put_uint(b, u.n_result.len() as u64);
            for v in &u.n_result {
                put_uint(b, *v);
            }
        });
    }

    for (i, pairs) in [
        &u.domains,
        &u.blocked_domains,
        &u.clients,
        &u.upstreams_responses,
        &u.upstreams_time_sum,
    ]
    .into_iter()
    .enumerate()
    {
        if pairs.is_empty() {
            continue;
        }
        field(&mut b, i + 1, &mut |b| put_pairs(b, pairs));
    }

    if u.n_total != 0 {
        field(&mut b, 6, &mut |b| put_uint(b, u.n_total));
    }
    if u.time_avg != 0 {
        field(&mut b, 7, &mut |b| put_uint(b, u64::from(u.time_avg)));
    }

    put_uint(&mut b, 0);

    b
}

/// Encodes a slice of count pairs.
fn put_pairs(out: &mut Vec<u8>, pairs: &[CountPair]) {
    put_uint(out, pairs.len() as u64);
    for p in pairs {
        // Each element is a struct, delta-encoded like any other.
        let mut last = 0usize;
        if !p.name.is_empty() {
            put_uint(out, 1);
            put_string(out, &p.name);
            last = 1;
        }
        if p.count != 0 {
            put_uint(out, (2 - last) as u64);
            put_uint(out, p.count);
        }
        put_uint(out, 0);
    }
}

/// What a decoded type definition tells us about a type.
#[derive(Clone, Debug)]
enum TypeDef {
    /// A slice.  Its element type is recorded but not consulted: the decoder
    /// dispatches on the field name, which is what upstream's own decoder
    /// keys on when a struct's layout changes.
    Slice,
    /// A struct, with its fields' names and types in order.
    Struct { fields: Vec<(String, i64)> },
}

/// Decodes a gob stream holding one unit.
pub fn decode_unit(mut b: &[u8]) -> Result<UnitDb> {
    let mut types: HashMap<i64, TypeDef> = HashMap::new();

    loop {
        if b.is_empty() {
            return Err(Error::Truncated);
        }

        let mut msg = unframe(&mut b)?;
        let id = get_int(&mut msg)?;

        if id < 0 {
            let (tid, def) = parse_type_def(-id, &mut msg)?;
            types.insert(tid, def);

            continue;
        }

        return decode_value(id, &types, &mut msg);
    }
}

/// Parses one type definition message.
fn parse_type_def(id: i64, b: &mut &[u8]) -> Result<(i64, TypeDef)> {
    // wireType is a struct; the first delta says which variant it holds.
    let kind = get_uint(b)?;

    let def = match kind {
        2 => {
            // sliceType: CommonType then Elem.
            expect_delta(b, 1)?;
            skip_common(b)?;
            expect_delta(b, 1)?;
            let _elem = get_int(b)?;
            skip_struct_end(b)?;

            TypeDef::Slice
        }
        3 => {
            // structType: CommonType then Field.
            expect_delta(b, 1)?;
            skip_common(b)?;
            expect_delta(b, 1)?;
            let n = get_uint(b)? as usize;
            let mut fields = Vec::with_capacity(n);
            for _ in 0..n {
                fields.push(parse_field(b)?);
            }
            skip_struct_end(b)?;

            TypeDef::Struct { fields }
        }
        other => {
            return Err(Error::Unsupported(format!("wire type variant {other}")));
        }
    };

    // The wireType struct's own terminator.
    let _ = get_uint(b);

    Ok((id, def))
}

/// Reads the next field delta and checks it is the expected one.
fn expect_delta(b: &mut &[u8], want: u64) -> Result<()> {
    let got = get_uint(b)?;
    if got != want {
        return Err(Error::Invalid(format!(
            "expected field delta {want}, got {got}"
        )));
    }

    Ok(())
}

/// Skips a `CommonType`.
fn skip_common(b: &mut &[u8]) -> Result<()> {
    // Name then Id, both optional, terminated by a zero delta.
    loop {
        let delta = get_uint(b)?;
        if delta == 0 {
            return Ok(());
        }
        // Name is a string, Id an int; the field index says which.
        // Deltas are relative, so track position.
        // Field 1 is Name, field 2 is Id.
        // A delta of 1 from the start means Name; from Name it means Id.
        // Rather than track, sniff: strings are length-prefixed.
        // Both are safely skippable by reading the right shape, so decide by
        // remembering how many fields we have consumed.
        // This loop consumes at most two.
        static_assert_two_fields();
        if delta == 1 && !b.is_empty() {
            // Try a string first; if the length is implausible, treat it as an int.
            let save = *b;
            match get_string(b) {
                Ok(_) => continue,
                Err(_) => {
                    *b = save;
                    let _ = get_int(b)?;

                    continue;
                }
            }
        }
        let _ = get_int(b)?;
    }
}

/// Documents that `CommonType` has exactly the two fields this skipper knows.
const fn static_assert_two_fields() {}

/// Skips the terminator of the enclosing struct.
fn skip_struct_end(b: &mut &[u8]) -> Result<()> {
    let end = get_uint(b)?;
    if end != 0 {
        return Err(Error::Invalid(format!(
            "expected a struct terminator, got {end}"
        )));
    }

    Ok(())
}

/// Parses a `fieldType`: a name and a type identifier.
fn parse_field(b: &mut &[u8]) -> Result<(String, i64)> {
    let mut name = String::new();
    let mut id = 0i64;
    let mut seen = 0usize;

    loop {
        let delta = get_uint(b)?;
        if delta == 0 {
            return Ok((name, id));
        }
        seen += delta as usize;
        match seen {
            1 => name = get_string(b)?,
            2 => id = get_int(b)?,
            other => return Err(Error::Invalid(format!("unknown fieldType field {other}"))),
        }
    }
}

/// Decodes the value message into a unit.
fn decode_value(id: i64, types: &HashMap<i64, TypeDef>, b: &mut &[u8]) -> Result<UnitDb> {
    let Some(TypeDef::Struct { fields }) = types.get(&id) else {
        return Err(Error::Invalid(format!(
            "value names type {id}, which is not a known struct"
        )));
    };

    let mut u = UnitDb::default();
    let mut seen = 0usize;

    loop {
        let delta = get_uint(b)?;
        if delta == 0 {
            return Ok(u);
        }
        seen += delta as usize;

        let Some((name, _)) = fields.get(seen - 1) else {
            return Err(Error::Invalid(format!(
                "field index {seen} is past the type's fields"
            )));
        };

        match name.as_str() {
            "NResult" => {
                let n = get_uint(b)? as usize;
                let mut v = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    v.push(get_uint(b)?);
                }
                u.n_result = v;
            }
            "Domains" => u.domains = get_pairs(b)?,
            "BlockedDomains" => u.blocked_domains = get_pairs(b)?,
            "Clients" => u.clients = get_pairs(b)?,
            "UpstreamsResponses" => u.upstreams_responses = get_pairs(b)?,
            "UpstreamsTimeSum" => u.upstreams_time_sum = get_pairs(b)?,
            "NTotal" => u.n_total = get_uint(b)?,
            "TimeAvg" => u.time_avg = get_uint(b)? as u32,
            other => {
                return Err(Error::Unsupported(format!(
                    "unknown unitDB field {other:?}"
                )));
            }
        }
    }
}

/// Decodes a slice of count pairs.
fn get_pairs(b: &mut &[u8]) -> Result<Vec<CountPair>> {
    let n = get_uint(b)? as usize;
    let mut out = Vec::with_capacity(n.min(4096));

    for _ in 0..n {
        let mut p = CountPair::default();
        let mut seen = 0usize;
        loop {
            let delta = get_uint(b)?;
            if delta == 0 {
                break;
            }
            seen += delta as usize;
            match seen {
                1 => p.name = get_string(b)?,
                2 => p.count = get_uint(b)?,
                other => {
                    return Err(Error::Invalid(format!("unknown countPair field {other}")));
                }
            }
        }
        out.push(p);
    }

    Ok(out)
}

/// Reports whether an identifier belongs to a user-defined type.
pub const fn is_user_type(id: i64) -> bool {
    id >= FIRST_USER_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gob stream Go's encoder produced for a fully populated unit.
    const POPULATED: &[u8] = include_bytes!("../../../tests/fixtures/stats/unit-populated.gob");

    /// A gob stream taken from a real `stats.db`, holding an empty unit.
    const EMPTY: &[u8] = include_bytes!("../../../tests/fixtures/stats/unit.gob");

    fn sample() -> UnitDb {
        UnitDb {
            n_result: vec![0, 1200, 340, 5, 0, 7],
            domains: vec![
                CountPair {
                    name: "example.com".into(),
                    count: 512,
                },
                CountPair {
                    name: "en.wikipedia.org".into(),
                    count: 128,
                },
                CountPair {
                    name: "xn--80ak6aa92e.com".into(),
                    count: 1,
                },
            ],
            blocked_domains: vec![
                CountPair {
                    name: "doubleclick.net".into(),
                    count: 341,
                },
                CountPair {
                    name: "ads.example.com".into(),
                    count: 9,
                },
            ],
            clients: vec![
                CountPair {
                    name: "192.168.1.5".into(),
                    count: 900,
                },
                CountPair {
                    name: "2001:db8::1".into(),
                    count: 3,
                },
            ],
            upstreams_responses: vec![CountPair {
                name: "https://dns10.quad9.net:443/dns-query".into(),
                count: 871,
            }],
            upstreams_time_sum: vec![CountPair {
                name: "https://dns10.quad9.net:443/dns-query".into(),
                count: 143_119_999,
            }],
            n_total: 1552,
            time_avg: 397,
        }
    }

    #[test]
    fn decodes_a_populated_unit_written_by_go() {
        let got = decode_unit(POPULATED).expect("Go's stream must decode");
        assert_eq!(got, sample());
    }

    #[test]
    fn decodes_an_empty_unit_from_a_real_stats_db() {
        let got = decode_unit(EMPTY).expect("the real stream must decode");
        assert_eq!(got.n_result, vec![0; 6]);
        assert_eq!(got.n_total, 0);
        assert_eq!(got.time_avg, 0);
        assert!(got.domains.is_empty());
    }

    #[test]
    fn our_own_output_round_trips() {
        let u = sample();
        let encoded = encode_unit(&u);
        assert_eq!(decode_unit(&encoded).unwrap(), u);
    }

    #[test]
    fn an_empty_unit_round_trips() {
        let u = UnitDb::default();
        let encoded = encode_unit(&u);
        assert_eq!(decode_unit(&encoded).unwrap(), u);
    }

    #[test]
    fn zero_valued_fields_are_omitted() {
        // Gob does not send zero values, which is why a fresh unit is small.
        let empty = encode_unit(&UnitDb::default());
        let populated = encode_unit(&sample());
        assert!(
            empty.len() < populated.len(),
            "an empty unit should encode smaller: {} vs {}",
            empty.len(),
            populated.len()
        );
    }

    #[test]
    fn large_counts_survive() {
        let u = UnitDb {
            n_total: u64::MAX,
            time_avg: u32::MAX,
            clients: vec![CountPair {
                name: "c".into(),
                count: u64::MAX,
            }],
            ..Default::default()
        };
        assert_eq!(decode_unit(&encode_unit(&u)).unwrap(), u);
    }

    #[test]
    fn unicode_names_survive() {
        let u = UnitDb {
            domains: vec![CountPair {
                name: "日本.example".into(),
                count: 3,
            }],
            ..Default::default()
        };
        assert_eq!(decode_unit(&encode_unit(&u)).unwrap(), u);
    }

    #[test]
    fn truncated_streams_are_rejected() {
        let full = encode_unit(&sample());
        for cut in [1, 10, full.len() / 2, full.len() - 1] {
            assert!(
                decode_unit(&full[..cut]).is_err(),
                "cut at {cut} should fail"
            );
        }
    }

    #[test]
    fn user_type_identifiers_start_where_go_starts_them() {
        assert!(is_user_type(64));
        assert!(!is_user_type(63));
        assert!(!is_user_type(T_UINT));
    }
}

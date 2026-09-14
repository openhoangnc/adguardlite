//! Persisting statistics to `stats.db`.
//!
//! The file is a bbolt database holding one bucket per hourly unit, named by
//! the absolute hour number as a big-endian 64-bit integer, each holding a
//! single key `[0]` whose value is the unit gob-encoded.  That is exactly what
//! `internal/stats` writes, so an existing database carries over and a
//! database this writes can be read back by the Go implementation.

use std::collections::BTreeMap;
use std::path::Path;

use crate::unit::{CountPair, UnitDb};

/// The page size to write.  bbolt uses the OS page size, and reads any size,
/// so a fixed 4 KiB keeps output reproducible across machines.
const PAGE_SIZE: usize = 4096;

/// A failure loading or saving statistics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The database could not be read or written.
    #[error("statistics database: {0}")]
    Bolt(#[from] agl_bolt::Error),

    /// A unit's contents could not be decoded.
    #[error("statistics unit for hour {hour}: {source}")]
    Gob {
        /// The hour whose unit failed.
        hour: u32,
        /// The underlying error.
        #[source]
        source: agl_gob::Error,
    },
}

/// Loads every unit from a database file.
///
/// A missing file is not an error: a fresh installation has none.
pub fn load(path: &Path) -> Result<Vec<(u32, UnitDb)>, Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let db = agl_bolt::Db::open(path)?;
    let buckets = db.buckets()?;

    let mut out = Vec::with_capacity(buckets.len());
    for (name, keys) in buckets {
        let Some(hour) = hour_from_name(&name) else {
            continue;
        };
        let Some(blob) = keys.get([0u8].as_slice()) else {
            continue;
        };

        let u = agl_gob::decode_unit(blob).map_err(|source| Error::Gob { hour, source })?;
        out.push((hour, from_gob(&u)));
    }

    Ok(out)
}

/// Writes every unit to a database file, replacing what was there.
pub fn save(path: &Path, units: &[(u32, UnitDb)]) -> Result<(), Error> {
    let mut buckets: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();

    for (hour, u) in units {
        let blob = agl_gob::encode_unit(&to_gob(u));
        buckets.insert(name_from_hour(*hour), BTreeMap::from([(vec![0u8], blob)]));
    }

    agl_bolt::write_file(path, &buckets, PAGE_SIZE)?;

    Ok(())
}

/// Decodes a bucket name into an hour number.
fn hour_from_name(name: &[u8]) -> Option<u32> {
    let b: [u8; 8] = name.try_into().ok()?;

    Some(u64::from_be_bytes(b) as u32)
}

/// Encodes an hour number as a bucket name.
///
/// Upstream stores it as a 64-bit big-endian value even though the identifier
/// is 32 bits, so the same widening happens here.
fn name_from_hour(hour: u32) -> Vec<u8> {
    u64::from(hour).to_be_bytes().to_vec()
}

/// Converts the gob representation into this crate's.
fn from_gob(u: &agl_gob::UnitDb) -> UnitDb {
    let pairs = |v: &[agl_gob::CountPair]| -> Vec<CountPair> {
        v.iter()
            .map(|p| CountPair { name: p.name.clone(), count: p.count })
            .collect()
    };

    UnitDb {
        n_result: u.n_result.clone(),
        domains: pairs(&u.domains),
        blocked_domains: pairs(&u.blocked_domains),
        clients: pairs(&u.clients),
        upstreams_responses: pairs(&u.upstreams_responses),
        upstreams_time_sum: pairs(&u.upstreams_time_sum),
        n_total: u.n_total,
        time_avg: u.time_avg,
    }
}

/// Converts this crate's representation into the gob one.
fn to_gob(u: &UnitDb) -> agl_gob::UnitDb {
    let pairs = |v: &[CountPair]| -> Vec<agl_gob::CountPair> {
        v.iter()
            .map(|p| agl_gob::CountPair { name: p.name.clone(), count: p.count })
            .collect()
    };

    agl_gob::UnitDb {
        n_result: u.n_result.clone(),
        domains: pairs(&u.domains),
        blocked_domains: pairs(&u.blocked_domains),
        clients: pairs(&u.clients),
        upstreams_responses: pairs(&u.upstreams_responses),
        upstreams_time_sum: pairs(&u.upstreams_time_sum),
        n_total: u.n_total,
        time_avg: u.time_avg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("agl-stats-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();

        d
    }

    fn unit(total: u64) -> UnitDb {
        UnitDb {
            n_result: vec![0, total, 0, 0, 0, 0],
            domains: vec![CountPair { name: "example.com".into(), count: total }],
            blocked_domains: vec![CountPair { name: "doubleclick.net".into(), count: 3 }],
            clients: vec![CountPair { name: "192.168.1.5".into(), count: total }],
            upstreams_responses: vec![CountPair {
                name: "https://dns10.quad9.net:443/dns-query".into(),
                count: total,
            }],
            upstreams_time_sum: vec![CountPair {
                name: "https://dns10.quad9.net:443/dns-query".into(),
                count: total * 1000,
            }],
            n_total: total,
            time_avg: 397,
        }
    }

    #[test]
    fn units_round_trip_through_a_file() {
        let d = tmpdir("roundtrip");
        let p = d.join("stats.db");

        let units = vec![(497_049u32, unit(10)), (497_050, unit(20)), (497_051, unit(0))];
        save(&p, &units).unwrap();

        let mut back = load(&p).unwrap();
        back.sort_by_key(|(h, _)| *h);
        assert_eq!(back, units);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_missing_file_loads_as_empty() {
        let d = tmpdir("missing");
        assert!(load(&d.join("nothing.db")).unwrap().is_empty());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_empty_set_writes_a_valid_file() {
        let d = tmpdir("empty");
        let p = d.join("stats.db");
        save(&p, &[]).unwrap();
        assert!(p.exists());
        assert!(load(&p).unwrap().is_empty());

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_months_worth_of_units_round_trips() {
        let d = tmpdir("month");
        let p = d.join("stats.db");

        let units: Vec<(u32, UnitDb)> = (0..24u32 * 30)
            .map(|i| (500_000 + i, unit(u64::from(i))))
            .collect();
        save(&p, &units).unwrap();

        let mut back = load(&p).unwrap();
        back.sort_by_key(|(h, _)| *h);
        assert_eq!(back.len(), 720);
        assert_eq!(back, units);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_unit_with_many_top_entries_round_trips() {
        // 100 domains and 100 clients is the most a unit ever stores, and is
        // well past bbolt's inline-bucket threshold.
        let d = tmpdir("large");
        let p = d.join("stats.db");

        let mut u = unit(5000);
        u.domains = (0..100)
            .map(|i| CountPair { name: format!("domain{i}.example.com"), count: 100 - i })
            .collect();
        u.clients = (0..100)
            .map(|i| CountPair { name: format!("10.0.0.{i}"), count: 100 - i })
            .collect();

        save(&p, &[(1u32, u.clone())]).unwrap();
        assert_eq!(load(&p).unwrap(), vec![(1u32, u)]);

        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn bucket_names_match_upstreams_widening() {
        // Upstream stores a 32-bit hour as a 64-bit big-endian name.
        assert_eq!(name_from_hour(497_049), vec![0, 0, 0, 0, 0, 7, 149, 153]);
        assert_eq!(hour_from_name(&name_from_hour(497_049)), Some(497_049));
        assert_eq!(hour_from_name(&[1, 2, 3]), None);
    }

    #[test]
    fn reads_a_database_written_by_go() {
        use std::io::Read as _;

        let gz: &[u8] = include_bytes!("../../../tests/fixtures/stats/go-stats.db.gz");
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(gz).read_to_end(&mut data).unwrap();

        let d = tmpdir("gofile");
        let p = d.join("stats.db");
        std::fs::write(&p, &data).unwrap();

        let units = load(&p).expect("a Go-written database must load");
        assert!(!units.is_empty(), "the fixture holds hourly units");
        for (hour, u) in &units {
            assert!((400_000..1_000_000).contains(hour));
            assert_eq!(u.n_result.len(), 6, "six result categories");
        }

        std::fs::remove_dir_all(&d).ok();
    }
}

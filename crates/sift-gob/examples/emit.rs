//! Writes a populated statistics unit as a gob stream, so Go's decoder can be
//! pointed at it.
//!
//! Paired with `tests/compat/gob-oracle`, which encodes the same value with
//! Go: together they check that each implementation reads the other's bytes.

use sift_gob::{CountPair, UnitDb, encode_unit};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: emit <out.gob>")?;

    // The same value tests/compat/gob-oracle encodes.
    let u = UnitDb {
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
    };

    let bytes = encode_unit(&u);
    std::fs::write(&path, &bytes)?;
    println!("wrote {} bytes to {path}", bytes.len());

    Ok(())
}

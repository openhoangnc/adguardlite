//! A DNS load generator, for comparing this server against another.
//!
//! Sends UDP queries at a fixed concurrency for a fixed duration and reports
//! throughput and latency percentiles.  Queries are drawn from a name list, so
//! the same corpus can be replayed against both servers.
//!
//! ```text
//! cargo run --release --example loadgen -- 127.0.0.1:15353 names.txt 10 64
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target: SocketAddr = args
        .next()
        .ok_or("usage: loadgen <addr> <names-file> [seconds] [concurrency]")?
        .parse()?;
    let names_path = args.next().ok_or("missing names file")?;
    let seconds: u64 = args.next().unwrap_or_else(|| "10".into()).parse()?;
    let concurrency: usize = args.next().unwrap_or_else(|| "64".into()).parse()?;

    let names: Arc<Vec<String>> = Arc::new(
        std::fs::read_to_string(&names_path)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| if l.ends_with('.') { l.to_string() } else { format!("{l}.") })
            .collect(),
    );
    if names.is_empty() {
        return Err("the names file is empty".into());
    }

    // Pre-encode the queries so the generator measures the server, not itself.
    let wire: Arc<Vec<Vec<u8>>> = Arc::new(
        names
            .iter()
            .filter_map(|n| {
                let mut m = Message::query();
                m.metadata.recursion_desired = true;
                m.add_query(Query::query(Name::from_utf8(n).ok()?, RecordType::A));

                m.to_bytes().ok()
            })
            .collect(),
    );

    let sent = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(parking_lot::Mutex::new(Vec::<u32>::with_capacity(1 << 20)));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let started = Instant::now();

    let mut workers = Vec::with_capacity(concurrency);
    for w in 0..concurrency {
        let (wire, sent, ok, lost, latencies) =
            (wire.clone(), sent.clone(), ok.clone(), lost.clone(), latencies.clone());

        workers.push(tokio::spawn(async move {
            let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            if sock.connect(target).await.is_err() {
                return;
            }

            let mut buf = vec![0u8; 4096];
            let mut i = w;
            let mut local = Vec::with_capacity(4096);

            while Instant::now() < deadline {
                let q = &wire[i % wire.len()];
                i += concurrency;

                let t0 = Instant::now();
                if sock.send(q).await.is_err() {
                    lost.fetch_add(1, Ordering::Relaxed);

                    continue;
                }
                sent.fetch_add(1, Ordering::Relaxed);

                match tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
                    Ok(Ok(n)) if Message::from_bytes(&buf[..n]).is_ok() => {
                        ok.fetch_add(1, Ordering::Relaxed);
                        local.push(t0.elapsed().as_micros().min(u128::from(u32::MAX)) as u32);
                    }
                    _ => {
                        lost.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            latencies.lock().extend_from_slice(&local);
        }));
    }

    for w in workers {
        let _ = w.await;
    }

    let elapsed = started.elapsed().as_secs_f64();
    let sent = sent.load(Ordering::Relaxed);
    let ok = ok.load(Ordering::Relaxed);
    let lost = lost.load(Ordering::Relaxed);

    let mut lat = latencies.lock().clone();
    lat.sort_unstable();
    let pct = |p: f64| -> f64 {
        if lat.is_empty() {
            return 0.0;
        }
        let i = ((lat.len() as f64 - 1.0) * p).round() as usize;

        f64::from(lat[i]) / 1000.0
    };

    println!("target      : {target}");
    println!("duration    : {elapsed:.2} s, concurrency {concurrency}");
    println!("sent        : {sent}");
    println!("answered    : {ok}");
    println!("lost        : {lost}");
    println!("throughput  : {:.0} queries/s", ok as f64 / elapsed);
    println!("latency p50 : {:.3} ms", pct(0.50));
    println!("latency p90 : {:.3} ms", pct(0.90));
    println!("latency p99 : {:.3} ms", pct(0.99));

    Ok(())
}

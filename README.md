# adguardlite

A Rust backend for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome),
built as a drop-in replacement for the Go binary of release **v0.107.79**: the
same config file, the same on-disk data, the same HTTP API, the same web
interface, and the same Docker contract — in a smaller image, with less memory
and more throughput.

It is not a complete reimplementation. The DNS filtering path, the web
interface and the storage formats are done and verified against the Go build;
DHCP, the encrypted inbound listeners and several smaller features are not.
[What is not implemented](#what-is-not-implemented) lists every gap.

## Measured against the Go build

Both running the same config and the same 179,334-rule AdGuard DNS filter, on
the same machine.

| | Go v0.107.79 | adguardlite | |
|---|---:|---:|---|
| Docker image | 110 MB | **50.8 MB** | 2.2× smaller |
| Binary (with web UI) | 33.6 MB | **15.9 MB** | 2.1× smaller |
| Binary (`dist` profile) | 33.6 MB | **8.9 MB** | 3.8× smaller |
| Memory, idle with lists loaded | 129.9 MB | **72.8 MB** | 1.8× less |
| Memory, after load | 233.4 MB | **117.7 MB** | 2.0× less |
| Throughput (blocked queries) | 44,184 q/s | **49,627 q/s** | 1.12× |
| Latency p90 | 2.496 ms | **1.501 ms** | 1.7× better |
| Latency p99 | 4.329 ms | **2.545 ms** | 1.7× better |

Throughput was measured with the load generator in
`crates/adguardlite/examples/loadgen.rs`, which runs on the same machine as the
servers and so competes with them for CPU; treat the ratio as meaningful and
the absolute numbers as a floor.

## Compatibility, and how it was checked

Every claim below was verified against a running AdGuard Home v0.107.79, not
read off the source.

| Surface | Status | How it was checked |
|---|---|---|
| `AdGuardHome.yaml` (schema 34) | byte-identical | The same sequence of API changes applied to both servers produces byte-identical config files, quoting included. |
| Filtering verdicts | exact | 4,190 domains against the real 179,334-rule list: every verdict matches. 99.2% also cite the same rule; the rest are ties where upstream's choice falls out of its index's bucket balancing. |
| DNS responses | exact | 2,046 names over A and AAAA against both servers: no verdict differs. |
| HTTP API | exact | Response shapes for all 25 endpoints the web UI loads. |
| `querylog.json` | byte-identical | 43 real log lines, one per distinct entry shape, re-encode byte for byte. |
| `stats.db` (bbolt + gob) | interoperable | The Rust server wrote a database; a Go AdGuardHome read it and reported the same counts. Go's own gob encoder is not byte-stable, so byte-equality is not the bar. |
| Filter lists on disk | same files | The same `data/filters/<id>.txt` layout; an existing download is used as-is. |
| Docker | same contract | Same binary path, working directory, ports and entrypoint arguments; run against a config and data directory a Go instance produced. |

Reproduce it with `scripts/verify.sh` (see [Verifying](#verifying)).

## What is not implemented

These are real gaps, not oversights in the documentation.

**Answer 501 rather than pretending to succeed:** every `/control/dhcp/*`
write endpoint, `/control/tls/configure`, `/control/tls/validate`, and
`/control/update`.

**Not implemented at all:**

- **DHCP server.** `/control/dhcp/status` reports the stored config; nothing
  serves leases.
- **Encrypted inbound listeners** — DNS-over-TLS, DNS-over-HTTPS,
  DNS-over-QUIC and DNSCrypt. Plain DNS over UDP and TCP is served. *Outbound*
  DoT and DoH upstreams do work.
- **DNS-over-QUIC and DNSCrypt upstreams.** A config naming one is reported at
  startup and skipped.
- **Safe browsing and parental control.** The toggles persist and the API
  reports them; no hash-prefix lookups are performed.
- **Safe search** rewriting.
- **Per-client settings.** Persistent clients round-trip through the config and
  the API, but per-client filtering, upstreams and tags do not affect
  resolution.
- **Runtime client discovery** — ARP, rDNS, WHOIS, DHCP leases.
  `/control/clients` reports an empty `auto_clients`.
- **HTTPS for the web interface.** It serves plain HTTP.
- **Automatic updates**, **ipset**, **DNS64**, **EDNS Client Subnet**,
  `upstream_dns_file`, `bogus_nxdomain`, `trusted_proxies`, DDR handling, and
  duplicate-request coalescing.
- **Config migration** from schema versions below 34. A newer schema is
  refused rather than misread.
- **Session persistence.** Sessions live in memory, so a restart signs users
  out. `sessions.db` is neither read nor written.

## Layout

```
crates/agl-core      shared types matching Go's wire and on-disk forms
crates/agl-config    AdGuardHome.yaml: schema 34, and a Go-yaml.v3 emitter
crates/agl-filter    the rule engine, list storage, services catalogue
crates/agl-dns       wire codec, cache, upstreams, listeners, resolver
crates/agl-querylog  querylog.json
crates/agl-bolt      a minimal bbolt reader and writer
crates/agl-gob       Go `gob` for the statistics unit
crates/agl-stats     statistics collection, aggregation and persistence
crates/agl-api       the control API and the embedded web interface
crates/adguardlite   the binary
```

## Building

```bash
cargo build --release            # fast to build, fast to run
cargo build --profile dist       # fat LTO, stripped: the 8.9 MB binary
```

The workspace is split so `cargo` parallelises across crates, dependencies are
compiled at `opt-level = 2` even in debug builds so they are paid for once, and
debug info is line tables only. An incremental rebuild after touching one file
is about 8 seconds.

The web interface is committed pre-built and gzip-compressed under `web/build`.
To rebuild it from upstream's sources:

```bash
scripts/build-frontend.sh
```

## Running

```bash
cargo run --release -- --no-check-update -c ./AdGuardHome.yaml -w ./work
```

Or with Docker, as a drop-in for `adguard/adguardhome`:

```bash
docker build -f docker/Dockerfile -t adguardlite .
```

```bash
docker run -d --name adguardhome \
  -v "$PWD/work:/opt/adguardhome/work" \
  -v "$PWD/conf:/opt/adguardhome/conf" \
  -p 53:53/tcp -p 53:53/udp -p 3000:3000/tcp \
  adguardlite
```

## Verifying

`cargo test --workspace` runs 344 unit and integration tests, including the
differential against the real filter list and the query-log and gob golden
files — none of which need a network or a running Go build.

The cross-implementation checks need both servers running:

```bash
scripts/verify.sh
```

It builds the Go reference from `upstream/`, starts both, and runs the config,
DNS, API and statistics comparisons described above.

## Licence

GPL-3.0, matching AdGuard Home.

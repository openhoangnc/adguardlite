# adguardlite — Rust backend for AdGuard Home v0.107.79

A drop-in replacement for the Go `AdGuardHome` binary: same config file, same
on-disk data, same HTTP API, same Docker contract — smaller, faster, leaner.

## 0. Compatibility contract (what "drop-in" means here)

Discovered by reading upstream `v0.107.79`:

| Surface | Contract |
|---|---|
| Config file | `AdGuardHome.yaml`, **schema_version 34**, field order significant |
| Binary path | `/opt/adguardhome/AdGuardHome` |
| CMD | `--no-check-update -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/work` |
| Work dir | `<work>/data/{querylog.json,querylog.json.1,stats.db,sessions.db,filters/}` |
| Query log | JSONL, keys `T,QH,QT,QC,CP,IP,Result,Elapsed,Upstream,Answer,...` |
| Stats | bbolt file + Go **gob**-encoded `unitDB` per hourly bucket |
| HTTP API | 81 paths under `/control/*` (openapi/openapi.yaml) |
| Web UI | React SPA served from embedded FS at `/` |
| Ports | 53 tcp/udp, 67-68 udp, 80, 443 tcp/udp, 853 tcp/udp, 3000, 5443, 6060 |

## 1. Architecture

Cargo workspace — many small crates so `cargo build` parallelises well:

```
crates/
  agl-core       shared types: Reason, RRType, domain name, errors, clock
  agl-config     AdGuardHome.yaml (serde), schema-34 model, migrations, atomic save
  agl-filter     adblock + hosts rule engine, rewrites, blocked services, safesearch
  agl-dns        wire codec, cache, upstreams (UDP/TCP/DoT/DoH), server (UDP/TCP/DoH/DoT)
  agl-querylog   JSONL writer/reader, rotation, search
  agl-stats      bbolt reader/writer + gob codec, hourly units, aggregation
  agl-gob        minimal Go `gob` encoder/decoder for the unitDB shape
  agl-bolt       minimal bbolt (Go B+tree) reader/writer
  agl-api        axum HTTP API, auth/sessions, static UI
  adguardlite    binary: CLI, wiring, supervision
```

## 2. Phases

- **P1 Foundations** — workspace, build profiles, `agl-core`.
- **P2 Config** — full schema-34 model; round-trip byte-compat against Go output.
- **P3 Filtering** — rule parser + matcher, hosts rules, modifiers, rewrites, services.
- **P4 DNS** — codec, cache, upstream pool, UDP/TCP server, upstream modes.
- **P5 Storage** — query log (JSONL), stats (bbolt+gob).
- **P6 API+UI** — 81 endpoints, sessions, install wizard, embedded React UI.
- **P7 Docker** — multi-stage, static musl, matching the upstream image contract.
- **P8 Test** — unit + differential harness (Go vs Rust) + benchmarks.

## 3. Build-speed strategy

- Workspace split → parallel codegen across crates.
- `[profile.dev.package."*"] opt-level = 2` — deps compiled fast once, cached.
- `debug = "line-tables-only"` in dev — big link-time win.
- `lld` on Linux / default `ld64` on macOS; `mold` if present.
- Two release profiles: `release` (thin LTO, cu=16 — fast to build) and
  `dist` (fat LTO, cu=1, panic=abort, strip, opt-level=z→s — small & fast).
- Dependency hygiene: `rustls` not OpenSSL, no `reqwest` default features,
  no proc-macro-heavy crates where a hand-written impl is cheap.

## 4. Verification

1. `cargo test --workspace` — unit + property tests.
2. Config round-trip: Go writes → Rust reads → Rust writes → byte-diff.
3. DNS differential: same config, same 500-query corpus to both, diff answers.
4. API differential: same request set to both, diff JSON (time fields normalised).
5. Query-log cross-read: Rust writes → Go reads → Go API output matches.
6. Bench: qps, p99 latency, RSS, binary size vs Go.

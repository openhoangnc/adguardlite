# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A Rust backend for AdGuard Home, built as a **drop-in replacement** for the Go
binary of release **v0.107.79**. It reads and writes the same config file, the
same on-disk data, serves the same HTTP API and the same web interface, and
ships in a Docker image with the same runtime contract.

The overriding constraint is **compatibility, not elegance**. Where a format or
a behaviour looks odd, it is almost certainly odd because Go does it that way,
and changing it breaks a real user's installation. Read the comments before
"fixing" anything in a serialiser, a wire format or an API response shape.

## The drop-in contract

What "drop-in" means, concretely. Changing any of these breaks an existing
installation.

| Surface | Contract |
|---|---|
| Config file | `AdGuardHome.yaml`, `schema_version: 34`, field order significant |
| Binary path | `/opt/adguardhome/AdGuardHome` |
| Docker CMD | `--no-check-update -c /opt/adguardhome/conf/AdGuardHome.yaml -w /opt/adguardhome/work` |
| Work dir | `<work>/data/{querylog.json,querylog.json.1,stats.db,sessions.db,filters/,userfilters/}` |
| Query log | JSON lines, keys `T,QH,QT,QC,CP,IP,Result,Elapsed,Upstream,Answer,…` |
| Statistics | bbolt file, one bucket per hour named by big-endian `u64`, value a gob `unitDB` under key `[0]` |
| HTTP API | 81 paths under `/control/*`, all routed |
| Web interface | single-page app served from the embedded filesystem at `/` |
| Ports | 53 tcp/udp, 67–68 udp, 80, 443 tcp/udp, 853 tcp/udp, 3000, 5443, 6060 |

## Commands

```bash
cargo build --release            # fast to build and to run
cargo build --profile dist       # fat LTO, panic=abort, stripped: ~8.9 MB
cargo test --workspace           # 344 tests, no network or Go build needed
cargo clippy --workspace --all-targets
```

Running one test or one crate:

```bash
cargo test -p agl-filter                          # one crate
cargo test -p agl-filter --lib engine             # one module's tests
cargo test -p agl-filter --test differential      # one integration test file
cargo test -p agl-config reproduces_the_reference -- --exact --nocapture
```

Tests that need outbound network are `#[ignore]`d:

```bash
cargo test -p agl-dns --test live -- --ignored     # real DoT/DoH upstreams
```

Running the server:

```bash
cargo run --release -- --no-check-update -c ./AdGuardHome.yaml -w ./work
```

Cross-implementation verification — needs `upstream/` and a Go toolchain:

```bash
scripts/verify.sh                 # builds Go, starts both, runs every comparison
```

## Getting the reference implementation

`upstream/` is **gitignored**: it holds a checkout of AdGuard Home itself, used
as the oracle and to build the web interface. `cargo test` does not need it —
every in-repo test runs against committed fixtures. `scripts/verify.sh` and
`scripts/build-frontend.sh` do.

```bash
git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git upstream
```

## How compatibility work is done here

Capture behaviour from a **running** AdGuard Home; do not infer it from its
source. Every divergence found so far was invisible in the source and obvious
the moment two servers were compared:

- patterns without a URL prefix match the bare hostname, not `http://<host>`;
- every filtering pattern is compiled case-insensitively;
- an allowlist match is still the query's recorded verdict;
- `/control/querylog/config` reports its interval in **milliseconds**, while
  the legacy `/control/querylog_info` reports **days**.

The comparison harnesses live in `tests/compat/`:

- `api_diff.py` — response *shapes* of both servers, live. Each endpoint
  declares the status a GET should produce, so two servers failing the same way
  is a failure, not a match.
- `dns_diff.py` — DNS answers from both servers over A and AAAA.
- `gob-oracle/` — a small Go program that encodes and decodes the statistics
  unit with Go's own `encoding/gob`, so the Rust codec is checked against the
  implementation it must interoperate with.

Committed fixtures under `tests/fixtures/` were all captured from a real
instance: the reference config, 43 query-log lines (one per distinct entry
shape), a real `stats.db`, gob payloads, and the 179,334-rule AdGuard DNS
filter with the verdict Go gave for 4,190 domains.

## Architecture

Ten crates, layered so nothing depends upwards:

```
agl-core                        Go-compatible primitives: durations, byte sizes,
                                filtering reasons, Go's JSON time format
agl-config    -> core           AdGuardHome.yaml, schema 34, and a YAML emitter
                                that reproduces Go yaml.v3's output
agl-filter    -> core, config   rule parser and matcher, list storage,
                                blocked-services catalogue
agl-dns       -> core, filter   wire codec, cache, upstreams, listeners, the
                                resolver that orders every step
agl-querylog  -> core           querylog.json
agl-bolt                        a minimal bbolt reader and writer
agl-gob                         Go `gob` for the statistics unit
agl-stats     -> core, bolt,    collection, aggregation, persistence
                 gob
agl-api       -> all of the     the control API and the embedded web interface
                 above
adguardlite   -> all            the binary: CLI, wiring, supervision
```

`agl-api` and `agl-filter` deliberately hold no HTTP client. Downloading filter
lists is injected by the binary through the `ListFetcher` trait in
`agl-api/src/state.rs`, and pushing config changes into the running server goes
through `Reloader` in the same file. That is why `agl-filter::lists::Manager`
exposes `apply_fetched` rather than a `refresh` that downloads.

### The request path

`agl-dns/src/resolver.rs` is the file to read first. The **order** of its steps
is observable behaviour copied from `internal/dnsforward`:

1. a request without exactly one question gets `FORMERR`;
2. `ANY` is refused with `NOTIMP` when `refuse_any` is set;
3. an access-blocked host is **dropped** on UDP and `REFUSED` on TCP — silence
   on a datagram transport is deliberate, so a spoofed source gains no
   amplification;
4. rewrites apply *even when protection is off*;
5. filtering, where an allowlist match sets the verdict but still resolves;
6. `AAAA` suppression;
7. cache;
8. upstream.

### Things that look wrong but are not

- **Config field order is the file format.** Upstream warns against reordering,
  and the emitter preserves declaration order. Adding a field in the wrong
  place changes the file a user diffs.
- **`agl-config`'s YAML emitter is hand-written** because Go's yaml.v3 indents
  sequences under their key and prefers single quotes, and no Rust YAML crate
  does both. `reproduces_the_reference_config_byte_for_byte` guards it.
- **`NetworkRule` is 56 bytes and that is load-bearing.** A real list holds
  ~180,000 of them. When the modifiers were stored inline the struct was 296
  bytes and the engine used *more* memory than Go. `crates/agl-filter/tests/
  sizes.rs` fails if the layout regresses.
- **Reserved filter list IDs** match upstream's `rulelist.APIID`: `0` custom
  rules, `-1` the system hosts file, `-2` blocked services. The resolver maps
  these to the reason the web UI expects.
- **Byte-identical `gob` output is not a goal.** Go's own encoder does not
  reproduce its own bytes for the same value, because type-definition order
  depends on how the types were first walked. The bar is that each side decodes
  the other.
- **The binary target is named `AdGuardHome`**, so `module_path!` reports that,
  not the package name. A log filter spelled `adguardlite=info` compiles and
  matches nothing; `crates/adguardlite/src/main.rs` has a test guarding this.

## Build speed

The workspace is split so `cargo` parallelises across crates. Dependencies are
built at `opt-level = 2` even in debug so they are paid for once; our own crates
stay unoptimised with line-tables-only debug info. An incremental rebuild after
touching one file is roughly 8 seconds. Prefer a hand-written implementation to
a new dependency when the need is narrow — that is why `agl-bolt`, `agl-gob`
and the HTTPS fetch in `crates/adguardlite/src/fetch.rs` exist.

## The web interface

Committed pre-built and gzip-compressed under `web/build` (9.7 MB of assets →
2.5 MB in the binary), embedded by `agl-api/src/ui.rs`, which serves the stored
bytes to clients that accept gzip and decompresses for those that do not.
Rebuild it with `scripts/build-frontend.sh` after changing the pinned release.

## Housekeeping

`rust-toolchain.toml` pins the compiler; the code needs edition 2024,
let-chains, `Option::is_none_or` and `u64::is_multiple_of`. CI enforces
`cargo fmt --all --check` and a clippy run with `-D warnings`, and both are
clean — keep them that way rather than adding `allow`s.

This is a derivative work of a GPL-3.0 project and redistributes AdGuard's
compiled frontend, their services catalogue and captured fixtures. `NOTICE.md`
records what came from where; update it when adding anything else of theirs.

## Scope

`README.md` records what is and is not implemented. Endpoints for unimplemented
features answer **501** rather than pretending to succeed — keep it that way; a
setting that silently does nothing is worse than one that reports it cannot.
`TASK.md` tracks the work item by item.

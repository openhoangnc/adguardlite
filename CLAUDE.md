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

## Where things are written down

- **`TASK.md`** — what is done, what is not, and the deliberate deviations.
  **Read it before starting work, and update it when work lands**: it is the
  handoff between sessions, and it is only worth anything if it stays true.
- `README.md` — what this is, and what was measured against the Go build.
- `NOTICE.md` — what came from AdGuard, and how to regenerate it.
- This file — how to work in the repository.

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
| Sessions | `<work>/data/sessions.db`, bucket `sessions-2`, 16-byte token key |
| Web interface | single-page app served from the embedded filesystem at `/` |
| Ports | 53 tcp/udp, 67–68 udp, 80, 443 tcp/udp, 853 tcp/udp, 3000, 5443, 6060 |

## Commands

```bash
cargo build --release            # fast to build and to run
cargo build --profile dist       # fat LTO, panic=abort, stripped: ~10.7 MB
cargo test --workspace           # 585 tests, no network or Go build needed
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
- `dropin.sh` — the migration itself. It configures a real
  `adguard/adguardhome` container, generates traffic, swaps this image in
  underneath it on the same volume, swaps back, and has the Go build read
  everything this one wrote. It needs Docker and both images, nothing else:

  ```bash
  tests/compat/dropin.sh                          # the published image
  tests/compat/dropin.sh adguardlite:local        # one you just built
  ```

  What it checks is that **nothing on the volume has to change**: the config
  file is untouched, sessions issued by either build are honoured by the
  other, and the statistics and query log continue rather than reset. Run it
  after anything that touches an on-disk format, a file mode, or the image.

Committed fixtures under `tests/fixtures/` were all captured from a real
instance: the reference config, 43 query-log lines (one per distinct entry
shape), a real `stats.db`, gob payloads, and the 179,334-rule AdGuard DNS
filter with the verdict Go gave for 4,190 domains.

## Architecture

Ten crates, layered so nothing depends upwards:

```
agl-core                        Go-compatible primitives: durations, byte sizes,
                                filtering reasons, Go's JSON time format, the
                                weekly schedule
agl-config    -> core           AdGuardHome.yaml, schema 34, a YAML emitter that
                                reproduces Go yaml.v3's output, and the
                                migrations from every older schema
agl-filter    -> core, config   rule parser and matcher, list storage,
                                blocked-services catalogue, safe-search rules
agl-dns       -> core, filter   wire codec, cache, upstreams, listeners, EDNS,
                                DNS64, DDR, client registry, the hash-prefix
                                checker, and the resolver that orders every step
agl-querylog  -> core           querylog.json
agl-bolt                        a minimal bbolt reader and writer
agl-gob                         Go `gob` for the statistics unit
agl-stats     -> core, bolt,    collection, aggregation, persistence
                 gob
agl-api       -> all, bolt      the control API, the embedded web interface, the
                                HTTP/3 listener, session storage
adguardlite   -> all            the binary: CLI, wiring, supervision, client
                                discovery, ipset, logging, OS settings, service
                                control
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
4. DDR (`_dns.resolver.arpa`) is answered locally;
5. rewrites apply *even when protection is off*;
6. filtering, in upstream's order: blocklists, then blocked services, then safe
   browsing, then parental control, then safe search. An allowlist match sets
   the verdict but still resolves, and short-circuits everything after it;
7. `AAAA` suppression;
8. a private `PTR` is routed to the local resolvers or answered `NXDOMAIN`;
9. cache;
10. upstream — which is where the client subnet, the DNSSEC `DO` bit,
    request coalescing, `bogus_nxdomain` and DNS64 live.

Which settings apply is decided *before* step 1, by `Resolver::effective`: a
persistent client that does not use the global settings overrides the filtering
toggles, its own blocked services and its own safe search.

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
- **The blocked-services schedule is inverted.** A day range says when the
  block is *paused*, not when it applies, so an empty schedule blocks around
  the clock. `agl-core/src/schedule.rs` exposes `blocks_at` for that reason.
- **Blocked services are a separate engine** from the blocklists, so the
  schedule can pause them per request without rebuilding anything.
- **The config is read before the tokio runtime starts.** Two of the things it
  decides — where the log goes and which user to run as — must be settled while
  the process is still single-threaded, because `setuid` acts on the calling
  thread on Linux.

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

## Encrypted listeners

DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC and HTTP/3 are served. Five things
about how they fit:

- **DoH shares the router with the web interface**, because upstream serves
  both on the HTTPS port. `routes::router(state, secure)` takes whether the
  listener is encrypted; DoH answers over plain HTTP only when
  `http.doh.insecure_enabled` is set, so an operator cannot expose queries by
  accident.
- **DoH goes through `agl_dns::server::Server::handle`**, not straight to the
  resolver, so it gets the same rate limiting, access control, query log and
  statistics as UDP and TCP. Anything added to that path applies to DoH for
  free; anything that bypasses it silently does not.
- **DoQ reuses the same framing.** A query arrives on its own bidirectional
  stream carrying the two-byte length prefix that TCP and DoT use, so only the
  transport differs. `Proto` is exhaustively matched in the query-log mapping,
  so adding a transport there fails the build until it is given a name.
- **HTTP/3 is a fourth listener on the HTTPS port**, over UDP rather than TCP,
  and it hands requests to the same `Router`. `agl-api/src/http3.rs` inserts
  `ConnectInfo` itself, because nothing does it for a hand-driven router.
- **The certificate is reloadable.** The listeners are built around
  `tls::Reloadable`, a `ResolvesServerCert` that reads from a shared slot, so
  `/control/tls/configure` takes effect on the next handshake. Listener *ports*
  still need a restart.

`tests/compat/dns-oracle` is the check that matters: it drives AdGuard's own
dnsproxy client against a listener, with the certificate verified rather than
skipped.

## Three exclusions, all deliberate

DHCP, DNSCrypt and replacing the binary with an AdGuard Home release are
decisions, not gaps. Each refuses clearly where a user would notice, and
`TASK.md` records the reasoning for each.

**DHCP.** The API reports the feature off and refuses every change, so the
interface cannot store settings nothing acts on. Two things follow that are
easy to get wrong:

- **`DhcpConfig` in `agl-config` stays.** The config file must round-trip byte
  for byte, and a user switching back to the Go build keeps their settings.
  Deleting the model breaks the golden test in `agl-config/src/file.rs`.
- **`dhcp_status` must not echo the stored config.** Reporting a stored
  `enabled: true` tells the interface a server is running when none is.

**DNSCrypt.** No listener, and an `sdns://` upstream is reported at startup and
skipped. It is the only protocol left that needs cryptography the tree does not
already carry, and a mistake in it fails silently.

**`POST /control/update`.** The published releases are AdGuard Home's own Go
binaries, so installing one would swap in a different implementation. The
version *check* works, caches for eight hours, and reports
`can_autoupdate: false` so the interface does not offer the button.

## Scope, and keeping it honest

Endpoints for unimplemented features answer **501** rather than pretending to
succeed — keep it that way. A setting that silently does nothing is worse than
one that reports it cannot: blocked services and the hosts file were both
stored, exposed through the API and ignored by the resolver for a while, which
looked like working features from the UI.

When something lands, move it in `TASK.md` and say how it was verified. When
something turns out to be deliberate rather than missing, record it under the
exclusions or the deviations there instead of leaving it to be rediscovered.

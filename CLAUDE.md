# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**Sift** is a Rust backend for AdGuard Home, built as a **drop-in
replacement** for the Go binary of release **v0.107.79**. It reads and writes
the same config file, the same on-disk data, serves the same HTTP API, and
ships in a Docker image with the same runtime contract. The web interface is a
**fork** of AdGuard Home's, under `web/client`, with the excluded features
taken out of it and the branding changed.

The binary reports its **own** version — `sift_core::VERSION`, from the
workspace version, starting at v0.2.0. `sift_core::AGH_COMPAT_VERSION` records
the AdGuard Home release the formats are matched against; that is what every
compatibility claim in the tree means, not the reported version.

The overriding constraint is **compatibility, not elegance**. Where a format or
a behaviour looks odd, it is almost certainly odd because Go does it that way,
and changing it breaks a real user's installation. Read the comments before
"fixing" anything in a serialiser, a wire format or an API response shape.

## Where things are written down

- **`docs/`** — the documentation the web interface links to: FAQ,
  configuration, clients, encryption, privacy. A behaviour described there is a
  promise; check it against the code before repeating it.
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
| Version | **not** part of the contract: this build reports its own, not v0.107.79 |
| Ports | 53 tcp/udp, 67–68 udp, 80, 443 tcp/udp, 853 tcp/udp, 3000, 5443, 6060 |

## Commands

```bash
cargo build --release            # fast to build and to run
cargo build --profile dist       # fat LTO, panic=abort, stripped: ~10.7 MB
cargo test --workspace           # 706 tests, no network or Go build needed
cargo clippy --workspace --all-targets
```

Running one test or one crate:

```bash
cargo test -p sift-filter                          # one crate
cargo test -p sift-filter --lib engine             # one module's tests
cargo test -p sift-filter --test differential      # one integration test file
cargo test -p sift-config reproduces_the_reference -- --exact --nocapture
```

Tests that need outbound network are `#[ignore]`d:

```bash
cargo test -p sift-dns --test live -- --ignored     # real DoT/DoH upstreams
```

Running the server:

```bash
cargo run --release -- --no-check-update -c ./AdGuardHome.yaml -w ./work
```

Rebuilding the web interface — needs Node:

```bash
scripts/build-frontend.sh         # web/client -> web/build, brotli-compressed
scripts/sync-frontend.sh v0.1.2   # merge a newer upstream client into the fork
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
  the legacy `/control/querylog_info` reports **days**;
- a plain entry in `dns.blocked_hosts` matches that name and *nothing else* —
  not its subdomains — while `||name^` matches the subdomains too.

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
  tests/compat/dropin.sh sift:local        # one you just built
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
sift-core                        Go-compatible primitives: durations, byte sizes,
                                filtering reasons, Go's JSON time format, the
                                weekly schedule
sift-config    -> core           AdGuardHome.yaml, schema 34, a YAML emitter that
                                reproduces Go yaml.v3's output, and the
                                migrations from every older schema
sift-filter    -> core, config   rule parser and matcher, list storage,
                                blocked-services catalogue, safe-search rules
sift-dns       -> core, filter   wire codec, cache, upstreams, listeners, EDNS,
                                DNS64, DDR, client registry, the hash-prefix
                                checker, and the resolver that orders every step
sift-querylog  -> core           querylog.json
sift-bolt                        a minimal bbolt reader and writer
sift-gob                         Go `gob` for the statistics unit
sift-stats     -> core, bolt,    collection, aggregation, persistence
                 gob
sift-api       -> all, bolt      the control API, the embedded web interface, the
                                HTTP/3 listener, session storage
sift   -> all            the binary: CLI, wiring, supervision, client
                                discovery, ipset, logging, OS settings, service
                                control
```

`sift-api` and `sift-filter` deliberately hold no HTTP client. Downloading filter
lists is injected by the binary through the `ListFetcher` trait in
`sift-api/src/state.rs`, and pushing config changes into the running server goes
through `Reloader` in the same file. That is why `sift-filter::lists::Manager`
exposes `apply_fetched` rather than a `refresh` that downloads.

### The request path

`sift-dns/src/resolver.rs` is the file to read first. The **order** of its steps
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
- **`sift-config`'s YAML emitter is hand-written** because Go's yaml.v3 indents
  sequences under their key and prefers single quotes, and no Rust YAML crate
  does both. `reproduces_the_reference_config_byte_for_byte` guards it.
- **`NetworkRule` is 56 bytes and that is load-bearing.** A real list holds
  ~180,000 of them. When the modifiers were stored inline the struct was 296
  bytes and the engine used *more* memory than Go. `crates/sift-filter/tests/
  sizes.rs` fails if the layout regresses.
- **Reserved filter list IDs** match upstream's `rulelist.APIID`: `0` custom
  rules, `-1` the system hosts file, `-2` blocked services. The resolver maps
  these to the reason the web UI expects.
- **Byte-identical `gob` output is not a goal.** Go's own encoder does not
  reproduce its own bytes for the same value, because type-definition order
  depends on how the types were first walked. The bar is that each side decodes
  the other.
- **The binary target is named `AdGuardHome`**, so `module_path!` reports that,
  not the package name. A log filter spelled `sift=info` compiles and
  matches nothing; `crates/sift/src/main.rs` has a test guarding this.
- **The blocked-services schedule is inverted.** A day range says when the
  block is *paused*, not when it applies, so an empty schedule blocks around
  the clock. `sift-core/src/schedule.rs` exposes `blocks_at` for that reason.
- **Blocked services are a separate engine** from the blocklists, so the
  schedule can pause them per request without rebuilding anything.
- **`dns.blocked_hosts` holds rules, not names**, and an `@@` exception in it
  *blocks*. Upstream's `isBlockedHost` keeps only "something matched" from its
  engine and throws the match itself away, so an exception rule refuses the
  query like any other. `sift-dns/src/blocked.rs` reproduces that deliberately,
  and its tests record what a running Go build answered for each form.
- **The config is read before the tokio runtime starts.** Two of the things it
  decides — where the log goes and which user to run as — must be settled while
  the process is still single-threaded, because `setuid` acts on the calling
  thread on Linux.

## Build speed

The workspace is split so `cargo` parallelises across crates. Dependencies are
built at `opt-level = 2` even in debug so they are paid for once; our own crates
stay unoptimised with line-tables-only debug info. An incremental rebuild after
touching one file is roughly 8 seconds. Prefer a hand-written implementation to
a new dependency when the need is narrow — that is why `sift-bolt`, `sift-gob`
and the HTTPS fetch in `crates/sift/src/fetch.rs` exist.

## The web interface

**The sources live in `web/client`** — a fork of AdGuard Home v0.107.79's
`client/` at commit `05ba17b2`, with DHCP and DNSCrypt removed, the branding
changed to Sift and every outbound link repointed. `NOTICE.md` lists
what changed, states the modification for GPL-3.0 §5(a), and records the
trademark position. Before editing, remember it is someone else's React app:
match its shape rather than improving it.

**Taking a newer upstream client**: `scripts/sync-frontend.sh v0.107.80` three-way
merges upstream's own diff between the recorded base and that tag. It prints
the checks to run afterwards — chiefly that DHCP and DNSCrypt have not come
back and that no `link.adtidy.org` link has. Bump the base in the script and in
`NOTICE.md` when a sync lands.

The build is committed under `web/build`, **brotli**-compressed (9.1 MB of
assets → 1.7 MB in the binary), and embedded by `sift-api/src/ui.rs`. Rebuild it
with `scripts/build-frontend.sh` after **any** change under `web/client` — the
committed output is what ships, and a source change nobody built is invisible.

Three things about how assets are served:

- **Brotli only, no gzip on the wire.** The stored form is `.br`; a client that
  accepts `br` gets those bytes, and anything else is decompressed on the way
  out. Over plain HTTP most browsers still advertise only gzip, so those
  clients pay a decompression — which is affordable only because of the
  caching below.
- **A name carrying a content hash is cached forever.** `is_content_addressed`
  spots webpack's `main.<20 hex>.js`, and those get `immutable` with a year's
  `max-age`. The three HTML shells and the icons get `no-cache`, so a new build
  is picked up.
- **Every response carries an `ETag`** — the stored file's SHA-256, per
  *representation*: the compressed and decompressed forms must not share one,
  or a cache hands the wrong bytes to the wrong client. `If-None-Match` is
  answered with a 304 before the body is touched.

Working on the frontend:

```bash
cd web/client
npx tsc --noEmit                 # typecheck
npx eslint --ext .ts,.tsx src    # lint; CI-clean, keep it that way
npx vitest --run                 # unit tests
```

Locale keys live in `src/__locales/*.json`, 36 files, alphabetically sorted.
`en.json` is the source of truth; a key removed there must be removed from all
36. All 36 say "Sift" — when renaming across them, check what attaches
to the name: Korean particles and Finnish vowel harmony both change with it,
and `TASK.md` records which ones moved.

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
- **DoH goes through `sift_dns::server::Server::handle`**, not straight to the
  resolver, so it gets the same rate limiting, access control, query log and
  statistics as UDP and TCP. Anything added to that path applies to DoH for
  free; anything that bypasses it silently does not.
- **DoQ reuses the same framing.** A query arrives on its own bidirectional
  stream carrying the two-byte length prefix that TCP and DoT use, so only the
  transport differs. `Proto` is exhaustively matched in the query-log mapping,
  so adding a transport there fails the build until it is given a name.
- **HTTP/3 is a fourth listener on the HTTPS port**, over UDP rather than TCP,
  and it hands requests to the same `Router`. `sift-api/src/http3.rs` inserts
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

- **`DhcpConfig` in `sift-config` stays.** The config file must round-trip byte
  for byte, and a user switching back to the Go build keeps their settings.
  Deleting the model breaks the golden test in `sift-config/src/file.rs`.
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

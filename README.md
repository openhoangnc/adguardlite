# sift

[![Docker](https://github.com/openhoangnc/sift/actions/workflows/docker.yml/badge.svg)](https://github.com/openhoangnc/sift/actions/workflows/docker.yml)
[![Image](https://img.shields.io/badge/ghcr.io-openhoangnc%2Fsift-blue?logo=docker&logoColor=white)](https://github.com/openhoangnc/sift/pkgs/container/sift)

**Sift** is a Rust backend for
[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), built as a drop-in
replacement for the Go binary of release **v0.107.79**: the same config file,
the same on-disk data, the same HTTP API, and the same Docker contract — in a
smaller image, with less memory and more throughput. The web interface is a
fork of AdGuard Home's own, with the features this build does not have taken
out of it.

The DNS filtering path, the web interface, the storage formats, the encrypted
listeners and the operational surface are done and verified against the Go
build. Three things are **deliberately excluded** rather than pending —
DHCP, DNSCrypt, and replacing this binary with a release — and each refuses
clearly at the point a user would notice. [What is excluded, and
why](#what-is-excluded-and-why) explains each one.

It is not produced, endorsed or supported by AdGuard; see
[NOTICE.md](NOTICE.md). Documentation is under [`docs/`](docs/):
[FAQ](docs/faq.md) · [Configuration](docs/configuration.md) ·
[Clients](docs/clients.md) · [Encryption](docs/encryption.md) ·
[Privacy](docs/privacy.md).

## Measured against the Go build

Both running the same config and the same 179,334-rule AdGuard DNS filter, on
the same machine.

| | Go v0.107.79 | sift | |
|---|---:|---:|---|
| Docker image | 110 MB | **56.9 MB** | 1.9× smaller |
| Binary (with web UI) | 33.6 MB | **20.3 MB** | 1.7× smaller |
| Binary (`dist` profile) | 33.6 MB | **10.7 MB** | 3.1× smaller |
| Memory, idle with lists loaded | 85.2 MB | **73.2 MB** | 1.2× less |
| Memory, after load | 186.8 MB | **83.1 MB** | 2.2× less |
| Throughput (blocked queries) | 39,059 q/s | **51,509 q/s** | 1.32× |
| Latency p90 | 2.896 ms | **1.436 ms** | 2.0× better |
| Latency p99 | 6.178 ms | **1.960 ms** | 3.2× better |

Memory, throughput and latency were measured in one sitting with both servers
running the same config and the same filter list, 15 seconds at concurrency 64
against 5,000 blocked names. The load generator in
`crates/sift/examples/loadgen.rs` runs on the same machine as the
servers and so competes with them for CPU; treat the ratios as meaningful and
the absolute numbers as a floor. The binary sizes compare against AdGuard's
published release, not a local `go build`, which is larger because it keeps
its debug info.

### At a larger list count

That table is one 179,334-rule list, which is a modest deployment. A real one
with **37 lists and 2,272,040 rules**, measured the same way on the same
machine with the same data:

| | Go v0.107.79 | sift | |
|---|---:|---:|---|
| Time to answer DNS from a cold start | 4 s | **2 s** | 2× quicker |
| Memory, after loading the lists | 346 MB | **267 MB** | 1.3× less |

It took work to get there, and the starting point is worth recording: the same
deployment once took **55 seconds and 4.2 GB** — fourteen times Go's startup
and twelve times its memory. Three things were wrong, each found by measuring
rather than reading:

- **Every rule that is not `||domain^` compiled a regular expression at load.**
  156,557 of them here. They are built on first use now, which was 22 of those
  55 seconds.
- **The match path allocated per candidate rule and per query** — a formatted
  `String` to test an empty `$badfilter` set, a `format!` for the URL, a hash
  set for deduplication.
- **The indexes were far larger than the data they held**: a domain index of
  boxed key strings costing 148 MB for 1.1M domains, and rule text copied into
  the engine when the list manager already held every byte of it.

The shortcut index is the piece worth reading: `crates/sift-filter/src/
shortcut.rs` replaced an Aho-Corasick automaton, which is the textbook answer
and was the wrong one here. Its 37.6 MB is walked one state-transition per
byte, each dependent on the last, so a hostname's length buys a chain of cache
misses. The haystack is tiny and the patterns are long, so each pattern is
filed instead under whichever eight-byte window of itself is *rarest* across
the whole set, and a query hashes its own windows independently — 7.4 MB, and
the probes overlap in the memory system instead of chaining.

Guards: `rules_needing_an_expression_load_as_cheaply_as_plain_ones` in
`crates/sift-filter/tests/differential.rs` fails if expressions go back to
being built at load. `cargo run --release -p sift-filter --example loadprofile
<dir of lists>` prints the phase timings, a footprint breakdown and per-query
costs, which is how all of the above was measured.

## The published image

A multi-architecture image — `linux/amd64` and `linux/arm64`, so it runs on a
Raspberry Pi as well as a server — is published to the GitHub Container
Registry on every push to `main`:

```bash
docker pull ghcr.io/openhoangnc/sift:latest
```

| Tag | What it points at |
|---|---|
| `latest` | the newest build of `main` |
| `sha-<short>` | one specific commit |
| `1.2.3`, `1.2` | a `v1.2.3` release tag |

The registry keeps only the **newest three releases**; everything older is
deleted, `sha-` tags included. Deploy against a `sha-` tag rather than `latest`
if you want a restart to redeploy the same bytes, and mirror the image into
your own registry — or rebuild it from the commit — if you need one to stay
pullable for longer than three builds.

It is a drop-in for `adguard/adguardhome`: same binary path, working directory,
exposed ports and entrypoint arguments. An existing deployment only changes its
`image:` line, and keeps its config and data directory as they are — bind
mounts or named volumes alike, and nobody is signed out.

Switching back is the same one-line change. Both builds read each other's
`AdGuardHome.yaml`, `querylog.json`, `stats.db`, `sessions.db` and downloaded
filter lists, so a rollback costs nothing.

```yaml
services:
  adguardhome:
    image: ghcr.io/openhoangnc/sift:latest
    container_name: adguardhome
    restart: unless-stopped
    volumes:
      - ./work:/opt/adguardhome/work
      - ./conf:/opt/adguardhome/conf
    ports:
      - 53:53/tcp
      - 53:53/udp
      - 3000:3000/tcp
```

Or directly:

```bash
docker run -d --name adguardhome \
  -v "$PWD/work:/opt/adguardhome/work" \
  -v "$PWD/conf:/opt/adguardhome/conf" \
  -p 53:53/tcp -p 53:53/udp -p 3000:3000/tcp \
  ghcr.io/openhoangnc/sift:latest
```

To build the same image yourself:

```bash
docker build -f docker/Dockerfile -t sift .
```

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
| DNS-over-TLS, -HTTPS and -QUIC | interoperable | AdGuard's own dnsproxy client, verifying the certificate, resolves through all three listeners. |
| Config migration | all 34 steps | A port of `internal/configmigrate`; a config from any older schema is upgraded and the upgraded file written back. |
| `sessions.db` | same layout | Sessions are stored the way the Go build stores them, so a restart signs nobody out and either build reads the other's file. |
| Docker | same contract | Entrypoint, command, working directory, user, volumes, exposed ports, environment, healthcheck and stop signal are identical. A configured `adguard/adguardhome` container was swapped to this image on the same volumes and swapped back: the config file survived byte for byte, sessions stayed valid in both directions, and each build read the other's `querylog.json`, `stats.db` and filter cache. |

Reproduce it with `scripts/verify.sh` (see [Verifying](#verifying)).

## What is excluded, and why

Three features are decisions rather than gaps. Nothing else in the Go build's
surface is missing; `TASK.md` records the full state and the smaller deviations
(cited rule on ties, `gob` byte-equality, ipset through the command rather than
netlink, and a few more).

- **DHCP.** This build will not serve DHCP; run it on your router or a
  dedicated service. `/control/dhcp/status` always reports the feature off and
  every settings change answers **501**, so the web interface cannot store DHCP
  configuration that nothing would act on. The `dhcp:` section of the config
  file is still read and written unchanged, so switching back to the Go build
  keeps your settings, and the DHCP settings page is gone from the web
  interface rather than present and inert.

- **DNSCrypt.** It is the one remaining protocol needing cryptography this
  project does not already have — X25519, Ed25519 and a NaCl-style secretbox —
  plus a signed-certificate protocol and AdGuard's provider-key file format,
  and a mistake there fails silently rather than visibly. `port_dnscrypt` and
  `dnscrypt_config_file` round-trip through the config untouched; the port is
  never bound, and an `sdns://` upstream is reported at startup and skipped.
  DNSCrypt itself is still in use — AdGuard's own provider list publishes
  stamps for it — so front sift with `dnscrypt-proxy` if you need it.
  The web interface no longer offers it anywhere.

- **Replacing its own binary.** `POST /control/update` answers **501**.
  Rewriting a running executable in place is the job of whatever installed it,
  and this ships as an image and as archives. The version check itself works:
  `/control/version.json` reads
  [this project's releases](https://github.com/openhoangnc/sift/releases),
  caches the answer for eight hours and reports `can_autoupdate: false`, so the
  interface can tell you a new version exists without offering to install it.
  See [the FAQ](docs/faq.md#manual-update).

## Layout

```
crates/sift-core      shared types matching Go's wire and on-disk forms
crates/sift-config    AdGuardHome.yaml: schema 34, and a Go-yaml.v3 emitter
crates/sift-filter    the rule engine, list storage, services catalogue
crates/sift-dns       wire codec, cache, upstreams, listeners, resolver
crates/sift-querylog  querylog.json
crates/sift-bolt      a minimal bbolt reader and writer
crates/sift-gob       Go `gob` for the statistics unit
crates/sift-stats     statistics collection, aggregation and persistence
crates/sift-api       the control API and the embedded web interface
crates/sift   the binary
web/client           the forked web interface, in TypeScript and React
web/build            the same, built and brotli-compressed for embedding
docs                 the documentation the web interface links to
```

## Building

```bash
cargo build --release            # fast to build, fast to run
cargo build --profile dist       # fat LTO, stripped: the 10.7 MB binary
```

The workspace is split so `cargo` parallelises across crates, dependencies are
compiled at `opt-level = 2` even in debug builds so they are paid for once, and
debug info is line tables only. An incremental rebuild after touching one file
is about 8 seconds.

The web interface's sources are forked into `web/client`, and the build is
committed under `web/build`, brotli-compressed: ~9.1 MB of JavaScript and CSS
become 1.7 MB in the binary. Rebuild it after any change under `web/client`:

```bash
scripts/build-frontend.sh
```

Hashed bundles go under `web/build/static/` and are served `immutable` for a
year; everything else revalidates and is answered with a `304` when nothing
moved.

To take a newer upstream client release into the fork:

```bash
scripts/sync-frontend.sh v0.107.80
```

## Running from source

```bash
cargo run --release -- --no-check-update -c ./AdGuardHome.yaml -w ./work
```

## Verifying

`cargo test --workspace` runs 706 unit and integration tests, including the
differential against the real filter list and the query-log and gob golden
files — none of which need a network or a running Go build.

The cross-implementation checks need both servers running:

```bash
scripts/verify.sh
```

It builds the Go reference from `upstream/`, starts both, and runs the config,
DNS, API and statistics comparisons described above.

The drop-in claim has its own check, which needs only Docker and the two
images:

```bash
tests/compat/dropin.sh
```

It configures a real `adguard/adguardhome` container, generates traffic, swaps
this image in on the same volume, swaps back, and has the Go build read
everything this one wrote — 27 assertions, from the image's entrypoint and
exposed ports through to whether a session issued by one build is still
honoured by the other.

## Continuous integration

One workflow runs on its own. `.github/workflows/docker.yml` builds the image
for both architectures on native runners — no emulation — publishes a single
multi-architecture tag to GHCR, and then prunes the package back to the newest
three releases. Documentation-only commits are skipped, and a newer push
cancels an in-flight build.

`.github/workflows/ci.yml` — formatting, lints, the 621-test suite, and the
differential against a freshly cloned AdGuard Home — is `workflow_dispatch`
only. It costs nothing until it is started from the Actions tab, because all of
it also runs locally: `cargo test --workspace` and `scripts/verify.sh`.

## Licence

GPL-3.0, matching AdGuard Home. This is a derivative work: it redistributes
AdGuard's compiled web interface, their blocked-services catalogue and
fixtures captured from a running instance. [NOTICE.md](NOTICE.md) lists what
came from where, and how to regenerate it.

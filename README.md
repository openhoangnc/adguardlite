# adguardlite

A Rust backend for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome),
built as a drop-in replacement for the Go binary of release **v0.107.79**: the
same config file, the same on-disk data, the same HTTP API, the same web
interface, and the same Docker contract — in a smaller image, with less memory
and more throughput.

The DNS filtering path, the web interface, the storage formats, the encrypted
listeners and the operational surface are done and verified against the Go
build. Three things are **deliberately excluded** rather than pending —
DHCP, DNSCrypt, and replacing this binary with an AdGuard Home release — and
each refuses clearly at the point a user would notice. [What is excluded, and
why](#what-is-excluded-and-why) explains each one.

## Measured against the Go build

Both running the same config and the same 179,334-rule AdGuard DNS filter, on
the same machine.

| | Go v0.107.79 | adguardlite | |
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
`crates/adguardlite/examples/loadgen.rs` runs on the same machine as the
servers and so competes with them for CPU; treat the ratios as meaningful and
the absolute numbers as a floor. The binary sizes compare against AdGuard's
published release, not a local `go build`, which is larger because it keeps
its debug info.

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
| Docker | same contract | Same binary path, working directory, ports and entrypoint arguments; run against a config and data directory a Go instance produced. |

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
  keeps your settings.

- **DNSCrypt.** It is the one remaining protocol needing cryptography this
  project does not already have — X25519, Ed25519 and a NaCl-style secretbox —
  plus a signed-certificate protocol and AdGuard's provider-key file format,
  and a mistake there fails silently rather than visibly. `port_dnscrypt` and
  `dnscrypt_config_file` round-trip through the config untouched; the port is
  never bound, and an `sdns://` upstream is reported at startup and skipped.
  DNSCrypt itself is still in use — AdGuard's own provider list publishes
  stamps for it — so front adguardlite with `dnscrypt-proxy` if you need it.

- **Replacing its own binary.** `POST /control/update` answers **501**. The
  releases the announcement server publishes are AdGuard Home's own Go
  binaries; writing one over this executable would swap in a different
  implementation, which is not an update. The version check itself works:
  `/control/version.json` reports the latest release with
  `can_autoupdate: false`, so the interface can tell you a new version exists
  without offering to install it. Replace the binary through whatever installed
  it.

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
cargo build --profile dist       # fat LTO, stripped: the 10.7 MB binary
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

`cargo test --workspace` runs 555 unit and integration tests, including the
differential against the real filter list and the query-log and gob golden
files — none of which need a network or a running Go build.

The cross-implementation checks need both servers running:

```bash
scripts/verify.sh
```

It builds the Go reference from `upstream/`, starts both, and runs the config,
DNS, API and statistics comparisons described above.

## Continuous integration

`.github/workflows/ci.yml` runs three jobs: formatting, lints and the test
suite; the cross-implementation differential against a freshly cloned AdGuard
Home; and a Docker build whose image is then started and queried.

## Licence

GPL-3.0, matching AdGuard Home. This is a derivative work: it redistributes
AdGuard's compiled web interface, their blocked-services catalogue and
fixtures captured from a running instance. [NOTICE.md](NOTICE.md) lists what
came from where, and how to regenerate it.

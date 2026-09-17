# Task tracker

Work status for Sift, against AdGuard Home **v0.107.79**.

Legend: **[x]** done and verified · **[~]** partial, see the note · **[ ]** not started

Verification claims below are reproducible with `scripts/verify.sh` and
`cargo test --workspace` (706 tests).

---

## Summary

| Area | State |
|---|---|
| Config file | done, byte-identical to Go · migrates schema 0–33 |
| Filtering engine | done, every verdict matches Go on the real list |
| DNS (plain UDP/TCP) | done |
| Upstreams | plain UDP/TCP, DoT, DoH, DoH/3, DoQ done · DNSCrypt **out of scope** |
| Query log | done, byte-identical |
| Statistics | done, `stats.db` interoperable both ways |
| HTTP API | all 81 paths routed · 73 implemented, 8 refuse by design |
| Web interface | forked into `web/client`, built to `web/build`, embedded |
| Docker | done, same runtime contract |
| DHCP | **out of scope** — API reports it off and refuses changes |
| Encrypted inbound listeners | DoT, DoH, HTTP/3 and DoQ done · DNSCrypt **out of scope** |
| Safe browsing / parental / safe search | done |
| Clients | persistent settings, ClientID, ARP/rDNS/WHOIS/hosts discovery |
| Operations | logging, rotation, pidfile, privileges, service install |
| Self-update | **out of scope** — the check reports releases, the install refuses |
| Version reported | this project's own, from the workspace version — v0.3.0 |

---

## Done

### Configuration
- [x] `AdGuardHome.yaml` schema 34: full model, field order preserved
- [x] YAML emitter reproducing Go yaml.v3's style — sequence indentation,
      single-quote preference, `""` for the empty string, `[]`/`{}` inline
- [x] Byte-identical round-trip against a config a real instance wrote
- [x] Byte-identical output after the same API changes applied to both servers
- [x] Atomic save (write to a sibling temp file, then rename, mode 0600)
- [x] Default config written on first run
- [x] A newer schema version is refused rather than misread
- [x] **Migration from every older schema**, a port of `internal/configmigrate`:
      all 34 steps, including the ones that are easy to get backwards — a
      statistics interval of zero becomes *disabled* with a one-day interval,
      and a bare `.` in an ignore list becomes `|.^`. The upgraded file is
      written back, as upstream does

### Filtering engine
- [x] Adblock rule parser: `||domain^`, `|`, `^`, `*`, `@@` exceptions, `/regex/`
- [x] Hosts-file rules, including address-family selection for A/AAAA
- [x] Modifiers: `$important`, `$badfilter`, `$dnstype`, `$client`, `$ctag`,
      `$denyallow`, `$dnsrewrite`; HTTP-only modifiers accepted and ignored
- [x] Pattern → regex translation mirroring urlfilter, including the two
      details that decide real results: bare patterns match the **hostname**
      rather than the pseudo-URL, and every pattern is case-insensitive
- [x] Indexed lookup: domain suffix walk, Aho–Corasick shortcut prefilter,
      scan list for the remainder
- [x] Rule priority matching upstream: whitelist+important, important,
      whitelist, then specifier count
- [x] Separate allowlist engine that short-circuits
- [x] **Verified**: 4,190 domains against the real 179,334-rule AdGuard DNS
      filter — every verdict matches Go; 99.2% also cite the same rule
- [x] Memory layout guarded at 56 bytes per rule (`tests/sizes.rs`)
- [x] Legacy DNS rewrites, including wildcards and the `A`/`AAAA` suppressors
- [x] Blocked services, enforced from the bundled 139-service catalogue
- [x] Blocked-services **schedule**: the weekly pause windows are honoured, in
      the configured time zone, globally and per client
- [x] System hosts file, when `hostsfile_enabled` is set
- [x] Filter list storage in `data/filters/<id>.txt`, download and refresh
- [x] **Safe search**, from AdGuard's own rule files for Bing, DuckDuckGo,
      Ecosia, Google, Pixabay, Yandex and YouTube, global and per client
- [x] **Safe browsing** and **parental control** over the hash-prefix protocol:
      SHA-256 prefixes in a `TXT` question to AdGuard's family resolver, with
      the bucket cache upstream keeps

### DNS
- [x] Plain DNS over UDP and TCP, with TCP connection reuse and idle timeout
- [x] Truncation handling, both directions
- [x] Upstreams: plain UDP, TCP, DNS-over-TLS, DNS-over-HTTPS, DNS-over-QUIC,
      and DNS-over-HTTPS carried by HTTP/3 (`use_http3_upstreams`, falling
      back to HTTP/2 when a server does not speak it, and remembering that it
      had to)
- [x] **Upstream connections are kept**, not built per query: one multiplexed
      HTTP/2 connection per DoH address, one QUIC connection per DoQ and
      HTTP/3 address with a 20 s keep-alive under a 30 s idle timeout, and a
      checkout pool for DoT and TCP. Every reply is checked against the
      question that was asked before its connection is reused, as dnsproxy's
      `validateResponse` does. Measured against Quad9 and AdGuard, p50 per
      query: DoT 157.6 → 47.8 ms, DoH 162.7 → 54.2 ms, DoQ 160.9 → 55.3 ms,
      HTTP/3 162.9 → 53.9 ms, TCP 102.0 → 51.9 ms, with plain UDP flat at
      ~53 ms throughout as the control
- [x] `upstream_dns_file`, read afresh on each reload
- [x] The upstream pools are rebuilt when the settings behind them change, so
      an upstream edited through the interface takes effect without a restart
      — see *Found auditing the DNS settings page* below
- [x] Bootstrap resolution for encrypted upstreams' hostnames
- [x] Upstream specification syntax including `[/domain/]` groups and the `#`
      deferral form
- [x] Upstream modes: load balance (latency-ranked), parallel, fastest address
- [x] Fallback resolvers
- [x] Response cache: sized in bytes, sharded, TTL bounds, keyed on the EDNS
      `DO` bit so a validating client is never served a stripped answer
- [x] **Optimistic caching**: an expired entry still inside
      `cache_optimistic_max_age` is served at once, stamped with
      `cache_optimistic_answer_ttl`, and fetched again out of band. Measured
      answer-for-answer against the Go build — see *Found optimising the
      upstream query path* below
- [x] Blocking modes: default, custom IP, NXDOMAIN, null IP, REFUSED —
      including the negative-caching SOA's exact field values
- [x] Rate limiting per client subnet, with an exemption list
- [x] Access control: allowed and disallowed clients
- [x] Blocked hosts dropped on UDP, REFUSED on TCP
- [x] **EDNS Client Subnet**: the client's address masked to /24 or /56, or a
      configured one; never a loopback or private address, and recorded in the
      query log's `ECS` field
- [x] **DNSSEC**: the `DO` bit is set on upstream queries when `enable_dnssec`
      is on, so a validating client below this server receives signatures
- [x] **DNS64** synthesis (RFC 6147): an empty `AAAA` answer is retried as `A`
      and mapped into the NAT64 prefix, with the Well-Known Prefix as default
- [x] **`bogus_nxdomain`**: an answer inside a configured network becomes
      `NXDOMAIN`
- [x] **DDR** (`handle_ddr`): `_dns.resolver.arpa` is answered with `SVCB`
      records for the encrypted listeners that are actually running — DoT only
      when the certificate names an IP address, as upstream requires
- [x] **Duplicate-request coalescing** (`pending_requests`): identical
      questions in flight share one upstream exchange, keyed by question and
      client subnet
- [x] **`max_goroutines`** as a bound on requests handled at once
- [x] **Private reverse DNS**: a `PTR` for a locally-served address goes to
      `local_ptr_upstreams` — or the resolvers the operating system is
      configured with, when none are named — and is answered `NXDOMAIN` rather
      than forwarded when `use_private_ptr_resolvers` is off
- [x] **`ipset`** and **`ipset_file`**: resolved addresses are added to the
      named sets, with a cache so a repeat costs nothing
- [x] **Verified**: 2,046 names over A and AAAA against Go — no verdict differs

### Encryption
- [x] Certificate and key loading, inline or from a path, with the conflict
      upstream rejects
- [x] Chain verification against the trusted roots, reported as a warning while
      still serving — a self-signed certificate works and says so
- [x] `GET /control/tls/status`, `POST /control/tls/validate`,
      `POST /control/tls/configure`
- [x] **DNS-over-TLS listener**
- [x] **DNS-over-HTTPS listener**, GET and POST, with the ClientID path segment
- [x] **DNS-over-QUIC listener** (RFC 9250), one query per bidirectional
      stream, served concurrently on a shared connection
- [x] **HTTP/3** (`serve_http3`): the web interface and DNS-over-HTTPS over
      QUIC on the HTTPS port, sharing the router with the TCP listener
- [x] HTTPS for the web interface, sharing the port with DoH as upstream does
- [x] DoH refused over plain HTTP unless `insecure_enabled` is set
- [x] **`force_https`**: the plain listener redirects to the HTTPS port,
      leaving `/dns-query` alone because a DoH client follows no redirect
- [x] **Certificate reload without a restart**: the listeners are given a
      resolver rather than a certificate, so one replaced through
      `/control/tls/configure` is served on the next handshake
- [x] **Renewal on disk is picked up**: when the certificate or key is read
      from a path, the files are compared against what is being served on the
      maintenance tick, and a changed pair installed for the next handshake —
      an ACME client rewrites them on its own schedule and nothing in the
      config moves when it does. A pair caught half-written replaces nothing
      and is retried a minute later; a certificate inside a week of expiry
      with nothing renewing it is reported hourly, and an expired one as an
      error
- [x] **Verified**: AdGuard's own dnsproxy client, with full certificate
      verification, resolves through all three listeners; the query log records
      them as `dot`, `doh` and `doq`; `/control/tls/status` matches Go field for
      field with the same certificate loaded
- [x] **Verified**: a running server serving one certificate over HTTPS and
      DoT, its files overwritten underneath it — the certificate alone first,
      which was refused as a mismatched pair while the old one kept being
      served, then the key, after which both listeners handed out the new
      certificate on the next handshake without a restart

### Clients
- [x] Persistent clients matched by address, subnet, MAC or ClientID, most
      specific first
- [x] Per-client settings actually applied: filtering, safe browsing, parental
      control, safe search, blocked services and their schedule, and exclusion
      from the query log or the statistics
- [x] **ClientID** from the DoH path segment and from the name a DoT or DoQ
      client asks for — only the label directly below the server's own name, so
      an unrelated name cannot claim an identifier
- [x] **Discovery**: the system hosts file, the ARP table (`/proc/net/arp` or
      `arp -an`), reverse DNS through this server's own resolver, and WHOIS for
      addresses outside the local networks
- [x] `/control/clients` reports discovered clients as `auto_clients`, and the
      query log carries the name in `client_info`
- [x] **`trusted_proxies`**: `X-Forwarded-For` is honoured only from a listed
      proxy, so a client cannot claim another's address — and with it another
      client's settings

### Storage
- [x] `querylog.json`: exact JSON shape, in-memory buffer, reverse chunked
      reads for the API
- [x] Query log rotation on `querylog.interval`, decided from the first
      record in the file as upstream's `checkAndRotate` does
- [x] **Verified**: 43 real log lines re-encode byte for byte
- [x] Query log search by name, address, client name and ClientID, and the
      `older_than` cursor
- [x] Statistics: hourly units, upstream's result categories and quirks
- [x] One live hour held in full, finished hours held in the top-N form
      they are stored in, as `internal/stats` holds them
- [x] `sift-bolt`: bbolt reader and writer
- [x] `sift-gob`: Go `gob` for the statistics unit
- [x] **Session persistence** in `sessions.db`, in the layout the Go build
      uses, so a restart does not sign everyone out and either build reads the
      other's file
- [x] **Verified**: Go reads a `stats.db` this writes and reports the same
      counts; this reads a `stats.db` Go wrote

### HTTP API and interface
- [x] All 81 upstream paths routed
- [x] Sessions: `agh_session` cookie, HTTP Basic
- [x] Login rate limiting, on the form *and* on the Basic credentials
      every endpoint accepts: `auth_attempts` failures from an address
      within a minute start a `block_auth_min` block, answered 429 with
      `Retry-After`
- [x] The gate covers the pages as well as `/control`, so a signed-out
      browser is redirected to `/login.html` rather than handed a
      dashboard it cannot load
- [x] Setup wizard reachable before a user exists
- [x] **Verified**: response shapes match Go for all 25 endpoints the UI loads
- [x] Web interface forked into `web/client`, built to `web/build`, embedded
      brotli-compressed, served with content negotiation, immutable caching
      for hashed assets and `304` revalidation for the rest
- [x] Version check: `/control/version.json` fetches this project's latest
      GitHub release, caches it for eight hours, honours `--no-check-update`,
      and reports `can_autoupdate: false`

### Packaging and operations
- [x] CLI accepting every flag the Go binary documents
- [x] Docker image with upstream's runtime contract, verified against a config
      and data directory a Go instance produced
- [x] **Published image**: `.github/workflows/docker.yml` builds `linux/amd64`
      and `linux/arm64` on native runners, pushes each by digest, and joins
      them into one multi-architecture tag on `ghcr.io/openhoangnc/sift`.
      A prune step keeps the newest three releases and their per-architecture
      children — resolved from each kept index rather than counted, because
      deleting a child breaks `docker pull` for that architecture. Attestations
      are off (`provenance: false`) so every manifest in the package is either
      an index or a child of one. Verified on the first two runs: tagging
      `v0.107.79` on the commit `main` had just built moved every tag onto the
      new index, and the prune correctly reaped the old index and its two
      children.
- **A `sha-` tag names a commit, not a set of bytes.** `BUILD_DATE` is a build
      argument, so rebuilding the same commit produces a different digest; the
      new index takes the tags and the old one is then pruned as untagged. Pin
      a digest, not a tag, if the bytes have to be identical across a redeploy.
- [x] **CI is `workflow_dispatch` only.** Formatting, lints, the test suite and
      the differential against a cloned AdGuard Home all run locally with
      `cargo test --workspace` and `scripts/verify.sh`, so paying for them on
      every push buys nothing. Run `ci.yml` from the Actions tab before cutting
      a release tag.
- [x] Graceful shutdown persisting the query log, statistics and sessions
- [x] **`--logfile`** and the `log` block: a file, with rotation on
      `max_size`, `max_backups`, `max_age` and `compress`, or `syslog` over the
      local socket
- [x] **`--pidfile`**, written at start and removed at exit
- [x] **Privilege dropping**: `os.group`, `os.user` and `os.rlimit_nofile`,
      applied before the runtime starts so every thread is covered
- [x] **`-s install|uninstall|start|stop|restart|reload|status`**: a systemd
      unit on Linux, a launchd property list on macOS, naming this binary and
      the paths this invocation used

---

## Deliberate exclusions

Not missing work: decisions, with reasons. Each is refused clearly rather than
accepted and quietly ignored.

### DHCP

**This build will not serve DHCP.** Run DHCP on your router or a dedicated
service.

- `GET /control/dhcp/status` always reports `enabled: false` with empty ranges
  and no leases, whatever the config file holds. Echoing a stored
  `enabled: true` would tell the interface a server is running when nothing
  serves leases.
- `GET /control/dhcp/interfaces` returns `{}`.
- Every endpoint that would change DHCP settings answers **501** with a message
  saying so: `set_config`, `find_active_dhcp`, `add_static_lease`,
  `remove_static_lease`, `update_static_lease`, `reset`, `reset_leases`.
- The `dhcp:` section of `AdGuardHome.yaml` is still **read and written
  unchanged**. It has to be, for the file to round-trip byte for byte, and it
  means someone switching back to the Go build keeps their settings. Do not
  delete the model.

501 is what upstream's own API documents for a build without DHCP support, so
the web interface already knows how to present it.

### DNSCrypt

**This build serves no DNSCrypt listener and uses no `sdns://` upstream.**
Unlike DHCP, nothing about the API changes: `port_dnscrypt` and
`dnscrypt_config_file` round-trip through the config file untouched,
`/control/tls/status` reports them as stored, and no endpoint refuses anything.
The port is simply never bound, and a `sdns://` upstream is reported at startup
and skipped.

Why it was excluded rather than scheduled:

- It is the only remaining protocol that needs cryptography this project does
  not already have. DoT, DoH and DoQ came almost free once rustls and quinn
  were in the tree; DNSCrypt needs X25519 key exchange, Ed25519 signing and
  either XSalsa20-Poly1305 or XChaCha20-Poly1305, none of them present.
- On top of the primitives it needs a signed-certificate protocol served over
  DNS — client magic, resolver magic, padding rules — and a
  `dnscrypt_config_file` matching AdGuard's own format, including provider key
  material. Their Go library is roughly 4,400 lines.
- A mistake in key handling or nonce reuse is a silent security failure, not a
  visible bug, and this project has no way to test for one the way it tests
  everything else — by comparing against a running Go build.
- The protocols it would sit alongside all work, so a deployment that needs
  DNSCrypt can front sift with `dnscrypt-proxy`.

Note that DNSCrypt is **not** a dead protocol: AdGuard's own provider list at
<https://adguard-dns.io/kb/general/dns-providers/> still publishes DNSCrypt
addresses and `sdns://` stamps for AdGuard DNS, Quad9, OpenDNS, CleanBrowsing
and others. The exclusion is about the cost and risk of implementing it here,
not about nobody using it. If that trade changes, this is a session on its own,
with the Go implementation as an oracle throughout.

### Replacing its own binary

**`POST /control/update` answers 501.** Rewriting a running executable in place
is the job of whatever installed it; this ships as a container image and as
archives, and doing it silently from inside the process would be worse than
refusing.

What does work:

- `GET`/`POST /control/version.json` fetches
  `https://api.github.com/repos/openhoangnc/sift/releases/latest`,
  caches the answer for eight hours, and re-fetches on `recheck_now`.
- `can_autoupdate` is always `false`, which is how the interface is told not to
  offer the button.
- `--no-check-update` reports the feature as `disabled`, and nothing is
  fetched. The Docker `CMD` passes it.

`parse_version` accepts **two** documents: GitHub's, which names the version
`tag_name` and the page `html_url`, and the flat `version`/`announcement_url`
shape AdGuard's own announcement server serves — so pointing the checker at a
hand-written `version.json` keeps working. A repository with no release yet
answers 404, the fetch fails, and the handler reports the running version as
`new_version`, which the interface reads as "nothing newer".

**Why not AdGuard's announcement server any more.** It was the source while
this build reported `v0.107.79`. Now that it reports its own version, that
server would announce an AdGuard Home release as an update to Sift —
permanently, and naming something this binary could not become.

---

## Found by running the image, and fixed

The first end-to-end pass over the published container — the setup wizard in a
browser, then every API surface and the DNS path — turned up nine defects that
no unit test covered. Each now has one. They are recorded here because the
shape of the mistakes is worth keeping, not because the work is outstanding.

- **Nobody could log in.** `POST /control/login` answered 401 to correct
  credentials. The auth gate's allowlist was spelled in full paths
  (`/control/login`), but `Router::nest` strips the prefix before middleware
  layered on the inner router sees it, so the comparison never matched and the
  only unauthenticated route was closed. The wizard hid it: `needs_install()`
  opens everything, so a fresh instance worked right up until it had a user.
  `sift-api/tests/gate.rs` drives the assembled router, which is the only place
  the seam exists.

- **The first launch opened on a dashboard.** Upstream's `postInstallHandler`
  redirects everything outside `/install.` and `/assets/` to `install.html`
  until a user exists; its `preInstallHandler` then answers 403 for the wizard
  once one does. Neither existed here, so a new install showed an empty
  dashboard, and a configured server still served a wizard that could be run
  over it again. The wizard's own endpoints now 404 once configured, as
  upstream's do by never being registered.

- **`+00:00` where Go writes `Z`.** Go's `Z07:00` prints `Z` whenever the
  *offset* is zero; `format_zoned` also required the zone to be
  `TimeZone::UTC` by identity. The container resolves its zone by name, so
  every timestamp the image produced diverged — including the `T` field of
  `querylog.json`, which is supposed to be byte-identical. The golden fixtures
  were captured at `+07:00` and never exercised it. Checked against the Go
  toolchain: `Etc/UTC` and a wintertime `Europe/London` both render `Z`.

- **A partial request body was a 422.** `PUT /control/safesearch/settings`
  rejected a body missing any flag, where Go's `encoding/json` leaves an
  omitted field at its zero value and answers 200. Every API request type now
  carries `#[serde(default)]` for the same reason.

- **A blocked client was cut off rather than refused.** Upstream drops only on
  UDP and DNSCrypt, where a spoofed source would make the answer
  amplification; every connected transport gets `REFUSED`. Returning nothing
  on TCP, DoT, DoH and DoQ closed the connection instead, which `dig +tcp`
  reports as `communications error: end of file`. The blocked-*host* path had
  this right; the blocked-*client* path, which runs earlier in
  `server::Server::handle`, did not.

- **Filter lists refreshed on uptime, not staleness.** The maintenance loop
  fired when the minute counter hit a multiple of the interval, so a fresh
  install had no rules for 24 hours, and a server restarted more often than
  the interval never refreshed at all — the counter reset every boot.
  Upstream refreshes a list when *its own* `last_updated` plus the interval
  has passed, which `Manager::stale_ids` now does; `last_updated` comes from
  the file on disk, so it survives a restart.

- **The wizard had no addresses to show.** `/control/install/get_addresses`
  returned `"interfaces": {}`, so the setup wizard listed no address to point
  a router at and both "Listen interface" dropdowns were empty. The interface
  list is real now (`sift-api/src/netiface.rs`); the wizard reads `name`,
  `ip_addresses` and `flags`, and greys out anything whose flags lack `up`.

- **`dhcp_available` was `true`.** Upstream sets it from whether it actually
  built a DHCP server. The interface gates its entire DHCP section on the
  field, so answering `true` sent it to `/control/dhcp/status` and rendered a
  settings page whose every save answers 501 — the exact failure the DHCP
  exclusion exists to avoid.

## Found by swapping a real Go deployment, and fixed

A second pass replaced a *configured* `adguard/adguardhome:v0.107.79`
container with this image on the same volumes, then swapped back, then had the
Go build read everything this one had written. The contract held — the image's
entrypoint, command, working directory, user, volumes, exposed ports,
environment, healthcheck and stop signal are identical, the config file came
through byte for byte, and neither build signs anyone out. Two things did not
hold.

- **The data directory was world-readable.** Upstream creates directories
  `0o700` and files `0o600` (`aghos.DefaultPermDir`, `aghos.DefaultPermFile`);
  this created `work/data`, `work/data/filters` and `querylog.json` at `0o755`
  and `0o644`. The query log records every name every client on the network
  looked up, so on a shared host — or in a volume mounted into a second
  container — that is a disclosure the Go build does not make. The modes now
  come from `sift_core::perms`, which the config writer, the query log, the
  filter cache and `Paths::ensure` all share.

- **The setup wizard suggested the wrong admin port.** `web_port` in
  `/control/install/get_addresses` is a suggestion for the *finished* install,
  not the port the wizard is being served on: upstream answers 80 while
  listening on 3000, and honours `ADGUARD_HOME_DEFAULT_WEB_PORT` when a
  deployment sets it. Echoing the live port instead quietly put every fresh
  install's admin interface on 3000. `dns_port` is likewise upstream's
  constant 53, not the configured port.

`ADGUARD_HOME_TEST_UPDATE_VERSION_URL` is the only other environment variable
upstream reads, and it is disabled for release builds, so it does nothing in
the image a user runs. Nothing to implement.

## Found on a real deployment, and fixed

A 37-list installation on an Orange Pi 5 — 2,272,040 rules — appeared not to
start: the log stopped after `loaded statistics` and nothing followed. It was
not stuck. It was compiling regular expressions.

**Expressions were built at load, not on first use.** Every rule that is not
`||domain^` needs one, and that installation had 156,557 of them. Building all
of those automata up front cost **22 seconds of parsing and most of a
gigabyte**, for expressions that a query only ever reaches once the domain
index or the Aho-Corasick scan has already named that rule a candidate —
a handful per query, and the overwhelming majority never at all.

`Pattern::Rx` now holds a `LazyRegex`: the source, and a `OnceLock` filled the
first time something matches against it. The `/regex/` form is still compiled
at load, because a user writes that one by hand and a typo in it should be
refused there rather than silently never matching.

Measured on that deployment's own filter files, same machine, same data:

| | before | after | Go v0.107.79 |
|---|---:|---:|---:|
| Time to answer DNS | 55 s | **6 s** | 4 s |
| Memory after loading | 4,196 MB | **532 MB** | 363 MB |

Two guards, both confirmed to fail against the eager code:
`an_expression_is_not_built_until_something_needs_it` asserts the automaton is
absent until a match needs it, and
`rules_needing_an_expression_load_as_cheaply_as_plain_ones` loads 60,000
expression rules and fails over three seconds — it took 9.4 eagerly.

**Why no test caught it.** Every fixture is the AdGuard DNS filter, which is
almost entirely `||domain^`; those take the fast path and never compile
anything. The cost only appears with the lists people actually stack up —
HaGeZi, OISD, 1Hosts — which carry wildcards and modifiers. The differential
fixture proves *verdicts*, and said nothing about what loading them costs.

**The README was wrong about memory.** Its "2.2× less than Go" was one list;
at 37 the ratio inverts to 1.5× more. Both figures are now stated with the
list count they were measured at.

`loading filter lists` is also logged before the work starts, not only after:
several seconds of silence between "starting" and "serving" is what made this
look like a hang in the first place.

## The filtering engine's shape, and why

At two million rules the engine's structure is the whole story, so the choices
are recorded here rather than rediscovered. All of it was measured on a real
37-list installation — 2,272,040 rules — with
`cargo run --release -p sift-filter --example loadprofile <dir>`.

**Expressions are built on first use.** Every rule that is not `||domain^`
needs one; 156,557 did. Building them all at load cost 22 seconds and most of
a gigabyte, for expressions a query only reaches once an index has already
named that rule a candidate. The `/regex/` form is still compiled at load,
because a user writes that by hand and a typo should be refused there.

**Rule text lives in the list, not the rule.** Nothing that decides whether a
rule matches reads the text — only a rule that has matched does. So it is off
the struct the hot loop walks, and it is not copied at all: the manager holds
every list to rebuild from, and rules point into those bytes through an
`Arc<str>`. `TextRef` is eight bytes, carrying its own source index, because a
range table plus `partition_point` cost 100 ns on every blocked query.

**The domain index keeps no keys** (`domidx.rs`). As a
`HashMap<Box<str>, Refs>` it was 148 MB for 1,122,077 domains. It is two
parallel arrays now — a 64-bit hash and a 32-bit value, 12 bytes a slot, 31 MB
— and a probe is confirmed by recovering the key from the matched rule's own
text. That verification costs ~85 ns on a blocked query and is not negotiable:
a hash collision would block a domain the user never blocked, and nobody could
diagnose it. Size it from the domains, not the pairs — 1,984,815 pairs name
1,122,077 domains, and sizing for the pairs left the table a third full at
twice the memory.

**The shortcut index is not an Aho-Corasick automaton** (`shortcut.rs`), which
is the textbook answer and was the wrong one. The automaton was 37.6 MB plus
an 11.2 MB map, walked one state transition per byte with each dependent on
the last, so a hostname's length bought a chain of cache misses through a
structure far larger than any cache. What makes it the wrong tool is that this
haystack is tiny and the patterns are long: 156,070 distinct shortcuts of mean
length 19.5, only 375 shorter than eight bytes. Each is filed under whichever
eight-byte window of itself is rarest across the set — a domain-like string's
rare windows are the ones real names rarely contain — and a query hashes its
own windows, which are independent and so overlap in the memory system. 7.4 MB.

**Both shortcut tables are gated by a bitset**, and this is not optional. The
tables are megabytes, so every probe is a miss; the gates are 8 KB and 256 KB
and stay in cache. Without the short gate, 375 patterns cost 437 ns of a 531 ns
clean lookup — the work is per position, not per pattern. Without the long
gate, a long hostname cost 838 ns against 364 with it.

**What did not improve.** A short clean hostname still costs ~530 ns, much as
it did under Aho-Corasick; the shortcut phase dominates it and neither
structure fixed that. It is the obvious place for the next person to look.

## Found by running the live tests, and fixed

- **Safe browsing and parental control could never start.** The family
  resolver's own name is bootstrapped over plain DNS, and `hashprefix` asked
  for it on **port 443** — where those hosts serve DoH, and where a plain
  query is answered by nothing. Every lookup timed out, `Checker::connect`
  failed, and both features stayed off with an error in the log while the
  interface reported them on. Port 53, and the unit test that asserted 443
  now asserts 53 and says why. Found because `cargo test -p sift-dns --test
  live -- --ignored` was run; nothing offline could have caught it, since the
  port only matters against a real resolver.
- **A live test asserted AdGuard's data rather than this build's behaviour.**
  `testsafebrowsing.adguard.com` was asserted to be reported unsafe; it is no
  longer in the set and no longer resolves at all. Which hosts are listed is
  not ours to pin, so the test now asserts what does break in practice — that
  the family resolver can be reached — and the matching itself stays pinned
  offline by `a_matching_hash_in_the_cache_blocks` and
  `hashing_matches_the_reference_vectors`.

## Found signing in from a second hostname, and fixed

An instance reachable both at `http://<ip>:3180` and at an HTTPS hostname
signed in fine on the first and answered the second with the *browser's* own
Basic sign-in dialog, every time. The hostname was not the cause — a different
origin is simply a different cookie jar, so it was the only one ever seen
signed out. Two defects met there.

- **The gate solicited Basic credentials.** `require_auth` answered 401 with
  `WWW-Authenticate: Basic realm="AdGuard Home"`. Upstream's
  `authMiddlewareDefault` writes a bare 401 and no such header, and the reason
  is the browser: presented with it, Chrome answers the interface's own
  background `fetch` with a native dialog of its own, which becomes the only
  prompt the user ever sees. `/login.html` never renders, and cancelling the
  dialog leaves nothing. Basic credentials are still *accepted* — that is what
  the scripted API users send — they are no longer *asked for*.

- **The web interface was not behind the gate at all.** The middleware was
  layered on the `/control` router only, so `GET /` served the dashboard shell
  to anyone. That is survivable in upstream's design and not in this one:
  upstream wraps its whole mux and redirects `/` and `/index.html` to
  `login.html` for a signed-out visitor, which is *the* route to the login
  form. The shipped interface sends itself there only when an API call answers
  **403** (`client/src/api/Api.ts`), and the gate answers 401 — so a dashboard
  handed to a signed-out browser is a dashboard that can never load. `serve_ui`
  now applies upstream's `handlePublicAccess`: `/assets/*`, `/login.*` and
  `/forgot_password.*` are served, `/` and `/index.html` redirect to the form,
  anything else is 401, and a visitor who *is* signed in is bounced off
  `/login.html` back to `/`.

**Verified** against a running build: signed out, `/` is `302 login.html`,
`/control/status` is a 401 carrying no `www-authenticate`, and the form and the
`login.<hash>.js`, `login.<hash>.css` and `/assets/*` it is built from all
serve; signed in, `/` is 200 and `/login.html` is `302 /`; Basic credentials
still open `/control/status`. A browser pointed at the root renders AdGuard's
login form with no native dialog and no console errors. Three tests in
`sift-api/tests/gate.rs` cover it, including the absence of the header.

## Found reading the code after that, and fixed

Two defects in the sign-in path, neither of which any test covered.

- **The login throttle was dead code.** `LoginLimiter` was written, exported
  and unit-tested, and nothing ever constructed it — so the admin password
  could be guessed at line rate, over the form or over the Basic credentials
  every other endpoint accepts. It lives on `AppState` now and both paths
  consult it, which matters: throttling only `/control/login` would have left
  an attacker free to guess against `GET /control/status` instead, where a 200
  says the same thing a 302 does. The cookie path is deliberately *not*
  throttled, as upstream's is not — a session token is sixteen random bytes,
  so nobody is guessing one, and throttling it would let a stale cookie lock
  an address out.

  The limiter's arithmetic is upstream's `authRateLimiter`, including the part
  that reads like a bug: until the count is spent every failure keeps the
  *first* one's one-minute deadline, so a trickle of guesses lapses instead of
  accumulating, and only the failure that reaches the threshold installs the
  full block. It keys on the connection's own peer address with the port
  dropped — never a forwarded-for header, which anyone could set to spend
  someone else's attempts or dodge their own block
  ([upstream #2799](https://github.com/AdguardTeam/AdGuardHome/issues/2799)) —
  and `auth_attempts: 0` or `block_auth_min: 0` switches it off with a warning
  at startup, as upstream's `emptyRateLimiter` does.

- **A failed login answered 401 where upstream answers 403.** Upstream's
  `handleLogin` hands `newCookie`'s error to `writeErrorWithIP` with
  `StatusForbidden`. Nothing in the interface reads the difference — the login
  page does not redirect itself from either — but it is a status on the
  drop-in surface, and it was wrong.

**Verified** against a running build: five wrong passwords answer 403 and the
sixth answers `429` with `Retry-After: 899` (900 seconds truncated, as Go's
`int(left.Seconds())` truncates); the block then refuses the *correct*
password and correct Basic credentials from that address; five wrong Basic
credentials block the login form for the same address; a request carrying no
credentials is not an attempt, so `/`, `/login.html` and an unauthenticated
`/control/status` behave normally throughout; and `auth_attempts: 0` logs
`login rate limiting is disabled` and never blocks. Four tests in
`sift-api/tests/gate.rs` and five in `sift-api/src/auth.rs` cover it; the two
throttle tests were confirmed to fail against an unlimited build, and the
clearing test against a build that never calls `record_success`.

## Found auditing the DNS settings page, and fixed

A report that **Access settings → Allowed clients** did nothing turned out to
be two defects, and looking for others on the same page turned up a third that
was larger than either.

- **The access lists understood only bare addresses.** `allowed_clients` and
  `disallowed_clients` were parsed with `filter_map(|s| s.parse::<IpAddr>())`,
  so every CIDR and every ClientID was silently dropped — and the reported
  allowlist was `mi12t`, `hoangnc-chrome`, `172.17.0.0/16`, `192.168.99.2/31`,
  which is *entirely* CIDRs and ClientIDs. It parsed to nothing, and an empty
  allowlist admits everybody: the operator had asked for a closed server and
  had an open one. The interface says the field takes "CIDRs, IP addresses, or
  ClientIDs" and upstream's `processAccessClients` accepts all three.

  `Access` now keeps the three apart, as upstream's `accessManager` does,
  because the two modes combine them differently and the asymmetry is
  load-bearing: in **allowlist** mode a client is refused only when *both* the
  address check and the ClientID check refuse it, so a listed ClientID gets in
  from an unlisted address and a listed address gets in over plain UDP with no
  ClientID at all; in **blocklist** mode either one refusing is enough. That is
  `IsBlockedClient`, and the check now reaches `Server::handle_as`, where the
  ClientID a DoH path segment or a DoT server name carries already sat unused.

- **`/control/access/set` stored what it could not parse.** Upstream refuses an
  entry that is not an address, a network or a ClientID, and refuses duplicates
  within a list and any entry appearing in both lists. This accepted anything,
  wrote it to the config file, and dropped it when the lists were built — the
  silent no-op the page above warns about. It also refused a request that set
  *both* lists, which upstream allows (the disallowed list is ignored while the
  allowed one is non-empty, exactly as the interface tells the user), and it
  mutated the in-memory config *before* validating, so a rejected request left
  the running server holding settings that were never saved.

- **Most of the page needed a restart.** `Reloader::reload` covered the
  resolver settings, rewrites, clients, safe search and the certificate, and
  nothing else — so a saved change to the upstream servers, the upstream mode,
  the fallback or bootstrap servers, the upstream timeout, the private reverse
  resolvers, the rate limit, either rate-limiting subnet prefix, the
  rate-limiting allowlist, the cache size or optimistic caching was written to
  the file and ignored until the process restarted. Upstream applies all of it
  live, through `dnsforward.Server.Reconfigure`. Measured before the fix:
  pointing every upstream at `127.0.0.1:1` and clearing the cache still
  resolved through the old resolver, and `ratelimit: 0` still answered only 20
  of a 100-query burst.

  `Limiter` and `Cache` hold their configuration behind a lock now and take a
  `set_config`; the pools are rebuilt through `SharedPool::store`. Rebuilding a
  pool resolves each upstream's host through the bootstrap resolvers, so it
  cannot run inside the synchronous `reload` — it is spawned, and queries keep
  going to the old upstreams until the new ones are ready rather than failing
  in between. Two guards come with that: a generation counter, so two saves in
  quick succession cannot leave the slower rebuild's pool installed, and a
  fingerprint of everything the pools are built from, so toggling protection
  does not reconnect every upstream. `upstream_dns_file` is fingerprinted by
  its *contents*, because it exists for a script to change the upstreams
  without touching `AdGuardHome.yaml`.

**Verified** against a running build, for each: an allowlist of the reported
shape drops a query from an unlisted address on UDP and answers `REFUSED` on
TCP, while an address inside a listed CIDR resolves; with the allowlist holding
one ClientID and no address at all, `/dns-query/mi12t` answers and both
`/dns-query` and `/dns-query/someone-else` are refused; a bad entry, a
duplicate and an intersecting entry each answer 400 with upstream's message,
and both lists together answer 200. Live, with no restart: the upstreams swap
to a dead address (SERVFAIL) and back (NOERROR); the rate limit answers 20, 100
and 5 of a 100-query burst at limits of 20, off and 5; switching the cache off
stops a repeated name being served from cache, and switching it back on
resumes; and a protection toggle plus a filter-rule save log no upstream
reload at all, where an upstream change logs one.

**"Disallowed domains" was a list of rules pretending to be a list of names.**
The same card's other field matched an entry against the host and its
subdomains, and ignored the wildcard (`*.example.org`) and rule
(`||example.org^`) forms the interface documents. Upstream's `newAccessCtx`
lowercases every entry, hands the whole list to `urlfilter.NewDNSEngine`, and
asks it whether anything matched — so all three forms are just rule syntaxes,
and the query *type* takes part in the match.

The fix is to do the same: `sift_dns::blocked::BlockedHosts` compiles the list
with `sift_filter`'s engine, the one the filter lists already use, so
`$dnstype`, hosts-file syntax and the rest come along rather than being
special-cased. One conversion is needed first, and it is the whole reason the
old behaviour looked defensible: upstream's parser tries `rules.NewHostRule`
before anything else, so a line holding a bare host name becomes a *host* rule
and is matched by **equality**. Entries that are bare names are emitted as
`0.0.0.0 <name>` for that reason; everything else is passed through as written.

What a Go build actually does, measured rather than inferred — and the old
matcher was wrong in both directions:

| entry | matches | does **not** match |
|---|---|---|
| `exact.example.org` | `exact.example.org`, any query type | `sub.exact.example.org`, `notexact.example.org`, `exact.example.org.evil.net` |
| `*.wild.example.org` | `a.wild.example.org`, `b.a.wild.example.org`, `a.wild.example.org.evil.net` | `wild.example.org`, `notwild.example.org` |
| `||rule.example.org^` | `rule.example.org`, `x.sub.rule.example.org` | `arule.example.org`, `rule.example.org.evil.net` |

Three findings there are worth keeping, because none is guessable:

- **A plain entry does not cover subdomains.** The old comment said it did,
  "as upstream's rule engine does for bare domain rules". It does not, and the
  shipped defaults are plain names, so `sub.version.bind` was being refused
  where the Go build answers it.
- **A wildcard is an unanchored pattern, not a suffix.** `*.wild.example.org`
  is the substring `.wild.example.org` appearing anywhere, which is why it
  covers `a.wild.example.org.evil.net` and does *not* cover
  `wild.example.org` itself.
- **An `@@` exception in this field blocks rather than permits.**
  `isBlockedHost` throws the match away and keeps only the "something matched"
  flag (`_, ok = ...MatchRequest(...)`), so `@@||allow.example.org^` listed
  here refuses `allow.example.org`. Confirmed on the Go build.

Plus two smaller ones: an underscore makes an entry a *pattern* rather than a
name, because upstream's host parser rejects it — so `_test.example.org`
listed plainly also refuses `sub._test.example.org` — and
`||typed.example.org^$dnstype=AAAA` refuses AAAA while answering A and TXT,
which is why the matcher takes a query type at all.

**Verified** by building `upstream/` v0.107.79 with Go 1.27 and running it
beside this one on high ports with an identical config, then comparing the
verdict for **70 cases** — every row of the table above plus the underscore,
hosts-file, exception and `$dnstype` forms, each over A and AAAA, plus TXT,
HTTPS and NS for a plain entry, and uppercase questions throughout. A blocked
host answers REFUSED on a connected transport, so every query went over TCP
where the verdict is visible. **0 mismatches.** Re-running the same comparison
before the fix showed 12 on the first sixteen cases alone. The list also
applies without a restart: a `||live.example.org^` added through
`/control/access/set` refuses the name and its subdomains on the next query,
and a name dropped from the list is answered again. Twelve tests in
`sift-dns/src/blocked.rs` carry the measured cases, each noted with what the Go
build did.

## Found optimising the upstream query path, and fixed

`cache_optimistic` was carried from the config file into the cache and then
ignored. That is the failure mode CLAUDE.md warns about: a setting the
interface offers, the config file records, and nothing acts on.

- **An expired entry was recognised and then thrown away.** `Cache::get`
  returned `Freshness::Stale` for an entry inside `cache_optimistic_max_age`,
  and the resolver acted only on `Freshness::Fresh` — so the stale answer was
  cloned, had its TTLs decremented, and was dropped on the floor on the way
  upstream. `Freshness::Stale` was constructed in one place and read in none.
  Switching optimistic caching on bought nothing but the memory to hold expired
  entries for twelve hours, and a wasted clone per lookup.

  The entry is served immediately now, and fetched again behind the client.
  Measured against a running AdGuard Home v0.107.79 whose upstream answered a
  different address every time, so each answer says which exchange produced it,
  with a record TTL of 2s and `cache_optimistic_answer_ttl: 7s`:

  | | Go v0.107.79 | this build |
  |---|---|---|
  | t=0.0 first, a miss | `10.0.0.2` ttl 2 | `10.0.0.2` ttl 2 |
  | t=1.0 inside the TTL | `10.0.0.2` ttl 1 | `10.0.0.2` ttl 1 |
  | t=4.0 expired | `10.0.0.2` **ttl 7** | `10.0.0.2` **ttl 7** |
  | t=5.0 just after | `10.0.0.3` ttl 1 | `10.0.0.3` ttl 1 |
  | t=6.0 | `10.0.0.3` ttl 7 | `10.0.0.3` ttl 7 |
  | t=12.0 | `10.0.0.4` ttl 7 | `10.0.0.4` ttl 7 |
  | upstream exchanges for the name | 4 | 4 |
  | query log lines | 6 | 6 |

- **`cache_optimistic_answer_ttl` had no readers at all.** It defaulted to 30s
  in `sift-config` and nothing outside that crate ever looked at it. The run
  above is what settled its meaning: the configured TTL is *stamped* on an
  optimistically served answer rather than counted down from what the entry had
  left — which would hand the client a number that had already run out. The
  value used was a deliberately non-default 7s, so a build that hardcoded the
  30s default would have shown it. It now reaches `CacheConfig`, and applies on
  reload with the rest of the cache settings.

  `tests/compat/dns_diff.py` could not have caught this: it unpacks a record
  with `">HHIH"` and binds the TTL field to `_`.

- **The shard's eviction order leaked, without bound.** `Shard::order` was
  drained only by `evict_to_fit`, which runs only while a shard is over its
  budget. The expiry path in `get` removed the entry from `map` and decremented
  `bytes` without touching `order` — so on a cache comfortably inside its
  budget, which is the normal case, `order` grew by a slot for every
  expired-then-looked-up key and nothing ever collected them. Serving stale
  entries makes it far worse, because an expired entry now survives to be
  looked up again and again.

  Worse, a key stored again after expiring was pushed a second time, and the
  dead slot sorted ahead of the live one: the next eviction threw away the
  entry that had just been stored and kept an older one, which is exactly
  backwards. Slots carry the sequence number of the entry they were pushed for
  now, so a dead one is recognised and skipped, and a shard compacts its order
  once the dead slots outnumber the live entries — one pass, and it cannot run
  again until the shard has grown again.

---

## Found watching a container's memory, and fixed

A deployment reported 269 MB at start and 371 MB eighteen hours later, dropping
back to 269 MB on restart. All of it was statistics, and the restart is the
clue: what a restart loads is the *capped* form of each hour, and that is all
upstream ever holds.

- **Every hour in the window kept every name it had seen.** `Stats::units` was
  a `BTreeMap<u32, Unit>`, and a `Unit` holds `AHashMap<String, u64>` for
  queried domains, blocked domains, clients and the two upstream counters, with
  no cap. Only the way to `stats.db` capped anything: `to_db` takes the top 100
  of each. So the process grew with the number of distinct names asked for
  across the whole retention window — a day by default — while `stats.db` and
  everything a restart read back held 100 per hour.

  `internal/stats` keeps **one** live unit and reads the rest back from the
  database; `loadUnits` serialises the current one for every request, so even
  the live hour is reported capped. Finished hours are now compacted to the
  form they are stored in, which is both what upstream reports and what a
  restart here already produced.

- **Every save and every `/control/stats` call copied the lot.** `data()`
  cloned every unit — maps and all — before merging, and `snapshot()`, which
  the maintenance tick calls every 60 seconds, ran `to_pairs` over every
  unit, and `to_pairs` cloned every key in the map to sort them and then threw
  all but 100 away. Both costs grew with uptime, and neither is memory the
  process gets back: the allocator holds the high-water mark.

  `data()` now merges the stored form, taking the finished hours by `Arc`
  without copying them at all, and `to_pairs` copies only the names that
  survive the cut, selecting them with `select_nth_unstable_by` rather than
  sorting the hour.

Measured on one machine, same binary either side, against the same load: 100k
distinct names per round through a stub upstream, one list of 180,049 rules,
`statistics.interval: 1d`.

| | before | after |
|---|---:|---:|
| RSS, idle with the list loaded | 43 MB | 43 MB |
| RSS after 500k distinct names in one hour | 170 MB | 127 MB |
| RSS after three `/control/stats` calls on that | **266 MB** | **127 MB** |
| One `/control/stats` call | 0.31 s | **0.04 s** |
| RSS with statistics switched off, 500k names | 59 MB | 59 MB |

That last row is the attribution: with `statistics.enabled: false` the same
half-million distinct names leave RSS flat, so the cache, the query log, the
client registry and the connection pools were not what grew.

The hour boundary is what a short run cannot show, so the restart stands in for
it: 600k distinct names live is 130 MB, and the same statistics after a restart
— the same counts, the same top lists, read back from `stats.db` — is 45 MB.
That compaction now happens every hour rather than only when the process dies.
`a_finished_hour_holds_only_what_is_stored` guards it, and
`an_hour_that_goes_quiet_is_compacted_by_the_sweep` covers the resolver that
stops being asked before the hour turns.

**What this changes in the response.** The top lists for a multi-hour window
are now merged from each hour's top 100 rather than from complete maps, so a
name that is 101st in every hour no longer sums its way into the list. That is
what upstream reports, and what this build already reported for any hour it had
restarted through; it is now the same before and after a restart.

**Left alone.** The live hour still holds every name, because upstream's does
and it is bounded by an hour of traffic — around 6 MB at the rate the reporting
deployment grew. `store::save` still rewrites the whole database every 60
seconds where upstream writes a unit when it rotates; that is I/O, not memory,
and it is a durability choice worth keeping.

---

## Found counting writes against the Go build, and fixed

A deployment on flash storage asked what this writes and why. The way to
answer it was to run `adguard/adguardhome:v0.107.79` and this build under the
same load — 20 queries a second for six minutes through a stub upstream, the
same config either side — and record every time a file in `data/` changed.

| in six minutes, 7,200 queries | Go v0.107.79 | this build, before | after |
|---|---:|---:|---:|
| `stats.db` writes | **0** | 6 | **0** |
| `querylog.json` writes | 7 | 13 | **7** |
| bytes per query-log write | 268 KB | 268 KB and 50 KB alternating | 263 KB |

The Go build wrote `stats.db` exactly once in an hour of watching, at
`13:00:00` — `internal/stats` writes a unit when it rotates and when it shuts
down, and at no other time. It never flushed the query log on a timer: the
writes landed 50.2 s apart, which at 20 q/s is the 1,000-entry `size_memory`
buffer filling, and a four-minute run at 2 q/s — not enough to fill it —
produced no write at all.

- **`stats.db` was rewritten every 60 seconds, whole.** The maintenance tick
  called `save` unconditionally, and `sift-bolt` writes a database by writing
  all of it. At the default day-long window that is 1,440 rewrites of a
  311 KB file — **448 MB a day** — and the file grows with the window: 2.1 MB
  at seven days, 8.9 MB at thirty, 26.6 MB at ninety, where the same tick
  comes to **38 GB a day**. `Stats::claim_save` now reports the changes the
  file does not hold — an hour rotating, units falling out of the window, a
  reset — and the tick writes only for those. What it costs is upstream's
  cost: an unclean kill loses the hour in progress. A signal does not, because
  the shutdown path saves; that was checked by stopping the server and reading
  the counts back.

- **The query log was flushed on the same tick.** Its buffer already flushes
  when it fills, which is what upstream does and all upstream does, so the
  tick only added a second, partial write between the full ones — the 50 KB
  entries in the table above. Removed.

- **Every refresh rewrote every list, unchanged or not.** `apply_fetched`
  wrote the file and reported success whatever came back, so the caller
  counted it as an update, wrote the configuration and **rebuilt the whole
  engine**. On the 37-list installation that is a daily rewrite of every list
  and a rebuild of 2,272,040 rules for nothing. Upstream downloads to a
  temporary file, compares a checksum with the one it holds, and on a match
  discards the download and calls `os.Chtimes` on the real file instead
  (`update` in `internal/filtering/filter.go`); `refreshFiltersIntl` returns
  early without `EnableFilters` when no list changed. `apply_fetched` now
  returns `Fetched::Unchanged` and touches the file's timestamps, and both
  callers rebuild and save only when something actually differed.

## Found while counting those writes: the query log never rotated

`QueryLog::rotate` was implemented and tested and **called by nothing**, so
`querylog.interval` — 90 days by default — was carried from the config file,
reported by the API and acted on by no one. `querylog.json` grew for as long
as the server ran.

Upstream's `checkAndRotate` decides from the **first record in the file**: it
reads the first 512 bytes, takes the `T` field out of them, and renames the
file over `querylog.json.1` once that moment plus the interval has passed. It
checks when it starts and then hourly, whatever the interval is. That detail
is the whole of it — a file being appended to was modified moments ago, so a
build that rotated on the modification time would never rotate at all, which
is what the first attempt to observe this did.

`rotate_if_due` reads the first record the same way, and `maintenance` calls it
at startup and every hour after. Verified end to end: an interval of a minute
and a first entry three hours old rotated on startup, the API kept reading the
entries out of `querylog.json.1`, and a recent first entry left it alone.

**Left alone, deliberately.** `sift-bolt` writes a whole database where bbolt
writes the pages that changed, so an hour's rotation costs 311 KB against
upstream's ~13 KB. At 24 writes a day that is 7.5 MB against 312 KB, and an
incremental bbolt writer is a great deal of machinery for the difference.
Sessions are already written only when one is created, removed or swept, and
the configuration only when something changes it.

---

## Found watching the same container again, and fixed

Holding one hour of statistics instead of the whole window was a real leak and
not that deployment's. It kept growing: 380 MB eighteen hours after the fixed
image started, against a 269 MB baseline, and `memory.stat` said `anon`, so
none of it was page cache. The box turned out to answer **950 queries an hour**
across **147 distinct names** and **19 client addresses all told** — far too
little traffic for statistics, clients, connections or descriptors to be it.
Twenty-two open descriptors, nine threads, no filter refresh in eighteen hours.

**The expression cache had no ceiling.** `Pattern::Rx` holds a `LazyRegex`
whose `OnceLock` is filled the first time something matches against it, and
never emptied again. That solved what building 156,557 automata at load cost —
22 seconds and most of a gigabyte — by arriving at the same place slowly
instead: every name the network asks for that reaches a new candidate rule adds
an expression that is then held for the life of the process.

Reproduced with that installation's own 36 lists, 2,285,525 rules, in the
published image, asking for real names in batches of twenty thousand:

| distinct names asked for | unbounded | bounded |
|---|---:|---:|
| none (lists loaded) | 269.7 MB | 272.8 MB |
| 20,000 | 347.4 MB | 347.9 MB |
| 40,000 | 410.7 MB | 353.7 MB |
| 60,000 | 475.2 MB | 357.1 MB |
| 80,000 | 537.7 MB | 358.1 MB |
| 120,000 | — | 363.2 MB |

The same load with `filtering_enabled: false` moved it 20 MB and then stopped,
which is what said it was the engine and not the response cache, the query log
or the statistics.

An expression costs about 25 KB. It is the compiled program, not the lazy
DFA's cache — `dfa_size_limit` at 4 KB moved 24.4 KB to 21.7 KB and nothing
else did anything — so the only thing that bounds it is holding fewer of them.
`MAX_COMPILED` is 2,000, the oldest is dropped to make room, and an expression
that has matched since it was last considered gets a second chance first:
building one costs 105 microseconds, and the point is not to pay that again for
the one name the network asks for constantly. Dropping one costs nothing but
building it again, which `only_so_many_expressions_are_kept_built` checks along
with the verdict being the same either way.

## Found reading the Go search code beside ours, and fixed

Searching the query log for a client — `"192.168.99.1"`, `"hoangnc-chrome"` —
answered "Nothing found" for both. Two reasons, both in the same function.

- **A quoted term was matched with its quotes.** Upstream's
  `getDoubleQuotesEnclosedValue` strips a surrounding pair and turns the search
  from a substring into an exact match; `ctDomainOrClientCaseStrict` then
  compares the whole of the queried name, the client's address, its name and
  its ClientID. This build took the parameter as written and looked for
  `"192.168.99.1"`, quotes included, inside each field — which nothing ever
  contains. The interface quotes the term whenever the user picks a client out
  of the log, so the one search a user is most likely to run was the one that
  could never match.

- **Only discovered names were searched.** The name came from the runtime
  store alone, so a client the user had named in the interface was neither
  findable by that name nor shown beside its queries. Upstream's
  `clientOrArtificial` asks the persistent store first and the runtime one
  after, which is what `name_of` does now — and `client_info.name` carries the
  configured name with it.

Checked against a running server, five queries from a client named
`hoangnc-chrome`:

| search | before | after |
|---|---:|---:|
| `"127.0.0.1"` | 0 | 10 |
| `"hoangnc-chrome"` | 0 | 10 |
| `127.0.0` | 10 | 10 |
| `"127.0.0"` | 0 | 0 |
| `"hoangnc"` | 0 | 0 |

The last two are the point of the quotes: an exact match on a whole field, so a
part of one does not match.

**And the term's ASCII form.** Upstream converts the lowercased term with
`idna.ToASCII` and tries that against the queried name as well, because the log
stores a question as the wire carried it — punycode — while the user types
their own script. That is the third difference the comparison turned up, and it
is closed with the same `idna` the tree already carries.

---

## The web interface, forked

The interface was AdGuard's compiled output, embedded. It is now **this
project's fork of their sources**, at `web/client`, built by
`scripts/build-frontend.sh` into `web/build`. The reason to fork rather than
keep vendoring the build: two of the three exclusions are visible in the UI as
settings pages and upstream examples for things that do not exist here, and
there is no way to take them out of a compiled bundle.

`web/client` began as a verbatim copy of v0.107.79's `client/`, so
`diff -ru upstream/client web/client` is the complete list of modifications.
`NOTICE.md` records the copyright position; the changes themselves:

- **DHCP is gone.** `components/Settings/Dhcp/`, `containers/Dhcp.ts`,
  `reducers/dhcp.ts`, the route, the menu entry, the nine API methods, the
  twenty-odd actions, the `DhcpData`/`DhcpInterface` state, the placeholder
  helpers, the e2e spec, and 46 keys × 36 locale files. What is left that still
  mentions DHCP is about the *router's* DHCP, which is a real thing a user
  configures elsewhere.
- **DNSCrypt is gone.** The `sdns://` line in the upstream examples, the
  `dnscrypt` transport label in the query log, `port_dnscrypt` and
  `dnscrypt_config_file` in the TLS status type, and three setup-guide entries
  (DNSCloak and its DNS stamp, dnscrypt-proxy, dnscrypt.info's implementation
  list). Five locale keys × 36 files.
- **Rebranded to Sift.** AdGuard's shield is gone from `ui/svg/logo.tsx`,
  replaced by a funnel of this project's own, and the lettering is a `<text>`
  in the system UI stack rather than traced outlines. The mark and the wordmark
  are separate elements so the dark theme can flip the lettering without
  touching the gold; the three `filter: invert(1)` rules that used to flip the
  whole SVG are gone, because inverting gold gives blue. The icons are
  rasterised from the same path, filled rather than stroked, because a
  2.8-unit stroke disappears at 16px. See [Naming](#naming) below.
- **Links.** Seven `link.adtidy.org` redirectors resolved to their real
  destinations (recorded in the commit); repository and issue links pointed at
  this project; six AdGuard Home wiki links pointed at `docs/`, written for
  this purpose.
- **A Clear cache button** on the dashboard beside Refresh statistics, behind
  the same `confirm_dns_cache_clear` the DNS settings page uses.
- **`.twosky.json` dropped.** `helpers/twosky.ts` imported
  `../../../.twosky.json` — AdGuard's translation-service configuration, which
  lives *above* `client/` and so was not part of the fork. Replaced by
  `helpers/languages.ts`, carrying the same 36-language list.

### Assets: brotli, and cached properly

`sift-api/src/ui.rs` used to store gzip and serve it to whoever accepted gzip.
It now stores **brotli** — 9.1 MB of assets to 1.7 MB, against gzip's 2.5 MB —
compressed by `scripts/brotli.mjs` at quality 11, run from the build script.

The catch is that browsers advertise `br` only over a secure origin. Over plain
HTTP on a LAN address, a browser sends `gzip, deflate` and is served the
**decompressed** bytes: bigger on the wire than gzip was, and a decompression
per request. Two things make that affordable, and they are the rest of the
change:

- a name carrying a content hash — webpack's `main.<20 hex>.js` —
  is served `Cache-Control: public, max-age=31536000, immutable`, so it is
  fetched once per build and never asked about again;
- everything else is `no-cache` with an `ETag`, and `If-None-Match` is answered
  **304** without touching the body.

The `ETag` is the stored file's SHA-256, which rust-embed computes at build
time, suffixed with the encoding: `"<hash>-br"` and `"<hash>-identity"`. They
must differ — a shared validator lets a cache hand compressed bytes to a client
that asked for plain ones. `Vary: Accept-Encoding` is on every response.

`flate2`, `tower-http` and `mime_guess` left `sift-api`'s manifest with this:
the first because nothing decodes gzip there any more, the other two because
nothing had referenced them in the first place. `brotli-decompressor` replaced
them — the decoder only, since the encoding happens in Node at build time.

**Watch out for:** `content-length: 0` on a 304. hyper writes it and removing
it in the handler does not survive serialisation. RFC 9110 makes the header
optional there and a truthful value would mean decompressing the very body the
304 exists to avoid, so it stays.

## Found reviewing the fork, and fixed

Three things the first pass left behind, and one it introduced.

### Per-client upstreams were stored and ignored

`clients.rs` carried `Persistent::upstreams`, `app.rs` copied it into the
registry and the client form offered the field — and nothing read it. Every
client resolved through the global pool. The exact shape this tree warns
against everywhere else: a setting the interface accepts and the resolver
throws away.

Wired through, and the interesting part is what had to come with it:

- **`Resolver::client_pools`**, a map from an upstream set to its pool, built
  by `app::build_client_pools` and installed by `reload_upstreams` beside the
  global one. Keyed by `clients::upstream_key` — the normalised upstream lines,
  not the client's name — so two clients configured with the same servers share
  one pool, and renaming a client reconnects nothing.
- **`cache::Key::upstreams`.** Without this the fix would have been worse than
  the bug: client A resolves an intranet name through its company's
  split-horizon resolver, client B asks the same question, and B gets A's
  answer out of the shared cache. The key now carries the same identity the
  pool does, and `PendingKey` embeds `Key`, so request coalescing is namespaced
  for free. `None` is the global pool, so the common case costs one word.
- **Refreshes keep the entry's own upstreams.** `refresh::Job` already carried
  the `Key`; the worker reads the pool identity from it rather than from the
  settings, or a background refresh would overwrite a client's entry with an
  answer its resolvers never gave.
- **The reload window does not poison the cache.** Connecting takes seconds, so
  a client added by a settings save briefly has a key and no pool. It is
  answered from the global upstreams rather than failing — but `pool_for`
  reports that it did, and `forward` drops the cache key, so nothing from that
  window is stored as the client's own.
- `upstream_fingerprint` now includes every client's upstream list, or editing
  one would never trigger a rebuild.

Verified live: the same question from the same address, once plain and once
with a ClientID, went to `1.1.1.1` and `9.9.9.9` and took a cache entry each.

### The caching rule was a guess

`is_content_addressed` called any dotted segment of 16-plus hex characters a
content hash. Right for webpack's `[chunkhash]` today, and quietly wrong — for
a year, per client — the first time someone shortened the hash or added an
asset whose name read like a digest.

webpack now writes its hashed output under `static/` and nothing else there, so
the predicate is `starts_with("static/")`: a fact about the build rather than a
guess about the name. `everything_the_build_emitted_is_classified_the_way_it_was_built`
walks the real embedded assets and fails if that stops being true.

**That move broke the login page**, which is worth recording because nothing in
the suite noticed. `is_public_page` matched `/login.`, and the login bundle had
become `/static/login.<hash>.js`; a signed-out browser got a blank page and two
401s. Same for the setup wizard. Both gates now strip the directory before
matching the name, and two tests check them against the assets the build
actually emitted rather than against names typed into a test.

### The translations named the wrong product

All 35 non-English locales said "AdGuard Home" under a LITE logo. The reason to
hesitate was that a machine substitution can break languages that inflect a
name — so that was checked rather than assumed. Every locale uses the literal
ASCII string, and only two needed more than a replace:

- **Korean** particles have two forms, chosen by whether the preceding syllable
  ends in a consonant. "Home" is read 홈 and takes 은/이/을; "Lite" is 라이트 and
  takes 는/가/를. Twenty-two of them moved.
- **Finnish** vowel harmony: "Home" carries a back vowel and "Lite" does not, so
  one partitive went from `-a` to `-ä`. The genitive `-n` and the illative
  `-en` do not harmonise.

Danish and Swedish genitive `-s`, and the Japanese and Chinese particles, are
unaffected by what precedes them.

## Naming

The project was called **AdGuard Lite** and used a recoloured AdGuard shield.
Both are gone. The reason is not the licence — the GPL-3.0 covers all of the
code and is complied with — but trademark, which the GPL does not grant and
explicitly lets an upstream withhold (§7(e)):

- "AdGuard Lite" was built like a tier in their own product line — AdGuard
  Home, AdGuard DNS, AdGuard VPN — which is the worst case for likelihood of
  confusion as to source, the test that actually decides infringement.
- The gold shield was a recolour of their figurative mark. Colour is not what
  is protected; the shape is.
- Every substantial fork of a trademarked project renames: Firefox→Iceweasel,
  MySQL→MariaDB, Redis→Valkey, Terraform→OpenTofu.

**Sift** is its own name and its own mark: a funnel, drawn in
`ui/svg/logo.tsx`, and the word set in the system UI font. No AdGuard mark
appears anywhere in the interface, the icons, the repository or the image.

What the rename touched:

| | |
|---|---|
| Crates | `agl-*` → `sift-*`, and the binary crate `adguardlite` → `sift` |
| Binary | **unchanged**: `AdGuardHome` at `/opt/adguardhome/AdGuardHome` |
| Config | **unchanged**: `AdGuardHome.yaml` |
| Repository | `openhoangnc/adguardlite` → `openhoangnc/sift` |
| Image | `ghcr.io/openhoangnc/adguardlite` → `ghcr.io/openhoangnc/sift` |
| User-Agent | `AdGuardLite/<version>` → `Sift/<version>` |
| Locales | all 36, 1,682 strings |

The binary and config names stay because they are the drop-in contract, not
branding — an existing installation already has them at those paths. `NOTICE.md`
records that distinction so nobody "finishes the rename" and breaks every
deployment.

### What the translations needed beyond a replace

The same class of problem as the previous rename, in different languages,
because "Sift" ends in a consonant where "Lite" ended in a vowel:

- **Finnish** inserts a linking `i` before a case ending on a consonant-final
  foreign name: `Siftin`, `Siftiä`, `Siftiin`.
- **Hungarian** picks both the article and the suffix by sound. "AdGuard"
  opens with a vowel and carries a back one, so it took *az* and `-ot`/`-ban`;
  "Sift" opens with a consonant and carries a front vowel, so it takes *a* and
  `-et`/`-ben`.
- **Korean** needed nothing this time: 시프트 ends without a final consonant
  just as 라이트 did, so the particles fixed in the previous rename still hold.
- Danish and Swedish genitive `-s`, the German, Dutch and Norwegian compound
  hyphens, and the Japanese and Chinese particles are all unaffected by what
  precedes them.

One upstream typo surfaced while checking: the Dutch `update_announcement` had
no space before `{{version}}`, which rendered as "Sift0.2.0 is nu
beschikbaar". Fixed, since the file is ours now.

## Version numbering

The binary reports **its own** version, `sift_core::VERSION`, built from the
workspace version in the root `Cargo.toml`, starting at **v0.2.0**. It used to
report `v0.107.79`.

- `sift_core::AGH_COMPAT_VERSION` keeps `v0.107.79` as what the formats are
  matched against. Nothing reads it; it is there so the number has one home.
- Nothing on disk carried the version, so this changed no file format. The
  config's compatibility is `SCHEMA_VERSION`, which is untouched at 34.
- The inter-crate `version = "0.107.79"` pins in every `crates/*/Cargo.toml`
  were dropped in favour of bare `path` dependencies, so a version bump is one
  line in the root manifest rather than twenty-three.
- The outbound `User-Agent` is `Sift/<version>` (via `AdGuardLite/` before the
  rename). It was `AdGuardHome/<version>`, which after the bump would have
  claimed to be an AdGuard Home 0.2.0.

---

## Deliberate deviations


- **Upstream connections outlive the query.** dnsproxy pools DoT
  (`upstream/dot.go`), caches one `http.Client` for DoH and keeps a single
  QUIC connection for DoQ, so keeping connections is parity, not invention.
  Where this build goes further: **plain TCP is pooled too**, which dnsproxy
  dials per query, and the HTTP/2-versus-HTTP/3 choice is **remembered per
  upstream** with a timed retry rather than re-raced on every query. An
  operator watching outbound sockets will see a few long-lived connections
  per upstream where there were many short ones.
- **Every reply is checked against the question asked**, on every transport.
  This is dnsproxy's `validateResponse`, which this build did not have: an
  upstream answering a question nobody asked had its answer returned and
  cached under the name that *was* asked. A tolerant, misbehaving upstream
  that appeared to work will now fail over. Names compare by their labels,
  case-insensitively — not with `Name`'s own equality, which also compares
  whether a name is fully qualified and so rejects every bootstrap reply.
- **Each upstream address gets a bounded share of the timeout.**
  `upstream_timeout` defaults to ten seconds and addresses were tried in
  order, each with the whole budget, so one unroutable address cost the full
  ten seconds on every query and the remaining addresses were never reached
  before the client below had given up. Attempts are now capped at two
  seconds with the remainder carried to the last, and the address that
  answered is preferred next time. The upstream gets the same total budget;
  only its division changed.


**A first launch as a non-root user is allowed.** The Go build refuses one —
*"this is the first launch of adguard home; you must run it as
administrator"* — and exits. This build starts and serves the wizard. The
difference is confined to the first launch: an already-configured
installation runs as `--user 65534:65534` under both, logs in under both, and
behaves identically. Refusing to start would be the worse failure, so the
extra permissiveness stands.

Not bugs; recorded so nobody "fixes" them.

- **Cited rule on ties.** When several rules of equal priority match, upstream's
  choice falls out of its shortcut index's bucket balancing and the order it
  walks the URL. This engine uses a suffix-walk index and resolves ties by load
  order, so it may cite a different — equally valid — rule for about 0.8% of
  matches. The verdict is always identical.
- **`gob` byte-equality.** Not attempted: Go's own encoder does not reproduce
  its own bytes for the same value. The bar is mutual decodability, which is
  tested directly.
- **`stats.db` page size.** Written at a fixed 4 KiB rather than the OS page
  size, so output is reproducible across machines. bbolt reads any size.
- **Filter list identifiers.** Assigned sequentially rather than from a
  timestamp. Any unused identifier is valid.
- **ipset through the command, not netlink.** Upstream talks to the kernel
  directly. This runs `ipset add … -exist`, which needs no netlink
  implementation, and remembers what it has already added so the cost is one
  process per new address rather than one per query.
- **Safe browsing stops at the last label, not the public suffix.** Upstream
  consults a public suffix list so a name under `co.uk` is not hashed at the
  suffix itself. This build stops before the final label instead, which adds at
  most one hash prefix to the question for such a name. No entry can match it,
  so the verdict is the same.
- **Privilege dropping is Linux-only.** `os.user` and `os.group` use the
  thread-scoped `setuid`/`setgid` the safe wrapper exposes, applied before the
  runtime spawns a second thread. On other Unixes the setting is reported as
  unsupported rather than silently ignored. `os.rlimit_nofile` works
  everywhere.
- **User and group lookups read `/etc/passwd` and `/etc/group`.** A numeric id
  is used directly. Names defined only through NSS — LDAP, for instance — are
  not resolved; the container this ships in has a plain passwd file.
- **Refresh-ahead on a popular name.** Not an AdGuard Home feature, and given
  no config key of its own on purpose: adding one would change the file
  `reproduces_the_reference_config_byte_for_byte` guards. An entry in the last
  tenth of its TTL that has been served more than once is fetched again before
  it expires, so a name under constant query is never served stale at all. It
  is gated on `cache_optimistic` — the setting that says a stale answer is
  acceptable in the first place — so with optimistic caching off the cache
  behaves exactly as the Go build's does. A refresh calls `Resolver::forward`
  directly and never `Server::handle`, so it is not rate limited, not counted
  in `/control/stats` and not written to `querylog.json`: the Go build logs six
  lines for six client queries over a name it refreshed four times, and so does
  this one. The queue holds 1024 jobs with 32 running at once, and a job is
  dropped rather than queued when it is full — no client ever waits on somebody
  else's refresh.
- **A changed listener *port* still needs a restart.** The certificate is
  live-reloadable; which ports are bound is decided when the listeners start.
  Everything else on the DNS settings page now applies without one.
- **A certificate renewed on disk is picked up without being told.** The Go
  build reads `certificate_path` and `private_key_path` once, at startup and
  whenever the config is saved, so a certbot renewal is served only after the
  next restart — a deployment that never restarts serves an expired
  certificate. `docs/encryption.md` had already promised otherwise, which is
  what turned this up. When either path is set, the maintenance tick digests
  what the files hold and installs a pair that differs from the one being
  served; inline PEM is left alone, because it can only change through
  `/control/tls/configure`, which installs it itself. No config key: the file
  `reproduces_the_reference_config_byte_for_byte` guards must not grow one.
  Three things make it safe to run on a timer rather than on a signal. The new
  pair has to parse and prove itself against rustls before anything is
  installed, so a renewal caught between its two files replaces nothing and is
  retried a minute later. The comparison is of contents, not mtime, so a
  renewal script that rewrites both files nightly costs one digest rather than
  a rebuilt signing key. And the same failure is logged once rather than every
  minute, so a genuinely broken pair does not bury the log. The watch runs only
  when encrypted listeners actually started: installing into a slot nothing
  serves would log a reload that reached nobody.

---

## Not implemented

Nothing outstanding. The features listed under **Deliberate exclusions** above
are decisions rather than gaps, and each refuses clearly at the point a user
would notice.

### Weighed while keeping connections, and left alone

Designed, costed, and not built, because each buys less than it risks once the
handshakes are gone. Recorded so the next person does not re-derive them.

- **A circuit breaker on `pool::Member`.** A dead upstream still costs the full
  `upstream_timeout` on the query that discovers it, every time, because
  `failures` decays only on success and a member demoted by `score()` is never
  chosen again to earn one. Time-decayed failures plus an open/half-open state
  would turn that into one slow query per backoff window. The reason to wait is
  that it has to fail *open* when every member is broken, or a transient blip
  becomes a total outage, and that is worth measuring rather than reasoning
  about. Note `record_success` is a load-then-store, not a CAS, so concurrent
  successes lose updates; fix that with it.
- **Hedging the second-best upstream** once the chosen one passes its own p90.
  Worth roughly 6× on the upstream p99 for ~10% more upstream queries, which
  is a real trade to make deliberately and not a free win.
- **A pool of UDP source sockets.** `udp_exchange` binds and closes a socket
  per query: ~8-10 µs of syscalls on a path that then waits 50 ms for the
  network, so it is a throughput item and not a latency one. It also trades
  away source-port entropy, which is a defence against off-path spoofing.
  Not worth paying that for a win that does not show up in p50, p90 or p99.
- **`loadgen` is closed-loop**, so its tail figures understate stalls: when the
  server stops answering the generator stops offering load. Anything measured
  with it should be read as a floor, the numbers above included.
- **The HTTP/1.1 DoH fallback has no test.** It is reviewed by reading only;
  every reachable DoH server negotiates h2, so exercising it needs an h1-only
  local server that nothing else in the tree wants.

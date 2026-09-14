# Task tracker

Work status for the Rust backend, against AdGuard Home **v0.107.79**.

Legend: **[x]** done and verified · **[~]** partial, see the note · **[ ]** not started

Verification claims below are reproducible with `scripts/verify.sh` and
`cargo test --workspace` (555 tests).

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
| Web interface | done, embedded |
| Docker | done, same runtime contract |
| DHCP | **out of scope** — API reports it off and refuses changes |
| Encrypted inbound listeners | DoT, DoH, HTTP/3 and DoQ done · DNSCrypt **out of scope** |
| Safe browsing / parental / safe search | done |
| Clients | persistent settings, ClientID, ARP/rDNS/WHOIS/hosts discovery |
| Operations | logging, rotation, pidfile, privileges, service install |
| Self-update | **out of scope** — the check reports releases, the install refuses |

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
      back to HTTP/2 when a server does not speak it)
- [x] `upstream_dns_file`, read afresh on each reload
- [x] Bootstrap resolution for encrypted upstreams' hostnames
- [x] Upstream specification syntax including `[/domain/]` groups and the `#`
      deferral form
- [x] Upstream modes: load balance (latency-ranked), parallel, fastest address
- [x] Fallback resolvers
- [x] Response cache: sized in bytes, sharded, TTL bounds, optimistic serving,
      keyed on the EDNS `DO` bit so a validating client is never served a
      stripped answer
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
- [x] **Verified**: AdGuard's own dnsproxy client, with full certificate
      verification, resolves through all three listeners; the query log records
      them as `dot`, `doh` and `doq`; `/control/tls/status` matches Go field for
      field with the same certificate loaded

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
- [x] `querylog.json`: exact JSON shape, rotation, in-memory buffer, reverse
      chunked reads for the API
- [x] **Verified**: 43 real log lines re-encode byte for byte
- [x] Query log search by name, address, client name and ClientID, and the
      `older_than` cursor
- [x] Statistics: hourly units, upstream's result categories and quirks
- [x] `agl-bolt`: bbolt reader and writer
- [x] `agl-gob`: Go `gob` for the statistics unit
- [x] **Session persistence** in `sessions.db`, in the layout the Go build
      uses, so a restart does not sign everyone out and either build reads the
      other's file
- [x] **Verified**: Go reads a `stats.db` this writes and reports the same
      counts; this reads a `stats.db` Go wrote

### HTTP API and interface
- [x] All 81 upstream paths routed
- [x] Sessions: `agh_session` cookie, HTTP Basic, login rate limiting
- [x] Setup wizard reachable before a user exists
- [x] **Verified**: response shapes match Go for all 25 endpoints the UI loads
- [x] Web interface embedded, gzip-compressed, served with content negotiation
- [x] Version check: `/control/version.json` fetches AdGuard's announcement,
      caches it for eight hours, honours `--no-check-update`, and reports
      `can_autoupdate: false`

### Packaging and operations
- [x] CLI accepting every flag the Go binary documents
- [x] Docker image with upstream's runtime contract, verified against a config
      and data directory a Go instance produced
- [x] **Published image**: `.github/workflows/docker.yml` builds `linux/amd64`
      and `linux/arm64` on native runners, pushes each by digest, and joins
      them into one multi-architecture tag on `ghcr.io/openhoangnc/adguardlite`.
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
  DNSCrypt can front adguardlite with `dnscrypt-proxy`.

Note that DNSCrypt is **not** a dead protocol: AdGuard's own provider list at
<https://adguard-dns.io/kb/general/dns-providers/> still publishes DNSCrypt
addresses and `sdns://` stamps for AdGuard DNS, Quad9, OpenDNS, CleanBrowsing
and others. The exclusion is about the cost and risk of implementing it here,
not about nobody using it. If that trade changes, this is a session on its own,
with the Go implementation as an oracle throughout.

### Replacing its own binary

**`POST /control/update` answers 501.** The releases the announcement server
publishes are AdGuard Home's own Go binaries; downloading one and writing it
over this executable would replace adguardlite with a different
implementation. That is not an update, and doing it silently would be worse
than refusing.

What does work:

- `GET`/`POST /control/version.json` fetches
  `https://static.adtidy.org/adguardhome/release/version.json`, caches the
  answer for eight hours, and re-fetches on `recheck_now`. The interface can
  therefore say a newer AdGuard Home exists.
- `can_autoupdate` is always `false`, which is how the interface is told not to
  offer the button.
- `--no-check-update` reports the feature as `disabled`, and nothing is
  fetched.

Replace the binary through whatever installed it: the package manager, the
container image, or `-s stop`, copy, `-s start`.

---

## Deliberate deviations

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
- **A changed listener *port* still needs a restart.** The certificate is
  live-reloadable; which ports are bound is decided when the listeners start.

---

## Not implemented

Nothing outstanding. The features listed under **Deliberate exclusions** above
are decisions rather than gaps, and each refuses clearly at the point a user
would notice.

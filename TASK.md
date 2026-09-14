# Task tracker

Work status for the Rust backend, against AdGuard Home **v0.107.79**.

Legend: **[x]** done and verified · **[~]** partial, see the note · **[ ]** not started

Verification claims below are reproducible with `scripts/verify.sh` and
`cargo test --workspace` (344 tests).

---

## Summary

| Area | State |
|---|---|
| Config file | done, byte-identical to Go |
| Filtering engine | done, every verdict matches Go on the real list |
| DNS (plain UDP/TCP) | done |
| Upstreams | plain UDP/TCP, DoT, DoH done · DoQ, DNSCrypt missing |
| Query log | done, byte-identical |
| Statistics | done, `stats.db` interoperable both ways |
| HTTP API | all 81 paths routed · 71 implemented, 10 answer 501 |
| Web interface | done, embedded |
| Docker | done, same runtime contract |
| DHCP | **out of scope** — API reports it off and refuses changes |
| Encrypted inbound listeners | DoT, DoH and DoQ done · DNSCrypt **out of scope** |
| Safe browsing / parental / safe search | not implemented |

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
- [x] System hosts file, when `hostsfile_enabled` is set
- [x] Filter list storage in `data/filters/<id>.txt`, download and refresh

### DNS
- [x] Plain DNS over UDP and TCP, with TCP connection reuse and idle timeout
- [x] Truncation handling, both directions
- [x] Upstreams: plain UDP, TCP, DNS-over-TLS, DNS-over-HTTPS
- [x] Bootstrap resolution for encrypted upstreams' hostnames
- [x] Upstream specification syntax including `[/domain/]` groups and the `#`
      deferral form
- [x] Upstream modes: load balance (latency-ranked), parallel, fastest address
- [x] Fallback resolvers
- [x] Response cache: sized in bytes, sharded, TTL bounds, optimistic serving
- [x] Blocking modes: default, custom IP, NXDOMAIN, null IP, REFUSED —
      including the negative-caching SOA's exact field values
- [x] Rate limiting per client subnet, with an exemption list
- [x] Access control: allowed and disallowed clients
- [x] Blocked hosts dropped on UDP, REFUSED on TCP
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
- [x] HTTPS for the web interface, sharing the port with DoH as upstream does
- [x] DoH refused over plain HTTP unless `insecure_enabled` is set
- [x] **Verified**: AdGuard's own dnsproxy client, with full certificate
      verification, resolves through all three listeners; the query log records
      them as `dot`, `doh` and `doq`; `/control/tls/status` matches Go field for
      field with the same certificate loaded

### Storage
- [x] `querylog.json`: exact JSON shape, rotation, in-memory buffer, reverse
      chunked reads for the API
- [x] **Verified**: 43 real log lines re-encode byte for byte
- [x] Statistics: hourly units, upstream's result categories and quirks
- [x] `agl-bolt`: bbolt reader and writer
- [x] `agl-gob`: Go `gob` for the statistics unit
- [x] **Verified**: Go reads a `stats.db` this writes and reports the same
      counts; this reads a `stats.db` Go wrote

### HTTP API and interface
- [x] All 81 upstream paths routed
- [x] Sessions: `agh_session` cookie, HTTP Basic, login rate limiting
- [x] Setup wizard reachable before a user exists
- [x] **Verified**: response shapes match Go for all 25 endpoints the UI loads
- [x] Web interface embedded, gzip-compressed, served with content negotiation

### Packaging
- [x] CLI accepting every flag the Go binary documents
- [x] Docker image with upstream's runtime contract, verified against a config
      and data directory a Go instance produced
- [x] Graceful shutdown persisting the query log and statistics

---

## Not implemented

### Endpoints answering 501
Routed, and refusing rather than pretending to succeed.

Pending — these become real work when the feature lands:

- [ ] `POST /control/update`

Settled — these stay 501 by design, see [DHCP](#dhcp--out-of-scope-not-pending):

- [x] `POST /control/dhcp/set_config`
- [x] `POST /control/dhcp/find_active_dhcp`
- [x] `POST /control/dhcp/add_static_lease`
- [x] `POST /control/dhcp/remove_static_lease`
- [x] `PUT  /control/dhcp/update_static_lease`
- [x] `POST /control/dhcp/reset`
- [x] `POST /control/dhcp/reset_leases`

### DHCP — out of scope, not pending

**This build will not serve DHCP.** It is a deliberate exclusion, not a gap
waiting to be filled: run DHCP on your router or a dedicated service.

What that means in practice:

- `GET /control/dhcp/status` always reports `enabled: false` with empty ranges
  and no leases, whatever the config file holds. Echoing a stored
  `enabled: true` would tell the interface a server is running when nothing
  serves leases.
- `GET /control/dhcp/interfaces` returns `{}`.
- Every endpoint that would change DHCP settings answers **501** with a message
  saying so: `set_config`, `find_active_dhcp`, `add_static_lease`,
  `remove_static_lease`, `update_static_lease`, `reset`, `reset_leases`.
  Accepting them would write settings into the config that nothing acts on.
- The `dhcp:` section of `AdGuardHome.yaml` is still **read and written
  unchanged**. It has to be, for the file to round-trip byte for byte, and it
  means someone switching back to the Go build keeps their settings. Do not
  delete the model.

501 is what upstream's own API documents for a build without DHCP support, so
the web interface already knows how to present it.

### Encrypted inbound listeners — the rest
DoT, DoH, DoQ and HTTPS are done; these are what remain.

- [ ] HTTP/3 for DNS-over-HTTPS (`serve_http3`, `use_http3_upstreams`)
- [ ] The HTTP→HTTPS redirect (`force_https` is stored and unread)
- [ ] Certificate reload without a restart: a certificate replaced through
      `/control/tls/configure` is stored, but the running listeners keep the
      one they started with

### Encrypted upstreams
- [ ] DNS-over-QUIC (`quic://`)
- [ ] DNSCrypt (`sdns://` stamps)

Both parse today and are reported at startup and skipped.

These are separate from the listeners, and the DNSCrypt one is worth more than
its listener: a `sdns://` upstream means *using* a DNSCrypt provider, and
AdGuard's own provider list publishes stamps for AdGuard DNS, Quad9, OpenDNS
and others. A user migrating a config that names one loses their upstream
today. The client side also needs far less than the server side — no
certificate to serve, no provider keys to manage.

### DNSCrypt listener — out of scope, not pending

**This build will not serve DNSCrypt.** Unlike DHCP, nothing about the API
changes: `port_dnscrypt` and `dnscrypt_config_file` round-trip through the
config file untouched, `/control/tls/status` reports them as stored, and no
endpoint refuses anything. The port is simply never bound.

Why it was excluded rather than scheduled:

- It is the only remaining protocol that needs cryptography this project does
  not already have. DoT, DoH and DoQ came almost free once rustls and quinn
  were in the tree; DNSCrypt needs X25519 key exchange, Ed25519 signing and
  NaCl box (XSalsa20-Poly1305), none of them present.
- On top of the primitives it needs a signed-certificate protocol served over
  DNS — client magic, resolver magic, padding rules — and a
  `dnscrypt_config_file` matching AdGuard's own format, including provider key
  material. Their Go library is roughly 4,400 lines.
- A mistake in key handling or nonce reuse is a silent security failure, not a
  visible bug, and this project has no way to test for one the way it tests
  everything else — by comparing against a running Go build.
- The three protocols it would sit alongside all work, so a deployment that
  needs DNSCrypt can front adguardlite with `dnscrypt-proxy`.

Note that DNSCrypt is **not** a dead protocol: AdGuard's own provider list at
<https://adguard-dns.io/kb/general/dns-providers/> still publishes DNSCrypt
addresses and `sdns://` stamps for AdGuard DNS, Quad9, OpenDNS, CleanBrowsing
and others. The exclusion is about the cost and risk of implementing it here,
not about nobody using it. If that trade changes, this is a session on its own,
with the Go implementation as an oracle throughout.

### Filtering features
- [ ] Safe browsing: the hash-prefix lookup protocol and its cache
- [ ] Parental control: same protocol, different list
- [ ] Safe search: rewriting to each provider's safe endpoint. The rule files
      ship in upstream's `internal/filtering/safesearch/rules/`
- [ ] Blocked-services **schedule** — the weekly time ranges are stored and
      round-trip through the config, but the block applies at all times
- [ ] Per-client settings: a persistent client's own filtering toggles,
      upstreams, tags and blocked services do not affect resolution
- [ ] ClientID: the DoH path segment is routed and accepted, but the identifier
      is not yet used to select per-client settings

### Client discovery
- [ ] ARP table
- [ ] Reverse DNS
- [ ] WHOIS
- [ ] Hosts file as a client source (it is used for *filtering*, not naming)

`/control/clients` reports an empty `auto_clients`, and query log entries carry
an empty `client_info.name`.

### DNS features
- [ ] EDNS Client Subnet — `edns_client_subnet` is stored and unread
- [ ] DNS64 synthesis (`use_dns64`, `dns64_prefixes`)
- [ ] `ipset` and `ipset_file`
- [ ] `bogus_nxdomain`
- [ ] `trusted_proxies` and `X-Forwarded-For` handling
- [ ] `upstream_dns_file`
- [ ] Private reverse DNS: `local_ptr_upstreams`, `private_networks`,
      `use_private_ptr_resolvers`
- [ ] DDR handling (`handle_ddr`)
- [ ] Duplicate-request coalescing (`pending_requests`)
- [ ] `max_goroutines` as a concurrency bound
- [ ] DNSSEC — `enable_dnssec` is stored and unread: the DO bit is not set on
      upstream queries and no answer is validated. The cache does key on the
      request's AD flag, so a validating client's queries stay separate

### Operations
- [ ] Config migration from schema versions below 34
- [ ] Session persistence in `sessions.db` — sessions are in memory, so a
      restart signs users out
- [ ] Automatic updates and the version check
- [ ] Service install/uninstall (`-s install`, etc.)
- [ ] `--pidfile`, `--logfile` and log rotation (`log.max_size`,
      `max_backups`, `max_age`, `compress`)
- [ ] Dropping privileges (`os.user`, `os.group`, `os.rlimit_nofile`)
- [ ] Query log search by client, and the `older_than` cursor

---

## Deliberate deviations

Not bugs; recorded so nobody "fixes" them.

- **No DNSCrypt listener.** Excluded on purpose: the only remaining protocol
  needing cryptography not already in the tree, and untestable against the Go
  build the way everything else here is. See
  [DNSCrypt](#dnscrypt-listener--out-of-scope-not-pending).
- **No DHCP server.** Excluded on purpose. The API reports the feature off and
  refuses every change; the config section still round-trips. See
  [DHCP](#dhcp--out-of-scope-not-pending).

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

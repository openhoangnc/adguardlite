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
| DHCP | not implemented |
| Encrypted inbound listeners | not implemented |
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
These are routed and return `501 Not Implemented` rather than pretending to
succeed.

- [ ] `POST /control/dhcp/set_config`
- [ ] `POST /control/dhcp/find_active_dhcp`
- [ ] `POST /control/dhcp/add_static_lease`
- [ ] `POST /control/dhcp/remove_static_lease`
- [ ] `PUT  /control/dhcp/update_static_lease`
- [ ] `POST /control/dhcp/reset`
- [ ] `POST /control/dhcp/reset_leases`
- [ ] `POST /control/tls/configure`
- [ ] `POST /control/tls/validate`
- [ ] `POST /control/update`

### DHCP
- [ ] DHCPv4 server: discover/offer/request/ack, lease store, conflict probing
- [ ] DHCPv6 server and router advertisements
- [ ] Static leases
- [ ] Lease-derived DNS names and client identification
- [ ] `/control/dhcp/interfaces` currently returns an empty object

Needs raw-socket handling and per-platform interface enumeration; the largest
single item remaining.

### Encrypted inbound listeners
- [ ] DNS-over-TLS listener (port 853)
- [ ] DNS-over-HTTPS listener, including the `{ClientID}` routes already
      present in the config model
- [ ] DNS-over-QUIC listener
- [ ] DNSCrypt listener
- [ ] HTTP/3 for the above
- [ ] HTTPS for the web interface, and the HTTP→HTTPS redirect
- [ ] Certificate loading, validation and the `/control/tls/*` endpoints

`agl-dns` already owns a rustls client config; the server side needs a
certificate resolver and one listener per protocol. DoT and DoH are the
worthwhile first two — the resolver and `Proto` enum already model them.

### Encrypted upstreams
- [ ] DNS-over-QUIC (`quic://`)
- [ ] DNSCrypt (`sdns://` stamps)

Both parse today and are reported at startup and skipped.

### Filtering features
- [ ] Safe browsing: the hash-prefix lookup protocol and its cache
- [ ] Parental control: same protocol, different list
- [ ] Safe search: rewriting to each provider's safe endpoint. The rule files
      ship in upstream's `internal/filtering/safesearch/rules/`
- [ ] Blocked-services **schedule** — the weekly time ranges are stored and
      round-trip through the config, but the block applies at all times
- [ ] Per-client settings: a persistent client's own filtering toggles,
      upstreams, tags and blocked services do not affect resolution
- [ ] ClientID extraction from DoH/DoT paths

### Client discovery
- [ ] ARP table
- [ ] Reverse DNS
- [ ] WHOIS
- [ ] DHCP leases
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

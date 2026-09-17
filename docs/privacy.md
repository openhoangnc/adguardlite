# Privacy

Sift runs entirely on your own machine. It has no accounts, no
telemetry, no analytics and no crash reporting, and it never uploads your query
log, your statistics or your configuration anywhere.

Everything below is the complete list of what the server sends off the machine,
and what stays on it.

## What stays on your machine

| Data | Where it lives |
|---|---|
| The query log — every question, its verdict and who asked | `<work>/data/querylog.json` |
| Statistics — counters per hour | `<work>/data/stats.db` |
| Web interface sessions | `<work>/data/sessions.db` |
| Downloaded filter lists | `<work>/data/filters/` |
| Your own rules | `<work>/data/userfilters/` |
| Everything else you configure | `AdGuardHome.yaml` |

Nothing reads these but the server and whoever can reach the machine. The query
log's retention is set in **Settings → General settings**, and it can be turned
off entirely; so can statistics. A client can be excluded from either with
**Ignore query log** and **Ignore statistics**.

## What leaves your machine

### Your DNS queries, to the upstreams you chose

This is the point of the software. Each query is forwarded to the upstream
servers configured in **Settings → DNS settings**, unless it is answered from
the cache, blocked, or rewritten first. Those servers see the queries, and
their own privacy policy governs what they do with them — pick upstreams you
are willing to trust, and prefer an encrypted transport so nothing in between
sees them too.

Two settings widen what an upstream is told:

- **EDNS client subnet** attaches a truncated form of the asking client's
  address to the query, so the upstream can answer with a nearby server. It is
  off by default.
- **Enable reverse resolving of clients' IP addresses** sends `PTR` queries for
  client addresses. Private addresses go to the private resolvers; public ones
  go to the ordinary upstreams.

### Filter list downloads

The URLs you added under **Filters**, fetched over HTTPS when a list is
refreshed. Each server learns your IP address and that you use Sift —
the request carries `User-Agent: AdGuardLite/<version>` — but nothing about
what you resolved.

### Safe browsing and parental control, if you enable them

Both are off by default. When on, the hostname itself is **never sent**. Each
of the name's parent labels is hashed with SHA-256, the first two bytes of each
hash become labels of a `TXT` query, and the server answers with every full
hash it knows in those buckets; the match is then made locally. The server
learns a two-byte bucket, which many names share, not the name.

Those queries go to `family.adguard-dns.com` over DNS-over-HTTPS, whose
addresses are built in so the lookup cannot depend on this very server.
AdGuard operates that endpoint and their [privacy policy][agpp] governs it.

[agpp]: https://adguard.com/en/privacy/dns.html

### The update check

Once every eight hours, a request to
`api.github.com/repos/openhoangnc/sift/releases/latest` to learn whether
a newer release exists. GitHub sees your IP address and the request. Nothing
about your configuration or your queries is sent, and nothing is installed —
`can_autoupdate` is always false.

Start the server with `--no-check-update` to switch this off. The Docker image
does, by default.

### Nothing else

There is no other outbound request. In particular there is no usage reporting,
no license check and no phone-home of any kind.

## Reaching the web interface

The interface is served over plain HTTP unless you configure a certificate
under **Settings → Encryption settings**. Over HTTP, the session cookie and
everything you type — including the password — cross the network in the clear.
Serve it over HTTPS, or keep it on a network where that does not matter.

Sessions live in `<work>/data/sessions.db`. Deleting that file signs everyone
out.

## Third parties

This project is not affiliated with AdGuard Software Limited. It is an
independent reimplementation of AdGuard Home, which is theirs and is licensed
GPL-3.0; see [NOTICE.md](../NOTICE.md). The AdGuard services it can be
configured to talk to — the family resolver above, and AdGuard's DNS resolvers
if you choose them as upstreams — are operated by AdGuard under their own
policies, not by this project.

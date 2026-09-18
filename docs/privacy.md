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

### The update check

Once every eight hours, a request to
`api.github.com/repos/openhoangnc/sift/releases/latest` to learn whether
a newer release exists. GitHub sees your IP address and the request. Nothing
about your configuration or your queries is sent.

Nothing is downloaded by the check itself. The release archive is fetched only
when somebody presses **Install** in the interface, and then from
`github.com`, which sees the same.

Start the server with `--no-check-update` to switch both off. The Docker image
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
configured to talk to — AdGuard's DNS resolvers, if you choose them as
upstreams, and their filter lists, if you subscribe to them — are operated by
AdGuard under their own policies, not by this project.

This build makes no safe browsing or parental control lookups. AdGuard Home
checks each name against AdGuard's hash-prefix service when those are on; there
is no such check here, and nothing about a name you resolve is sent to AdGuard
unless you chose one of their resolvers as an upstream.

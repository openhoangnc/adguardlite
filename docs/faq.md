# FAQ

Questions the web interface links to, answered for this build. AdGuard Home's
own [knowledge base][kb] covers the parts that behave identically; what follows
is where Sift differs, or where the answer depends on how this binary
ships.

[kb]: https://adguard-dns.io/kb/adguard-home/

## Manual update

Sift does not replace its own binary. `POST /control/update` answers
`501`, and the interface is told `can_autoupdate: false` so it never offers an
update button. Rewriting a running executable in place is the job of whatever
installed it, and this build ships as a container image and as archives rather
than as a self-updating binary.

`/control/version.json` still reports the latest release, so the interface can
say one exists. It reads
[this repository's releases](https://github.com/openhoangnc/sift/releases)
and caches the answer for eight hours. `--no-check-update` turns the check off
entirely.

To update:

**Docker.** Pull the new image and recreate the container against the same
volume. Nothing on the volume has to change between versions.

```bash
docker pull ghcr.io/openhoangnc/sift:latest
docker rm -f sift
docker run -d --name sift ...   # your usual run arguments
```

**An archive.** Stop the service, replace the binary, start it again.

```bash
sudo systemctl stop AdGuardHome
sudo install -m 0755 ./AdGuardHome /opt/adguardhome/AdGuardHome
sudo systemctl start AdGuardHome
```

The configuration file and the work directory are read in place and are not
rewritten by an upgrade, so a downgrade works the same way.

## Address already in use

The server could not bind a port because something else already holds it. On a
default install this is almost always port 53, and on Linux the other holder is
usually `systemd-resolved`.

Find the holder:

```bash
sudo ss -lptn 'sport = :53'
sudo ss -lpun 'sport = :53'
```

### systemd-resolved

Stop it listening on 53 without losing local name resolution: set
`DNSStubListener=no` in `/etc/systemd/resolved.conf`, point `/etc/resolv.conf`
at the real resolver file, and restart it.

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/sift.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

### Another DNS server

`dnsmasq`, `named`, `unbound` and a second AdGuard Home or Sift all bind
53. Stop and disable whichever one you are not keeping.

### Ports below 1024 without root

Binding 53, 80, 443 or 853 needs privilege. Either grant the capability to the
binary:

```bash
sudo setcap 'CAP_NET_BIND_SERVICE=+eip' /opt/adguardhome/AdGuardHome
```

or move the listener to a high port in **Settings → DNS settings** and redirect
to it in your firewall.

### macOS

`mDNSResponder` holds 53 on some configurations, and the port cannot be taken
from it. Run the DNS listener on another port and point your clients at that.

## Which AdGuard Home features are missing

Three, all deliberate, all of which report themselves rather than pretending to
work:

- **DHCP.** No server. The API reports the feature off and refuses every change,
  so the interface cannot store settings nothing acts on. Your existing DHCP
  settings in `AdGuardHome.yaml` are preserved untouched, so switching back to
  AdGuard Home keeps them.
- **DNSCrypt.** No listener, and an `sdns://` upstream is reported at startup
  and skipped.
- **Self-update.** See [Manual update](#manual-update) above.

Everything else — filtering, blocked services, safe search, safe browsing,
parental control, rewrites, clients, the query log, statistics, DoT, DoH, DoQ
and HTTP/3 — is implemented.

## Where is my data

Under the work directory given by `-w`:

| Path | What it holds |
|---|---|
| `data/querylog.json`, `data/querylog.json.1` | the query log, JSON lines |
| `data/stats.db` | statistics, a bbolt database |
| `data/sessions.db` | web interface sessions |
| `data/filters/` | downloaded filter lists |
| `data/userfilters/` | your own rules |

The configuration lives wherever `-c` points, `AdGuardHome.yaml` by default.
Every one of these files is byte-compatible with AdGuard Home v0.107.79: the
same installation can be run by either build, in either order.

## Password reset

See [Configuration → Password reset](configuration.md#password-reset).

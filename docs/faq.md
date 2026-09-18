# FAQ

Questions the web interface links to, answered for this build. AdGuard Home's
own [knowledge base][kb] covers the parts that behave identically; what follows
is where Sift differs, or where the answer depends on how this binary
ships.

[kb]: https://adguard-dns.io/kb/adguard-home/

## Updating

`/control/version.json` reads
[this repository's releases](https://github.com/openhoangnc/sift/releases) and
caches the answer for eight hours, so the interface can tell you a newer one
exists. `--no-check-update` turns the check off entirely, and the Docker image
passes it.

**From the web interface.** When the top bar says a release is available, it
offers **Install**. The server downloads the archive for its own machine,
checks it against the published `checksums.txt`, runs the new binary — once
for its version and once over your real configuration with `--check-config` —
and only then moves it into place and restarts into it. The binary it replaced
and a copy of your config file are left in `<work>/agh-backup`, which is where
AdGuard Home's updater puts them, so going back is a stop, a `mv` and a start.

The button appears only where it would work. It is **not** offered inside a
container, where the image is what gets updated and a replaced binary is
thrown away by the next `docker run`; nor where the executable's directory is
read-only; nor where a restart could not bind the ports the server uses now —
which on Unix means running as root when anything below port 1024 is bound.

`SIFT_VERSION_URL` and `SIFT_RELEASES_URL` point the check and the download at
a private mirror instead. The checksum still has to match, so neither is a way
to install something else.

The other ways to update:

**Docker.** Pull the new image and recreate the container against the same
volume. Nothing on the volume has to change between versions.

```bash
docker pull ghcr.io/openhoangnc/sift:latest
docker rm -f sift
docker run -d --name sift ...   # your usual run arguments
```

**The installer.** Run the same line that installed it. It compares the
installed version against the newest release, replaces only the binary, and
puts the old one back if the service does not stay up.

```bash
curl -s -S -L https://raw.githubusercontent.com/openhoangnc/sift/main/scripts/install.sh | sh -s -- -v
```

**An archive, by hand.** Stop the service, replace the binary, start it again.

```bash
sudo systemctl stop AdGuardHome
sudo install -m 0755 ./AdGuardHome /opt/AdGuardHome/AdGuardHome
sudo systemctl start AdGuardHome
```

The configuration file and the work directory are read in place and are not
rewritten by an upgrade, so a downgrade works the same way — including a
downgrade to AdGuard Home itself.

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

Two, both deliberate, and both of which report themselves rather than
pretending to work:

- **DHCP.** No server. The API reports the feature off and refuses every change,
  so the interface cannot store settings nothing acts on. Your existing DHCP
  settings in `AdGuardHome.yaml` are preserved untouched, so switching back to
  AdGuard Home keeps them.
- **DNSCrypt.** No listener, and an `sdns://` upstream is reported at startup
  and skipped.

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

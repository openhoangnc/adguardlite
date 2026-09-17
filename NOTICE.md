# Notices and attribution

`sift` is a derivative work of
[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), Copyright (C)
AdGuard Software Ltd., licensed under the GNU General Public License version 3.
This project is licensed under the same terms; see [LICENSE](LICENSE).

It is an independent reimplementation of the AdGuard Home backend in Rust,
built to be interchangeable with release **v0.107.79**, shipping a fork of
AdGuard Home's own web interface. It is not produced, endorsed or supported by
AdGuard.

## Statement of modification

Required by GPL-3.0 section 5(a).

**This is a modified version of AdGuard Home.** It is not AdGuard Home and
AdGuard did not make it.

| | |
|---|---|
| Modified from | AdGuard Home v0.107.79, commit `05ba17b282da1c4393d6a4ba4db0cf519194a362` |
| Backend | rewritten in Rust; no upstream source carried over |
| Web interface | forked from that commit's `client/` on **2026-09-17**, modified since — see [The forked web interface](#the-forked-web-interface) |
| Removed | DHCP, DNSCrypt, self-update |
| Renamed | to "Sift"; see [Trademarks](#trademarks) |

Every release since carries its changes in [TASK.md](TASK.md) and in the git
history of <https://github.com/openhoangnc/sift>, which is the
Corresponding Source for any binary or container image distributed from it.

## Trademarks

"AdGuard" and the AdGuard shield are trademarks of AdGuard Software Ltd. The
GPL-3.0 grants rights over copyright and not over trademarks, so this project
uses neither.

**Sift is its own name and its own mark.** The wordmark is the word "Sift" set
in the system UI font; the icon is a funnel, drawn here. Neither derives from
anything of AdGuard's, and no AdGuard mark appears in the interface, the icons,
the repository name or the container image.

AdGuard is named in three places, all of them factual statements about
provenance rather than branding: this file, the interface footer ("Sift is an
independent fork of AdGuard Home, not affiliated with or endorsed by
AdGuard"), and the copyright notice on the interface code, which the GPL
requires be kept intact.

Sift is not produced, endorsed or supported by AdGuard Software Ltd., and it is
not AdGuard Home.

### One deliberate exception

The binary is installed as `AdGuardHome` at `/opt/adguardhome/AdGuardHome`, and
the config file is `AdGuardHome.yaml`. Those are not branding: they are the
paths an existing AdGuard Home installation already uses, and being a drop-in
replacement means not moving them. They are never shown to a user as the name
of this program.

## Material included from AdGuard Home

These are AdGuard's work, redistributed under the GPL-3.0:

| In this repository | Taken from | What it is |
|---|---|---|
| `web/client/` | `client/` at `05ba17b2` | The web interface's **sources**, forked and modified — see below |
| `web/build/` | `web/client/`, built | The same, compiled and brotli-compressed |
| `crates/sift-filter/data/blocked-services.json.gz` | `/control/blocked_services/all` | The 139-service catalogue: names, icons and blocking rules |
| `crates/sift-filter/src/safesearch/*.txt` | `internal/filtering/safesearch/rules/` | The safe-search rules for the seven supported providers, verbatim |
| `tests/fixtures/` | a running v0.107.79 instance | Reference config, query-log lines, `stats.db`, gob payloads, and the verdicts Go gave for 4,190 domains |
| `docker/Dockerfile` (runtime stage) | `docker/build.Dockerfile` | The image's runtime contract |

`tests/fixtures/filters/adguard-dns-filter.txt.gz` is the AdGuard DNS filter
list, redistributed for testing. The list is maintained by AdGuard and
published from
[HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).

`web/client/src/components/ui/Tabler.css` carries AdGuard's vendored copy of
[Bootstrap](https://github.com/twbs/bootstrap) 4.0.0, MIT; its copyright notice
is kept in the file's header, where upstream left it.

`upstream/` is not part of this repository — it is gitignored, and holds a
checkout of AdGuard Home used as the reference implementation during
development.

## The forked web interface

`web/client/` began as AdGuard Home v0.107.79's `client/` directory, copied
verbatim. It is AdGuard's code under the GPL-3.0, and the modifications are
this project's, under the same licence. What changed:

- **DHCP removed** — the settings page, its container, reducer, actions and API
  calls, and every `dhcp_*` string in all 36 locale files. This build has no
  DHCP server, and a settings page that saves nothing is worse than none.
- **DNSCrypt removed** — the `sdns://` upstream example, the DNSCrypt entries in
  the setup guide, the query-log transport label, and the related strings.
  There is no DNSCrypt listener.
- **Rebranded to Sift** — AdGuard's shield replaced by a funnel of this
  project's own, the icons redrawn to match, and all 36 locales and the page
  titles renamed. The footer states the fork relationship where users see it.
- **Links repointed** — `link.adtidy.org` redirectors replaced by the pages
  they resolve to, repository and issue links pointed at this project, and the
  AdGuard Home wiki links pointed at [`docs/`](docs/).
- **A Clear cache button** on the dashboard, beside Refresh statistics.
- **`.twosky.json` dropped** — upstream reads its language list from AdGuard's
  translation-service configuration, which lives above `client/`. The fork
  carries the list in `src/helpers/languages.ts` instead, so nothing outside
  `web/client/` is needed to build.
- **Build output** — webpack writes to `web/build/`, and the assets are stored
  brotli-compressed rather than gzip.

The upstream original of any file is
`https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/client/<path>`.

## Rebuilding the included material

The generated artefacts can be regenerated rather than trusted as committed
blobs:

```bash
scripts/build-frontend.sh          # regenerates web/build/ from web/client/
```

To compare the fork against what it came from, or to regenerate the material
copied verbatim, clone the reference implementation:

```bash
git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git upstream
diff -ru upstream/client web/client   # every modification, as a patch
```

To take a newer upstream client release into the fork, `scripts/sync-frontend.sh`
three-way merges upstream's own diff between two tags:

```bash
scripts/sync-frontend.sh v0.107.80
```

The services catalogue is captured from a running instance's
`/control/blocked_services/all`, and the safe-search rules are copied
verbatim from the upstream checkout:

```bash
cp upstream/internal/filtering/safesearch/rules/*.txt \
   crates/sift-filter/src/safesearch/
```

## Third-party Rust dependencies

Their licences are those declared in `Cargo.lock`; `cargo tree` lists the tree
and `cargo license` (if installed) summarises it.

## Third-party JavaScript dependencies

`web/client/package.json` declares them and `web/client/package-lock.json`
pins them. They are build-time dependencies whose compiled output is bundled
into `web/build/`; the bundler collects their licence notices into the
`*.LICENSE.txt` files alongside each bundle, which are served with it.

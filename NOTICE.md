# Notices and attribution

`adguardlite` is a derivative work of
[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), Copyright (C)
AdGuard Software Ltd., licensed under the GNU General Public License version 3.
This project is licensed under the same terms; see [LICENSE](LICENSE).

It is an independent reimplementation of the AdGuard Home backend in Rust,
built to be interchangeable with release **v0.107.79**. It is not produced,
endorsed or supported by AdGuard.

## Material included from AdGuard Home

These are AdGuard's work, redistributed under the GPL-3.0:

| In this repository | Taken from | What it is |
|---|---|---|
| `web/build/` | `client/`, built | The web interface, compiled and gzip-compressed |
| `crates/agl-filter/data/blocked-services.json.gz` | `/control/blocked_services/all` | The 139-service catalogue: names, icons and blocking rules |
| `tests/fixtures/` | a running v0.107.79 instance | Reference config, query-log lines, `stats.db`, gob payloads, and the verdicts Go gave for 4,190 domains |
| `docker/Dockerfile` (runtime stage) | `docker/build.Dockerfile` | The image's runtime contract |

`tests/fixtures/filters/adguard-dns-filter.txt.gz` is the AdGuard DNS filter
list, redistributed for testing. The list is maintained by AdGuard and
published from
[HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).

`upstream/` is not part of this repository — it is gitignored, and holds a
checkout of AdGuard Home used as the reference implementation during
development.

## Rebuilding the included material

Both of the generated artefacts above can be regenerated from upstream rather
than trusted as committed blobs:

```bash
git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git upstream
scripts/build-frontend.sh          # regenerates web/build/
```

The services catalogue is captured from a running instance's
`/control/blocked_services/all`.

## Third-party Rust dependencies

Their licences are those declared in `Cargo.lock`; `cargo tree` lists the tree
and `cargo license` (if installed) summarises it.

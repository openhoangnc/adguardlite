# Notices and attribution

`sift` is a derivative work of
[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome), Copyright (C)
AdGuard Software Ltd., licensed under the GNU General Public License version 3.
This project is licensed under the same terms; see [LICENSE](LICENSE).

It is an independent reimplementation of the AdGuard Home backend in Rust,
built to be interchangeable with release **v0.107.79**, with a web interface
written for it. It is not produced, endorsed or supported by AdGuard.

## Statement of modification

Required by GPL-3.0 section 5(a).

**This is a modified version of AdGuard Home.** It is not AdGuard Home and
AdGuard did not make it.

| | |
|---|---|
| Modified from | AdGuard Home v0.107.79, commit `05ba17b282da1c4393d6a4ba4db0cf519194a362` |
| Backend | rewritten in Rust; no upstream source carried over |
| Web interface | written for this project; no AdGuard source, text or design — see [The web interface](#the-web-interface) |
| Removed | DHCP, DNSCrypt, safe browsing and parental control |
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

AdGuard is named in two places, both factual statements about provenance
rather than branding: this file, and the interface footer ("Sift is an
independent reimplementation of AdGuard Home. It is not affiliated with,
endorsed by, or supported by AdGuard.").

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
| `crates/sift-filter/data/blocked-services.json.gz` | `/control/blocked_services/all` | The 139-service catalogue: names, icons and blocking rules |
| `crates/sift-filter/data/blocklists.json.gz` | `client/src/helpers/filters/filters.ts` at `v0.107.79` | The 64 vetted blocklists AdGuard compiles from their [HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry): names, categories, homepages and addresses. The **tags, notes, country codes, rule counts and any list added here are this project's** — see below |
| `crates/sift-filter/src/safesearch/*.txt` | `internal/filtering/safesearch/rules/` | The safe-search rules for the seven supported providers, verbatim |
| `tests/fixtures/` | a running v0.107.79 instance | Reference config, query-log lines, `stats.db`, gob payloads, and the verdicts Go gave for 4,190 domains |
| `docker/Dockerfile` (runtime stage) | `docker/build.Dockerfile` | The image's runtime contract |

`tests/fixtures/filters/adguard-dns-filter.txt.gz` is the AdGuard DNS filter
list, redistributed for testing. The list is maintained by AdGuard and
published from
[HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry).

`upstream/` is not part of this repository — it is gitignored, and holds a
checkout of AdGuard Home used as the reference implementation during
development.

## The web interface

`web/client` is this project's own: React 19, TypeScript, react-router and
ECharts, written against the same control API. **No AdGuard material is in it
at all** — no JavaScript, no CSS, no markup, no icons, no wording, and not
their layout. Every string a user reads was written for this project.

It did not start that way. The interface was first AdGuard's compiled bundle,
then a fork of their client sources, and briefly a rewrite that kept their 36
translation catalogues. Those catalogues are gone too, and the interface is
English only; [TASK.md](TASK.md) records why.

`web/build/` is `web/client/` compiled and brotli-compressed, so it carries
whatever the sources do — which is nothing of AdGuard's.

Two things of AdGuard's do reach the interface, both through the API rather
than through its code, and both listed in the table above: the **services
catalogue** the blocked-services page renders, and the **blocklist catalogue**
the "Choose blocklists" picker offers. AdGuard Home bundles the second one in
its own client; carrying it on this side of the API is what keeps
`web/client` free of their material.

Neither catalogue's *names for its groups* came across: upstream stores those
as translation keys, so the category and group headings in this interface were
written for it.

The blocklist catalogue also carries material that is **not** AdGuard's and
never was. `scripts/blocklist-notes.json` holds, for this project:

- a tag set and a written note for every list — what it blocks, who it suits,
  and what to expect of it;
- the ISO 3166-1 country each regional list serves, which the interface draws
  as a flag;
- `_add`, lists this project carries that upstream's registry does not.
  Currently one: [hostsVN](https://github.com/bigdargon/hostsVN), MIT, ©
  BigDargon — linked and fetched at runtime like every other list, not
  redistributed here.

The rule count beside each list is measured by downloading it, not copied from
anywhere. `scripts/import-blocklists.py` merges all of it into the generated
blob.

## Rebuilding the included material

The generated artefacts can be regenerated rather than trusted as committed
blobs:

```bash
scripts/build-frontend.sh          # regenerates web/build/ from web/client/
```

To regenerate the material copied verbatim, clone the reference
implementation:

```bash
git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git upstream
```

The services catalogue is captured from a running instance's
`/control/blocked_services/all`, and the safe-search rules are copied
verbatim from the upstream checkout:

```bash
cp upstream/internal/filtering/safesearch/rules/*.txt \
   crates/sift-filter/src/safesearch/
```

The blocklist catalogue is converted from upstream's generated
`client/src/helpers/filters/filters.ts`, which is itself generated from the
HostlistsRegistry, and merged with this project's own annotations:

```bash
# Re-import, downloading every list to count and validate it.
python3 scripts/import-blocklists.py \
    upstream/client/src/helpers/filters/filters.ts --measure

# Re-import offline, keeping the counts already committed.  Use this after
# editing a note or a tag.
python3 scripts/import-blocklists.py upstream/client/src/helpers/filters/filters.ts
```

`--measure` refuses to write the catalogue if any list fails to download or
comes back with no rules in it, so a list that has gone away is caught here
rather than by a user who picked it.

## Third-party Rust dependencies

Their licences are those declared in `Cargo.lock`; `cargo tree` lists the tree
and `cargo license` (if installed) summarises it.

## Third-party JavaScript dependencies

`web/client/package.json` declares them and `web/client/package-lock.json`
pins them. Four are bundled into `web/build/`: **React** and **ReactDOM** (MIT,
Meta), **react-router** (MIT, Remix Software), and **Apache ECharts** (Apache
2.0, The Apache Software Foundation). The rest — Vite, TypeScript and their
trees — are build-time only and are not redistributed.

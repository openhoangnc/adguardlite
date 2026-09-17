#!/bin/sh
# Takes a newer AdGuard Home client release into this fork.
#
# web/client started as a verbatim copy of AdGuard Home v0.107.79's client/
# directory (commit 05ba17b282da1c4393d6a4ba4db0cf519194a362), so upstream's
# own diff between two tags applies to it directly.  This fetches that diff and
# three-way merges it, leaving conflict markers where our changes and theirs
# touched the same lines.
#
#   scripts/sync-frontend.sh v0.107.80
#
# Afterwards: resolve any conflicts, re-check that DHCP and DNSCrypt have not
# come back, then `scripts/build-frontend.sh` and run the suite.  Update the
# base recorded in NOTICE.md and at the top of this file once it lands.

set -e -u

new="${1:-}"
if [ -z "$new" ]; then
	echo "usage: $0 <upstream-tag>   e.g. $0 v0.107.80" >&2
	exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
upstream="$root/upstream"

# The release web/client was branched from.  Bump it when a sync lands.
base="v0.107.79"

if [ ! -d "$upstream/.git" ]; then
	echo "no upstream checkout at $upstream" >&2
	echo "clone it with:" >&2
	echo "  git clone https://github.com/AdguardTeam/AdGuardHome.git $upstream" >&2
	exit 1
fi

echo "fetching $new"
git -C "$upstream" fetch --tags origin

if ! git -C "$upstream" rev-parse -q --verify "$new^{commit}" >/dev/null; then
	echo "$new is not a tag in the upstream repository" >&2
	exit 1
fi

if ! git -C "$root" diff --quiet -- web/client; then
	echo "web/client has uncommitted changes; commit or stash them first" >&2
	exit 1
fi

patch="$(mktemp)"
trap 'rm -f "$patch"' EXIT

git -C "$upstream" diff "$base".."$new" -- client/ > "$patch"
if [ ! -s "$patch" ]; then
	echo "upstream changed nothing under client/ between $base and $new"
	exit 0
fi

echo "applying $(grep -c '^diff --git' "$patch") changed files"

# -p2 drops the leading client/, --directory puts them under web/client.
if git -C "$root" apply -p2 --directory=web/client --3way "$patch"; then
	echo "applied cleanly"
else
	echo
	echo "conflicts left in the working tree; resolve them, then:" >&2
	echo "  scripts/build-frontend.sh && cargo test --workspace" >&2
	exit 1
fi

cat <<NEXT

applied $base -> $new.  Before committing:

  1. git diff web/client              -- read every hunk
  2. grep -ril dhcp web/client/src    -- upstream may have added some back
  3. grep -ril dnscrypt web/client/src
  4. grep -rn 'link.adtidy.org\|AdguardTeam/AdGuardHome' web/client/src
  5. cd web/client && npx tsc --noEmit && npx eslint --ext .ts,.tsx src
  6. scripts/build-frontend.sh && cargo test --workspace
  7. update the base in this script and in NOTICE.md to $new
NEXT

#!/bin/sh
# Rebuilds the embedded web interface from upstream's sources.
#
# The result is committed under web/build, gzip-compressed: roughly 9.7 MB of
# JavaScript and CSS become 2.5 MB in the binary.  Run this after changing the
# pinned upstream release.

set -e -u

root="$(cd "$(dirname "$0")/.." && pwd)"
upstream="$root/upstream"

if [ ! -d "$upstream/client" ]; then
	echo "no upstream checkout at $upstream" >&2
	echo "clone it with:" >&2
	echo "  git clone --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git $upstream" >&2
	exit 1
fi

echo "building the frontend from $upstream/client"
cd "$upstream/client"
npm ci --no-audit --no-fund
npm run build-prod

built="$upstream/build/static"
if [ ! -d "$built" ]; then
	echo "the build produced nothing at $built" >&2
	exit 1
fi

echo "installing into $root/web/build"
rm -rf "$root/web/build"
mkdir -p "$root/web/build"
cp -R "$built"/* "$root/web/build/"

# Store text assets compressed; ui.rs serves them as-is to clients that accept
# gzip and decompresses for those that do not.
find "$root/web/build" -type f \
	\( -name '*.js' -o -name '*.css' -o -name '*.html' -o -name '*.svg' \
	   -o -name '*.txt' -o -name '*.json' \) \
	-exec gzip -9 -k {} \;
find "$root/web/build" -type f -name '*.gz' -exec sh -c 'rm -f "${1%.gz}"' _ {} \;

echo "done: $(du -sh "$root/web/build" | cut -f1) in $(find "$root/web/build" -type f | wc -l | tr -d ' ') files"

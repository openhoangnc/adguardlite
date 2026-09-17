#!/bin/sh
# Rebuilds the embedded web interface from this project's own frontend sources.
#
# The sources live in web/client: a fork of AdGuard Home's client at v0.107.79,
# with DHCP and DNSCrypt removed, the branding changed and the outbound links
# repointed.  The result is committed under web/build, brotli-compressed:
# roughly 9.7 MB of JavaScript and CSS become ~2 MB in the binary.
#
# Run this after any change under web/client.

set -e -u

root="$(cd "$(dirname "$0")/.." && pwd)"
client="$root/web/client"

if [ ! -d "$client/src" ]; then
	echo "no frontend sources at $client" >&2
	exit 1
fi

echo "building the frontend from $client"
cd "$client"
npm ci --no-audit --no-fund
npm run build-prod

if [ ! -f "$root/web/build/index.html" ]; then
	echo "the build produced no $root/web/build/index.html" >&2
	exit 1
fi

# Store text assets brotli-compressed; ui.rs serves them as-is to clients that
# accept br and decompresses for those that do not.
node "$root/scripts/brotli.mjs" "$root/web/build"

echo "done: $(du -sh "$root/web/build" | cut -f1) in $(find "$root/web/build" -type f | wc -l | tr -d ' ') files"

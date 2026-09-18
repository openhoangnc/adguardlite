#!/bin/sh
# Rebuilds the embedded web interface from this project's own frontend sources.
#
# The sources live in web/client: React 19, TypeScript and react-router, with
# ECharts for the dashboard and no other runtime dependency.  Vite builds the
# three documents the server serves -- the app, the login form and the setup
# wizard -- one build each, because they must not share a chunk; see ENTRIES in
# web/client/vite.config.ts.
#
# The result is committed under web/build, brotli-compressed.
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
npm run typecheck
npm run build

for page in index login install; do
	if [ ! -f "$root/web/build/$page.html" ]; then
		echo "the build produced no $root/web/build/$page.html" >&2
		exit 1
	fi
done

# Store text assets brotli-compressed; ui.rs serves them as-is to clients that
# accept br and decompresses for those that do not.
node "$root/scripts/brotli.mjs" "$root/web/build"

echo "done: $(du -sh "$root/web/build" | cut -f1) in $(find "$root/web/build" -type f | wc -l | tr -d ' ') files"

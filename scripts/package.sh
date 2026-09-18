#!/bin/sh

# Packages a built binary into the archive the installer downloads.
#
#	scripts/package.sh <binary> <os> <cpu> [out_dir]
#
# The layout inside the archive is AdGuard Home's own, so unpacking it with
# `tar -C /opt` lands the binary where their installer would have put it:
#
#	AdGuardHome/AdGuardHome
#	AdGuardHome/LICENSE.txt
#	AdGuardHome/README.md
#
# scripts/install.sh reads that layout, so the two move together.

set -e -f -u

if [ "$#" -lt '3' ]; then
	echo "usage: $0 <binary> <os> <cpu> [out_dir]" 1>&2

	exit 2
fi

bin="$1"
os="$2"
cpu="$3"
out_dir="${4:-dist}"
readonly bin os cpu out_dir

root="$(cd "$(dirname "$0")/.." && pwd)"
readonly root

if [ ! -f "$bin" ]; then
	echo "$bin: not a file" 1>&2

	exit 1
fi

stage="$(mktemp -d)"
readonly stage
trap 'rm -r -f "$stage"' EXIT INT TERM

mkdir -p "${stage}/AdGuardHome" "$out_dir"

# The binary keeps the name it has in the Docker image and in AdGuard Home's
# own package: the unit files both builds write name it, and an upgrade that
# renamed it would leave the service pointing at the old one.
cp "$bin" "${stage}/AdGuardHome/AdGuardHome"
chmod 0755 "${stage}/AdGuardHome/AdGuardHome"

cp "${root}/LICENSE" "${stage}/AdGuardHome/LICENSE.txt"
cp "${root}/README.md" "${stage}/AdGuardHome/README.md"
chmod 0644 "${stage}/AdGuardHome/LICENSE.txt" "${stage}/AdGuardHome/README.md"

pkg="${out_dir}/sift_${os}_${cpu}.tar.gz"
readonly pkg

# Two things tar does by default are wrong for an archive somebody else
# unpacks as root:
#
#   - it records the ids of whoever built it, and the installer's tar restores
#     them, so the binary ends up owned by a uid that means nothing there;
#   - Apple's tar writes a ._name AppleDouble entry beside every file carrying
#     an extended attribute, and a file downloaded on macOS carries one.
#
# The flag spellings differ between GNU tar and the bsdtar macOS ships.
if tar --version 2>/dev/null | head -1 | grep -q 'GNU tar'; then
	set -- --owner=0 --group=0 --numeric-owner
else
	set -- --uid 0 --gid 0 --uname root --gname root
fi

COPYFILE_DISABLE=1 tar -C "$stage" -c -z -f "$pkg" "$@" AdGuardHome

echo "$pkg"

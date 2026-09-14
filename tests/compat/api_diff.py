#!/usr/bin/env python3
"""Compare the control API of a Go AdGuardHome and an adguardlite instance.

Both must be running with the same configuration.  For each endpoint the
script compares the JSON *shape* — the set of keys and the type of each value,
recursively — rather than the values, because counters, timestamps and
upstream-dependent data legitimately differ between two live servers.

A shape mismatch means the web UI would see something it does not expect.
"""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request

# Endpoints the UI calls on load.  Anything here must match.
ENDPOINTS = [
    "/control/status",
    "/control/dns_info",
    "/control/filtering/status",
    "/control/querylog_info",
    "/control/querylog/config",
    "/control/stats_info",
    "/control/stats/config",
    "/control/stats",
    "/control/clients",
    "/control/access/list",
    "/control/blocked_services/list",
    "/control/blocked_services/get",
    "/control/blocked_services/all",
    "/control/rewrite/list",
    "/control/rewrite/settings",
    "/control/safebrowsing/status",
    "/control/parental/status",
    "/control/safesearch/status",
    "/control/safesearch/settings",
    "/control/tls/status",
    "/control/dhcp/status",
    "/control/profile",
    "/control/querylog?limit=5",
    "/control/filtering/check_host?name=doubleclick.net",
    "/control/filtering/check_host?name=example.com",
]


# Paths whose object *keys* are data rather than schema: the statistics
# top-N lists are rendered as single-key objects keyed by domain, client or
# upstream address, so two servers legitimately differ there.
DATA_KEYED = {
    "top_queried_domains[]",
    "top_clients[]",
    "top_blocked_domains[]",
    "top_upstreams_responses[]",
    "top_upstreams_avg_time[]",
}


def merge(a, b):
    """Unions two shapes, so an optional field present in either is kept."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = merge(out[k], v) if k in out else v
        return out
    if isinstance(a, list) and isinstance(b, list):
        if a and b:
            return [merge(a[0], b[0])]
        return a or b
    return a


def shape(v, path="", depth=0):
    """Reduces a JSON value to its structure.

    List elements are merged rather than sampled, so a field that only some
    entries carry still shows up.  Objects at a data-keyed path collapse to a
    single `*` key, because their names are values, not schema.
    """
    if depth > 6:
        return "..."
    if isinstance(v, dict):
        if path in DATA_KEYED:
            inner = [shape(x, path + ".*", depth + 1) for x in v.values()]
            merged = inner[0] if inner else "null"
            for i in inner[1:]:
                merged = merge(merged, i)
            return {"*": merged}
        return {k: shape(v[k], f"{path}.{k}" if path else k, depth + 1) for k in sorted(v)}
    if isinstance(v, list):
        if not v:
            return []
        elems = [shape(x, path + "[]", depth + 1) for x in v]
        merged = elems[0]
        for e in elems[1:]:
            merged = merge(merged, e)
        return [merged]
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    return "string"


def get(base, path, auth):
    """Fetches one endpoint, returning (status, parsed-json-or-text)."""
    req = urllib.request.Request(base + path, headers={"Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read()
            try:
                return r.status, json.loads(body)
            except json.JSONDecodeError:
                return r.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - report, don't crash the run
        return 0, f"{type(e).__name__}: {e}"


def diff_shape(a, b, path=""):
    """Yields human-readable differences between two shapes."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in a:
                yield f"{p}: only in rust"
            elif k not in b:
                yield f"{p}: only in go"
            else:
                yield from diff_shape(a[k], b[k], p)
    elif isinstance(a, list) and isinstance(b, list):
        if a and b:
            yield from diff_shape(a[0], b[0], path + "[]")
    elif a != b:
        # "null" against a concrete type is a value difference, not a shape
        # one: Go emits null for an empty slice and a populated one otherwise.
        if "null" in (a, b):
            return
        yield f"{path}: go={a} rust={b}"


def seed_traffic(hosts, ports):
    """Sends the same queries to both servers so data-shaped endpoints match.

    Several responses carry optional fields whose presence depends on what is
    in the log, so comparing two servers with different histories produces
    differences that say nothing about compatibility.
    """
    import socket
    import struct

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5.0)
            for i, h in enumerate(hosts):
                q = struct.pack(">HHHHHH", 0x1000 + i, 0x0100, 1, 0, 0, 0)
                q += b"".join(bytes([len(p)]) + p.encode() for p in h.split(".") if p)
                q += b"\x00" + struct.pack(">HH", 1, 1)
                try:
                    s.sendto(q, ("127.0.0.1", port))
                    s.recvfrom(4096)
                except Exception:  # noqa: BLE001 - best effort seeding
                    pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="http://127.0.0.1:13000")
    ap.add_argument("--rust", default="http://127.0.0.1:13001")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="test123")
    ap.add_argument("--go-dns-port", type=int, default=15353)
    ap.add_argument("--rust-dns-port", type=int, default=15354)
    args = ap.parse_args()

    seed_traffic(
        ["example.com", "doubleclick.net", "github.com", "en.wikipedia.org"],
        [args.go_dns_port, args.rust_dns_port],
    )

    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    problems = 0
    for ep in ENDPOINTS:
        gs, gv = get(args.go, ep, auth)
        rs, rv = get(args.rust, ep, auth)

        if gs != rs:
            print(f"FAIL {ep}\n  status go={gs} rust={rs}")
            if rs != 200:
                print(f"  rust body: {str(rv)[:200]}")
            problems += 1
            continue

        if gs != 200:
            continue

        diffs = list(diff_shape(shape(gv), shape(rv)))
        if diffs:
            print(f"DIFF {ep}")
            for d in diffs[:12]:
                print(f"  {d}")
            problems += 1
        else:
            print(f"ok   {ep}")

    print(f"\n{len(ENDPOINTS) - problems}/{len(ENDPOINTS)} endpoints match")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

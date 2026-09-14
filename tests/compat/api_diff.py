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


def shape(v, depth=0):
    """Reduces a JSON value to its structure."""
    if depth > 6:
        return "..."
    if isinstance(v, dict):
        return {k: shape(v[k], depth + 1) for k in sorted(v)}
    if isinstance(v, list):
        # Lists are homogeneous here; one sample describes the element shape.
        return [shape(v[0], depth + 1)] if v else []
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="http://127.0.0.1:13000")
    ap.add_argument("--rust", default="http://127.0.0.1:13001")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="test123")
    args = ap.parse_args()

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

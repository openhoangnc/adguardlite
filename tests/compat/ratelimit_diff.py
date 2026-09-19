#!/usr/bin/env python3
"""Compare which transports each server applies the query rate limit to.

The limit exists so a spoofed datagram cannot be turned into amplification: the
attacker puts a victim's address in the source field and the answer goes there.
A client that completed a handshake cannot do that -- the address it claims is
the one the packets came back to -- so upstream gates the check on the
transport:

    // ratelimit based on IP only, protects CPU cycles and outbound connections
    if d.Proto == ProtoUDP && p.isRatelimited(ip) {
        // Don't reply to ratelimited clients.
        return nil
    }

A server that limits a stream client too cuts off everyone behind one busy
address -- a NAT, an office, a phone hotspot -- and does it silently, since
there is no answer to carry the reason.

**This script changes a setting on both servers**, because the rate limit has to
be on for any of this to be visible and `scripts/verify.sh` seeds it off so the
other comparisons are not throttled.  It sets `ratelimit` through
`/control/dns_config`, measures, and puts the old value back on the way out --
which is why `verify.sh` runs it last among the DNS comparisons, and why putting
it back also walks `ratelimit` through the config round-trip the step after
this one checks.
"""

import argparse
import base64
import collections
import json
import socket
import struct
import sys
import time
import urllib.error
import urllib.request

# Low enough that a burst of plain queries passes it, high enough that a
# handful of warm-up queries do not.
LIMIT = 20
BURST = 60


def api(base, path, auth, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        base + path,
        data=body,
        method="GET" if body is None else "POST",
        headers={
            "Authorization": "Basic " + auth,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return json.loads(raw) if raw and body is None else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{base}{path}: HTTP {e.code} {e.read()[:200]!r}") from e
    except OSError as e:
        raise SystemExit(f"{base}{path}: {e}") from e


def build(qid, name="example.com"):
    h = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"

    return h + q + struct.pack(">HH", 1, 1)


def over_udp(port, qid):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        try:
            s.sendto(build(qid), ("127.0.0.1", port))
            s.recv(65535)
            return "answered"
        except socket.timeout:
            return "dropped"


def over_tcp(port, qid, reuse=None):
    """One query over TCP, on a fresh connection unless `reuse` is given."""
    s = reuse or socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(3)
        if reuse is None:
            s.connect(("127.0.0.1", port))
        msg = build(qid)
        s.sendall(struct.pack(">H", len(msg)) + msg)
        head = s.recv(2)
        if len(head) < 2:
            return "closed with no answer"
        want = struct.unpack(">H", head)[0]
        got = b""
        while len(got) < want:
            chunk = s.recv(want - len(got))
            if not chunk:
                return "cut off mid-answer"
            got += chunk
        return "answered"
    except socket.timeout:
        return "dropped"
    except ConnectionError:
        return "connection broken"
    finally:
        if reuse is None:
            s.close()


def burst(port):
    """Fires three bursts and reports what came back for each."""
    out = {}
    out["udp"] = collections.Counter(over_udp(port, 0xC000 + i) for i in range(BURST))

    time.sleep(2)
    out["tcp"] = collections.Counter(over_tcp(port, 0xC800 + i) for i in range(BURST))

    time.sleep(2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.connect(("127.0.0.1", port))
        out["tcp, one connection"] = collections.Counter(
            over_tcp(port, 0xD000 + i, reuse=s) for i in range(BURST)
        )

    return out


def set_limit(base, auth, value):
    api(base, "/control/dns_config", auth, {"ratelimit": value})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="http://127.0.0.1:13000")
    ap.add_argument("--rust", default="http://127.0.0.1:13001")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="test123")
    ap.add_argument("--go-dns-port", type=int, default=15353)
    ap.add_argument("--rust-dns-port", type=int, default=15354)
    args = ap.parse_args()

    auth = base64.b64encode(f"{args.user}:{args.password}".encode()).decode()
    servers = {"go": (args.go, args.go_dns_port), "rust": (args.rust, args.rust_dns_port)}

    before = {
        k: api(base, "/control/dns_info", auth).get("ratelimit", 0)
        for k, (base, _) in servers.items()
    }
    results = {}
    try:
        for label, (base, port) in servers.items():
            set_limit(base, auth, LIMIT)
        # A moment for the new limit to be in force before the first burst.
        time.sleep(1)
        for label, (base, port) in servers.items():
            results[label] = burst(port)
            time.sleep(2)
    finally:
        for label, (base, _) in servers.items():
            set_limit(base, auth, before[label])

    print(f"ratelimit {LIMIT}/s, bursts of {BURST} from one address\n")
    problems = []
    for transport in ("udp", "tcp", "tcp, one connection"):
        for label in servers:
            got = dict(results[label][transport])
            print(f"  {label:<4} {transport:<21} {got}")

        answered = {k: results[k][transport]["answered"] for k in servers}
        if transport == "udp":
            # Both must limit datagrams, or the defence is not there at all.
            for label, n in answered.items():
                if n == BURST:
                    problems.append(f"{label}: every one of {BURST} datagrams was answered")
        else:
            for label, n in answered.items():
                if n < BURST:
                    problems.append(
                        f"{label}: {BURST - n} of {BURST} queries over {transport} "
                        "went unanswered, and a stream client has proved its address"
                    )
        print()

    for p in problems:
        print(f"  {p}")
    if not problems:
        print("both servers limit datagrams and neither limits a connection")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

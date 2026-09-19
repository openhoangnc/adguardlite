#!/usr/bin/env python3
"""Check that both servers cut a UDP answer down to what the client can receive.

A datagram larger than the client's buffer is not a long answer, it is a lost
one: the client never learns there was an answer at all, and anything over the
path MTU is fragmented as well, which firewalls drop.  The protocol's remedy is
to send what fits with the truncation bit set, so the client asks again over
TCP.

What is compared is a *property* rather than the bytes, because the two servers
cache their own copy of an upstream's answer and the records come back in a
different order each time: how many fit is not a fact about the server.  What
is a fact about the server is that the answer fits, that the bit is set when
anything was left out, and that a stream transport is not cut at all.

The exception is a request carrying **no OPT record at all**, where this build
deliberately differs: it holds such a client to the 512 bytes RFC 1035 gives it,
while the Go build sends up to 2048.  That number is an artifact -- dnsproxy
adds an `OPT(2048, DO)` to the request on its way upstream and then reads the
client's limit back out of the request it just edited -- and it only appears
with `enable_dnssec` and the cache both on.  It is reported here rather than
failed on; see TASK.md.
"""

import argparse
import socket
import struct
import sys

# Names with answers far too large for one datagram.  A TXT set is the usual
# way a real deployment meets this: SPF, DKIM and half a dozen verification
# tokens add up.
NAMES = ("adobe.com", "cloudflare.com", "microsoft.com", "salesforce.com")
TXT = 16
MIN_UDP_PAYLOAD = 512
# What the Go build gives a client that sent no OPT record, when enable_dnssec
# and the cache are both on.  Measured, not chosen.
GO_NO_EDNS_LIMIT = 2048


def build(name, qtype, edns, bufsize=4096, qid=0x6C6C):
    """Encodes a query, writing the OPT record by hand so it can be left out."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1 if edns else 0)
    labels = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".") if p
    )
    question = labels + b"\x00" + struct.pack(">HH", qtype, 1)
    opt = b"" if not edns else b"\x00" + struct.pack(">HHIH", 41, bufsize, 0, 0)

    return header + question + opt


def counts(buf):
    _, flags, _, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])

    return {"len": len(buf), "tc": bool(flags & 0x0200), "records": an + ns + ar}


def over_udp(addr, name, edns, bufsize=4096, timeout=6.0, tries=3):
    """Asks once, and again if nothing came back.

    A public upstream fails on its own now and then, and a server having a bad
    moment is not a difference between the two of them.
    """
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(build(name, TXT, edns, bufsize), addr)
                return counts(s.recv(65535))
            except (socket.timeout, struct.error):
                continue

    return None


def over_tcp(addr, name, timeout=6.0, tries=3):
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect(addr)
                msg = build(name, TXT, edns=False)
                s.sendall(struct.pack(">H", len(msg)) + msg)
                want = struct.unpack(">H", s.recv(2))[0]
                buf = b""
                while len(buf) < want:
                    chunk = s.recv(want - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                if len(buf) == want:
                    return counts(buf)
            except (socket.timeout, struct.error, ConnectionError):
                continue

    return None


def check(label, addr, name, whole):
    """Reports every way `addr` mishandles a large answer for `name`."""
    problems = []

    for advertised in (512, 1024, 1232, 1400, 2048, 4096):
        got = over_udp(addr, name, edns=True, bufsize=advertised)
        if got is None:
            problems.append(f"{label} {name}: no answer advertising {advertised}")
            continue

        limit = max(MIN_UDP_PAYLOAD, advertised)
        if got["len"] > limit:
            problems.append(
                f"{label} {name}: {got['len']} bytes for a client that asked for {advertised}"
            )
        if whole > limit and not got["tc"]:
            problems.append(
                f"{label} {name}: cut to {got['len']} bytes advertising {advertised} "
                "without setting the truncation bit"
            )
        if whole <= limit and got["tc"]:
            problems.append(
                f"{label} {name}: truncation bit set although the answer fits in {advertised}"
            )

    streamed = over_tcp(addr, name)
    if streamed is None:
        problems.append(f"{label} {name}: no answer over TCP")
    elif streamed["tc"]:
        problems.append(f"{label} {name}: truncated over TCP, which carries its own length")

    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="127.0.0.1:15353")
    ap.add_argument("--rust", default="127.0.0.1:15354")
    args = ap.parse_args()

    def split(a):
        h, p = a.rsplit(":", 1)
        return (h, int(p))

    servers = {"go": split(args.go), "rust": split(args.rust)}
    problems, checked = [], 0

    for name in NAMES:
        # The whole answer, from each server, so "should this have been cut?"
        # is asked against what that server actually holds.
        whole = {k: over_udp(v, name, edns=True, bufsize=65535) for k, v in servers.items()}
        if any(w is None for w in whole.values()):
            print(f"skipped {name}: a server did not answer")
            continue
        if all(w["len"] <= MIN_UDP_PAYLOAD for w in whole.values()):
            print(f"skipped {name}: its answer fits in a datagram, so nothing is truncated")
            continue

        for label, addr in servers.items():
            checked += 1
            problems += check(label, addr, name, whole[label]["len"])

        # The one case the two are known to answer differently.
        plain = {k: over_udp(v, name, edns=False) for k, v in servers.items()}
        if all(p is not None for p in plain.values()):
            go_len, rust_len = plain["go"]["len"], plain["rust"]["len"]
            note = "as documented" if rust_len <= MIN_UDP_PAYLOAD else "UNEXPECTED"
            print(
                f"{name}: no OPT record -> go {go_len}B (limit {GO_NO_EDNS_LIMIT}), "
                f"rust {rust_len}B (limit {MIN_UDP_PAYLOAD}) -- {note}"
            )
            if rust_len > MIN_UDP_PAYLOAD:
                problems.append(
                    f"rust {name}: {rust_len} bytes to a client that sent no OPT record"
                )

    print(f"\nchecked {checked} server-name pairs")
    for p in problems:
        print(f"  {p}")
    if not problems:
        print("both servers cut every oversized answer to what was asked for")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Check that both servers answer the resolver-discovery name themselves.

A client asks `_dns.resolver.arpa` for SVCB records to find out which encrypted
transports *this* resolver offers.  If the query is forwarded, the answer comes
back describing the **upstream's** encrypted endpoints, and a client that acts
on it stops talking to this server altogether.  So the name has to be answered
here whether or not there is anything to advertise: with records when there is,
and empty when there is not.

Both servers must be running with `handle_ddr` on.  What is compared is the
shape of the answer, which is what separates the two outcomes: a local empty
answer has no records at all, while a forwarded one comes back carrying the
upstream's SVCB records and their address glue.

The rest of `resolver.arpa` is *not* special: the Go build forwards
`resolver.arpa`, `foo.resolver.arpa` and `_dns.foo.resolver.arpa`, and only
intercepts the one name.  Those are compared too, so an over-eager fix is
caught as well as a missing one.
"""

import argparse
import socket
import struct
import sys
import time

TYPES = {1: "A", 2: "NS", 6: "SOA", 16: "TXT", 28: "AAAA", 41: "OPT", 64: "SVCB", 65: "HTTPS"}
QTYPES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# The name itself, asked for the type DDR uses and for types it does not: a
# running AdGuard Home answers every type for this name, not just SVCB.
HANDLED = "_dns.resolver.arpa"
KINDS = ("SVCB", "A", "AAAA", "HTTPS")

# Names under the same zone that are ordinary questions, forwarded like any
# other.
FORWARDED = ("resolver.arpa", "foo.resolver.arpa", "_dns.foo.resolver.arpa")


def build(name, qtype, qid=0xDD01):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 1)
    labels = b"".join(
        bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".") if p
    )
    question = labels + b"\x00" + struct.pack(">HH", qtype, 1)

    return header + question + b"\x00" + struct.pack(">HHIH", 41, 4096, 0, 0)


def read_name(buf, off):
    while True:
        if off >= len(buf):
            raise ValueError("truncated name")
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def shape(buf):
    """The answer reduced to what tells a local answer from a forwarded one."""
    _, flags, qd, *counts = struct.unpack(">HHHHHH", buf[:12])
    out = {"rcode": RCODES.get(flags & 0xF, str(flags & 0xF))}

    off = 12
    for _ in range(qd):
        off = read_name(buf, off) + 4
    for section, n in zip(("answer", "authority", "additional"), counts):
        kinds = []
        for _ in range(n):
            off = read_name(buf, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10 + rdlen
            if rtype == 41:
                continue
            kinds.append(TYPES.get(rtype, f"TYPE{rtype}"))
        out[section] = kinds

    return out


def ask(addr, name, kind, tries=3, timeout=6.0):
    for _ in range(tries):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(build(name, QTYPES[kind]), addr)
                return shape(s.recv(65535))
            except (socket.timeout, ValueError, struct.error):
                time.sleep(0.2)

    return None


def render(got):
    if got is None:
        return "no answer"

    return (
        f"{got['rcode']} answer=[{','.join(got['answer']) or '-'}] "
        f"authority=[{','.join(got['authority']) or '-'}] "
        f"additional=[{','.join(got['additional']) or '-'}]"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="127.0.0.1:15353")
    ap.add_argument("--rust", default="127.0.0.1:15354")
    args = ap.parse_args()

    def split(a):
        h, p = a.rsplit(":", 1)
        return (h, int(p))

    go, rust = split(args.go), split(args.rust)
    problems, checked = [], 0

    for name, kinds in [(HANDLED, KINDS)] + [(n, ("SVCB",)) for n in FORWARDED]:
        for kind in kinds:
            g, r = ask(go, name, kind), ask(rust, name, kind)
            checked += 1
            if g is None or r is None:
                print(f"skipped {name} {kind}: a server did not answer")
                continue
            if g != r:
                problems.append((name, kind, g, r))

            # Beyond agreeing with each other, the handled name must not be
            # answered with anything an upstream said.
            if name == HANDLED and r["answer"]:
                problems.append(
                    (name, kind, {"note": "answered with records from somewhere"}, r)
                )

    print(f"compared {checked} answers")
    for name, kind, g, r in problems:
        print(f"\n{name} {kind}")
        print(f"  go:   {render(g) if 'rcode' in g else g['note']}")
        print(f"  rust: {render(r)}")

    if not problems:
        print("both servers answer the discovery name themselves and forward the rest")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

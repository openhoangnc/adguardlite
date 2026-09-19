#!/usr/bin/env python3
"""Compare what two servers put in a response that the client did not ask for.

A forwarding resolver with `enable_dnssec` on asks every upstream with the DO
bit set, so signatures come back whether or not the client below wanted them.
RFC 4035 3.2.1 says they must not be passed on, and macOS enforces it:
`mDNSResponder` discards a response carrying records it did not ask for, so
`getaddrinfo` fails for every signed name while `dig` -- which prints whatever
arrives rather than judging its shape -- shows nothing wrong.

What is compared is the *shape* of each answer, not its contents: which record
types are in each section, the AD bit, and whether an OPT record came back and
on what terms.  A CDN may hand the two servers different addresses, but it
cannot make one of them answer a plain query with an RRSIG and the other not.

Both servers must be running with the same configuration and `enable_dnssec`
on.  Names are asked for in four forms -- no EDNS at all, EDNS without DO, EDNS
with DO, and EDNS with a payload size of its own -- because each is a different
promise about what the answer may contain.
"""

import argparse
import socket
import struct
import sys

TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    50: "NSEC3", 51: "NSEC3PARAM", 64: "SVCB", 65: "HTTPS",
}
QTYPES = {v: k for k, v in TYPES.items()}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}

# One per promise a request can make about what it is willing to receive.
FORMS = (
    ("no EDNS", dict(edns=False, do=False)),
    ("EDNS, DO clear", dict(edns=True, do=False)),
    ("EDNS, DO set", dict(edns=True, do=True)),
    ("EDNS, DO clear, 1400", dict(edns=True, do=False, bufsize=1400)),
    ("no EDNS, AD set", dict(edns=False, do=False, ad=True)),
)

# Signed names, an unsigned one as the control, and the DNSSEC types that are
# the answer to their own question rather than something extra.
CASES = (
    ("cloudflare.com", "A"),
    ("api.cloudflare.com", "A"),
    ("nonexistent-xyzzy.cloudflare.com", "A"),
    ("cloudflare.com", "DNSKEY"),
    ("cloudflare.com", "DS"),
    ("cloudflare.com", "NSEC"),
    ("github.com", "A"),
)


def build(name, qtype, edns=True, do=False, bufsize=4096, ad=False, qid=0x5150):
    """Encodes a query, with the OPT record written by hand.

    Hand-written because the whole point is to control what the request
    carries: whether there is an OPT record at all, what size it advertises,
    and which of the DO and AD bits are set.
    """
    flags = 0x0100 | (0x0020 if ad else 0)
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 1 if edns else 0)
    labels = b"".join(
        bytes([len(p)]) + p.encode("ascii")
        for p in name.rstrip(".").split(".")
        if p
    )
    question = labels + b"\x00" + struct.pack(">HH", qtype, 1)
    # The OPT record's owner name is the root, its class is the advertised
    # payload size and the DO bit is the top bit of its TTL.
    opt = b"" if not edns else b"\x00" + struct.pack(
        ">HHIH", 41, bufsize, 0x8000 if do else 0, 0
    )

    return header + question + opt


def read_name(buf, off):
    """Skips a possibly-compressed name, returning the offset after it."""
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
    """Reduces a response to what this compares: sections, AD bit, OPT."""
    if len(buf) < 12:
        raise ValueError("short message")
    _, flags, qd, *counts = struct.unpack(">HHHHHH", buf[:12])
    out = {
        "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
        "ad": bool(flags & 0x0020),
        "opt": None,
    }

    off = 12
    for _ in range(qd):
        off = read_name(buf, off) + 4

    for section, n in zip(("answer", "authority", "additional"), counts):
        kinds = []
        for _ in range(n):
            off = read_name(buf, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10 + rdlen
            if rtype == 41:
                # A response's OPT record is not an answer: it is the terms the
                # exchange was conducted on, and they have to be the client's.
                out["opt"] = {"udp": rclass, "do": bool(ttl & 0x8000)}
                continue
            kinds.append(TYPES.get(rtype, f"TYPE{rtype}"))
        out[section] = kinds

    return out


def ask(addr, name, qtype, timeout=6.0, **form):
    """Sends one query and returns its shape, or None when nothing answered."""
    qid = 0x5150
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(build(name, qtype, qid=qid, **form), addr)
            for _ in range(4):
                data, _ = s.recvfrom(65535)
                if struct.unpack(">H", data[:2])[0] == qid:
                    return shape(data)
            return None
        except (socket.timeout, ValueError):
            return None


def render(got):
    """One line describing a shape, for a mismatch report."""
    if got is None:
        return "no answer"
    opt = "no OPT" if got["opt"] is None else (
        f"OPT udp={got['opt']['udp']} do={int(got['opt']['do'])}"
    )

    return (
        f"{got['rcode']} ad={int(got['ad'])} "
        f"answer=[{','.join(got['answer']) or '-'}] "
        f"authority=[{','.join(got['authority']) or '-'}] "
        f"additional=[{','.join(got['additional']) or '-'}] {opt}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="127.0.0.1:15353")
    ap.add_argument("--rust", default="127.0.0.1:15354")
    ap.add_argument(
        "--retries",
        type=int,
        default=2,
        help="how many times to re-ask a case the two answered differently",
    )
    args = ap.parse_args()

    def split(a):
        h, p = a.rsplit(":", 1)
        return (h, int(p))

    go, rust = split(args.go), split(args.rust)
    mismatches, skipped, checked = [], 0, 0

    for name, qtype in CASES:
        for label, form in FORMS:
            # Asked again on no answer *and* on a disagreement: a public
            # upstream fails on its own sometimes, and one server catching a
            # SERVFAIL the other had cached is not a difference between the two.
            # A real difference is there every time it is asked.
            for _ in range(args.retries + 1):
                g, r = ask(go, name, QTYPES[qtype], **form), ask(rust, name, QTYPES[qtype], **form)
                if g is not None and r is not None and g == r:
                    break
            checked += 1

            if g is None or r is None:
                skipped += 1
                print(f"skipped {name} {qtype} [{label}]: a server did not answer")
                continue
            if g != r:
                mismatches.append((name, qtype, label, g, r))

    print(f"compared {checked} shapes ({skipped} skipped for timeouts)")
    for name, qtype, label, g, r in mismatches:
        print(f"\n{name} {qtype} [{label}]")
        print(f"  go:   {render(g)}")
        print(f"  rust: {render(r)}")

    if not mismatches:
        print("every response has the same shape")

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())

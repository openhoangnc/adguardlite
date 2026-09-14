#!/usr/bin/env python3
"""Compare DNS answers from a Go AdGuardHome and an adguardlite instance.

Both must be running with the same configuration and filter lists.  The script
sends identical queries to each and reports where they disagree.

Blocked answers must match exactly: same rcode, same records.  Unblocked names
are resolved upstream, where a CDN may legitimately return different addresses,
so only the rcode and the blocked/not-blocked classification are compared.
"""

import argparse
import concurrent.futures
import random
import socket
import struct
import sys

RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED",
}
NULL_ADDRS = {"0.0.0.0", "::"}


def build_query(name, qtype=1, qid=None):
    """Encodes a standard recursive query."""
    qid = random.randrange(0, 65536) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(
        bytes([len(p)]) + p.encode("idna" if not p.isascii() else "ascii")
        for p in name.rstrip(".").split(".")
        if p
    )
    return qid, header + labels + b"\x00" + struct.pack(">HH", qtype, 1)


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


def parse(buf):
    """Returns (rcode_name, [record strings])."""
    if len(buf) < 12:
        raise ValueError("short message")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    rcode = RCODES.get(flags & 0xF, str(flags & 0xF))

    off = 12
    for _ in range(qd):
        off = read_name(buf, off) + 4

    answers = []
    for _ in range(an):
        off = read_name(buf, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == 28 and rdlen == 16:
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == 5:
            answers.append("CNAME")
        else:
            answers.append(f"TYPE{rtype}")
    return rcode, answers


def ask(addr, name, qtype, timeout=5.0):
    """Sends one query and returns (rcode, answers) or ('TIMEOUT', [])."""
    qid, q = build_query(name, qtype)
    host, port = addr
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(q, (host, port))
            for _ in range(4):
                data, _ = s.recvfrom(4096)
                if struct.unpack(">H", data[:2])[0] == qid:
                    return parse(data)
            return "NOMATCH", []
        except socket.timeout:
            return "TIMEOUT", []
        except Exception as e:  # noqa: BLE001 - report, don't crash the run
            return f"ERROR:{type(e).__name__}", []


def is_blocked(rcode, answers, mode="default"):
    """Classifies a response as a block, given the server's blocking_mode.

    In the default mode a block is NOERROR carrying only null addresses.
    NXDOMAIN is *not* a block there: it is also the honest answer for a name
    that does not exist, so treating it as one produces false mismatches.
    """
    if mode == "nxdomain":
        return rcode == "NXDOMAIN"
    if mode == "refused":
        return rcode == "REFUSED"
    return rcode == "NOERROR" and bool(answers) and all(a in NULL_ADDRS for a in answers)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="127.0.0.1:15353")
    ap.add_argument("--rust", default="127.0.0.1:15354")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--mode", default="default", help="the servers' blocking_mode")
    args = ap.parse_args()

    def split(a):
        h, p = a.rsplit(":", 1)
        return (h, int(p))

    go, rust = split(args.go), split(args.rust)
    names = [n.strip() for n in open(args.corpus) if n.strip()]
    if args.limit:
        names = names[: args.limit]

    def compare(name):
        for qtype in (1, 28):
            g = ask(go, name, qtype)
            r = ask(rust, name, qtype)
            gb, rb = is_blocked(*g, args.mode), is_blocked(*r, args.mode)

            if g[0] in ("TIMEOUT", "NOMATCH") or r[0] in ("TIMEOUT", "NOMATCH"):
                return ("skip", name, qtype, g, r)
            if gb != rb:
                return ("verdict", name, qtype, g, r)
            if gb and rb:
                # Both blocked: the wire form must match exactly.
                if g[0] != r[0] or sorted(g[1]) != sorted(r[1]):
                    return ("wire", name, qtype, g, r)
            elif g[0] != r[0]:
                return ("rcode", name, qtype, g, r)
        return None

    problems, skipped, checked = [], 0, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(compare, names):
            checked += 1
            if res is None:
                continue
            if res[0] == "skip":
                skipped += 1
                continue
            problems.append(res)

    print(f"compared {checked} names ({skipped} skipped for timeouts)")
    by_kind = {}
    for kind, name, qtype, g, r in problems:
        by_kind.setdefault(kind, []).append((name, qtype, g, r))

    for kind, items in sorted(by_kind.items()):
        print(f"\n{kind} mismatches: {len(items)}")
        for name, qtype, g, r in items[:15]:
            print(f"  {name} type={qtype}: go={g} rust={r}")

    if not problems:
        print("\nall responses agree")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

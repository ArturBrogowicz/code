#!/usr/bin/env python3
"""Check xdp_ddos_filter.c in the kernel without attaching it to an interface.

The program is loaded with BCC (the kernel verifier runs; nothing is attached and no packet
is sent) and driven through BPF_PROG_TEST_RUN with crafted Ethernet frames, which run the
program once per call on the supplied bytes. It checks:

  * the verifier accepts the program, and telemetry_map is an LRU per-CPU hash;
  * a valid TCP SYN, an IPv4 header with options (ihl 6) and a UDP datagram are parsed and
    counted correctly;
  * ihl < 5 is passed on uncounted, while a blacklisted source is still dropped first;
  * non-IPv4 and truncated frames are passed on uncounted;
  * with --sources distinct spoofed sources (default 150 000, more than the 100 000 slots) the
    table keeps taking new sources, and a newcomer is counted while it is saturated;
  * the userspace read of the saturated table (as the daemon's poll does), also while another
    thread keeps adding sources, so that the kernel evicts entries during the walk.

--reference loads a second build, the program as it was before the ihl and LRU changes
(`git show 3086e27:xdp_ddos_filter.c > /tmp/xdp_before.c`). The same frames must then show the
old behaviour (ihl 4 pollutes the maps, the table saturates and later sources go uncounted),
which shows that the checks can fail.

Needs root. Everything it creates in the kernel is freed when the process exits.

    sudo ./venv/bin/python bench/xdp_test_run.py [--reference /tmp/xdp_before.c] [--out r.json]
"""
import argparse
import ctypes as ct
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XDP_DROP, XDP_PASS = 1, 2
SERVER = 0x0A000001                          # 10.0.0.1
SYS_BPF = {"x86_64": 321, "aarch64": 280}.get(os.uname().machine)
BPF_PROG_TEST_RUN = 10
ETH_P_IPV6 = 0x86DD
SLOTS = 100_000                              # max_entries of telemetry_map


class TestAttr(ct.Structure):
    """The `test` member of union bpf_attr (BPF_PROG_TEST_RUN)."""
    _fields_ = [("prog_fd", ct.c_uint32), ("retval", ct.c_uint32),
                ("data_size_in", ct.c_uint32), ("data_size_out", ct.c_uint32),
                ("data_in", ct.c_uint64), ("data_out", ct.c_uint64),
                ("repeat", ct.c_uint32), ("duration", ct.c_uint32),
                ("ctx_size_in", ct.c_uint32), ("ctx_size_out", ct.c_uint32),
                ("ctx_in", ct.c_uint64), ("ctx_out", ct.c_uint64),
                ("flags", ct.c_uint32), ("cpu", ct.c_uint32),
                ("batch_size", ct.c_uint32), ("_pad", ct.c_uint32)]


def test_run(fd, buf, size, repeat=1):
    """Run the XDP program `repeat` times on buf[:size]; returns (action, average ns)."""
    libc = ct.CDLL(None, use_errno=True)
    attr = TestAttr()
    attr.prog_fd, attr.data_size_in, attr.data_in, attr.repeat = fd, size, ct.addressof(buf), repeat
    if libc.syscall(SYS_BPF, BPF_PROG_TEST_RUN, ct.byref(attr), ct.sizeof(attr)) < 0:
        err = ct.get_errno()
        raise OSError(err, f"BPF_PROG_TEST_RUN: {os.strerror(err)}")
    return attr.retval, attr.duration


def frame(src, ihl=5, proto=6, sport=40000, dport=80, flags=0x02, win=64240,
          options=b"", ethertype=0x0800, payload=b""):
    """Ethernet + IPv4 + TCP or UDP. `src` is the source address as a host-order integer.
    `ihl` is the header length the IPv4 header declares, in 32-bit words; `options` are the
    bytes placed after the 20 fixed header bytes (a valid ihl 6 needs 4 of them)."""
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01" + struct.pack(">H", ethertype)
    l4 = (struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, win, 0, 0)
          if proto == 6 else struct.pack(">HHHH", sport, dport, 8 + len(payload), 0))
    tot = 20 + len(options) + len(l4) + len(payload)
    ip = struct.pack(">BBHHHBBHII", (4 << 4) | ihl, 0, tot, 0, 0x4000, 64, proto, 0,
                     src, SERVER) + options
    return eth + ip + l4 + payload


def key_of(ip_int):
    """Map key of a source: the u32 as XDP stores it (network-order bytes read as little endian)."""
    return struct.unpack("<I", struct.pack(">I", ip_int))[0]


class Variant:
    """One loaded build of the program with its maps."""

    def __init__(self, name, path):
        from bcc import BPF
        self.name = name
        self.bpf = BPF(src_file=path)
        self.fd = self.bpf.load_func("xdp_ddos_mitigation", BPF.XDP).fd   # verifier runs here
        self.tel = self.bpf["telemetry_map"]
        self.flow = self.bpf["flow_map"]
        self.black = self.bpf["blacklist_map"]
        self.table_type = type(self.tel).__name__
        self.xdp_prog = None                 # filled in by main() from bpftool

    def run(self, pkt, repeat=1):
        buf = ct.create_string_buffer(pkt, len(pkt))
        return test_run(self.fd, buf, len(pkt), repeat)

    def tel_of(self, ip_int):
        """(packets, SYNs, bytes) summed over CPUs, or None if the source has no entry."""
        try:
            vals = self.tel[self.tel.Key(key_of(ip_int))]
        except KeyError:
            return None
        return (sum(v.packet_count for v in vals), sum(v.syn_count for v in vals),
                sum(v.byte_count for v in vals))

    def flows_of(self, ip_int):
        """[(sport, dport, proto, packets, init_win, header bytes, payload bytes)] of a source."""
        k = key_of(ip_int)
        return [(socket.ntohs(fk.src_port), socket.ntohs(fk.dst_port), fk.proto, ff.fwd_packets,
                 ff.init_win, ff.fwd_hdr_bytes, ff.fwd_payload_bytes)
                for fk, ff in self.flow.items() if fk.src_ip == k]


class Report:
    def __init__(self):
        self.checks = []

    def check(self, variant, name, ok, detail=""):
        self.checks.append({"variant": variant, "check": name, "ok": bool(ok), "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {variant:9s} {name}  {detail}", flush=True)

    @property
    def failed(self):
        return [c for c in self.checks if not c["ok"]]


def functional(v, rep, current):
    """Single-packet checks on fresh maps. `current` is False for the pre-fix reference."""
    n = v.name
    s_ok, s_ihl4, s_black, s_opt, s_udp, s_v6, s_short = (0x0A090001 + i for i in range(7))
    syn = (40000, 80, 6, 1, 64240, 20, 0)

    r, _ = v.run(frame(s_ok))
    rep.check(n, "valid SYN: XDP_PASS, counted once",
              r == XDP_PASS and v.tel_of(s_ok) == (1, 1, 40), f"ret={r} tel={v.tel_of(s_ok)}")
    f = v.flows_of(s_ok)
    rep.check(n, "valid SYN: flow parsed (ports, window, header bytes)", f == [syn], f"flow={f}")
    r, _ = v.run(frame(s_opt, ihl=6, options=b"\x01\x01\x01\x01"))
    f = v.flows_of(s_opt)
    rep.check(n, "ihl 6 with options: L4 read past the options", r == XDP_PASS and f == [syn],
              f"ret={r} flow={f}")
    r, _ = v.run(frame(s_udp, proto=17, sport=5353, dport=53, payload=b"x" * 10))
    t, f = v.tel_of(s_udp), v.flows_of(s_udp)
    rep.check(n, "UDP: counted, no SYN, payload length",
              r == XDP_PASS and t == (1, 0, 38) and f == [(5353, 53, 17, 1, 0, 8, 10)],
              f"ret={r} tel={t} flow={f}")

    r, _ = v.run(frame(s_ihl4, ihl=4))
    t, f = v.tel_of(s_ihl4), v.flows_of(s_ihl4)
    if current:
        rep.check(n, "ihl 4: XDP_PASS and left uncounted", r == XDP_PASS and t is None and f == [],
                  f"ret={r} tel={t} flow={f}")
    else:
        rep.check(n, "ihl 4 pollutes the maps (the behaviour the fix removes)",
                  r == XDP_PASS and t is not None and f != [], f"ret={r} tel={t} flow={f}")
    v.black[v.black.Key(key_of(s_black))] = v.black.Leaf(0)
    r, _ = v.run(frame(s_black, ihl=4))
    drops = v.black[v.black.Key(key_of(s_black))].value
    rep.check(n, "blacklisted source with ihl 4: still XDP_DROP, counter +1",
              r == XDP_DROP and drops == 1, f"ret={r} drops={drops}")
    r, _ = v.run(frame(s_v6, ethertype=ETH_P_IPV6))
    rep.check(n, "non-IPv4 ethertype: XDP_PASS, uncounted", r == XDP_PASS and v.tel_of(s_v6) is None,
              f"ret={r}")
    r, _ = v.run(frame(s_short)[:30])
    rep.check(n, "truncated frame (30 B): XDP_PASS, uncounted",
              r == XDP_PASS and v.tel_of(s_short) is None, f"ret={r}")


def spoofed_sources(v, rep, current, n_sources):
    """Distinct sources beyond the table size: does the table keep taking new ones?"""
    n = v.name
    base = 0x0A800000                          # 10.128.0.0 + i
    pkt = frame(base)
    buf = ct.create_string_buffer(pkt, len(pkt))
    t0 = time.perf_counter()
    bad = 0
    for i in range(n_sources):
        struct.pack_into(">I", buf, 26, base + i)
        bad += test_run(v.fd, buf, len(pkt))[0] != XDP_PASS
    inject_s = time.perf_counter() - t0
    entries = sum(1 for _ in v.tel)
    first, past_slots, last = (v.tel_of(base + i) for i in (0, SLOTS, n_sources - 1))
    print(f"  [info] {n:9s} {n_sources} distinct sources in {inject_s:.1f} s; telemetry_map holds "
          f"{entries} entries; first={first} source#{SLOTS}={past_slots} last={last}", flush=True)
    rep.check(n, "every spoofed-source frame returned XDP_PASS", bad == 0, f"non-PASS={bad}")
    newcomer = 0x0AC80001
    for _ in range(3):
        v.run(frame(newcomer))
    nc = v.tel_of(newcomer)
    if current:
        rep.check(n, "table stays within its slots", entries <= SLOTS, f"entries={entries}")
        rep.check(n, "the latest spoofed source is counted (new keys keep being taken)",
                  last is not None and last[0] == 1, f"last={last}")
        rep.check(n, "a new source is counted while the table is saturated",
                  nc is not None and nc[0] == 3, f"newcomer={nc}")
    else:
        rep.check(n, "table saturates at its slots", entries == SLOTS, f"entries={entries}")
        rep.check(n, "sources past the last slot go uncounted (the blind spot the fix removes)",
                  last is None, f"last={last}")
        rep.check(n, "a new source goes uncounted while the table is saturated", nc is None,
                  f"newcomer={nc}")
    t0 = time.perf_counter()
    items = v.tel.items()
    items_s = time.perf_counter() - t0
    print(f"  [info] {n:9s} telemetry_map.items(): {len(items)} entries in {items_s:.2f} s",
          flush=True)
    return {"entries": entries, "items_s": items_s, "items_n": len(items), "inject_s": inject_s}


def items_under_churn(v, base=0x0B000000, limit_s=60):
    """items() on the full table while another thread keeps adding new sources."""
    stop = threading.Event()
    injected = []
    pkt = frame(base)
    buf = ct.create_string_buffer(pkt, len(pkt))

    def writer():
        i = 0
        while not stop.is_set():
            struct.pack_into(">I", buf, 26, base + (i & 0xFFFFFF))
            test_run(v.fd, buf, len(pkt))
            i += 1
        injected.append(i)

    box = {}

    def reader():
        t0 = time.perf_counter()
        box["items"] = v.tel.items()
        box["s"] = time.perf_counter() - t0

    threads = [threading.Thread(target=writer), threading.Thread(target=reader)]
    for t in threads:
        t.start()
    threads[1].join(timeout=limit_s)
    stop.set()
    for t in threads:
        t.join()
    keys = [k.value for k, _ in box["items"]]
    res = {"entries": len(keys), "duplicates": len(keys) - len(set(keys)),
           "items_s": box["s"], "injected": injected[0], "exceeded_limit": box["s"] > limit_s}
    print(f"  [info] {v.name:9s} items() under churn: {res['entries']} entries "
          f"({res['duplicates']} duplicates) in {res['items_s']:.2f} s while {res['injected']} "
          "new sources were injected", flush=True)
    return res


def xdp_programs():
    out = subprocess.run(["bpftool", "prog", "show", "--json"], capture_output=True, text=True,
                         check=True).stdout
    return {p["id"]: p for p in json.loads(out) if p.get("type") == "xdp"}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("program", nargs="?", default=os.path.join(REPO, "xdp_ddos_filter.c"),
                    help="the program under test (default: the repository's)")
    ap.add_argument("--reference", help="the pre-fix build: it must show the old behaviour")
    ap.add_argument("--sources", type=int, default=150_000, help="distinct spoofed sources")
    ap.add_argument("--out", help="write a JSON report here")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (BPF program load). Nothing is attached.")
    if SYS_BPF is None:
        sys.exit(f"[-] no bpf() syscall number for {os.uname().machine}")

    print(f"[*] kernel {os.uname().release}, {os.cpu_count()} CPUs", flush=True)
    variants = []                                            # (Variant, is the program under test)
    for name, path, current in (("reference", args.reference, False),
                                ("current", args.program, True)):
        if path:
            before = set(xdp_programs())
            v = Variant(name, path)
            new = [xdp_programs()[i] for i in set(xdp_programs()) - before]
            v.xdp_prog = {k: new[0].get(k) for k in ("id", "bytes_xlated", "bytes_jited")} if new else None
            variants.append((v, current))
    rep = Report()
    for v, current in variants:
        rep.check(v.name, "loaded; the verifier accepted it", v.fd >= 0, f"{v.xdp_prog}")
        rep.check(v.name, "telemetry_map table type",
                  v.table_type == ("LruPerCpuHash" if current else "PerCpuHash"), v.table_type)
    out = {"kernel": os.uname().release, "program": args.program, "reference": args.reference,
           "loaded": {v.name: v.xdp_prog for v, _ in variants}, "per_packet_ns": {},
           "spoofed": {}, "churn": {}}
    for v, current in variants:
        print(f"[*] {v.name}: single-packet checks", flush=True)
        functional(v, rep, current)
    for v, _ in variants:
        out["per_packet_ns"][v.name] = v.run(frame(0x0A630001), repeat=200_000)[1]
    print(f"[info] BPF_PROG_TEST_RUN average ns per valid SYN: {out['per_packet_ns']}", flush=True)
    for v, current in variants:
        print(f"[*] {v.name}: {args.sources} distinct sources", flush=True)
        out["spoofed"][v.name] = spoofed_sources(v, rep, current, args.sources)
        if current:
            out["churn"][v.name] = items_under_churn(v)
    out["checks"], out["failed"] = rep.checks, rep.failed
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1, default=str)
            fh.write("\n")
    print(f"[{'+' if not rep.failed else '-'}] {len(rep.checks) - len(rep.failed)}/{len(rep.checks)} "
          "checks passed", flush=True)
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())

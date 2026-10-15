#!/usr/bin/env python3
"""Offline overhead benchmark for the L7-GRU ingestion design (docs/L7_GRU_DESIGN.md).

Measures, on synthetic data and CPU only (no nginx, no sockets, no traffic, no XDP):
  1. the cost of parsing one extended JSON access-log line and maintaining the per-IP
     state the daemon needs (rate/error window; request-sequence features);
  2. batched vs unbatched GRU inference, to size the "score once per poll in a batch"
     decision.

It answers the REPORT.md §9 overhead question (lines/s/core) with numbers this VM can
reproduce. Run:  ./venv/bin/python bench/l7_ingest_bench.py
"""
import hashlib
import json
import time
from collections import defaultdict, deque

import numpy as np
import torch

try:
    from GRU_ML_model import GRUDDoSClassifier
except ImportError:                       # allow running from inside bench/
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from GRU_ML_model import GRUDDoSClassifier

torch.set_num_threads(1)
N = 200_000
ROUNDS = 3


def make_line(i):
    """One line of the proposed extended JSON log_format (D10 + L7 features)."""
    return json.dumps({
        "msec": 1791882126.896 + i * 0.001, "client_ip": f"10.0.{(i % 250) + 1}.{(i % 200) + 1}",
        "client_port": 20000 + (i % 40000), "conn": 1000 + i, "conn_reqs": (i % 30) + 1,
        "method": "GET", "uri": f"/path/{i % 97}?r={i % 9999}", "status": 200 if i % 7 else 404,
        "request_time": 0.001 + (i % 50) / 1000, "upstream_time": "0.001",
        "request_length": 88 + (i % 400), "bytes_sent": 240 + (i % 1200),
        "proto": "HTTP/2.0", "tls": "TLSv1.3", "reused": "r" if i % 2 else ".",
        "limit_req": "" if i % 5 else "REJECTED", "ua": "Mozilla/5.0 (X11; Linux x86_64)"
    }, separators=(",", ":"))


def bench(label, fn):
    best = float("inf")
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    print(f"  {label:52s} {best * 1e6 / N:7.3f} us/line  {N / best / 1e6:6.3f} M lines/s/core")


def parse_only(lines):
    tot = 0
    for line in lines:
        tot += json.loads(line)["status"]
    return tot


def rate_window(lines):
    tracker = defaultdict(deque)
    banned = 0
    for line in lines:
        d = json.loads(line)
        ip, now = d["client_ip"], d["msec"]
        is_err = d["status"] >= 400 and d["status"] != 503
        q = tracker[ip]
        q.append((now, is_err))
        while q and now - q[0][0] > 10.0:
            q.popleft()
        if len(q) >= 5 and now - q[0][0] > 0 and len(q) / max(now - q[0][0], 1.0) > 50:
            banned += 1
    return banned


def seq_features(lines):
    seqs = defaultdict(lambda: deque(maxlen=15))
    last = {}
    scored = 0
    for line in lines:
        d = json.loads(line)
        ip, now = d["client_ip"], d["msec"]
        iat = now - last.get(ip, now)
        last[ip] = now
        uhash = int.from_bytes(hashlib.blake2b(d["uri"].split("?")[0].encode(), digest_size=4).digest(), "big")
        feat = (iat, d["request_time"], d["request_length"], d["bytes_sent"],
                1.0 if d["status"] >= 400 else 0.0, d["conn_reqs"],
                1.0 if d["limit_req"] == "REJECTED" else 0.0, uhash % 997)
        s = seqs[ip]
        s.append(feat)
        if len(s) == 15:
            scored += 1
    return scored


def inference():
    model = GRUDDoSClassifier(8, 64, 2)
    model.eval()

    @torch.no_grad()
    def score(W):
        return torch.sigmoid(model(torch.from_numpy(W.astype(np.float32)))).numpy()

    for b in (1, 8, 64, 256, 1024):
        W = np.random.rand(b, 15, 8)
        score(W)
        best = float("inf")
        for _ in range(20):
            t0 = time.perf_counter()
            score(W)
            best = min(best, time.perf_counter() - t0)
        print(f"  batch={b:5d}  {best * 1e3:8.3f} ms/batch  {best / b * 1e6:8.2f} us/window  "
              f"{b / best:10.0f} windows/s")


def engine_poll():
    """The full Phase-P2 poll: encode K updated (IP, UA) windows of 20 requests
    (l7_features) and score them in one batch with a production-sized GRU
    (hidden 64, 2 layers), versus features-only. Untrained weights: cost only."""
    import shutil
    import tempfile

    import l7_engine
    import l7_ingest
    import l7_scorer
    from l7_features import columns

    pkg = tempfile.mkdtemp(prefix="l7bench_")
    try:
        cols = columns()
        model = GRUDDoSClassifier(len(cols), 64, 2)
        l7_scorer.save_package(pkg, model, cols, 20, [0.0] * len(cols), [1.0] * len(cols),
                               0.95, 3, hidden_size=64, num_layers=2)
        for label, path in (("features-only", None), ("scored (GRU 64x2)", pkg)):
            for k in (64, 256, 1024):
                eng = l7_engine.build_engine(path)
                for key in range(k):
                    for i in range(20):
                        eng.on_record(l7_ingest.normalise(
                            {"ip": f"10.1.{key // 250}.{key % 250}", "ua": "u", "uri": f"/{i % 5}",
                             "msec": 1000.0 + i * 0.5, "rt": 0.01, "status": 200, "method": "GET",
                             "rlen": 120, "bsent": 900, "creq": i + 1, "compl": "OK", "urt": "0.004"}))
                t0 = time.perf_counter()
                eng.poll(1100.0)
                dt = time.perf_counter() - t0
                print(f"  {label:18s} {k:5d} windows/poll  {dt * 1e3:8.2f} ms/poll  "
                      f"{dt / k * 1e6:7.1f} us/window")
    finally:
        shutil.rmtree(pkg, ignore_errors=True)


def main():
    lines = [make_line(i) for i in range(N)]
    blob = sum(len(line) + 1 for line in lines)
    print(f"ingestion: {N} lines, mean {blob // N} B/line, {blob / 1e6:.1f} MB total")
    bench("json.loads + one field", lambda: parse_only(lines))
    bench("json + per-IP rate/error window (current L7 rule)", lambda: rate_window(lines))
    bench("json + 8 request-sequence features (blake2b URI)", lambda: seq_features(lines))
    print("inference (deployed 8-feat/seq15/h64/l2 architecture, CPU, 1 thread):")
    inference()
    print("P2 engine poll (encode updated windows + one batched score, CPU, 1 thread):")
    engine_poll()


if __name__ == "__main__":
    main()

"""Shared fixtures for the L7 tests (not a test module itself)."""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import numpy as np

import l7_features as F
import l7_ingest


def obj(ip="10.0.1.5", ua="Mozilla/5.0", uri="/", msec=1000.0, rt=0.01, status=200,
        method="GET", rlen=100, bsent=500, creq=1, compl="OK", lreq="", urt="0.005",
        proto="HTTP/1.1", tls="", reused=".", conn=1):
    """One l7json log object, as nginx would emit it."""
    return {"msec": msec, "ip": ip, "port": 40000, "conn": conn, "creq": creq,
            "proto": proto, "tls": tls, "reused": reused, "method": method, "uri": uri,
            "status": status, "compl": compl, "rt": rt, "uct": "0.001", "urt": urt,
            "rlen": rlen, "bsent": bsent, "lreq": lreq, "lconn": "", "ua": ua}


def rec(**kw):
    """A normalised record, through the real l7_ingest.normalise path."""
    return l7_ingest.normalise(obj(**kw))


class StubScorer:
    """Deterministic stand-in for L7Scorer: p = `hi` when the window's mean of
    column `col` over its valid rows is above `cut`, else `lo`. Records the size
    of every batch it scores."""

    def __init__(self, cols=None, seq_len=20, col="m_post", cut=0.5, hi=0.99, lo=0.01,
                 threshold=0.95, consecutive=3):
        self.cols = list(cols or F.columns())
        self.seq_len = seq_len
        self.col, self.cut, self.hi, self.lo = col, cut, hi, lo
        self.threshold, self.consecutive = threshold, consecutive
        self.sha256 = "stub"
        self.calls = []

    def score(self, batch):
        batch = np.asarray(batch, dtype=np.float32)
        self.calls.append(len(batch))
        j = self.cols.index(self.col)
        valid = batch[..., 0]
        mean = (batch[..., j] * valid).sum(axis=1) / np.maximum(valid.sum(axis=1), 1)
        return np.where(mean > self.cut, self.hi, self.lo).astype(np.float32)


def tiny_package(path, cols=None, seq_len=8, seed=0, threshold=0.5, consecutive=2):
    """An UNTRAINED, seeded GRU package — for pipeline mechanics only."""
    import torch

    import l7_scorer
    from GRU_ML_model import GRUDDoSClassifier
    torch.manual_seed(seed)
    cols = list(cols or F.columns())
    model = GRUDDoSClassifier(input_size=len(cols), hidden_size=8, num_layers=1)
    return l7_scorer.save_package(path, model, cols, seq_len, [0.0] * len(cols),
                                  [1.0] * len(cols), threshold, consecutive,
                                  hidden_size=8, num_layers=1,
                                  meta={"note": "untrained test package"})

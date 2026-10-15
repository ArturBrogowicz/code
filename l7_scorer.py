"""Batched scoring of L7 request windows with a model package (Phase P2).

A *model package* is a directory with
    config.json   format, columns, seq_len, architecture, scaling, decision policy,
                  SHA-256 of the weights, free-form metadata (training provenance)
    model.pth     the GRU state_dict (loaded with torch.load(weights_only=True))
P4's trainer writes packages with save_package(); the daemon, the replay tool and
the probe harness load them with L7Scorer.load(). Loading validates the package
against l7_features (column names must be known features, `valid` first) and
refuses any mismatch, so a model can never be fed columns it was not trained on.

Windows are scaled with l7_features.apply_scaling, the same function the trainer
uses, and scored in one batch: ~30 µs/window at batch 64–256 vs ~540 µs unbatched
(bench/l7_ingest_bench.py).
"""
import hashlib
import json
import os

import numpy as np
import torch

import l7_features as F
from GRU_ML_model import GRUDDoSClassifier

PACKAGE_FORMAT = "l7-gru-package/1"
CONFIG_FILE = "config.json"
WEIGHTS_FILE = "model.pth"


class PackageError(ValueError):
    """The model package is missing, corrupt, or incompatible with l7_features."""


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_columns(cols):
    """A column list is valid if it starts with `valid` and names only known
    features, each once."""
    if not cols or cols[0] != F.VALID:
        raise PackageError(f"columns must start with '{F.VALID}': {cols[:3]}")
    unknown = [c for c in cols[1:] if c not in F.ALL_FEATURES]
    if unknown:
        raise PackageError(f"unknown feature columns: {unknown}")
    if len(set(cols)) != len(cols):
        raise PackageError("duplicate columns")


def save_package(path, model, cols, seq_len, mean, std, threshold, consecutive,
                 hidden_size, num_layers, meta=None):
    """Write a model package. Returns the config dict."""
    validate_columns(list(cols))
    if len(mean) != len(cols) or len(std) != len(cols):
        raise PackageError("mean/std must have one value per column")
    os.makedirs(path, exist_ok=True)
    weights = os.path.join(path, WEIGHTS_FILE)
    torch.save(model.state_dict(), weights)
    cfg = {"format": PACKAGE_FORMAT, "arch": "gru", "columns": list(cols),
           "seq_len": int(seq_len), "hidden_size": int(hidden_size),
           "num_layers": int(num_layers),
           "mean": [float(x) for x in mean], "std": [float(x) for x in std],
           "threshold": float(threshold), "consecutive": int(consecutive),
           "weights_sha256": _sha256(weights), "meta": meta or {}}
    with open(os.path.join(path, CONFIG_FILE), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=1)
        fh.write("\n")
    return cfg


class L7Scorer:
    """Scores (B, seq_len, C) raw window matrices; returns P(attack) per window."""

    def __init__(self, model, cfg, path=None):
        self.model = model
        self.cfg = cfg
        self.path = path
        self.cols = list(cfg["columns"])
        self.seq_len = int(cfg["seq_len"])
        self.mean = np.asarray(cfg["mean"], dtype=np.float32)
        self.std = np.asarray(cfg["std"], dtype=np.float32)
        self.threshold = float(cfg["threshold"])
        self.consecutive = int(cfg["consecutive"])
        self.sha256 = cfg.get("weights_sha256", "")

    @classmethod
    def load(cls, path):
        cfg_path = os.path.join(path, CONFIG_FILE)
        weights = os.path.join(path, WEIGHTS_FILE)
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as e:
            raise PackageError(f"cannot read {cfg_path}: {e}") from e
        if cfg.get("format") != PACKAGE_FORMAT or cfg.get("arch") != "gru":
            raise PackageError(f"unsupported package format/arch: "
                               f"{cfg.get('format')}/{cfg.get('arch')}")
        cols = list(cfg.get("columns", []))
        validate_columns(cols)
        if len(cfg.get("mean", [])) != len(cols) or len(cfg.get("std", [])) != len(cols):
            raise PackageError("mean/std length does not match columns")
        if int(cfg.get("seq_len", 0)) < 1:
            raise PackageError("seq_len must be >= 1")
        if not 0.0 < float(cfg.get("threshold", -1)) < 1.0:
            raise PackageError("threshold must be in (0, 1)")
        if int(cfg.get("consecutive", 0)) < 1:
            raise PackageError("consecutive must be >= 1")
        if not os.path.isfile(weights):
            raise PackageError(f"missing {weights}")
        if cfg.get("weights_sha256") and _sha256(weights) != cfg["weights_sha256"]:
            raise PackageError("weights SHA-256 does not match config.json")
        model = GRUDDoSClassifier(input_size=len(cols), hidden_size=int(cfg["hidden_size"]),
                                  num_layers=int(cfg["num_layers"]))
        try:
            model.load_state_dict(torch.load(weights, map_location="cpu", weights_only=True))
        except (RuntimeError, OSError, ValueError) as e:
            raise PackageError(f"weights do not fit the declared architecture: {e}") from e
        model.eval()
        return cls(model, cfg, path=path)

    def score(self, batch):
        """P(attack) for each window of a (B, seq_len, C) batch of raw matrices."""
        batch = np.asarray(batch, dtype=np.float32)
        if batch.ndim != 3 or batch.shape[1] != self.seq_len or batch.shape[2] != len(self.cols):
            raise ValueError(f"expected (B, {self.seq_len}, {len(self.cols)}), got {batch.shape}")
        if batch.shape[0] == 0:
            return np.zeros(0, dtype=np.float32)
        x = F.apply_scaling(batch, self.mean, self.std)
        with torch.no_grad():
            p = torch.sigmoid(self.model(torch.from_numpy(x))).numpy().ravel()
        return p

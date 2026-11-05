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

L7 v2 (docs/L7V2_DESIGN.md 8.1): format "l7-gru-package/2" adds "level". A "view"
package holds the two-level model (l7_view_model.ViewGRU, arch "view-gru") over
view-token columns (l7_features.TOKEN_COLUMNS) and "max_views"; a "request" package
holds the per-request GRU (arch "gru", "seq_len"), e.g. the seq-64 ablation. Format 1
packages (P4/P5c) load as level "request", unchanged. load(path, level=...) refuses
a package of another level, as validate_columns refuses unknown columns.
"""
import hashlib
import json
import os

import numpy as np
import torch

import l7_features as F
from GRU_ML_model import GRUDDoSClassifier

PACKAGE_FORMAT = "l7-gru-package/1"
PACKAGE_FORMAT_V2 = "l7-gru-package/2"
LEVELS = ("request", "view")
ARCH = {"request": "gru", "view": "view-gru"}
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


def validate_columns(cols, level="request"):
    """A column list is valid if it starts with `valid` and names only known
    features of its level (request features, or view-token features), each once."""
    if not cols or cols[0] != F.VALID:
        raise PackageError(f"columns must start with '{F.VALID}': {cols[:3]}")
    known = F.TOKEN_FEATURES if level == "view" else F.ALL_FEATURES
    unknown = [c for c in cols[1:] if c not in known]
    if unknown:
        raise PackageError(f"unknown {level}-level feature columns: {unknown}")
    if len(set(cols)) != len(cols):
        raise PackageError("duplicate columns")


def save_view_package(path, model, cols, max_views, mean, std, threshold, consecutive,
                      embed_size, hidden_size, num_layers, meta=None):
    """Write an L7 v2 view-level package (format 2, level "view"). Returns the config dict."""
    validate_columns(list(cols), "view")
    if len(mean) != len(cols) or len(std) != len(cols):
        raise PackageError("mean/std must have one value per column")
    os.makedirs(path, exist_ok=True)
    weights = os.path.join(path, WEIGHTS_FILE)
    torch.save(model.state_dict(), weights)
    cfg = {"format": PACKAGE_FORMAT_V2, "level": "view", "arch": ARCH["view"], "columns": list(cols),
           "max_views": int(max_views), "embed_size": int(embed_size), "hidden_size": int(hidden_size),
           "num_layers": int(num_layers),
           "mean": [float(x) for x in mean], "std": [float(x) for x in std],
           "threshold": float(threshold), "consecutive": int(consecutive),
           "weights_sha256": _sha256(weights), "meta": meta or {}}
    with open(os.path.join(path, CONFIG_FILE), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=1)
        fh.write("\n")
    return cfg


def save_package(path, model, cols, seq_len, mean, std, threshold, consecutive,
                 hidden_size, num_layers, meta=None, level=None):
    """Write a model package. Returns the config dict. level=None writes format 1 (P4/P5c,
    byte for byte as before); level="request" writes format 2 with its level (L7 v2's
    per-request ablation)."""
    if level not in (None, "request"):
        raise PackageError("save_package writes request-level packages; use save_view_package")
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
    if level is not None:
        cfg = {"format": PACKAGE_FORMAT_V2, "level": level, **{k: v for k, v in cfg.items() if k != "format"}}
    with open(os.path.join(path, CONFIG_FILE), "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=1)
        fh.write("\n")
    return cfg


def package_level(cfg):
    """The level of a package config ("request" for format 1), or a PackageError for an unknown format or a level
    whose arch does not match."""
    if cfg.get("format") == PACKAGE_FORMAT and cfg.get("arch") == "gru":
        return "request"
    level = cfg.get("level")
    if cfg.get("format") == PACKAGE_FORMAT_V2 and level in LEVELS and cfg.get("arch") == ARCH[level]:
        return level
    raise PackageError(f"unsupported package format/level/arch: "
                       f"{cfg.get('format')}/{cfg.get('level')}/{cfg.get('arch')}")


class L7Scorer:
    """Scores (B, seq_len, C) raw window matrices, or for a view package (B, max_views, C) token matrices; returns
    P(attack) per window."""

    def __init__(self, model, cfg, path=None):
        self.model = model
        self.cfg = cfg
        self.path = path
        self.level = cfg.get("level", "request")
        self.cols = list(cfg["columns"])
        # the window length: requests for a request package, complete views for a view package
        self.seq_len = int(cfg["max_views"] if self.level == "view" else cfg["seq_len"])
        self.max_views = self.seq_len if self.level == "view" else None
        self.mean = np.asarray(cfg["mean"], dtype=np.float32)
        self.std = np.asarray(cfg["std"], dtype=np.float32)
        self.threshold = float(cfg["threshold"])
        self.consecutive = int(cfg["consecutive"])
        self.sha256 = cfg.get("weights_sha256", "")

    @classmethod
    def load(cls, path, level=None):
        """Load and validate a package; with `level`, refuse a package of another level."""
        cfg_path = os.path.join(path, CONFIG_FILE)
        weights = os.path.join(path, WEIGHTS_FILE)
        try:
            with open(cfg_path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as e:
            raise PackageError(f"cannot read {cfg_path}: {e}") from e
        got = package_level(cfg)
        if level is not None and got != level:
            raise PackageError(f"package level {got!r} where {level!r} is required")
        cfg = {**cfg, "level": got}
        cols = list(cfg.get("columns", []))
        validate_columns(cols, got)
        if len(cfg.get("mean", [])) != len(cols) or len(cfg.get("std", [])) != len(cols):
            raise PackageError("mean/std length does not match columns")
        if int(cfg.get("max_views" if got == "view" else "seq_len", 0)) < 1:
            raise PackageError("max_views must be >= 1" if got == "view" else "seq_len must be >= 1")
        if not 0.0 < float(cfg.get("threshold", -1)) < 1.0:
            raise PackageError("threshold must be in (0, 1)")
        if int(cfg.get("consecutive", 0)) < 1:
            raise PackageError("consecutive must be >= 1")
        if not os.path.isfile(weights):
            raise PackageError(f"missing {weights}")
        if cfg.get("weights_sha256") and _sha256(weights) != cfg["weights_sha256"]:
            raise PackageError("weights SHA-256 does not match config.json")
        if got == "view":
            from l7_view_model import ViewGRU
            model = ViewGRU(input_size=len(cols), embed_size=int(cfg["embed_size"]),
                            hidden_size=int(cfg["hidden_size"]), num_layers=int(cfg["num_layers"]))
        else:
            model = GRUDDoSClassifier(input_size=len(cols), hidden_size=int(cfg["hidden_size"]),
                                      num_layers=int(cfg["num_layers"]))
        try:
            model.load_state_dict(torch.load(weights, map_location="cpu", weights_only=True))
        except (RuntimeError, OSError, ValueError) as e:
            raise PackageError(f"weights do not fit the declared architecture: {e}") from e
        model.eval()
        return cls(model, cfg, path=path)

    def score(self, batch):
        """P(attack) for each window of a (B, seq_len, C) batch of raw matrices (for a view package: seq_len is
        max_views and the matrices are l7_features.token_matrix's)."""
        batch = np.asarray(batch, dtype=np.float32)
        if batch.ndim != 3 or batch.shape[1] != self.seq_len or batch.shape[2] != len(self.cols):
            raise ValueError(f"expected (B, {self.seq_len}, {len(self.cols)}), got {batch.shape}")
        if batch.shape[0] == 0:
            return np.zeros(0, dtype=np.float32)
        x = F.apply_scaling(batch, self.mean, self.std)
        with torch.no_grad():
            p = torch.sigmoid(self.model(torch.from_numpy(x))).numpy().ravel()
        return p

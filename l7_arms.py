"""One enforcement path for every arm (docs/L7V2_DESIGN.md 9.5, section 10; T-025c).

The enforcing arm (L7_ENFORCE=1) loads its detector from a frozen L7 v2 selection (ml/train_l7v2.py `select`:
selection.json, format l7v2-selection/1, its sha256 recorded in selection.sha256) by the arm's name, so every arm,
the view GRU, the HGB and the LR on the same windows' token summaries, or a rule, is the same thing to the daemon:
a view-level Detector behind score(batch) -> p, scored by the same l7_engine.L7ViewEngine with its OWN operating point
(threshold, consecutive) from the selection, and acted on by the same l7_enforce.Arm (9.1-9.4).

Refused for enforcement (DetectorError), so the daemon does not start:
  * a selection whose sha256 is not the one the runner gives (L7_SELECTION_SHA256), or not of this format;
  * an arm whose artifact is missing or altered (its sha256 in the selection);
  * an arm without an operating point: `select` writes null when no grid point fits the benign budget, and the
    package then carries the placeholder 0.5 x 1 (T-025b report 6), which no arm may enforce;
  * the ablations, which are scored by replay only: the shuffled GRU and the per-request seq-64 GRU;
  * a GRU package whose own operating point, or whose record of where it came from, is not the selection's.
A rule arm (section 10: per-endpoint cost budget, multi-scale rate, population-level) is an arm entry with
"kind": "rule" whose artifact is a JSON spec {"format": "l7v2-rule/1", "rule": <name>, "params": {...}} naming a
function registered in RULES; it gives p in {0, 1}. No rule arm is built yet (T-025b report 6, follow-up a), so
RULES is empty and a rule arm is refused until its function is registered.
"""
import hashlib
import json
import os
import pickle

import numpy as np

import l7_features as F

SEL_FORMAT = "l7v2-selection/1"            # ml/train_l7v2.SEL_FORMAT
RULE_FORMAT = "l7v2-rule/1"
LIVE = {"view_gru": "gru", "hgb": "tabular", "lr": "tabular"}
REPLAY_ONLY = {"gru_shuffled": "the shuffled-GRU is an ablation, scored by replay only",
               "request_gru": "the per-request seq-64 GRU is the offline ablation (section 10)"}
RULES = {}                                 # rule name -> factory(**params) -> fn(batch) -> p in {0, 1}


class DetectorError(ValueError):
    """The arm cannot be enforced (see the module docstring)."""


def summaries(batch):
    """Token summaries of a stack of token matrices, the HGB's and the LR's input: ml/train_l7v2.summaries, restated
    (tests/test_l7_arms.py keeps the two equal) so that the daemon does not import the trainer."""
    return np.array([F.token_summary(x)[0] for x in batch], dtype=np.float64).reshape(len(batch), -1)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Detector:
    """A view-level detector of any kind, as the engine and the arm see it: cols, max_views, threshold, consecutive,
    sha256 (of the artifact), cfg["meta"]["arm"], and score(batch) -> P(attack) per window."""

    level = "view"

    def __init__(self, arm, kind, threshold, consecutive, sha256, fn, selection_sha256, cols=None, max_views=None):
        self.arm, self.kind = arm, kind
        self.cols = list(cols or F.TOKEN_COLUMNS)
        self.max_views = self.seq_len = int(max_views or F.MAX_VIEWS)
        self.threshold, self.consecutive = float(threshold), int(consecutive)
        self.sha256, self.selection_sha256 = sha256, selection_sha256
        self.cfg = {"meta": {"arm": arm, "kind": kind, "operating_point": "selection.json"}}
        self._fn = fn

    def score(self, batch):
        batch = np.asarray(batch, dtype=np.float32)
        if batch.ndim != 3 or batch.shape[1:] != (self.max_views, len(self.cols)):
            raise ValueError(f"expected (B, {self.max_views}, {len(self.cols)}), got {batch.shape}")
        p = np.asarray(self._fn(batch), dtype=np.float64).ravel()
        if p.shape != (len(batch),):
            raise ValueError(f"{self.arm}: {p.shape[0]} scores for {len(batch)} windows")
        if self.kind == "rule" and not np.isin(p, (0.0, 1.0)).all():
            raise ValueError(f"{self.arm}: a rule gives p in {{0, 1}}")
        return p


def load(selection_path, selection_sha256, arm):
    """The Detector of `arm` in the frozen selection at `selection_path`, or DetectorError."""
    if not selection_sha256:
        raise DetectorError("the frozen selection's sha256 must be given")
    try:
        actual = _sha256(selection_path)
        with open(selection_path, encoding="utf-8") as fh:
            sel = json.load(fh)
    except (OSError, ValueError) as e:
        raise DetectorError(f"cannot read the selection {selection_path}: {e}") from e
    if actual != selection_sha256:
        raise DetectorError(f"{selection_path} has sha256 {actual}, not the recorded {selection_sha256}")
    if not isinstance(sel, dict) or sel.get("format") != SEL_FORMAT:
        raise DetectorError(f"{selection_path} is not a {SEL_FORMAT} file")
    entry = (sel.get("arms") or {}).get(arm)
    if entry is None:
        raise DetectorError(f"no arm {arm!r} in the selection (arms: {sorted(sel.get('arms') or {})})")
    if arm in REPLAY_ONLY:
        raise DetectorError(REPLAY_ONLY[arm])
    kind = entry.get("kind") or LIVE.get(arm)
    if kind not in ("gru", "tabular", "rule"):
        raise DetectorError(f"arm {arm!r} is of no kind this daemon can enforce")
    op = entry.get("operating_point")
    if not op:
        raise DetectorError(f"arm {arm!r} has no operating point (selection null; its package carries the "
                            "placeholder 0.5 x 1): it is not enforced")
    threshold, consecutive = float(op["threshold"]), int(op["consecutive"])
    if not (0.0 <= threshold < 1.0 and consecutive >= 1):
        raise DetectorError(f"arm {arm!r}: operating point {threshold} x {consecutive} is out of range")
    base = os.path.dirname(os.path.abspath(selection_path))
    path = os.path.normpath(os.path.join(base, str(entry.get("artifact", ""))))
    if not path.startswith(base + os.sep) or not os.path.isfile(path) or _sha256(path) != entry.get("artifact_sha256"):
        raise DetectorError(f"the artifact of {arm!r} is missing, outside the selection's directory, or altered")
    sha = entry["artifact_sha256"]
    if kind == "gru":
        import l7_scorer  # torch only for a GRU arm
        try:
            scorer = l7_scorer.L7Scorer.load(os.path.dirname(path), level="view")
        except l7_scorer.PackageError as e:
            raise DetectorError(f"arm {arm!r}: {e}") from e
        meta = scorer.cfg.get("meta") or {}
        if (scorer.threshold, scorer.consecutive) != (threshold, consecutive) or meta.get("operating_point") != \
                "selection.json":
            raise DetectorError(f"arm {arm!r}: the package's operating point ({scorer.threshold} x "
                                f"{scorer.consecutive}, from {meta.get('operating_point')}) is not the selection's")
        return Detector(arm, kind, threshold, consecutive, scorer.sha256 or sha, scorer.score, selection_sha256,
                        scorer.cols, scorer.max_views)
    if kind == "tabular":
        with open(path, "rb") as fh:
            clf = pickle.load(fh)   # our own artifact, its sha256 checked against the frozen selection
        return Detector(arm, kind, threshold, consecutive, sha,
                        lambda batch: clf.predict_proba(summaries(batch))[:, 1] if len(batch) else np.zeros(0),
                        selection_sha256)
    try:
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
    except ValueError as e:
        raise DetectorError(f"arm {arm!r}: the rule spec is not JSON: {e}") from e
    if not isinstance(spec, dict) or spec.get("format") != RULE_FORMAT or spec.get("rule") not in RULES:
        raise DetectorError(f"arm {arm!r}: not a {RULE_FORMAT} spec of a registered rule ({sorted(RULES)})")
    return Detector(arm, kind, threshold, consecutive, sha, RULES[spec["rule"]](**(spec.get("params") or {})),
                    selection_sha256)

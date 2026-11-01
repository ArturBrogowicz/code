"""One enforcement path for every arm (docs/L7V2_DESIGN.md 9.5, section 10; T-025c).

The enforcing arm (L7_ENFORCE=1) loads its detector from a frozen L7 v2 selection (ml/train_l7v2.py `select`:
selection.json, format l7v2-selection/1, its sha256 recorded in selection.sha256) by the arm's name, so every arm,
the view GRU, the HGB and the LR on the same windows' token summaries, or a rule, is the same thing to the daemon:
a view-level Detector behind score(batch) -> p, scored by the same l7_engine.L7ViewEngine with its OWN operating point
(threshold, consecutive) from the selection, and acted on by the same l7_enforce.Arm (9.1-9.4).

Refused for enforcement (DetectorError), so the daemon does not start:
  * a selection whose sha256 is not the one the runner gives (L7_SELECTION_SHA256), or not of this format;
  * a selection not marked valid_for_claims (ml/train_l7v2.py writes false for a --smoke run or a legacy capture;
    T-042 E05): it would enforce like a real arm and look like one in the events;
  * an arm whose artifact is missing or altered (its sha256 in the selection);
  * an arm without an operating point: `select` writes null when no grid point fits the benign budget, and the
    package then carries the placeholder 0.5 x 1 (T-025b report 6), which no arm may enforce;
  * the ablations, which are scored by replay only: the shuffled GRU and the per-request seq-64 GRU;
  * a GRU package whose own operating point, or whose record of where it came from, is not the selection's.

R*, the best rule arm (section 10; T-025e), comes from the frozen RULE selection (ml/l7v2_rules.py select:
rules_selection.json, L7_SELECTION_SHA256 its sha256) by the arm's name "R*". A rule decides at its own (IP, UA) level on
its statistics, never on view windows (T042-E08), so it is a RuleDetector on l7_rule_engine's path, and the replay's own
RuleStats and RuleScorer run in the daemon, imported from ml/l7v2_rules.py (0.05 s and 5 MB on top of torch, measured,
and no root module shares a name with one in ml/). The same refusals apply: a selection that is not the recorded one or
not valid for claims, an altered artifact, an operating point that is not the selection's. So do two of its own: the
calibration record it was tuned on must be frozen and the package's, since its thresholds are in that record's costs, and
its rule spec must be the one in this tree. Only R* runs live: the other rule arms and the fixed replays are scored by
the replay, and a selection in which no rule fits the budget has no R*.
"""
import hashlib
import json
import os
import pickle
import sys

import numpy as np

import l7_features as F

SEL_FORMAT = "l7v2-selection/1"            # ml/train_l7v2.SEL_FORMAT
RULE_SEL_PREFIX = "l7v2-rule-selection/"    # ml/l7v2_rules.SELECTION_FORMAT without its version, which that module holds
RSTAR = "R*"
LIVE = {"view_gru": "gru", "hgb": "tabular", "lr": "tabular"}
REPLAY_ONLY = {"gru_shuffled": "the shuffled-GRU is an ablation, scored by replay only",
               "request_gru": "the per-request seq-64 GRU is the offline ablation (section 10)"}


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
        self.valid_for_claims = True                # load() refuses any other selection
        self.cfg = {"meta": {"arm": arm, "kind": kind, "operating_point": "selection.json"}}
        self._fn = fn

    def score(self, batch):
        batch = np.asarray(batch, dtype=np.float32)
        if batch.ndim != 3 or batch.shape[1:] != (self.max_views, len(self.cols)):
            raise ValueError(f"expected (B, {self.max_views}, {len(self.cols)}), got {batch.shape}")
        p = np.asarray(self._fn(batch), dtype=np.float64).ravel()
        if p.shape != (len(batch),):
            raise ValueError(f"{self.arm}: {p.shape[0]} scores for {len(batch)} windows")
        return p


class RuleDetector:
    """R* as the engine and the arm see it: level "rule", the rule's name, threshold and consecutive, sha256 (the
    package's), new_stats() (the replay's RuleStats with the package's class costs) and score(rows) -> p in {0, 1}, where
    a row is an (IP, UA) key's statistics in one poll."""

    level = "rule"
    kind = "rule"

    def __init__(self, rules_module, rule, selection_sha256):
        self._rules, self.rule = rules_module, rule
        self.arm, self.rule_name = RSTAR, rule.arm
        self.threshold, self.consecutive = rule.threshold, rule.consecutive
        self.sha256, self.selection_sha256 = rule.sha256, selection_sha256
        self.valid_for_claims = True                # load() refuses any other selection
        self.cfg = {"meta": {"arm": RSTAR, "kind": "rule", "rule": rule.arm, "operating_point": "rules_selection.json"}}
        self.stat_thresholds = {c: float(t) for c, t in zip(rule.stat_columns, rule.thresholds, strict=True)}
        self.calibration_sha256 = rule.cfg["calibration"]["sha256"]

    def new_stats(self):
        return self._rules.RuleStats(self.rule.costs)

    def score(self, rows):
        return self.rule.score(self.rule.select(rows))

    def statistic(self, row):
        """The rule's statistics in one row, for the events: {column: value}."""
        return {c: round(float(v), 6) for c, v in zip(self.rule.stat_columns, self.rule.select(row)[0], strict=True)}


def rules_module():
    """ml/l7v2_rules.py, the module the replay runs (imported only for a rule arm)."""
    ml = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml")
    if ml not in sys.path:
        sys.path.insert(0, ml)
    import l7v2_rules
    return l7v2_rules


def _artifact(selection_path, name, entry):
    """The checked path of an arm's artifact (inside the selection's directory, its sha256 the recorded one)."""
    base = os.path.dirname(os.path.abspath(selection_path))
    path = os.path.normpath(os.path.join(base, str(entry.get("artifact", ""))))
    if not path.startswith(base + os.sep) or not os.path.isfile(path) or _sha256(path) != entry.get("artifact_sha256"):
        raise DetectorError(f"the artifact of {name!r} is missing, outside the selection's directory, or altered")
    return path


def _load_rstar(sel, selection_path, selection_sha256, arm):
    """The RuleDetector of a frozen rule selection whose sha256 and validity load() has checked."""
    rules = rules_module()
    if sel["format"] != rules.SELECTION_FORMAT:
        raise DetectorError(f"{selection_path} is not a {rules.SELECTION_FORMAT} file")
    if arm != RSTAR:
        raise DetectorError(f"a rule selection enforces {RSTAR} only (section 10), not {arm!r}; the replay scores the rest")
    cal = sel.get("calibration") or {}
    if cal.get("status") != "frozen":
        raise DetectorError(f"{selection_path} was tuned on a {cal.get('status')!r} calibration record, not a frozen one: "
                            "it is not enforced")
    if sel.get("spec_sha256") != rules.spec_sha256():
        raise DetectorError(f"{selection_path} was tuned under another rule spec ({sel.get('spec_sha256')}), not this "
                            f"tree's ({rules.spec_sha256()})")
    name = sel.get("r_star")
    entry = (sel.get("arms") or {}).get(name)
    op = (entry or {}).get("operating_point")
    if not op:
        raise DetectorError(f"the selection has no {RSTAR}: no rule arm fits the benign budget (r_star {name!r})")
    path = _artifact(selection_path, name, entry)
    try:
        rule = rules.RuleScorer.load(path)
    except (ValueError, KeyError, TypeError) as e:
        raise DetectorError(f"arm {name!r}: {e}") from e
    own = (rule.arm, rule.stat_columns, list(rule.cfg["thresholds"]), rule.consecutive)
    if own != (name, list(op["columns"]), list(op["thresholds"]), int(op["consecutive"])):
        raise DetectorError(f"arm {name!r}: the package's operating point is not the selection's")
    if rule.cfg.get("calibration") != cal or rule.cfg.get("spec_sha256") != sel["spec_sha256"]:
        raise DetectorError(f"arm {name!r}: the package's calibration record or rule spec is not the selection's")
    return RuleDetector(rules, rule, selection_sha256)


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
    fmt = sel.get("format") if isinstance(sel, dict) else None
    is_rules = isinstance(fmt, str) and fmt.startswith(RULE_SEL_PREFIX)
    if fmt != SEL_FORMAT and not is_rules:
        raise DetectorError(f"{selection_path} is not a {SEL_FORMAT} file")
    if sel.get("valid_for_claims") is not True:
        raise DetectorError(f"{selection_path} is marked valid_for_claims={sel.get('valid_for_claims')!r} (a smoke run "
                            "or a legacy capture): it is not enforced")
    if is_rules:
        return _load_rstar(sel, selection_path, selection_sha256, arm)
    entry = (sel.get("arms") or {}).get(arm)
    if entry is None:
        raise DetectorError(f"no arm {arm!r} in the selection (arms: {sorted(sel.get('arms') or {})})")
    if arm in REPLAY_ONLY:
        raise DetectorError(REPLAY_ONLY[arm])
    kind = LIVE.get(arm)
    if kind is None:
        raise DetectorError(f"arm {arm!r} is of no kind this daemon can enforce")
    op = entry.get("operating_point")
    if not op:
        raise DetectorError(f"arm {arm!r} has no operating point (selection null; its package carries the "
                            "placeholder 0.5 x 1): it is not enforced")
    threshold, consecutive = float(op["threshold"]), int(op["consecutive"])
    if not (0.0 <= threshold < 1.0 and consecutive >= 1):
        raise DetectorError(f"arm {arm!r}: operating point {threshold} x {consecutive} is out of range")
    path = _artifact(selection_path, arm, entry)
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
    with open(path, "rb") as fh:
        clf = pickle.load(fh)   # our own artifact, its sha256 checked against the frozen selection
    return Detector(arm, kind, threshold, consecutive, sha,
                    lambda batch: clf.predict_proba(summaries(batch))[:, 1] if len(batch) else np.zeros(0),
                    selection_sha256)

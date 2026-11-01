#!/usr/bin/env python3
"""The replay scorer (docs/L7V2_DESIGN.md 11 "Detection metrics"; T-025b follow-up (c)): a recorded run (the
l7_engine.EngineRecorder stream of records and poll ticks; for P1 the U run, unmitigated, so every arm sees the same
traffic) through every arm at the live engine's poll cadence, giving per arm its decisions, times to decision and
benign units, attributed from the run's manifest.

  view arms (view_gru, hgb, lr, gru_shuffled)  each through its own l7_engine.L7ViewEngine with the arm's scorer at
                                               its frozen (theta, k): the engine's windows (at most 4 new ones per key
                                               and poll, the age gate, flood suppression), its k-consecutive rule (the
                                               one T038-06 aligned the evaluator with) and its l7_would_ban events
  age_only (view level)                        through TapEngine, the same engine with one addition: the windows it is
                                               about to score are handed to the arm first (its row is the window's age)
  rule arms (ml/l7v2_rules.py packages)        on their own (IP, UA) path, RulePath (ml/l7v2_rules_prereg_v3.json,
                                               T042-E08, D-043): every record feeds the rule's statistics, every poll tick
                                               gives one row per (IP, UA) key with requests since the previous tick,
                                               and the section-9 policy (k consecutive rows, a flood clears the runs)
A key is decided at the poll of its first decision; an entity's time to decision is that poll minus the entity's first
request start (the evaluators use the completion of the deciding window's or row's last request, at most one poll
earlier). Offline; nothing here touches the network or the VM.

    arms = load_arms(SEL/selection.json, <sha>, RULES/rules_selection.json, <sha>)
    res = replay(read_items(RUN/l7_record.jsonl), arms, RunLabels(manifest))
"""
import gzip
import json
import math
import os
import pickle
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import l7v2_model_prereg as MPRE
import l7v2_rules as R
import replay_l7
import train_l7v2 as V

import l7_dataset as D
import l7_engine as E
import l7_features as F
import l7_ingest as I

RESULT_FORMAT = "l7v2-replay/1"


class ReplayError(ValueError):
    """A frozen selection or package is missing or altered, or an arm cannot be replayed."""


# ───────────────────────────── the engine, tapped ─────────────────────────────

class TapEngine(E.L7ViewEngine):
    """l7_engine.L7ViewEngine unchanged, except that every record is also shown to the scorer (observe) and the
    windows the engine is about to score are handed to it (tap) before the poll's batch is scored."""

    def on_record(self, rec, now=None):
        key = super().on_record(rec, now)
        self.scorer.observe(rec)
        return key

    def _windows(self, key, agg):
        out = super()._windows(key, agg)
        if out:
            self.scorer.tap(out)
        return out


class _Tapped:
    """The engine-facing side of an arm whose rows are computed from window context: level view, the token columns and
    max_views the engine encodes (unused), threshold, consecutive, sha256; observe() tracks each key's session (as
    train_l7v2.sessions: a new session after a start gap above the idle timeout), tap() queues the rows of the windows
    about to be scored, score() returns their p in the engine's batch order."""

    level = "view"

    def __init__(self, threshold, consecutive, sha256, idle_s=None):
        self.cols, self.max_views, self.seq_len = list(F.TOKEN_COLUMNS), F.MAX_VIEWS, F.MAX_VIEWS
        self.threshold, self.consecutive, self.sha256 = float(threshold), int(consecutive), sha256
        self.idle_s = MPRE.load()["ingest"]["idle_timeout_s"] if idle_s is None else idle_s
        self._sess, self._queue = {}, []

    def observe(self, rec):
        key, s = I.key_v2(rec), F.start_time(rec)
        st = self._sess.get(key)
        if st is None or s - st[1] > self.idle_s:
            self._sess[key] = [s, s]
        else:
            st[0], st[1] = min(st[0], s), max(st[1], s)

    def contexts(self, windows):
        return [(key, recs[-1]["msec"], self._sess[key][0], F.start_time(recs[-1])) for key, _j, recs in windows]

    def tap(self, windows):
        self._queue.append(self.rows(self.contexts(windows)))

    def score(self, batch):
        rows = np.concatenate(self._queue) if self._queue else np.zeros(0)
        self._queue = []
        if len(rows) != len(batch):
            raise ReplayError(f"{len(rows)} tapped rows for a batch of {len(batch)}")
        return self.p(rows)


class RulePath:
    """A rule package on its own (IP, UA) path (ml/l7v2_rules_prereg_v3.json r_star_live and decision_points), the
    path R* runs live: every record feeds RuleStats; every poll tick gives the rows of the (IP, UA) keys with a request
    since the previous tick, scored with the package (score(batch) -> p); p > theta in k consecutive rows of a key
    decides it; a suppressing tick (flood) clears every run and decides nothing, as the engine's poll does. Without
    ticks (a plain access log), polls are synthesised at whole seconds of the log clock, as the evaluator's."""

    level = "rule"

    def __init__(self, package):
        self.rule = package
        self.threshold, self.consecutive, self.sha256 = package.threshold, package.consecutive, package.sha256

    def run(self, items):
        """{(ip, ua_h): decision poll time} over the stream items, and the counts of polls and rows."""
        stats, hits, decided = R.RuleStats(self.rule.costs), {}, {}
        counts = {"polls": 0, "suppressed_polls": 0, "rows": 0, "late": 0}
        was_supp = False

        def tick(now, supp):
            nonlocal was_supp
            rows = stats.poll()
            counts["polls"] += 1
            if supp:
                if not was_supp:
                    hits.clear()
                was_supp = True
                counts["suppressed_polls"] += 1
                return
            was_supp = False
            if not rows:
                return
            counts["rows"] += len(rows)
            p = self.rule.score(self.rule.select(np.stack([row for _k, _t, row in rows])))
            for (key, _t, _row), pi in zip(rows, p, strict=True):
                h = hits.get(key, 0) + 1 if pi > self.threshold else 0
                hits[key] = h
                if h >= self.consecutive and key not in decided:
                    decided[key] = now

        has_ticks = any(it[0] == "poll" for it in items)
        poll_s, nxt = R.load_spec()["decision_points"]["poll_s"], None
        for it in items:
            if it[0] == "poll":
                tick(it[1], it[2])
                continue
            rec = I.normalise(it[1])
            if rec is None:
                continue
            if not has_ticks:
                b = (math.floor(rec["msec"] / poll_s) + 1) * poll_s
                if nxt is not None and b != nxt:
                    tick(nxt, False)
                nxt = b
            stats.observe(rec)
        if not has_ticks and nxt is not None:
            tick(nxt, False)
        counts["late"] = stats.late
        return decided, counts


class AgeArm(_Tapped):
    """The age-only baseline (ml/l7v2_model_prereg.json baselines.age_only): the window's age is its opener's start
    minus the key session's first start; p = train_l7v2.age_scores against the training benign ages."""

    def __init__(self, benign_train_ages, threshold, consecutive, sha256=None):
        super().__init__(threshold, consecutive, sha256)
        self.ref = list(benign_train_ages)

    def rows(self, ctx):
        return np.asarray([s - s0 for _k, _t, s0, s in ctx], dtype=np.float64)

    def p(self, rows):
        return V.age_scores(self.ref, [{"age": a} for a in rows])


class ShuffledScorer:
    """The shuffled-GRU in the engine: the fitted view GRU scoring each window with its valid tokens shuffled
    (train_l7v2.shuffled_stack's shuffles, seeded once per replay)."""

    level = "view"

    def __init__(self, gru, seed, pin_first=False):
        self.gru, self.rng, self.pin_first = gru, np.random.default_rng(seed), pin_first
        self.cols, self.max_views, self.seq_len = gru.cols, gru.max_views, gru.seq_len
        self.threshold, self.consecutive, self.sha256 = gru.threshold, gru.consecutive, gru.sha256

    def score(self, batch):
        shuffle = V.shuffle_rows_pin_first if self.pin_first else F.shuffle_valid_rows
        return self.gru.score(np.stack([shuffle(x, self.rng) for x in batch]) if len(batch) else batch)


# ───────────────────────────── labels ─────────────────────────────

class RunLabels:
    """The run's attribution from its manifest (l7_dataset.labeler by address and time, user_units, kind_or_family),
    the same as train_l7.load_records gives a capture's records."""

    def __init__(self, manifest):
        self.m = manifest
        self.label = D.labeler(manifest)
        self.t0 = D.time_origin(manifest)
        self.kof = D.kind_or_family(manifest)
        self.by_entity = manifest.get("format") in D.FORMATS_P3
        self.plan_users = R.plan_users(manifest)
        self.units = {}
        if self.by_entity:
            for _u, ent, role in D.user_units(manifest):
                if role != "attack":
                    self.units[ent] = self.units.get(ent, 0) + 1

    def of(self, rec):
        """(class, family, held_out, entity, kind or family) of one normalised record."""
        cls, fam, held, ent = self.label(rec["ip"], None if self.t0 is None else F.start_time(rec) - self.t0)
        return cls, fam, held, ent, self.kof.get(ent if self.by_entity else rec["ip"])


def read_items(path):
    """The stream items of a recording or an access log (l7_engine.read_stream), plain or gzipped."""
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8", errors="replace") as fh:
        return list(E.read_stream(fh))


def ground_truth(items, labels):
    """Each key's entity (its first labelled record's), each entity's class, kind and first request start, the attack
    entities with a labelled request (recall's denominator) and the benign units."""
    key_ent, ent = {}, {}
    rule_ent, sids = {}, {}
    for it in items:
        if it[0] != "record":
            continue
        rec = I.normalise(it[1])
        if rec is None:
            continue
        cls, fam, _held, e, kof = labels.of(rec)
        if cls == D.OTHER:
            continue
        key_ent.setdefault(I.key_v2(rec), e)
        rule_ent.setdefault(R.rule_key(rec), e)
        sids.setdefault(R.rule_key(rec), set()).add(rec.get("sid_h", I.NO_SID))
        info = ent.setdefault(e, {"cls": cls, "family": fam, "kind": kof or fam, "first": math.inf})
        info["first"] = min(info["first"], F.start_time(rec))
    attack = {e for e, i in ent.items() if i["cls"] == D.ATTACK}
    units = labels.units or {e: 1 for e, i in ent.items() if i["cls"] == D.BENIGN}
    rule_cost = {k: labels.plan_users.get(k) or len(s) for k, s in sids.items()}   # the users behind it (D-043, E-4)
    return {"view": key_ent, "rule": rule_ent, "rule_cost": rule_cost}, ent, attack, units


# ───────────────────────────── the replay ─────────────────────────────

def make_engine(scorer):
    """An observe-only view engine around `scorer`, as l7_engine.build_engine builds one for a view package; tapped
    when the scorer computes its rows from window context."""
    store = I.L7KeyStore(idle_timeout=I.V2_IDLE_TIMEOUT, max_views=scorer.max_views)
    cls = TapEngine if isinstance(scorer, _Tapped) else E.L7ViewEngine
    return cls(store, scorer=scorer, min_views=MPRE.load()["engine"]["min_views"])


def score_arm(items, scorer, truth):
    """One arm's replay: its decisions per key (a view arm's first l7_would_ban, a rule's first decision on its own
    path), entity outcomes and benign units."""
    key_maps, ent, attack, units = truth
    if isinstance(scorer, RulePath):
        decided, counts = scorer.run(items)
        key_ent, key_cost = key_maps["rule"], key_maps["rule_cost"]
    else:
        events = replay_l7.replay(items, make_engine(scorer))
        decided = {}
        for e in events:
            if e.get("kind") == "l7_would_ban":
                decided.setdefault((e["ip"], e["ua_h"], e["sid_h"]), e["t_poll"])
        summary = [e for e in events if e.get("kind") == "l7_gru_poll"]
        counts = {"windows": sum(s.get("windows", 0) for s in summary),
                  "skipped": sum(s.get("skipped", 0) for s in summary)}
        key_ent, key_cost = key_maps["view"], {}          # D-031: one unit per view-level key
    caught, flagged = {}, {}
    for key, t in decided.items():
        e = key_ent.get(key)
        if e is None:
            continue
        if e in attack:
            caught[e] = min(caught.get(e, math.inf), t - ent[e]["first"])
        else:
            flagged[e] = flagged.get(e, 0) + key_cost.get(key, 1)
    fam, kinds = {}, {}
    for e in attack:
        f = str(ent[e]["family"])
        fam.setdefault(f, [0, 0])
        fam[f][0] += int(e in caught)
        fam[f][1] += 1
    for e, n in flagged.items():
        kinds[str(ent[e]["kind"])] = kinds.get(str(ent[e]["kind"]), 0) + min(n, units.get(e, 1))
    ttds = sorted(caught.values())
    return {"level": getattr(scorer, "level", "view"), "threshold": scorer.threshold, "consecutive": scorer.consecutive, "sha256": scorer.sha256,
            "caught": len(caught), "attack_entities": len(attack),
            "recall": round(len(caught) / len(attack), 4) if attack else None,
            "benign_units_flagged": sum(min(n, units.get(e, 1)) for e, n in flagged.items()),
            "benign_units": sum(units.values()), "benign_entities_flagged": len(flagged),
            "median_ttd_s": round(ttds[len(ttds) // 2], 3) if ttds else None,
            "by_family": {f: {"caught": c, "entities": n} for f, (c, n) in sorted(fam.items())},
            "benign_units_flagged_by_kind": dict(sorted(kinds.items())),
            "caught_entities": sorted(caught), "decisions": len(decided), **counts}


def replay(items, arms, labels):
    """Every arm of `arms` {name: scorer at its frozen point} through the recording `items`; arms without an
    operating point are given as None and reported so."""
    truth = ground_truth(items, labels)
    out = {"format": RESULT_FORMAT, "attack_entities": len(truth[2]), "benign_units": sum(truth[3].values()),
           "polls": sum(1 for it in items if it[0] == "poll"), "arms": {}}
    for name, scorer in arms.items():
        out["arms"][name] = {"note": "no operating point"} if scorer is None else score_arm(items, scorer, truth)
    return out


# ───────────────────────────── the frozen arms ─────────────────────────────

def load_rules(path, expected_sha256):
    """The frozen rule selection after its sha256 check and every package's, {arm: RuleScorer or None}, and R*."""
    if not expected_sha256 or V._sha_file(path) != expected_sha256:
        raise ReplayError(f"refusing to replay: {path} is not the recorded rule selection")
    with open(path, encoding="utf-8") as fh:
        sel = json.load(fh)
    if sel.get("format") != R.SELECTION_FORMAT:
        raise ReplayError(f"{path} is not a {R.SELECTION_FORMAT} file")
    base, arms = os.path.dirname(os.path.abspath(path)), {}
    for name, arm in sel["arms"].items():
        if "fixed" in arm:
            f = arm["fixed"]
            cfg = R.make_package(name, {"params": f["params"], "columns": f["columns"], "thresholds": f["thresholds"],
                                        "threshold": 0.5, "consecutive": 1}, {}, sel["calibration"])
            # the fixed replays read no cost column, so they carry no class costs
            arms[name] = R.RuleScorer(cfg)
            continue
        if arm.get("operating_point") is None:
            arms[name] = None
            continue
        p = os.path.join(base, arm["artifact"])
        if V._sha_file(p) != arm["artifact_sha256"]:
            raise ReplayError(f"refusing to replay: the package of {name} is altered")
        arms[name] = R.RuleScorer.load(p)
    return arms, sel.get("r_star")


def load_arms(selection_path, selection_sha256, rules_path=None, rules_sha256=None):
    """The scorers of every arm at its frozen operating point: the learned arms and the age-only baseline from the
    frozen selection (train_l7v2.load_selection checks every hash), the rule arms on their own path from the frozen
    rule selection; R* is also given under its own name 'R*'."""
    import l7_scorer as S
    sel = V.load_selection(selection_path, selection_sha256)
    base = os.path.dirname(os.path.abspath(selection_path))
    pre = MPRE.load()
    arms = {}
    gru = None
    for name, arm in sel["arms"].items():
        op = arm["operating_point"]
        if name == "request_gru":
            continue                                  # the offline seq-64 ablation: no engine runs it (build_engine)
        if op is None:
            arms[name] = None
            continue
        if name in ("view_gru", "gru_shuffled"):
            sc = S.L7Scorer.load(os.path.dirname(os.path.join(base, arm["artifact"])), level="view")
            sc.threshold, sc.consecutive = float(op["threshold"]), int(op["consecutive"])
            if name == "view_gru":
                gru = sc
                arms[name] = sc
            else:
                arms[name] = ShuffledScorer(sc, pre["models"]["gru_shuffled"]["shuffle_seed"])
        else:
            with open(os.path.join(base, arm["artifact"]), "rb") as fh:
                clf = pickle.load(fh)                  # our own artifact, hash-checked by load_selection
            sc = V.ArmScorer("view", F.TOKEN_COLUMNS, F.MAX_VIEWS, op["threshold"],
                             lambda X, _c=clf: V.tab_scores(_c, X))
            sc.consecutive = int(op["consecutive"])
            arms[name] = sc
    for name, b in sel.get("baselines", {}).items():
        op = b["operating_point"]
        if op is None:
            arms[name] = None
            continue
        with open(os.path.join(base, b["artifact"]), encoding="utf-8") as fh:
            ages = json.load(fh)["benign_train_ages"]
        arms[name] = AgeArm(ages, op["threshold"], op["consecutive"], b["artifact_sha256"])
    if gru is not None and "gru_shuffled" in arms and arms["gru_shuffled"] is not None:
        arms["gru_shuffled_pin_first"] = ShuffledScorer(gru, pre["models"]["gru_shuffled"]["shuffle_seed"], True)
    if rules_path:
        rules, r_star = load_rules(rules_path, rules_sha256)
        for name, sc in rules.items():
            arms[name] = None if sc is None else RulePath(sc)
        arms["R*"] = None if r_star is None or rules.get(r_star) is None else RulePath(rules[r_star])
    return arms

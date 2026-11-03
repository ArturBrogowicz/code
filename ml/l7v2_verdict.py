#!/usr/bin/env python3
"""The P1 verdict per class (docs/L7V2_DESIGN.md section 11; constants from ml/l7v2_verdict_prereg_v3.json, frozen first).

judge(cls, inputs) applies the ladder to one class's evaluation results and claims one verdict:
  * harm contrasts: Q in percent per block and arm, paired by block, judged by eval/run_level_stats (decide,
    t_interval, blocks_for_power) with the pre-registered effect sizes (beats >= 5 pp and supported; equivalent when the
    95 % interval lies strictly inside +-5 pp over >= 10 blocks);
  * detection contrasts: per-entity caught flags of each arm's replay of the same U runs, on the class's primary
    families (D-043: C3b@M2 for C3b; M1, M3 and M2exp get their own descriptive contrasts), with the two-stage cluster
    bootstrap over (block, entity), B 2000, percentile 95 % (beats >= 10 pp with the interval excluding 0; equivalent
    when it lies strictly inside +-10 pp);
  * the testing order (D-051): harm admission, budget, mitigation, then V-A's conditions jointly, an intersection-union test
    with no gate on the best learned arm; only when they do not hold, best learned vs R*, GRU vs HGB, GRU vs shuffled-GRU for
    V-B and V-C. Every GRU contrast of an admitted class is computed and reported, whatever the verdict;
  * the budget (D-051): its step counts the contenders R*, the HGB and the GRU only, and an arm over the budget cannot carry
    a verdict: V-B's carrier is the best learned arm, V-C's is R*, and the class is then inconclusive with the arm named;
  * a class admitted on latency alone gets V-D unless some live M's mean gain in Q reaches 5 pp (D-051): Q is the only harm
    outcome the ladder reads;
  * the rungs V-D, V-A, V-B, V-C, inconclusive, the first that holds; V-A is blocked (inconclusive, the block named) on
    an age-confounded validation set, a structureless benign model, and never given on a non-frozen record;
  * the settled choices (D-044): the best learned arm has the higher validation recall at the budget, frozen in the
    selection (ties: the GRU), for V-B and V-C only; the budget on evaluation is the live reading, with the replay's reported
    beside it; V-A's live baselines include U; when R* beats the best learned arm on harm the verdict is V-C.

Pure (numpy and eval/run_level_stats); it reads no capture. The inputs come from the P1 runner, after the selections
were frozen; judge() refuses without their sha256s and without a frozen calibration record.
"""
import math
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "eval"))
import l7v2_model_prereg as MPRE
import l7v2_verdict_prereg as PRE
import run_level_stats as RLS

GRU, HGB, SHUF, AGE, RSTAR, U = "view_gru", "hgb", "gru_shuffled", "age_only", "R*", "U"


class VerdictError(ValueError):
    """The inputs cannot be judged: a non-frozen record, unfrozen selections, or inconsistent data."""


# ───────────────────────────── contrasts ─────────────────────────────

def harm_contrast(qa, qb, pre=None):
    """Arm A minus arm B in pp of Q, paired by block: {mean, lo, hi, n, decision, outcome, power_blocks}. outcome is
    'beats', 'loses', 'equivalent' or 'not shown' (pre-registered effect sizes)."""
    pre = pre or PRE.load()
    eff, n_min = pre["effect_sizes"], pre["units"]["min_blocks"]
    d = np.asarray(qa, dtype=np.float64) - np.asarray(qb, dtype=np.float64)
    if not len(d):
        raise VerdictError("a harm contrast needs blocks")
    mean, lo, hi = RLS.t_interval(d)
    dec = RLS.decide(d, n_min)
    if dec == "supported (+)" and mean >= eff["harm_beats_pp"]:
        out = "beats"
    elif dec == "supported (-)" and mean <= -eff["harm_beats_pp"]:
        out = "loses"
    elif len(d) >= n_min and -eff["harm_equivalence_pp"] < lo and hi < eff["harm_equivalence_pp"]:
        out = "equivalent"
    else:
        out = "not shown"
    sd = float(d.std(ddof=1)) if len(d) > 1 else math.nan
    power = RLS.blocks_for_power(mean, sd) if out == "not shown" and math.isfinite(sd) else None
    return {"mean_pp": round(mean, 4), "lo": None if math.isnan(lo) else round(lo, 4),
            "hi": None if math.isnan(hi) else round(hi, 4), "n": len(d), "decision": dec, "outcome": out,
            "power_blocks": power}


def detection_contrast(blocks, caught_a, caught_b, pre=None):
    """Pooled entity recall of A minus B in pp over the same attack entities, with the two-stage cluster bootstrap of
    the pre-registration (blocks with replacement, then entities with replacement within each drawn block).
    `blocks` gives each entity's block; outcome as harm_contrast's at the detection effect sizes."""
    pre = pre or PRE.load()
    st, eff = pre["statistics"]["detection"], pre["effect_sizes"]
    blocks = np.asarray(blocks)
    a, b = np.asarray(caught_a, dtype=np.float64), np.asarray(caught_b, dtype=np.float64)
    if not (len(blocks) == len(a) == len(b)) or not len(a):
        raise VerdictError("a detection contrast needs the same attack entities for both arms")
    diff = 100.0 * (a.mean() - b.mean())
    ids = sorted(set(blocks.tolist()))
    members = [np.flatnonzero(blocks == x) for x in ids]
    rng = np.random.default_rng(st["seed"])
    boot = np.empty(st["B"])
    for i in range(st["B"]):
        idx = np.concatenate([m[rng.integers(0, len(m), len(m))] for m in
                              (members[j] for j in rng.integers(0, len(ids), len(ids)))])
        boot[i] = 100.0 * (a[idx].mean() - b[idx].mean())
    tail = 100.0 * (1.0 - st["level"]) / 2.0
    lo, hi = (float(x) for x in np.percentile(boot, [tail, 100.0 - tail]))
    if diff >= eff["detection_beats_pp"] and lo > 0:
        out = "beats"
    elif diff <= -eff["detection_beats_pp"] and hi < 0:
        out = "loses"
    elif -eff["detection_equivalence_pp"] < lo and hi < eff["detection_equivalence_pp"]:
        out = "equivalent"
    else:
        out = "not shown"
    return {"diff_pp": round(diff, 4), "lo": round(lo, 4), "hi": round(hi, 4), "entities": len(a),
            "blocks": len(ids), "outcome": out}


# ───────────────────────────── the ladder ─────────────────────────────

def _meets(entry):
    flagged, total = entry
    return flagged <= math.floor(MPRE.selection()["budget"] * total + 1e-9)


def _check(cls, inputs, pre):
    if inputs.get("record_status") != "frozen":
        raise VerdictError(f"the calibration record is {inputs.get('record_status')!r}: only a frozen record gives a "
                           "verdict (ml/l7v2_prereg.json harm.verdict_record)")
    frozen = inputs.get("frozen") or {}
    if not frozen.get("selection_sha256") or not frozen.get("rules_selection_sha256"):
        raise VerdictError("refusing to judge: the learned and rule selections must be frozen (their sha256s given)")
    live = pre["live_set"]["per_class"].get(cls)
    if live is None:
        raise VerdictError(f"no live set for class {cls!r}")
    harm = inputs.get("harm") or {}
    if inputs.get("admitted") and set(live) - set(harm):
        raise VerdictError(f"{cls}: harm per block is missing for {sorted(set(live) - set(harm))}")
    if inputs.get("admitted"):
        if inputs.get("admitted_on") not in ("Q", "latency"):
            raise VerdictError(f"{cls}: an admitted class must say what admitted it, 'Q' or 'latency' (D-051)")
        caught = (inputs.get("detection") or {}).get("caught") or {}
        missing = {GRU, HGB, SHUF, RSTAR} - set(caught)
        if missing:
            raise VerdictError(f"{cls}: every GRU contrast is reported, and the replay lacks {sorted(missing)}")
    if not all(isinstance(v, dict) for v in harm.values()):
        raise VerdictError(f"{cls}: harm is keyed by block, {{arm: {{block: Q}}}} (D-054, T048-12)")
    if len({frozenset(v) for v in harm.values()}) > 1:
        raise VerdictError(f"{cls}: every arm needs Q for the same blocks, got " + str({a: sorted(v) for a, v in sorted(harm.items())}))
    if inputs.get("detection") is not None:
        ent = pre["detection_entities"]["per_class"][cls]
        unknown = set(inputs["detection"]["families"]) - set(ent["primary"]) - set(ent["reported_separately"])
        if unknown:
            raise VerdictError(f"{cls}: attack entities of families no contrast of the class reads: {sorted(unknown)}")
    return live


def _subset(det, families):
    """The detection inputs restricted to the attack entities of `families`."""
    idx = [i for i, f in enumerate(det["families"]) if f in families]
    return {"blocks": [det["blocks"][i] for i in idx],
            "caught": {a: [v[i] for i in idx] for a, v in det["caught"].items()}}


def _best_learned(option, live, harm, val_recall):
    learned = [a for a in (GRU, HGB) if a in live]
    if len(learned) == 1 or option == "gru":
        return GRU
    if option == "eval_q":
        score = {a: float(np.mean(list(harm[a].values()))) for a in learned}
    else:
        if set(learned) - set(val_recall):
            raise VerdictError("the best learned arm needs the validation recall of every live learned arm")
        score = {a: float(val_recall[a]) for a in learned}
    return max(learned, key=lambda a: (score[a], a == GRU))


def _ladder(cls, live, inputs, opts, pre, memo):
    """The class's verdict under the settled choices `opts`: (verdict, the steps taken, notes)."""
    steps, notes = [], []
    if not inputs["admitted"]:
        steps.append(("harm_admission", "fails"))
        return "V-D", steps, ["U fails harm admission"]
    steps.append(("harm_admission", "passes"))
    harm, budget = inputs["harm"], inputs["budget"][opts["OC-2"]]
    enforcing = [a for a in live if a != U]
    meets = {a: _meets(budget[a]) for a in enforcing}

    def harm_c(a, b):
        if (a, b) not in memo:
            blocks = sorted(harm[a])
            memo[(a, b)] = harm_contrast([harm[a][x] for x in blocks], [harm[b][x] for x in blocks], pre)
        return memo[(a, b)]

    def det_c(a, b):
        key = ("det", a, b)
        if key not in memo:
            det = _subset(inputs["detection"], pre["detection_entities"]["per_class"][cls]["primary"])
            memo[key] = detection_contrast(det["blocks"], det["caught"][a], det["caught"][b], pre)
        return memo[key]

    # Every GRU contrast of an admitted class, whatever the verdict (D-051).
    gru_harm = {a: harm_c(GRU, a) for a in live if a != GRU}
    gru_det = {a: det_c(GRU, a) for a in (HGB, SHUF, RSTAR)}

    contenders = [a for a in enforcing if a in pre["arms"]["contenders"]]
    if not any(meets[a] for a in contenders):
        steps.append(("budget", "fails"))
        return "V-D", steps, ["no contender (R*, HGB, GRU) meets the budget on the evaluation seeds"]
    steps.append(("budget", "passes"))

    gains = {m: harm_c(m, U) for m in enforcing}
    if not any(c["decision"] == "supported (+)" for c in gains.values()):
        steps.append(("mitigation", "fails"))
        return "V-D", steps, ["no arm mitigates: Q(M) - Q(U) is not supported for any live M"]
    least = pre["latency_alone"]["min_mean_gain_pp"]
    if inputs["admitted_on"] == "latency" and not any(c["mean_pp"] >= least for c in gains.values()):
        steps.append(("mitigation", "fails"))
        return "V-D", steps, [f"admitted on latency alone, and no live M's mean gain in Q reaches {least:g} pp"]
    steps.append(("mitigation", "passes"))

    # V-A first: an intersection-union test of all its conditions, with no gate on the best learned arm (R-3).
    baselines = [a for a in live if a != GRU and (opts["OC-3"] == "with_u" or a != U)]
    unmet = []
    if not meets[GRU]:
        unmet.append("the GRU misses the budget")
    if not all(gru_harm[a]["outcome"] == "beats" for a in baselines):
        unmet.append("the GRU does not beat every live baseline")
    if gru_det[HGB]["outcome"] != "beats":
        unmet.append(f"GRU vs HGB on detection: {gru_det[HGB]['outcome']}")
    if gru_det[SHUF]["outcome"] != "beats":
        unmet.append(f"GRU vs shuffled-GRU on detection: {gru_det[SHUF]['outcome']}")
    if not unmet:
        steps.append(("v_a", "holds"))
        blocks = v_a_blocks(inputs, pre)
        if blocks:
            return "inconclusive", steps, [f"V-A blocked: {b}" for b in blocks]
        return "V-A", steps, notes
    steps.append(("v_a", "; ".join(unmet)))

    # V-B and V-C: the best learned arm (OC-1), and each verdict's carrier within the budget (D-051).
    best = _best_learned(opts["OC-1"], live, harm, inputs.get("validation_recall") or {})

    def v_b():
        if not meets[best]:
            return "inconclusive", steps, [f"V-B not claimed: {best} is over the budget"]
        return "V-B", steps, notes

    s3 = harm_c(best, RSTAR)["outcome"]
    steps.append(("best_learned_vs_rstar", f"{best}: {s3}"))
    if s3 in ("equivalent", "loses"):
        if s3 == "loses":
            notes.append("R* beats the best learned arm on harm (OC-4)")
            if opts["OC-4"] != "v_c":
                return "inconclusive", steps, notes
        if not meets[RSTAR]:
            return "inconclusive", steps, [*notes, "V-C not claimed: R* is over the budget"]
        return "V-C", steps, notes
    if s3 != "beats":
        return "inconclusive", steps, ["best learned vs R* not shown"]
    s4 = gru_det[HGB]["outcome"]
    steps.append(("gru_vs_hgb", s4))
    if s4 in ("equivalent", "loses"):
        return v_b()
    if s4 != "beats":
        return "inconclusive", steps, ["GRU vs HGB on detection not shown"]
    s5 = gru_det[SHUF]["outcome"]
    steps.append(("gru_vs_shuffled", s5))
    if s5 in ("equivalent", "loses"):
        return v_b()
    if s5 != "beats":
        return "inconclusive", steps, ["GRU vs shuffled-GRU on detection not shown"]
    return "inconclusive", steps, [f"V-A not met: {'; '.join(unmet)}"]


def v_a_blocks(inputs, pre=None):
    """The pre-registered blocks on V-A that apply (blocks_on_v_a)."""
    pre = pre or PRE.load()
    out = []
    auc = inputs.get("age_only_val_auc")
    band = pre["blocks_on_v_a"]["age_only"]["band"]
    if auc is None or abs(auc - 0.5) > band + 1e-12:
        out.append(f"age-confounded (age-only validation AUC {auc}, band 0.5 +- {band})")
    if not inputs.get("structured_benign_model"):
        out.append("against a structureless benign model")
    return out


def judge(cls, inputs, pre=None):
    """The class's verdict (see the module doc). `inputs`:
      record_status        the calibration record's status ('frozen' or refused)
      frozen               {"selection_sha256", "rules_selection_sha256"} of the frozen selections
      admitted             the harm admission of U_k (the harm gate's result, with its placebo)
      admitted_on          what admitted it when admitted: 'Q' if the Q criterion passed, 'latency' on the p95 criterion alone
      harm                 {arm: {block: Q in percent}} for every live arm of the class (U, R*, ...); different key sets are refused
      budget               {"live": {arm: (benign users wrongly acted on, benign users)} pooled over the arm's own M runs,
                           "replay": the same from the replays of the U runs, reported beside it} for every enforcing arm
      detection            {"blocks": [block of each attack entity], "families": [its family],
                           "caught": {arm: [0/1 per entity]}} for the GRU, the HGB, the shuffled-GRU, R* and, when
                           given, the age-only arm (replays of the U runs)
      validation_recall    {arm: recall} of the live learned arms at their frozen points (OC-1)
      age_only_val_auc     the age-only baseline's validation AUC
      structured_benign_model  True when the trained benign navigation is the TPC-W model"""
    pre = pre or PRE.load()
    live = _check(cls, inputs, pre)
    opts = PRE.resolutions(pre)
    memo = {}
    verdict, steps, notes = _ladder(cls, live, inputs, opts, pre, memo)
    out = {"class": cls, "verdict": verdict, "resolutions": opts, "steps": steps, "notes": notes, "contrasts": {},
           "v_a_blocks": v_a_blocks(inputs, pre)}
    for key, c in memo.items():
        name = f"detection {key[1]} vs {key[2]}" if key[0] == "det" else f"harm {key[0]} vs {key[1]}"
        out["contrasts"][name] = c
    budget = inputs.get("budget") or {}
    out["budget"] = {reading: {a: {"flagged": v[0], "users": v[1], "meets": _meets(v)} for a, v in entries.items()}
                     for reading, entries in budget.items()}
    det, ent = inputs.get("detection"), pre["detection_entities"]["per_class"][cls]
    if det is None:
        return out
    primary = _subset(det, ent["primary"])
    if AGE in det["caught"] and GRU in det["caught"] and primary["blocks"]:
        out["contrasts"]["detection view_gru vs age_only (descriptive)"] = detection_contrast(
            primary["blocks"], primary["caught"][GRU], primary["caught"][AGE], pre)
    out["reported_separately"] = {}
    for fam in ent["reported_separately"]:
        sub = _subset(det, [fam])
        if not sub["blocks"]:
            continue
        out["reported_separately"][fam] = {
            "entities": len(sub["blocks"]),
            **{f"detection view_gru vs {other}": detection_contrast(sub["blocks"], sub["caught"][GRU],
                                                                    sub["caught"][other], pre)
               for other in (HGB, SHUF, RSTAR) if other in sub["caught"]}}
    return out

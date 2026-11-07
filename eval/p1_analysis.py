#!/usr/bin/env python3
"""The P1 analysis (docs/L7V2_DESIGN.md 5.3, 10, 11): a finished campaign of eval/p1_runner.py through to one verdict per class.

Offline: it reads the runs' directories, ROOT/index.jsonl and the frozen selections; it starts nothing, and nothing that judges
moves here. For each class:
  * harm admission through eval/l7v2_harm.py (assess_block, admission), over every attempt, the last of each block counting; a
    campaign the admission finds INVALID (too few valid blocks, too many re-runs) gets no verdict, with its reasons, which is
    not the same as V-D "no harm";
  * the blocks it judges: the final attempts whose class is valid and whose live M runs are sound; the others are listed, and fewer than
    10 give no verdict, 'invalid (k of 10)' with their reasons (D-058, T050-05), which is not V-D either;
  * harm per block: Q of every live arm in the level window, from the attack's start + 90 s to its end (D-053, eval/l7v2_harm.py's
    figures); the whole attack window's Q is secondary, and admission reads that window, as registered;
  * the budget: live (D-044 OC-2), the benign users wrongly acted on in the arm's own M runs (eval/p1_records.acted_on), pooled over all
    attempts of all blocks, superseded and excluded ones too (D-058); and, reported beside it, the replay's benign units on the judged U runs;
  * detection per entity: each U run's recording through every arm (ml/l7v2_replay.py), the caught flags of the GRU, the HGB, the
    shuffled-GRU, R* and the age-only arm over the class's attack entities, with their block and family; l7v2_verdict reads the
    primary families (D-043) and reports the others;
  * the validation recall of the learned arms and the age-only AUC, from the frozen selection;
and then ml/l7v2_verdict.judge, with the minimum cut's live set when the campaign ran it. A record that is not frozen gets no
verdict (a dry run stops before judging, and says so).

Beside the judge, nothing reading it: each class's reported, the whole-window Q, time to decision and attack cost left (D-053,
ml/p1_prereg_2.json reported_per_class); and (D-049, ml/p1_prereg.json age_check) each class's age_only_on_U, the window-age AUC of its U
replays, per block and per family, and the age-only arm's recall at its frozen point, with each U run's recorded age check; and
view_level_contrasts, every contrast of the judge's output naming a view-level arm with that reading beside it.

ladder_knees() reads a finished ladder (phase ladder) into the knees a campaign needs: per class the lowest level whose harm
reaches the floor in both repeats (bench/calibration.knee, harm as bench/calibrate.harm against the session's control), each repeat by its
last sound attempt. --ladder writes the file a campaign takes (--knees).

health_result() reads the halving rule's steps (phase health, ml/p1_prereg.json) into the next step, the frozen factor or a refusal,
in the file that the ladder and the campaign take (--health). Its exit code is 1 on a refusal, and on a stop: a control unhealthy with a
server-side Q of at least 99 % waits for a dated decision (--health-decision, D-058).

point_check() replays the pilot's benign traffic through each arm at its frozen point, before the campaign (ml/p1_prereg_2.json
point_check, D-052), into the file the campaign takes (--points): one valid control per pilot seed at the frozen factor. An arm that may
stop the campaign and is over the budget there is named, the exit code is then 1, and nothing is re-tuned.

    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --selection SEL/selection.json --selection-sha256 H \\
        --rules RULES/rules_selection.json --rules-sha256 H --out p1_verdicts.json
    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --ladder --out knees.json
    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --health --out health.json
    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --points --selection SEL/selection.json --selection-sha256 H \\
        --rules RULES/rules_selection.json --rules-sha256 H --out points.json
"""
import argparse
import copy
import json
import os
import re
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), HERE, os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import calibration as CAL
import l7v2_harm as LH
import l7v2_replay as RP
import l7v2_verdict as J
import l7v2_verdict_prereg as VP
import p1_records as REC
import p1_runner as RUN
import p1_traffic as PT
import p4_runner as P4
import train_l7v2 as V

import l7_dataset as D

GRU, HGB, SHUF, AGE, RSTAR = J.GRU, J.HGB, J.SHUF, J.AGE, J.RSTAR
VIEW_ARMS = {GRU, HGB, SHUF}
DETECTION_ARMS = (GRU, HGB, SHUF, RSTAR, AGE)
STRUCTURED_KIND = "tpcw_browsing"      # design 12.1: the trained benign navigation is TPC-W's multi-step chain
LADDER_LABEL = re.compile(r"(?P<cls>[^_]+)_L(?P<level>[0-9.]+)_r(?P<repeat>\d+)$")


def live_set(pre, cut):
    """The pre-registration with the minimum cut's live set when the campaign ran it."""
    if not cut:
        return pre
    out = copy.deepcopy(pre)
    out["live_set"]["per_class"] = out["live_set"]["minimum_cut"]["per_class"]
    return out


def assess_attempts(root, cal, classes):
    """Every attempt of the campaign through eval/l7v2_harm.assess_block. A block with a run that never started is assessed as
    invalid for every class, with the harm module's own reason."""
    seen, out = set(), []
    for x in REC.index_lines(root):
        if x["phase"] != "campaign" or x["block_dir"] in seen:
            continue
        seen.add(x["block_dir"])
        path = os.path.join(root, x["block_dir"])
        try:
            out.append(LH.assess_block(path, cal))
        except LH.HarmError as exc:
            meta = REC.read_json(os.path.join(path, "block.json"))
            out.append({"dir": x["block_dir"], "block": meta["block"], "attempt": meta["attempt"], "seed": meta["seed"],
                        "calibration_sha256": meta["calibration_sha256"], "runs": {},
                        "classes": {k: {"valid": False, "reasons": [str(exc)]} for k in classes}})
    return out


def final_attempts(blocks):
    """The last attempt of each block, as the harm gate's re-run rule counts."""
    final = {}
    for b in sorted(blocks, key=lambda b: (b["block"], b["attempt"])):
        final[b["block"]] = b
    return [final[k] for k in sorted(final)]


def judged_blocks(final, cls, live):
    """([blocks the class's contrasts read], {block: why not}): the class valid in it, every live run sound with a Q."""
    names = [RUN.run_name(a, cls) for a in live]
    good, excluded = [], {}
    for b in final:
        c = b["classes"].get(cls)
        why = [] if c and c["valid"] else list((c or {}).get("reasons") or ["the class has no run"])
        for n in names:
            run = b["runs"].get(n)
            if run is None or run["metrics"]["Q"] is None:
                why.append(f"{n}: no figures")
            elif not run["checks"].get("ok"):
                why += [f"{n}: {r}" for r in run["checks"].get("reasons", ["not sound"])]
        if why:
            excluded[b["block"]] = why
        else:
            good.append(b)
    return good, excluded


def replay_block(root, block, cls, arms_factory, cal):
    """One U run through every arm: (the replay's result, with each arm's attack cost left, {attack entity: family}, its manifest), on
    its recording and the manifest's labels."""
    run_dir = os.path.join(root, "campaign", block["dir"], f"U_{cls}")
    man = REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
    items, labels = REC.recording(run_dir), RP.RunLabels(man)
    _keys, ent, attack, _units = RP.ground_truth(items, labels)
    res = RP.replay(items, arms_factory(run_dir, man), labels)
    rule = PT.prereg_2()["reported_per_class"]["attack_cost_left"]
    requests = RP.attack_requests(items, labels)
    first = {e: ent[e]["first"] for e in attack}
    for arm in res["arms"].values():
        arm["attack_cost"] = RP.cost_left(requests, first, arm.get("ttd_s") or {}, cal["route_costs_ms"], rule["key_age_gate_s"], rule["reload_s"])
    return res, {e: ent[e]["family"] for e in attack}, man


def default_factory(frozen):
    """The frozen arms, afresh for each U run: a scorer's tracked sessions are one run's."""
    def build(_run_dir, _man):
        return RP.load_arms(frozen["selection"], frozen["selection_sha256"], frozen["rules"], frozen["rules_sha256"])
    return build


def selection_inputs(frozen):
    """From the frozen selection: the learned arms' validation recall at their points (0 without a point), the age-only AUC."""
    sel = REC.read_json(frozen["selection"])
    recall = {}
    for a in (GRU, HGB):
        op = (sel["arms"].get(a) or {}).get("operating_point")
        recall[a] = float(op["recall"]) if op and op.get("recall") is not None else 0.0
    return recall, (sel.get("baselines", {}).get(AGE) or {}).get("val_auc")


def admitted_on(adm):
    """What admitted a class: 'Q' if the Q criterion passed, else 'latency', the p95 criterion alone (D-051)."""
    return "Q" if adm["criteria"]["Q"]["passed"] else "latency"


def level_q(root, block, run, cal):
    """A run's Q in the level window (D-053), which the verdict's harm contrasts read."""
    timeline = REC.read_json(os.path.join(root, "campaign", block["dir"], "block.json"))["timeline"]
    return LH.window_figures(os.path.join(root, "campaign", block["dir"], run), cal, timeline, PT.level_window(timeline))["Q"]


def window_q(root, block, run, cal, window_of):
    """A run's Q in another window of its timeline (`window_of(timeline)`), by the figures of the level window."""
    timeline = REC.read_json(os.path.join(root, "campaign", block["dir"], "block.json"))["timeline"]
    return LH.window_figures(os.path.join(root, "campaign", block["dir"], run), cal, timeline, window_of(timeline))["Q"]


def arm_runs(root, arm, cls):
    """Every run of `arm` in the class over all attempts of the campaign, superseded and excluded ones too: the dirs that hold a manifest."""
    name = RUN.run_name(arm, cls)
    seen = []
    for x in REC.index_lines(root):
        if x["phase"] == "campaign" and x["run"] == name and x["dir"] not in seen:
            seen.append(x["dir"])
    return [os.path.join(root, d) for d in seen if os.path.isfile(os.path.join(root, d, D.MANIFEST_FILE))]


def live_budget(root, arm, cls):
    """(benign users wrongly acted on, benign users) of an arm in a class, pooled over all attempts (D-058, ml/p1_prereg_4.json over_all_attempts): an
    arm's worst run does not vanish from the budget by being invalid. A run that never started has acted on nobody."""
    flagged = users = 0
    for run_dir in arm_runs(root, arm, cls):
        man = REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
        if D.time_origin(man) is None:
            continue
        rec = REC.acted_on(man, P4._events(os.path.join(run_dir, "ban_events.jsonl")), REC.read_json(os.path.join(run_dir, "run.json")).get("budget"))
        flagged += rec["benign_users"]
        users += rec["benign_users_total"]
    return flagged, users


def bans_over_attempts(root, arm, cls):
    """An arm's bans by engine in a class, over all attempts (D-058): {engine: count}."""
    out = {}
    for run_dir in arm_runs(root, arm, cls):
        for engine, n in (REC.read_json(os.path.join(run_dir, "run.json")).get("bans_by_engine") or {}).items():
            out[engine] = out.get(engine, 0) + n
    return out


def class_report(root, cal, cls, blocks, live, per_arm):
    """What is reported per class beside the verdict, and judges nothing (D-053, ml/p1_prereg_2.json reported_per_class; T050-11, T050-15,
    ml/p1_prereg_3.json reported): the whole attack window's Q; the server-side Q; the late window's Q; each run's largest view slip; time to
    decision per arm and family; the attack cost left, by the replay's worst case and, for an arm with M runs, measured."""
    ttd = {}
    for name, per in per_arm.items():
        ttd[name] = {fam: {"caught": len(v), "mean_s": round(float(np.mean(v)), 3), "median_s": round(float(np.median(v)), 3)}
                     for fam, v in sorted(per["ttd_s"].items())}
    replay = {name: (round(per["attack_cost"][0] / per["attack_cost"][1], 4) if per["attack_cost"][1] else None)
              for name, per in per_arm.items()}
    live_cost = {a: 0.0 for a in live}
    for b in blocks:
        timeline = REC.read_json(os.path.join(root, "campaign", b["dir"], "block.json"))["timeline"]
        lo = float(timeline["baseline_s"])
        for a in live:
            run_dir = os.path.join(root, "campaign", b["dir"], RUN.run_name(a, cls))
            log, man = REC.access_log(run_dir), REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
            if log:
                live_cost[a] += REC.attacker_cost_ms(log, man, (lo, lo + float(timeline["attack_s"])), cal["route_costs_ms"])
    measured = {a: (round(live_cost[a] / live_cost["U"], 4) if live_cost["U"] else None) for a in live if a != "U"}
    def per_block(read):
        return {a: {b["block"]: read(b, RUN.run_name(a, cls)) for b in blocks} for a in live}

    return {"note": "descriptive (D-053): the verdict does not read it. A share of 1 means that the arm removed none of the attack's cost",
            "whole_window_q": per_block(lambda b, run: b["runs"][run]["metrics"]["Q"]),
            "server_q": per_block(lambda b, run: (b["runs"][run]["server"] or {}).get("Q")),
            "late_window_q": per_block(lambda b, run: window_q(root, b, run, cal, PT.late_window)),
            "largest_view_slip_s": per_block(lambda b, run: (b["runs"][run]["metrics"].get("view_slip") or {}).get("largest_s")),
            "bans_over_attempts": {a: bans_over_attempts(root, a, cls) for a in live if a != "U"},
            "time_to_decision": ttd, "attack_cost_left": {"replay": replay, "live": measured}}


def class_inputs(root, cal, cls, blocks, live, frozen, arms_factory, on="Q"):
    """l7v2_verdict.judge's inputs for a class over its judged blocks (see the module doc), and the replay's summary."""
    enforcing = [a for a in live if a != "U"]
    harm = {a: {b["block"]: level_q(root, b, RUN.run_name(a, cls), cal) for b in blocks} for a in live}
    budget = {"live": {a: [0, 0] for a in enforcing}, "replay": {a: [0, 0] for a in enforcing}}
    det = {"blocks": [], "families": [], "caught": {a: [] for a in DETECTION_ARMS}}
    per_arm, structured = {}, bool(blocks)
    for a in enforcing:
        budget["live"][a] = list(live_budget(root, a, cls))
    for b in blocks:
        res, families, man = replay_block(root, b, cls, arms_factory, cal)
        structured = structured and any(e["kind_or_family"] == STRUCTURED_KIND for e in man["entities"])
        for a in enforcing:
            arm = res["arms"].get(a) or {}
            budget["replay"][a][0] += arm.get("benign_units_flagged", 0)
            budget["replay"][a][1] += res["benign_units"]
        for name, arm in res["arms"].items():
            per = per_arm.setdefault(name, {"caught": 0, "attack_entities": 0, "benign_units_flagged": 0, "by_family": {},
                                            "ttd_s": {}, "attack_cost": [0.0, 0.0]})
            for e, t in (arm.get("ttd_s") or {}).items():
                per["ttd_s"].setdefault(str(families.get(e)), []).append(t)
            for i, x in enumerate(arm.get("attack_cost") or (0.0, 0.0)):
                per["attack_cost"][i] += x
            per["caught"] += arm.get("caught", 0)
            per["attack_entities"] += res["attack_entities"]
            per["benign_units_flagged"] += arm.get("benign_units_flagged", 0)
            for fam, v in (arm.get("by_family") or {}).items():
                row = per["by_family"].setdefault(fam, {"caught": 0, "entities": 0})
                row["caught"] += v["caught"]
                row["entities"] += v["entities"]
        for ent in sorted(families):
            det["blocks"].append(b["block"])
            det["families"].append(families[ent])
            for a in DETECTION_ARMS:
                det["caught"][a].append(int(ent in ((res["arms"].get(a) or {}).get("caught_entities") or ())))
    recall, auc = selection_inputs(frozen)
    inputs = {"record_status": cal.get("status"),
              "frozen": {"selection_sha256": frozen["selection_sha256"], "rules_selection_sha256": frozen["rules_sha256"]},
              "admitted": True, "admitted_on": on, "harm": harm, "budget": {k: {a: tuple(v) for a, v in d.items()} for k, d in budget.items()},
              "detection": det, "validation_recall": recall, "age_only_val_auc": auc,
              "structured_benign_model": structured}
    return inputs, per_arm


def age_only_on_u(root, blocks, cls, per_arm):
    """The age-only reading on a class's U replays (D-049): descriptive, and nothing judges it. The window-age AUC pooled, per family
    and per block; the age-only arm's recall from the replay; each U run's recorded arrivals.age_check, which is not applied."""
    pooled, per_block = [], []
    for b in blocks:
        run_dir = os.path.join(root, "campaign", b["dir"], f"U_{cls}")
        man = REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
        windows = RP.age_windows(REC.recording(run_dir), RP.RunLabels(man))
        pooled += windows
        got = RP.age_auc(windows)
        report = (REC.read_json(os.path.join(run_dir, "run.json")).get("age_check") or {}).get("report") or {}
        per_block.append({"block": b["block"], "auc": got["auc"], "reading": got["reading"], "age_check_pass": report.get("pass")})
    got = RP.age_auc(pooled)
    arm = per_arm.get(AGE) or {}
    families = {}
    for fam, auc in got["auc_by_family"].items():
        hit = (arm.get("by_family") or {}).get(fam) or {"caught": None, "entities": None}
        families[fam] = {"auc": auc, "reading": V.age_reading(auc), **hit}
    return {"note": "descriptive (D-049): the verdict does not read it; AUC > 0.5 means that the attack's windows are younger",
            "auc": got["auc"], "reading": got["reading"], "windows_benign": got["windows_benign"],
            "windows_attack": got["windows_attack"], "caught": arm.get("caught"), "attack_entities": arm.get("attack_entities"),
            "benign_units_flagged": arm.get("benign_units_flagged"), "by_family": families, "per_block": per_block}


def view_level_contrasts(judged, reading, primary):
    """Every contrast of the judge's output that names a view-level arm, with the age-only reading on the U replays beside it: the
    primary families' for the verdict's contrasts, the family's for one reported separately. The judge's output stays as it is."""
    fams = reading["by_family"]
    out = {}
    for name, c in judged.get("contrasts", {}).items():
        if VIEW_ARMS & set(name.split()):
            out[name] = {"contrast": c, "age_only_on_U": {f: fams.get(f) for f in primary}}
    for fam, sub in (judged.get("reported_separately") or {}).items():
        for name, c in sub.items():
            if VIEW_ARMS & set(name.split()):
                out[f"{fam}: {name}"] = {"contrast": c, "age_only_on_U": {fam: fams.get(fam)}}
    return out


class SettingsError(ValueError):
    """The campaign's blocks did not run one setting, or the analysis was not given what they ran (T050-12)."""


def check_campaign(root, cal, frozen, cut=False):
    """One setting across the blocks, and the record, the selections and the live set the analysis judges with are the ones they ran under
    (T050-12, ml/p1_prereg_3.json one_setting): an arm replayed at X beside M runs made under Y is not a contrast. `cut` decides which
    baselines V-A has to beat, so a full campaign read with --cut would drop default_rules in the GRU's favour (T057-02)."""
    settings = {}
    for x in REC.index_lines(root):
        if x["phase"] == "campaign" and x["block_dir"] not in settings:
            settings[x["block_dir"]] = REC.read_json(os.path.join(root, x["block_dir"], "block.json")).get("settings") or {}
    names = sorted(settings)
    unsaid = [name for name in names if "cut" not in settings[name]]
    if unsaid:
        raise SettingsError(f"{', '.join(unsaid)} do not record whether they ran the cut, so --cut cannot be checked against them")
    for name in names[1:]:
        differ = sorted(k for k in set(settings[name]) | set(settings[names[0]]) if settings[name].get(k) != settings[names[0]].get(k))
        if differ:
            raise SettingsError(f"{', '.join(differ)} differ between {names[0]} and {name}")
    if names:
        ran = settings[names[0]]
        given = {"record_digest": cal.get("sha256"), "selection_sha256": frozen.get("selection_sha256"), "rules_sha256": frozen.get("rules_sha256")}
        differ = sorted(k for k, v in given.items() if ran.get(k) != v)
        if differ:
            raise SettingsError(f"the analysis was given another {', '.join(differ)} than the campaign ran")
        if ran["cut"] != bool(cut):
            ran_what, asked = ("the cut", "the full live set") if ran["cut"] else ("the full live set", "the cut (--cut)")
            raise SettingsError(f"the campaign ran {ran_what}, and the analysis was asked to read {asked}")


def analyse(root, cal, frozen, *, arms_factory=None, cut=False, dry_run=False, pre=None):
    """Every class's admission, inputs and verdict: {class: {"verdict", "admission", "judge", "excluded", "replay"}}. Blocks that did not run
    one setting, or a record or selection other than theirs, are refused (SettingsError)."""
    check_campaign(root, cal, frozen, cut)
    pre = live_set(pre or VP.load(), cut)
    arms_factory = arms_factory or default_factory(frozen)
    classes = sorted(pre["live_set"]["per_class"])
    attempts = assess_attempts(root, cal, classes)
    final = final_attempts(attempts)
    out = {}
    for cls in classes:
        adm = LH.admission(attempts, cal, cls, dry_run)
        row = {"class": cls, "admission": adm, "blocks_final": len(final), "verdict": None}
        out[cls] = row
        if adm["verdict"] == "INVALID":
            row["why_no_verdict"] = adm["reasons"]
            continue
        live = pre["live_set"]["per_class"][cls]
        if not adm["admitted"]:
            inputs = {"record_status": cal.get("status"), "admitted": False, "harm": {},
                      "frozen": {"selection_sha256": frozen["selection_sha256"], "rules_selection_sha256": frozen["rules_sha256"]}}
            row["judge"] = J.judge(cls, inputs, pre)
            row["verdict"] = row["judge"]["verdict"]
            continue
        blocks, excluded = judged_blocks(final, cls, live)
        row["excluded"] = excluded
        row["blocks_judged"] = [b["block"] for b in blocks]
        least = pre["units"]["min_blocks"]
        if len(blocks) < least:                # D-058, T050-05: too few blocks are no verdict, and never V-D "no arm mitigates"
            row["status"] = f"invalid ({len(blocks)} of {least})"
            row["why_no_verdict"] = [f"{len(blocks)} judged blocks, fewer than {least}"] + [f"block {b}: {r}" for b, why in sorted(excluded.items()) for r in why]
            continue
        inputs, per_arm = class_inputs(root, cal, cls, blocks, live, frozen, arms_factory, admitted_on(adm))
        row["replay"] = per_arm
        row["age_only_on_U"] = age_only_on_u(root, blocks, cls, per_arm)
        row["reported"] = class_report(root, cal, cls, blocks, live, per_arm)
        if dry_run:
            row["why_no_verdict"] = [f"a dry run on a {cal.get('status')} record gives no verdict"]
            continue
        row["judge"] = J.judge(cls, inputs, pre)
        row["verdict"] = row["judge"]["verdict"]
        row["view_level_contrasts"] = view_level_contrasts(row["judge"], row["age_only_on_U"],
                                                           pre["detection_entities"]["per_class"][cls]["primary"])
    return out


# --- the ladder --------------------------------------------------------------------------------------

def ladder_harm(root, cal):
    """A finished ladder's harm, as bench/calibrate.harm against the attempt's own control: ({class: {level: [harm per repeat]}}, the repeats
    with no sound attempt). Per (class, level, repeat) the last attempt with both runs sound counts (T050-13, ml/p1_prereg_3.json ladder):
    a clean re-run restores a level, and one with no sound attempt counts as no harm: never as passing. Those are named as well, so that
    the rule's zero is not read as a measured one (T063-01). A level the plan refused has no attempt and no row: it is 'not reachable'
    (ladder_status, D-074), never no harm."""
    import calibrate as K
    gate = cal["gate"]
    attempts = {}
    for x in REC.index_lines(root):
        m = LADDER_LABEL.match(x["label"] or "") if x["phase"] == "ladder" else None
        if m is not None and x["run"] != "C":
            key = (m.group("cls"), float(m.group("level")), int(m.group("repeat")))
            attempts.setdefault(key, []).append((x["attempt"], x["block_dir"], x["run"]))
    rows, unsound = {}, []
    for (cls, level, repeat), tries in sorted(attempts.items()):
        harm, sound = 0.0, False
        for _attempt, block_dir, run in sorted(tries, reverse=True):
            try:
                b = LH.assess_block(os.path.join(root, block_dir), cal)
            except LH.HarmError:
                continue
            control, attack = b["runs"].get("C"), b["runs"].get(run)
            if control and attack and control["checks"].get("ok") and attack["checks"].get("ok"):
                h, _parts = K.harm([control["metrics"]], attack["metrics"], gate["floor_pp"], gate["floor_log2_p95"])
                harm, sound = h or 0.0, True
                break
        if not sound:
            unsound.append({"class": cls, "level": int(level) if cls == "C3b" else level, "repeat": repeat, "attempts": len(tries)})
        rows.setdefault(cls, {}).setdefault(level, []).append(harm)
    return rows, unsound


def ladder_knees(root, cal, harm=None):
    """The knees of a finished ladder: {class: bench/calibration.knee's result} over ladder_harm's rows, or over the `harm` it gave."""
    rows, _unsound = harm or ladder_harm(root, cal)
    return {cls: CAL.knee(sorted(levels.items()), 1.0, 2) for cls, levels in sorted(rows.items())}


def ladder_status(root, harm, knees):
    """D-074 (ml/p1_prereg_5.json ladder.statuses and no_knee), per class: each registered level's status, 'run' (with its repeats that
    had no sound attempt), 'not reachable' (with the plan's reason, from the runner's ladder_unreachable.jsonl) or 'not run'; the top tested
    level, the highest whose repeats all had a sound attempt; and the class's line: its knee, or 'no harm reached up to X on this testbed'.
    'Not reachable' never reads as no harm."""
    rows, unsound = harm
    refused = {}
    for x in RUN.read_unreachable(root):
        refused.setdefault((x["class"], float(x["level"])), x["reason"])
    repeats = PT.ladder_repeats()
    out = {}
    for cls in sorted(PT.PRIMARY):
        knee = knees.get(cls) or {}
        passing = {float(x) for x in knee.get("passing") or []}
        levels, tested = {}, []
        for lv in PT.ladder_levels(cls):
            key = float(lv)
            holes = sorted(u["repeat"] for u in unsound if u["class"] == cls and float(u["level"]) == key)
            ran = rows.get(cls, {}).get(key)
            if ran is not None:
                st = {"status": "run", "repeats": len(ran), "no_sound_attempt": holes, "passed": key in passing}
                if len(ran) >= repeats and not holes:
                    tested.append(lv)
            elif (cls, key) in refused:
                st = {"status": "not reachable", "reason": refused[(cls, key)]}
            else:
                st = {"status": "not run"}
            if knee.get("level") is not None and key > knee["level"]:
                st["above_knee"] = True
            levels[f"{lv:g}"] = st
        top = max(tested) if tested else None
        out[cls] = {"levels": levels, "top_tested": top, "result": _ladder_line(cls, knee.get("level"), top, levels)}
    return out


def _ladder_line(cls, knee, top, levels):
    """A class's line in the ladder's report (D-074)."""
    if knee is not None:
        return f"{cls}: knee at {knee:g}"
    gone = [f"{lv} ({st['reason']})" for lv, st in levels.items() if st["status"] == "not reachable"]
    holes = [f"{lv} r{r}" for lv, st in levels.items() if st["status"] == "run" for r in st["no_sound_attempt"]]
    if not any(st["status"] == "run" for st in levels.values()):
        line = f"{cls}: not tested"
    elif top is None:
        line = f"{cls}: no level ran with every repeat sound"
    else:
        line = f"{cls}: no harm reached up to {top:g} on this testbed"
    if holes:
        line += f"; no sound attempt, counted as no harm: {', '.join(holes)}"
    if gone:
        line += f"; not reachable: {'; '.join(gone)}; the ladder was cut short below its registered top"
    return line


def knees_file(root, cal):
    """What --ladder writes and --knees takes (T050-13): each class's level at the top of the file, null and named under no_knee for a class
    without one, bound to the record and the factor. A campaign that needs a class without a knee refuses. Under no_sound_attempt, every
    (class, level, repeat) that had no sound attempt and so counted as no harm (T063-01). Under levels, top_tested and results, D-074's
    statuses and lines (ladder_status); P3 sizes a family without a knee at its top tested level (ml/p3_sizing_prereg.json)."""
    harm = ladder_harm(root, cal)
    knees = ladder_knees(root, cal, harm)
    status = ladder_status(root, harm, knees)
    levels, none = {}, []
    for cls in sorted(PT.PRIMARY):
        level = (knees.get(cls) or {}).get("level")
        levels[cls] = None if level is None else (int(level) if cls == "C3b" else float(level))
        if level is None:
            none.append(cls)
    return {"format": "p1-knees/1", "status": cal.get("status"), "record_sha256": cal.get("sha256"), "record_status": cal.get("status"),
            "benign_halvings": ladder_factor(root), **levels, "no_knee": none, "no_sound_attempt": harm[1],
            "top_tested": {c: s["top_tested"] for c, s in status.items()}, "levels": {c: s["levels"] for c, s in status.items()},
            "results": {c: s["result"] for c, s in status.items()}, "knees": knees}


def ladder_factor(root):
    """The one factor of a finished ladder. Several are refused: their knees would mix two benign mixes."""
    factors = {REC.read_json(os.path.join(root, x["block_dir"], "block.json"))["halvings"]
               for x in REC.index_lines(root) if x["phase"] == "ladder"}
    if len(factors) != 1:
        raise ValueError(f"the ladder's blocks ran at the halvings {sorted(factors)}: one factor, frozen before it, applies to all")
    return factors.pop()


# --- the halving rule --------------------------------------------------------------------------------

def health_step(root, block_dir, cal):
    """One step of the rule: its two controls' figures, whether both gave a reading and their control_health reasons. A control that
    never ran, or whose run checks failed, gives no reading and fires nothing (ml/p1_prereg.json halving.unsound)."""
    path = os.path.join(root, block_dir)
    step = {"dir": block_dir, "halvings": REC.read_json(os.path.join(path, "block.json"))["halvings"], "sound": True,
            "controls": {}, "reasons": [], "server_q": []}
    try:
        runs = LH.assess_block(path, cal)["runs"]
    except LH.HarmError as exc:
        return {**step, "sound": False, "why": str(exc)}
    for name in PT.prereg()["halving"]["controls"]:
        run = runs.get(name)
        if run is None or not run["checks"].get("ok"):
            step["sound"] = False
            step["controls"][name] = {"sound": False, "checks": run and run["checks"].get("reasons")}
            continue
        reasons, small = LH.control_health(run["metrics"], cal)
        timeline = REC.read_json(os.path.join(path, "block.json"))["timeline"]
        lo = float(timeline["baseline_s"])
        step["controls"][name] = {"sound": True, "Q": run["metrics"]["Q"], "reasons": reasons,
                                  "server_q": (run["server"] or {}).get("Q"),
                                  "cpu": REC.cpu_load(os.path.join(path, name), (lo, lo + float(timeline["attack_s"]))),
                                  "view_slip": run["metrics"].get("view_slip"), "small_classes": small}
        step["reasons"].append(reasons)
        step["server_q"].append((run["server"] or {}).get("Q"))
    return step


def parse_health_decision(text):
    """{step's dir: {"action", "text"}} of one --health-decision DIR=ACTION:TEXT; the text must name a date (D-058)."""
    head, _colon, words = text.partition(":")
    step, _eq, action = head.partition("=")
    if action not in ("fire", "repeat") or not re.search(r"\d{4}-\d{2}-\d{2}", words):
        raise ValueError(f"--health-decision takes DIR=fire:TEXT or DIR=repeat:TEXT, and TEXT names a dated decision; got {text!r}")
    return {step: {"action": action, "text": words.strip()}}


def health_result(root, cal, decisions=None):
    """The rule over its steps in the order they ran (ROOT/index.jsonl): the health file."""
    dirs = []
    for x in REC.index_lines(root):
        if x["phase"] == "health" and x["block_dir"] not in dirs:
            dirs.append(x["block_dir"])
    steps = [health_step(root, d, cal) for d in dirs]
    return {"format": RUN.HEALTH_FORMAT, "record_sha256": cal.get("sha256"), "record_status": cal.get("status"),
            "rule": "ml/p1_prereg.json halving", **PT.next_step(steps, decisions), "decisions": decisions or {}, "steps": steps}


# --- the frozen operating points on the pilot's benign traffic -----------------------------------------

def pilot_controls(root, factor):
    """One valid control C per pilot seed at the factor, the first of the index, of the phases health and ladder: {seed: its run dir}."""
    out = {}
    for x in REC.index_lines(root):
        if (x["phase"] in ("health", "ladder") and x["run"] == "C" and x["valid"] and x["block"] not in out
                and REC.read_json(os.path.join(root, x["block_dir"], "block.json"))["halvings"] == factor):
            out[x["block"]] = os.path.join(root, x["dir"])
    return out


def point_check(root, cal, frozen, factor, arms_factory=None):
    """The file of the check (D-052): per arm the benign units flagged at its frozen point, pooled over the pilot's seeds, against the
    budget; the arms that stop the campaign; the seeds missing. It reads the points and changes none."""
    rule = PT.prereg_2()["point_check"]
    arms_factory = arms_factory or default_factory(frozen)
    controls = pilot_controls(root, factor)
    rows, per_seed, units = {}, [], 0
    for seed, run_dir in sorted(controls.items()):
        man = REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
        res = RP.replay(REC.recording(run_dir), arms_factory(run_dir, man), RP.RunLabels(man))
        units += res["benign_units"]
        per_seed.append({"seed": seed, "benign_units": res["benign_units"],
                         "flagged": {a: v.get("benign_units_flagged", 0) for a, v in res["arms"].items()}})
        for name, arm in res["arms"].items():
            row = rows.setdefault(name, {"flagged": 0, "by_kind": {}, "note": arm.get("note")})
            row["flagged"] += arm.get("benign_units_flagged", 0)
            for kind, n in (arm.get("benign_units_flagged_by_kind") or {}).items():
                row["by_kind"][kind] = row["by_kind"].get(kind, 0) + n
    arms = {a: {**r, "units": units, "meets": J._meets((r["flagged"], units))} for a, r in sorted(rows.items())}
    over = [a for a in rule["stops"] if a in arms and not arms[a]["meets"]]
    missing = [s for s in rule["seeds"] if s not in controls]
    return {"format": RUN.POINTS_FORMAT, "record_sha256": cal.get("sha256"), "selection_sha256": frozen.get("selection_sha256"),
            "rules_sha256": frozen.get("rules_sha256"), "benign_halvings": factor, "rule": "ml/p1_prereg_2.json point_check",
            "status": "incomplete" if missing else ("over_budget" if over else "pass"), "over_budget": over,
            "missing_seeds": missing, "stops": rule["stops"], "arms": arms, "per_seed": per_seed}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("--calibration", required=True)
    ap.add_argument("--selection")
    ap.add_argument("--selection-sha256")
    ap.add_argument("--rules")
    ap.add_argument("--rules-sha256")
    ap.add_argument("--cut", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="a record that is not frozen: figures, no verdict")
    ap.add_argument("--ladder", action="store_true", help="the knees of a finished ladder")
    ap.add_argument("--health", action="store_true", help="the halving rule's next step, frozen factor or refusal")
    ap.add_argument("--points", action="store_true", help="the frozen operating points on the pilot's benign traffic")
    ap.add_argument("--health-decision", action="append", default=[], metavar="DIR=ACTION:TEXT",
                    help="a step the rule stopped at: fire or repeat it, by a dated decision (D-058)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    import l7_backend
    cal, _status, _tag = l7_backend.load_record(args.calibration)
    failed = False
    decisions = {}
    for text in args.health_decision:
        decisions.update(parse_health_decision(text))
    if args.health:
        res = health_result(args.root, cal, decisions)
        failed = res["decision"] in ("refused", "stopped")
        print(f"the halving rule: {res['decision']}: {res['why']}")
    elif args.points:
        health = health_result(args.root, cal, decisions)
        if health["decision"] != "frozen":
            print(f"no point check without a frozen factor: {health['decision']}: {health['why']}", file=sys.stderr)
            return 1
        res = point_check(args.root, cal, {"selection": args.selection, "selection_sha256": args.selection_sha256,
                                           "rules": args.rules, "rules_sha256": args.rules_sha256}, health["benign_halvings"])
        failed = res["status"] != "pass"
        print(f"the frozen points on the pilot's benign traffic: {res['status']}; over the budget: {res['over_budget']}; "
              f"seeds missing: {res['missing_seeds']}")
    elif args.ladder:
        res = knees_file(args.root, cal)
        holes = ", ".join(f"{h['class']} L{h['level']:g} r{h['repeat']}" for h in res["no_sound_attempt"]) or "none"
        print(f"the knees: { {c: res[c] for c in sorted(PT.PRIMARY)} }; no knee: {res['no_knee']}; "
              f"no sound attempt, counted as no harm (ml/p1_prereg_3.json ladder): {holes}")
        for line in res["results"].values():
            print(f"  {line}")
    else:
        frozen = {"selection": args.selection, "selection_sha256": args.selection_sha256, "rules": args.rules,
                  "rules_sha256": args.rules_sha256}
        try:
            classes = analyse(args.root, cal, frozen, cut=args.cut, dry_run=args.dry_run)
        except SettingsError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        res = {"format": "p1-verdicts/1", "record_sha256": cal.get("sha256"), "cut": args.cut, "dry_run": args.dry_run, "classes": classes}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

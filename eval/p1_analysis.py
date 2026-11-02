#!/usr/bin/env python3
"""The P1 analysis (docs/L7V2_DESIGN.md 5.3, 10, 11): a finished campaign of eval/p1_runner.py through to one verdict per class.

Offline: it reads the runs' directories, ROOT/index.jsonl and the frozen selections; it starts nothing, and nothing that judges
moves here. For each class:
  * harm admission through eval/l7v2_harm.py (assess_block, admission), over every attempt, the last of each block counting; a
    campaign the admission finds INVALID (too few valid blocks, too many re-runs) gets no verdict, with its reasons, which is
    not the same as V-D "no harm";
  * the blocks it judges: the final attempts whose class is valid and whose live M runs are sound; the others are listed;
  * harm per block: Q of every live arm (eval/l7v2_harm.py's figures);
  * the budget, pooled over those blocks: live (D-044 OC-2), the benign users wrongly acted on in the arm's own M runs
    (eval/p1_records.acted_on), and, reported beside it, the replay's benign units on the U runs;
  * detection per entity: each U run's recording through every arm (ml/l7v2_replay.py), the caught flags of the GRU, the HGB, the
    shuffled-GRU, R* and the age-only arm over the class's attack entities, with their block and family; l7v2_verdict reads the
    primary families (D-043) and reports the others;
  * the validation recall of the learned arms and the age-only AUC, from the frozen selection;
and then ml/l7v2_verdict.judge, with the minimum cut's live set when the campaign ran it. A record that is not frozen gets no
verdict (a dry run stops before judging, and says so).

Beside the judge, nothing reading it (D-049, ml/p1_prereg.json age_check): each class's age_only_on_U, the window-age AUC of its U
replays, per block and per family, and the age-only arm's recall at its frozen point, with each U run's recorded age check; and
view_level_contrasts, every contrast of the judge's output naming a view-level arm with that reading beside it.

ladder_knees() reads a finished ladder (phase ladder) into the knees a campaign needs: per class the lowest level whose harm
reaches the floor in both repeats (bench/calibration.knee, harm as bench/calibrate.harm against the session's control).

health_result() reads the halving rule's steps (phase health, ml/p1_prereg.json) into the next step, the frozen factor or a refusal,
in the file that the ladder and the campaign take (--health). Its exit code is 1 on a refusal.

    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --selection SEL/selection.json --selection-sha256 H \\
        --rules RULES/rules_selection.json --rules-sha256 H --out p1_verdicts.json
    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --ladder --out knees.json
    ./venv/bin/python eval/p1_analysis.py ROOT --calibration REC --health --out health.json
"""
import argparse
import copy
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), HERE, os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import calibration as CAL
import harm_gate as HG
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


def replay_block(root, block, cls, arms_factory):
    """One U run through every arm: (the replay's result, {attack entity: family}, its manifest), on its recording and the
    manifest's labels."""
    run_dir = os.path.join(root, "campaign", block["dir"], f"U_{cls}")
    man = REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE))
    items, labels = REC.recording(run_dir), RP.RunLabels(man)
    _keys, ent, attack, _units = RP.ground_truth(items, labels)
    return RP.replay(items, arms_factory(run_dir, man), labels), {e: ent[e]["family"] for e in attack}, man


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


def class_inputs(root, cal, cls, blocks, live, frozen, arms_factory):
    """l7v2_verdict.judge's inputs for a class over its judged blocks (see the module doc), and the replay's summary."""
    enforcing = [a for a in live if a != "U"]
    harm = {a: [b["runs"][RUN.run_name(a, cls)]["metrics"]["Q"] for b in blocks] for a in live}
    budget = {"live": {a: [0, 0] for a in enforcing}, "replay": {a: [0, 0] for a in enforcing}}
    det = {"blocks": [], "families": [], "caught": {a: [] for a in DETECTION_ARMS}}
    per_arm, structured = {}, bool(blocks)
    for b in blocks:
        for a in enforcing:
            run_dir = os.path.join(root, "campaign", b["dir"], RUN.run_name(a, cls))
            rec = REC.acted_on(REC.read_json(os.path.join(run_dir, D.MANIFEST_FILE)),
                               P4._events(os.path.join(run_dir, "ban_events.jsonl")),
                               REC.read_json(os.path.join(run_dir, "run.json")).get("budget"))
            budget["live"][a][0] += rec["benign_users"]
            budget["live"][a][1] += rec["benign_users_total"]
        res, families, man = replay_block(root, b, cls, arms_factory)
        structured = structured and any(e["kind_or_family"] == STRUCTURED_KIND for e in man["entities"])
        for a in enforcing:
            arm = res["arms"].get(a) or {}
            budget["replay"][a][0] += arm.get("benign_units_flagged", 0)
            budget["replay"][a][1] += res["benign_units"]
        for name, arm in res["arms"].items():
            per = per_arm.setdefault(name, {"caught": 0, "attack_entities": 0, "benign_units_flagged": 0, "by_family": {}})
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
              "admitted": True, "harm": harm, "budget": {k: {a: tuple(v) for a, v in d.items()} for k, d in budget.items()},
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


def analyse(root, cal, frozen, *, arms_factory=None, cut=False, dry_run=False, pre=None):
    """Every class's admission, inputs and verdict: {class: {"verdict", "admission", "judge", "excluded", "replay"}}."""
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
        inputs, per_arm = class_inputs(root, cal, cls, blocks, live, frozen, arms_factory)
        row["replay"] = per_arm
        row["blocks_judged"] = [b["block"] for b in blocks]
        row["age_only_on_U"] = age_only_on_u(root, blocks, cls, per_arm)
        if dry_run:
            row["why_no_verdict"] = [f"a dry run on a {cal.get('status')} record gives no verdict"]
            continue
        row["judge"] = J.judge(cls, inputs, pre)
        row["verdict"] = row["judge"]["verdict"]
        row["view_level_contrasts"] = view_level_contrasts(row["judge"], row["age_only_on_U"],
                                                           pre["detection_entities"]["per_class"][cls]["primary"])
    return out


# --- the ladder --------------------------------------------------------------------------------------

def ladder_knees(root, cal):
    """The knees of a finished ladder: {class: bench/calibration.knee's result}, harm as bench/calibrate.harm against the attempt's
    own control. A level with an invalid run, or that the plan refused, counts as no harm: never as passing."""
    import calibrate as K
    gate = cal["gate"]
    rows = {}
    for x in REC.index_lines(root):
        if x["phase"] != "ladder" or not x["label"]:
            continue
        m = LADDER_LABEL.match(x["label"])
        if m is None or x["run"] == "C":
            continue
        bdir = os.path.join(root, x["block_dir"])
        try:
            b = LH.assess_block(bdir, cal)
        except LH.HarmError:
            b = {"runs": {}, "classes": {}}
        control, attack = b["runs"].get("C"), b["runs"].get(x["run"])
        harm = 0.0
        if control and attack and control["checks"].get("ok") and attack["checks"].get("ok"):
            h, _parts = K.harm([control["metrics"]], attack["metrics"], gate["floor_pp"], gate["floor_log2_p95"])
            harm = h or 0.0
        cls, level = m.group("cls"), float(m.group("level"))
        rows.setdefault(cls, {}).setdefault(level, []).append(harm)
    return {cls: CAL.knee(sorted(levels.items()), 1.0, 2) for cls, levels in sorted(rows.items())}


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
            "controls": {}, "reasons": []}
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
        reasons = HG.control_health(run["metrics"], cal)
        step["controls"][name] = {"sound": True, "Q": run["metrics"]["Q"], "reasons": reasons}
        step["reasons"].append(reasons)
    return step


def health_result(root, cal):
    """The rule over its steps in the order they ran (ROOT/index.jsonl): the health file."""
    dirs = []
    for x in REC.index_lines(root):
        if x["phase"] == "health" and x["block_dir"] not in dirs:
            dirs.append(x["block_dir"])
    steps = [health_step(root, d, cal) for d in dirs]
    return {"format": RUN.HEALTH_FORMAT, "record_sha256": cal.get("sha256"), "record_status": cal.get("status"),
            "rule": "ml/p1_prereg.json halving", **PT.next_step(steps), "steps": steps}


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
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    import l7_backend
    cal, _status, _tag = l7_backend.load_record(args.calibration)
    if args.health:
        res = health_result(args.root, cal)
        print(f"the halving rule: {res['decision']}: {res['why']}")
    elif args.ladder:
        res = {"format": "p1-ladder/1", "record_sha256": cal.get("sha256"), "record_status": cal.get("status"),
               "benign_halvings": ladder_factor(args.root), "knees": ladder_knees(args.root, cal)}
    else:
        frozen = {"selection": args.selection, "selection_sha256": args.selection_sha256, "rules": args.rules,
                  "rules_sha256": args.rules_sha256}
        res = {"format": "p1-verdicts/1", "record_sha256": cal.get("sha256"), "cut": args.cut, "dry_run": args.dry_run,
               "classes": analyse(args.root, cal, frozen, cut=args.cut, dry_run=args.dry_run)}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")
    return 1 if args.health and res["decision"] == "refused" else 0


if __name__ == "__main__":
    sys.exit(main())

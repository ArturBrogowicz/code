#!/usr/bin/env python3
"""P4's halving rule (docs/P4_SLOW_DESIGN.md §4.2; D-073 (3), R-021; ml/p4_prereg.json halving): the health phase's steps read into the next
step, the frozen factor or a refusal, in the file the ladder, the validation and the campaign take (eval/p4_runner.py --health).

Re-registration record (D-073 (3), 2026-11-07T08:33Z, the user's approval of T-071, before any P4 data; P1's D-049 rule with D-058's guard),
committed before the code it judges. The two pilot controls the rule reads are C and C' of the health phase (eval/p4_runner.py --phase
health) on pilot seed 9101 at --halvings, before the ladder. Each step (one attempt of a health block, in the order of the run index) gives,
per control, whether it ran soundly (its run checks), its health (eval/p4_outcome.control_health: Q(C) at least 99 %, each route class of at
least 20 judged requests at least 95 %) and its server-side Q (eval/l7v2_harm.server_q over the attack window, the client side's recorded
entities). ml/p4_traffic.next_step applies the rule: the first sound and healthy step freezes the factor; an unhealthy one fires it (the next
step at halvings + 1); an unsound one is repeated, at most twice; past the floor of 2 halvings there is no factor; a control unhealthy with a
server-side Q of at least 99 % stops the rule for a dated decision (--health-decision DIR=fire:TEXT or DIR=repeat:TEXT, TEXT naming a date).
The file is bound to the calibration record by its sha256. Exit 0 when a factor is frozen or the next step is named, 1 when the rule refuses
or stops, 2 when the steps cannot be read.

    ./venv/bin/python eval/p4_health.py ROOT --calibration REC --out health.json [--health-decision DIR=fire:TEXT]
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_outcome as OUT
import p4_runner as R
import p4_traffic as PT

FORMAT = "p4-health/1"


def control_reading(run_dir, cal):
    """One control's figures: (sound, Q, its control_health reasons, small classes, server-side Q, run checks' reasons)."""
    import l7v2_harm as LH
    try:
        with open(os.path.join(run_dir, "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
    except (OSError, ValueError) as exc:
        return {"sound": False, "checks": [f"no run.json or manifest.json: {exc}"]}
    if not meta["checks"]["ok"]:
        return {"sound": False, "checks": meta["checks"]["reasons"]}
    t = man["timeline"]
    attack = (float(t["baseline_s"]), float(t["baseline_s"]) + float(t["attack_s"]))
    total = sum(float(t[k]) for k in ("baseline_s", "attack_s", "recovery_s"))
    rows, t0, cover = LH.run_rows(run_dir, man, attack)
    m = LH.metrics(rows, cal, (t0 + attack[0], t0 + attack[1]), t0, total)
    reasons, small = OUT.control_health(m, cal)
    log = os.path.join(run_dir, "access.log")
    server = LH.server_q(log, man, cal, attack, set(cover["recorded"])) if os.path.isfile(log) else None
    return {"sound": True, "Q": m["Q"], "reasons": reasons, "small_classes": small, "server_q": (server or {}).get("Q")}


def health_step(root, block_dir, rows, cal):
    """One step of the rule (an attempt of a health block): its two controls' readings, whether both gave one, their reasons and server Q."""
    with open(os.path.join(root, block_dir, "block.json"), encoding="utf-8") as fh:
        meta = json.load(fh)
    step = {"dir": block_dir, "halvings": meta["halvings"], "sound": True, "controls": {}, "reasons": [], "server_q": []}
    arms = {x["arm"]: x for x in rows if x["block_dir"] == block_dir}
    for name in PT.prereg()["halving"]["controls"]:
        x = arms.get(name)
        if x is None or not x["valid"]:
            step["sound"] = False
            step["controls"][name] = {"sound": False, "checks": x and x["reasons"]}
            continue
        reading = control_reading(os.path.join(root, x["dir"]), cal)
        step["controls"][name] = reading
        if not reading["sound"]:
            step["sound"] = False
            continue
        step["reasons"].append(reading["reasons"])
        step["server_q"].append(reading["server_q"])
    return step


def parse_health_decision(text):
    """{step's dir: {"action", "text"}} of one --health-decision DIR=ACTION:TEXT; the text must name a date (D-058)."""
    head, _colon, words = text.partition(":")
    step, _eq, action = head.partition("=")
    if action not in ("fire", "repeat") or not re.search(r"\d{4}-\d{2}-\d{2}", words):
        raise ValueError(f"--health-decision takes DIR=fire:TEXT or DIR=repeat:TEXT, and TEXT names a dated decision; got {text!r}")
    return {step: {"action": action, "text": words.strip()}}


def health_index_digest(root):
    """A digest of ROOT/index.jsonl's health lines (D-080, T078-08): the factor file is bound to the health runs it read, so a ladder in
    another root, or after the health phase was re-run, cannot borrow it. The raw lines are hashed in order; no health line hashes the empty
    string, as it does when the index does not exist."""
    import hashlib
    path = os.path.join(root, "index.jsonl")
    lines = []
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                try:
                    if json.loads(raw).get("phase") == "health":
                        lines.append(raw if raw.endswith("\n") else raw + "\n")
                except ValueError:
                    continue
    except OSError:
        pass
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def health_result(root, calibration, decisions=None):
    """The rule over its steps in the order they ran (ROOT/index.jsonl): the health file, bound to the calibration record and to the root and
    health index it read (D-080, T078-08)."""
    cal, status = R.read_record(calibration)
    rows = [x for x in R.read_index(root) if x["phase"] == "health"]
    dirs = []
    for x in rows:
        if x["block_dir"] not in dirs:
            dirs.append(x["block_dir"])
    for block_dir in dirs:
        with open(os.path.join(root, block_dir, "block.json"), encoding="utf-8") as fh:
            if json.load(fh)["calibration_sha256"] != R.sha256_file(calibration):
                raise ValueError(f"{block_dir} ran under another calibration record than {calibration}")
    steps = [health_step(root, d, rows, cal) for d in dirs]
    return {"format": FORMAT, "calibration_sha256": R.sha256_file(calibration), "calibration_status": status,
            "root": os.path.abspath(root), "index_digest": health_index_digest(root),
            "rule": "ml/p4_prereg.json halving", **PT.next_step(steps, decisions), "decisions": decisions or {}, "steps": steps}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", help="the runner's root: index.jsonl and the health phase's runs")
    ap.add_argument("--calibration", required=True, help="the record the health phase ran under")
    ap.add_argument("--out", required=True)
    ap.add_argument("--health-decision", action="append", default=[], metavar="DIR=ACTION:TEXT",
                    help="D-058: fire the rule at a stopped step, or take it as no reading (repeat); TEXT names the dated decision")
    args = ap.parse_args(argv)
    decisions = {}
    try:
        for text in args.health_decision:
            decisions.update(parse_health_decision(text))
        res = health_result(args.root, args.calibration, decisions)
    except (ValueError, OSError, KeyError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"{res['decision']}: {res['why']}")
    return 0 if res["decision"] in ("frozen", "run") else 1


if __name__ == "__main__":
    sys.exit(main())

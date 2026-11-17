"""T-132: the re-calibration recomputed offline from a copy of the PUBLISHED session directory, with bench/calibrate.py's own
functions (the code of the pin c6579fd; bench/calibrate.py, bench/calibration.py, eval/harm_gate.py and the placeholder template are
identical at the freeze's pin 9c0c25a, and executor.py's ORIGIN_SEED and GUNICORN are unchanged).

Reads only; writes only the files named by --out-dir. Never touches the VM or the network (run it in sbx).
  1. capacity: Q of every step of every repeat from the runs (metrics_by_step under the template), then capacity_of;
  2. the three ladders: each run's Q and p95 from its run directory (harm_gate.run_metrics under the session's draft record), then
     analyse_ladder (controls, harm, validity, knee) against ladder.json;
  3. the reference: each round's legit probe and attack runs (probe_metrics, attack_metrics) against reference.json's rows;
  4. the freeze: freeze_step on the copy with the committed record's created_utc, dumped with calibration.dump, against the
     committed record (bytes and fields);
  5. R4: each drift round's runs (probe_metrics, attack_metrics under the frozen record) against drift.json's rows, then judge_rounds
     on the recomputed rows and on drift.json's own rows (calibrate.judge_drift), against drift.json's check, confirmed, ok, reasons.
usage: python -B recompute_from_runs.py REPO SESSION_COPY RECORD OUT_DIR
"""
import gzip
import json
import math
import os
import shutil
import sys
import tempfile
import types

REPO, SESSION, RECORD, OUT = sys.argv[1:5]
sys.path.insert(0, os.path.join(REPO, "bench"))
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibrate as K  # noqa: E402
import calibration as C  # noqa: E402
import harm_gate as H  # noqa: E402

REL_TOL = 1e-9
lines = []
mismatches = []
counts = {"numbers": 0, "numbers_not_bit_equal": 0, "other_values": 0}


def say(text):
    lines.append(text)


def read(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    with gzip.open(path + ".gz", "rt", encoding="utf-8") as fh:      # a plan.json published as plan.json.gz
        return json.load(fh)


def close(a, b):
    if isinstance(a, bool) or isinstance(b, bool) or a is None or b is None:
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b or (math.isfinite(a) and math.isfinite(b) and abs(a - b) <= REL_TOL * max(1.0, abs(a), abs(b)))
    return a == b


def compare(where, got, want):
    """Deep comparison; numbers within REL_TOL (relative); every difference is recorded."""
    if isinstance(want, dict) and isinstance(got, dict):
        for k in sorted(set(got) | set(want)):
            if k not in got or k not in want:
                mismatches.append(f"{where}.{k}: only in {'recomputed' if k in got else 'recorded'}")
                continue
            compare(f"{where}.{k}", got[k], want[k])
    elif isinstance(want, list) and isinstance(got, list):
        if len(got) != len(want):
            mismatches.append(f"{where}: {len(got)} items recomputed, {len(want)} recorded")
            return
        for i, (g, w) in enumerate(zip(got, want, strict=True)):
            compare(f"{where}[{i}]", g, w)
    else:
        number = isinstance(want, (int, float)) and not isinstance(want, bool)
        counts["numbers" if number else "other_values"] += 1
        if number and got != want:
            counts["numbers_not_bit_equal"] += 1
        if not close(got, want):
            mismatches.append(f"{where}: recomputed {got!r}, recorded {want!r}")


def counted(label, before):
    n = len(mismatches) - before
    say(f"{label}: {'0 mismatches' if n == 0 else f'{n} MISMATCHES'}")


def main():
    template = C.load(C.PLACEHOLDER)
    origin = read(os.path.join(SESSION, "origin", "origin.json"))
    capacity = read(os.path.join(SESSION, "capacity", "capacity.json"))
    say(f"template bench/calibration/placeholder.json (digest {C.digest(template)[:16]}...); record "
        f"{os.path.basename(RECORD)}; the session's files as published (paths are not printed, so that the output does not "
        "depend on where the copy is)")

    # 1. capacity
    b = len(mismatches)
    levels, q = capacity["levels_rps"], []
    for r in range(1, 4):
        run_dir = os.path.join(SESSION, "capacity", f"r{r}", "C")
        steps = K.metrics_by_step(H.read_run(run_dir), template, len(levels), capacity["step_s"])
        q.append([m["Q"] for m in steps])
    compare("capacity.q_pct", q, capacity["q_pct"])
    got = K.capacity_of(levels, q)
    compare("capacity.c_slo/c_sat", got, {k: capacity[k] for k in ("c_slo_rps", "c_sat_rps", "first_unhealthy_rps")})
    say(f"capacity: C_slo {got['c_slo_rps']}, C_sat {got['c_sat_rps']}, first unhealthy {got['first_unhealthy_rps']} "
        f"(recomputed from the 3 staged runs, 36 steps)")
    counted("capacity, Q of 36 steps and C_slo/C_sat against capacity.json", b)

    # 2. the ladders
    draft = K.draft_record(template, origin, capacity)
    for family in sorted(K.FAMILY_SPECS):
        b = len(mismatches)
        base = os.path.join(SESSION, f"ladder_{family}")
        ladder = read(os.path.join(base, "ladder.json"))
        entries = []
        for i, (kind, level, repeat) in enumerate(ladder["sequence"], 1):
            label = f"{i:02d}_" + (f"L{level:g}_r{repeat}" if kind == "U" else f"control{repeat}")
            run_dir = os.path.join(base, label, kind)
            t = read(os.path.join(run_dir, "plan.json"))["timeline"]
            metrics = H.run_metrics(H.read_run(run_dir), draft, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})
            entries.append({"kind": kind, "level": level, "repeat": repeat, "run": label, "metrics": metrics})
        got = K.analyse_ladder(entries, draft)
        compare(f"ladder_{family}", got, {k: ladder[k] for k in got})
        say(f"ladder {family}: {len(entries)} runs; valid {got['valid']}, knee {got['knee']}")
        counted(f"ladder {family}: controls, every attack run's Q, p95 and harm, validity and knee against ladder.json", b)

    # 2b. the four runs set aside by H7 (prereg 7: published with their reasons and their Q and p95, descriptive only, never used)
    for d, _, fs in sorted(os.walk(SESSION)):
        if "HOSTINVALID" in fs:
            t = read(os.path.join(d, "plan.json"))["timeline"]
            # harm_gate.read_run knows a run by its directory's name (C, U, ...): read a copy named as the run was
            # (C.hostinvalid1 -> C) in a temporary directory, which is removed afterwards
            with tempfile.TemporaryDirectory() as tmp:
                named = os.path.join(tmp, os.path.basename(d).split(".")[0])
                shutil.copytree(d, named)
                m = H.run_metrics(H.read_run(named), draft, {k: t[k] for k in ("baseline_s", "attack_s", "recovery_s")})
            p95 = "none" if m["p95_s"] is None else f"{m['p95_s'] * 1000:.1f} ms"
            say(f"set aside (descriptive only, never used): {os.path.relpath(d, SESSION)}: Q {m['Q']:.2f} %, p95 {p95}, "
                f"{m['requests']} judged requests")

    # 3. the reference
    b = len(mismatches)
    reference = read(os.path.join(SESSION, "reference", "reference.json"))
    knees = reference["knees"]
    draft_k = K.draft_record(template, origin, capacity, knees)
    rows = []
    for row in reference["rounds"]:
        got_row = {"round": row["round"]}
        legit_dir = os.path.join(SESSION, row["legit"]["run"])
        got_row["legit"] = {**K.probe_metrics(H.read_run(legit_dir), draft_k), "seed": row["legit"]["seed"],
                            "run": row["legit"]["run"]}
        got_row["attacks"] = {}
        for family, a in row["attacks"].items():
            d = os.path.join(SESSION, a["run"])
            plan = read(os.path.join(d, "plan.json"))
            m = K.attack_metrics(types.SimpleNamespace(out=d, timeline=plan["timeline"]), draft_k)
            got_row["attacks"][family] = {"level": a["level"], **m, "seed": a["seed"], "run": a["run"]}
        rows.append(got_row)
    compare("reference.rounds", rows, reference["rounds"])
    counted(f"reference: {len(rows)} rounds (legit probe and {len(knees)} attack runs each), Q, p95 and requests against "
            "reference.json", b)

    # 4. the freeze
    b = len(mismatches)
    committed = C.load(RECORD)
    env = read(os.path.join(SESSION, "capacity", "r1", "C", "environment.json"))
    frozen = K.freeze_step(SESSION, template, env, created_utc=committed["created_utc"])
    out_record = os.path.join(OUT, "freeze_record_created_utc_as_committed.json")
    C.dump(frozen, out_record)
    same_bytes = open(out_record, "rb").read() == open(RECORD, "rb").read()
    compare("record", frozen, committed)
    say(f"freeze_step with created_utc {committed['created_utc']}: sha256 field {frozen['sha256']}; the committed record's "
        f"{committed['sha256']}; dumped file byte-identical to the committed file: {same_bytes}")
    counted("freeze: every field of the record against the committed record", b)

    # 5. R4, the confirmation
    b = len(mismatches)
    drift = read(os.path.join(SESSION, "confirmation", "drift", "drift.json"))
    rows = []
    for row in drift["rounds"]:
        got_row = {"round": row["round"]}
        legit_dir = os.path.join(SESSION, "confirmation", row["legit"]["run"])
        got_row["legit"] = {**K.probe_metrics(H.read_run(legit_dir), committed), "seed": row["legit"]["seed"],
                            "run": row["legit"]["run"]}
        got_row["attacks"] = {}
        for family, a in row["attacks"].items():
            d = os.path.join(SESSION, "confirmation", a["run"])
            plan = read(os.path.join(d, "plan.json"))
            m = K.attack_metrics(types.SimpleNamespace(out=d, timeline=plan["timeline"]), committed)
            got_row["attacks"][family] = {"level": a["level"], **m, "seed": a["seed"], "run": a["run"]}
        rows.append(got_row)
    compare("drift.rounds", rows, drift["rounds"])
    counted(f"R4: {len(rows)} rounds' Q, p95 and requests from the runs against drift.json", b)
    b = len(mismatches)
    judged_runs = K.judge_rounds(committed, rows, drift["families"])
    compare("drift.verdict(from the runs)", judged_runs, {k: drift[k] for k in judged_runs})
    judged_rows = K.judge_drift(committed, drift)
    compare("drift.verdict(from drift.json's rows)", judged_rows, {k: drift[k] for k in judged_rows})
    compare("drift.calibration_sha256", committed["sha256"], drift["calibration_sha256"])
    say(f"R4 judged again: ok {judged_runs['ok']}, confirmed {judged_runs['confirmed']}, reasons {judged_runs['reasons']}")
    counted("R4: the verdict (check, confirmed, ok, reasons) judged again, from the runs and from drift.json's rows", b)

    say(f"compared: {counts['numbers']} numbers ({counts['numbers_not_bit_equal']} not bit-equal, all within a relative "
        f"{REL_TOL:g} or listed below) and {counts['other_values']} other values (strings, booleans, None)")
    say(f"TOTAL: {len(mismatches)} mismatches")
    for m in mismatches:
        say("  " + m)
    with open(os.path.join(OUT, "recompute_from_runs.out"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())

"""P4's ladder (docs/P4_SLOW_DESIGN.md §5, §11; review T-057 T057-04): the knee of each family from the runs of a finished ladder, in the
file the validation and the campaign must take (--knees), so that their level and halvings are read and not typed.

The knee is §5's: the lowest level that harms in 2 of 2 repeats (bench/calibration.knee). Harm is the either-or of the gate, against the
repeat's own control, by bench/calibrate.harm at P4's pinned floors. A repeat is one (seed, label) of the run index; of its attempts the
last with both runs valid counts. One with no such attempt is missing, not harm 0 (D-067, review T-063 T063-01): no knee is read while a
repeat at or below it is missing, the knee needs 2 sound repeats, and "no knee" needs 2 sound repeats at every level that ran. The refusal
names the repeat, to be re-run with its reason. Asking every repeat to pass means a further repeat can only make a level harder to pass, so
it cannot re-roll one. A lower level of the ladder that was skipped is refused.

What the design leaves open is not chosen here (T-060), and both ways it stops rather than picks:
  * a family with no knee: its level is null and it is named under no_knee, this tool exits 1, and eval/p4_runner.py refuses a validation or
    campaign on the file. Whether such a family runs at the top level, is dropped, or reads "not harmful" with no campaign needs a decision;
  * which "two pilot controls" §4.2's halving rule reads. A ladder holds many, so any unhealthy one stops this tool, named, with no file.

    ./venv/bin/python eval/p4_ladder.py ROOT --calibration REC --out knees.json
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (HERE, os.path.join(os.path.dirname(HERE), "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import calibration as CAL
import p4_outcome as OUT
import p4_runner as R
import p4_traffic as PT

FORMAT = "p4-knees/1"
REPEATS = R.LADDER_REPEATS   # §5: "in 2 of 2 repeats"


def _repeats(root, rows, named):
    """{(family, level, seed, label): [(attempt, {arm: index row})]} of the ladder's blocks, and the halvings they ran at."""
    blocks, repeats, halvings = {}, {}, set()
    for x in rows:
        blocks.setdefault(x["block_dir"], {})[x["arm"]] = x
    for block_dir, arms in sorted(blocks.items()):
        with open(os.path.join(root, block_dir, "block.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta["settings"]["calibration_sha256"] != named:
            raise ValueError(f"{block_dir} ran under calibration {meta['settings']['calibration_sha256'][:8]}, not the one named")
        halvings.add(meta["settings"]["halvings"])
        family = next(a[2:] for a in meta["order"] if a.startswith("U_"))
        one = next(iter(arms.values()))
        if one["label"] not in R.ladder_labels(meta["sources"][family]):
            raise ValueError(f"{block_dir}: the label {one['label']!r} is not one of {R.ladder_labels(meta['sources'][family])} (T063-05)")
        repeats.setdefault((family, meta["sources"][family], one["block"], one["label"]), []).append((one["attempt"], arms))
    return repeats, halvings


def knees(root, record_path):
    """The record --out writes, or ValueError: what stops it is named. See the module docstring."""
    import calibrate as K
    cal, status = R.read_record(record_path)
    named = R.sha256_file(record_path)
    rows = [x for x in R.read_index(root) if x["phase"] == "ladder"]
    if not rows:
        raise ValueError(f"{root}: the index holds no ladder run")
    repeats, halvings = _repeats(root, rows, named)
    if len(halvings) != 1:
        raise ValueError(f"the ladder ran at {sorted(halvings)} halvings: a ladder holds one")
    harms, missing, controls = {f: {} for f in OUT.FAMILIES}, {f: {} for f in OUT.FAMILIES}, []
    for (family, level, seed, label), attempts in sorted(repeats.items()):
        harm = None
        for attempt, arms in sorted(attempts, key=lambda a: a[0], reverse=True):
            c, u = arms.get(OUT.CONTROL), arms.get(f"U_{family}")
            if c and u and c["valid"] and u["valid"]:
                control = R.run_record(os.path.join(root, c["dir"]), cal, seed, attempt)
                attack = R.run_record(os.path.join(root, u["dir"]), cal, seed, attempt)
                controls.append({"seed": seed, "label": label, "attempt": attempt, "Q": control["Q"], "reasons": control["control_reasons"]})
                harm = K.harm([control], attack, OUT.GATE["floor_pp"], OUT.GATE["floor_log2_p95"])[0] or 0.0
                break
        if harm is None:
            missing[family].setdefault(level, []).append((seed, label))
        else:
            harms[family].setdefault(level, []).append(harm)
    unhealthy = [c for c in controls if c["reasons"]]
    if unhealthy:
        raise ValueError(f"unhealthy ladder controls {[(c['seed'], c['label']) for c in unhealthy]}: which two the halving rule of §4.2 reads is not "
                         f"decided, so no knee is read over them: {unhealthy[0]['reasons'][0]}")
    levels, no_knee, families = {}, {}, {}
    for f in OUT.FAMILIES:
        ran = sorted(set(harms[f]) | set(missing[f]))
        if not ran:
            raise ValueError(f"the ladder holds no run of {f}")
        k = CAL.knee(sorted(harms[f].items()), 1.0, REPEATS)
        level = None if k["level"] is None else int(k["level"])
        ladder = PT.FAMILIES[f]["levels"]
        holes = [(n, seed, label) for n in ran if level is None or n <= level for seed, label in missing[f].get(n, ())]
        if holes:
            n, seed, label = holes[0]
            raise ValueError(f"{f} {n}: repeat {label} on seed {seed} has no sound attempt, so no knee is read across it: re-run it, with its "
                             f"reason (D-067)" + (f"; also {[(h[0], h[2], h[1]) for h in holes[1:]]}" if holes[1:] else ""))
        short = [n for n in ran if level is None and len(harms[f].get(n, ())) < REPEATS]
        if short:
            raise ValueError(f"{f}: no level passes, but level(s) {short} have fewer than {REPEATS} sound repeats, so no knee is not read either (D-067)")
        skipped = [n for n in ladder if level is not None and n < level and len(harms[f].get(n, ())) < REPEATS]
        if skipped:
            raise ValueError(f"{f}: the knee would be {level}, but level(s) {skipped} under it have not run {REPEATS} repeats")
        levels[f] = level
        if level is None:
            no_knee[f] = {"why": k["why"], "top_level_run": ladder[-1] in harms[f]}
        families[f] = {"rows": sorted(harms[f].items()), "passing": k["passing"], "monotone": k["monotone"],
                       "unsound_above_knee": sorted((n, seed, label) for n, rs in missing[f].items() for seed, label in rs)}
    return {"format": FORMAT, "levels": levels, "no_knee": no_knee, "halvings": halvings.pop(), "calibration_sha256": named,
            "calibration_status": status, "families": families, "controls": controls}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", help="the runner's root: index.jsonl and the ladder's runs")
    ap.add_argument("--calibration", required=True, help="the record the ladder ran under")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        rec = knees(args.root, args.calibration)
    except (ValueError, OSError, KeyError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"knees {rec['levels']}; halvings {rec['halvings']}; calibration {rec['calibration_status']}")
    for f, why in rec["no_knee"].items():
        print(f"  {f}: no knee: {why['why']}" + ("" if why["top_level_run"] else f"; the 4th level, {PT.FAMILIES[f]['levels'][-1]}, has not run (§11)"))
    return 1 if rec["no_knee"] else 0


if __name__ == "__main__":
    sys.exit(main())

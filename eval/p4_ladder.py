"""P4's ladder (docs/P4_SLOW_DESIGN.md §5, §11; review T-057 T057-04): the knee of each family from the runs of a finished ladder, in the
file the validation and the campaign must take (--knees), so that their level and halvings are read and not typed.

The knee is §5's: the lowest level that harms in 2 of 2 repeats (bench/calibration.knee). Harm is the either-or of the gate, against the
repeat's own control, by bench/calibrate.harm at P4's pinned floors. A repeat is one (seed, label) of the run index; of its attempts the
last with both runs valid counts. One with no such attempt is missing, not harm 0 (D-067, review T-063 T063-01): no knee is read while a
repeat at or below it is missing, the knee needs 2 sound repeats, and "no knee" needs 2 sound repeats at every level that ran. The refusal
names the repeat, to be re-run with its reason. Asking every repeat to pass means a further repeat can only make a level harder to pass, so
it cannot re-roll one. A lower level of the ladder that was skipped is refused.

The families read are the ones the ladder's blocks name in their settings (D-069, 2026-11-06T16:30Z: Slowloris only, ("loris",)), one
setting for the whole ladder; the record names them (`family_set`), and the runner refuses a validation or a campaign of other families.

Re-registration record (D-073 (1), D-073 (5) and D-074, 2026-11-07T08:33Z, the user's approval of T-071, before any ladder data), committed
before the code it judges. A ladder's first ml/p4_traffic.ALWAYS_RUN = 3 levels always run; a higher level runs only once every lower level
has 2 sound repeats and none of them is a knee (next_allowed(), which eval/p4_runner.py asks before it runs a ladder block). Each family's
reading has a status, in the record's `results`:
  * "knee": the lowest level that harms in 2 of 2 repeats, every level under it with 2 sound repeats;
  * "no knee": every level up to the reachable top has 2 sound repeats and none harms in 2 of 2. This is D-074's rule A, a reported result:
    P4 reads "<family> below the default rules' thresholds did not harm profile R up to N sources" (eval/p4_outcome.py --knees), with each
    level's figures, and no validation and no campaign run (eval/p4_runner.py refuses them on the file);
  * "incomplete": no knee among the levels that ran, and `next_level` has not run: the ladder goes on.
A level is "not reachable" (D-073 (5)) only as `--unreachable LEVEL --why TEXT`, TEXT naming the dated reading: the ladder's top, above the
always-run levels, when P4-S s2's feasibility reading fails there. It must not have run, and it never reads as no harm: "no knee" then stops
at the level below it, and the record names the level and why. The exit code is 0 when every family has a knee, 1 when one has none (rule A)
and none is incomplete, 3 when one is incomplete, and 2 on a refusal.

Re-registration record (D-073 (3), 2026-11-07T08:33Z, R-021), committed before the code it judges: the halving rule reads the health
phase's two controls (eval/p4_health.py), not the ladder's. A ladder attempt whose C is unhealthy (eval/p4_outcome.control_health) is not
sound: the repeat reads as missing until it is re-run, with that reason (eval/p4_runner.py check_attempt); it never fires the rule. Every
control read is in the record, with its reasons (D-080, T078-05): a repeat's superseded attempts, those whose C was unhealthy or that were
replaced by a later sound one, are all listed in `controls`, with `judged` marking the one its harm came from, so keeping only the healthy C
does not drop the reference arm silently.

    ./venv/bin/python eval/p4_ladder.py ROOT --calibration REC --out knees.json [--unreachable 500 --why "2026-11-..: P4-S s2 ..."]
"""
import argparse
import json
import os
import re
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
EXIT = {"knee": 0, "no knee": 1, "incomplete": 3}


def _repeats(root, rows, named):
    """{(family, level, seed, label): [(attempt, {arm: index row})]} of the ladder's blocks, the halvings they ran at and the families
    their settings name (D-069)."""
    blocks, repeats, halvings, families = {}, {}, set(), set()
    for x in rows:
        blocks.setdefault(x["block_dir"], {})[x["arm"]] = x
    for block_dir, arms in sorted(blocks.items()):
        with open(os.path.join(root, block_dir, "block.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta["settings"]["calibration_sha256"] != named:
            raise ValueError(f"{block_dir} ran under calibration {meta['settings']['calibration_sha256'][:8]}, not the one named")
        halvings.add(meta["settings"]["halvings"])
        families.add(OUT.settings_families(meta["settings"]))
        family = next(a[2:] for a in meta["order"] if a.startswith("U_"))
        one = next(iter(arms.values()))
        if one["label"] not in R.ladder_labels(meta["sources"][family]):
            raise ValueError(f"{block_dir}: the label {one['label']!r} is not one of {R.ladder_labels(meta['sources'][family])} (T063-05)")
        repeats.setdefault((family, meta["sources"][family], one["block"], one["label"]), []).append((one["attempt"], arms))
    return repeats, halvings, families


def _harms(root, repeats, cal, families):
    """({family: {level: [harm per sound repeat]}}, {family: {level: [(seed, label) without a sound attempt]}}, the controls read)."""
    import calibrate as K
    harms, missing, controls = {f: {} for f in families}, {f: {} for f in families}, []
    for (family, level, seed, label), attempts in sorted(repeats.items()):
        if family not in harms:
            continue
        harm = None
        for attempt, arms in sorted(attempts, key=lambda a: a[0], reverse=True):     # newest first: the newest healthy C is judged
            c, u = arms.get(OUT.CONTROL), arms.get(f"U_{family}")
            if not (c and u and c["valid"] and u["valid"]):
                continue
            control = R.run_record(os.path.join(root, c["dir"]), cal, seed, attempt)
            row = {"family": family, "level": level, "seed": seed, "label": label, "attempt": attempt, "Q": control["Q"],
                   "reasons": control["control_reasons"], "judged": False}
            controls.append(row)                             # D-080 (T078-05): every readable attempt, superseded ones included
            if control["control_reasons"] or harm is not None:    # D-073 (3): an unhealthy C makes the attempt unsound
                continue
            attack = R.run_record(os.path.join(root, u["dir"]), cal, seed, attempt)
            harm = K.harm([control], attack, OUT.GATE["floor_pp"], OUT.GATE["floor_log2_p95"])[0] or 0.0
            row["judged"] = True
        if harm is None:
            missing[family].setdefault(level, []).append((seed, label))
        else:
            harms[family].setdefault(level, []).append(harm)
    return harms, missing, controls


def _ladder(root, record_path):
    """What the ladder of ROOT holds under the record: (record's status, its sha256, halvings, families, harms, missing, controls)."""
    cal, status = R.read_record(record_path)
    named = R.sha256_file(record_path)
    rows = [x for x in R.read_index(root) if x["phase"] == "ladder"]
    if not rows:
        raise ValueError(f"{root}: the index holds no ladder run")
    repeats, halvings, family_sets = _repeats(root, rows, named)
    if len(halvings) != 1:
        raise ValueError(f"the ladder ran at {sorted(halvings)} halvings: a ladder holds one")
    if len(family_sets) != 1:
        raise ValueError(f"the ladder's blocks name the families {sorted(list(x) for x in family_sets)}: a ladder holds one setting (D-069)")
    family_set = family_sets.pop()
    stray = sorted({f for f, *_rest in repeats} - set(family_set))
    if stray:
        raise ValueError(f"the ladder holds runs of {stray}, and its blocks run the families {list(family_set)} (D-069)")
    harms, missing, controls = _harms(root, repeats, cal, family_set)
    return status, named, halvings.pop(), family_set, harms, missing, controls


def next_allowed(root, record_path, family, level):
    """D-073 (1): may a ladder block of `family` at `level` run? The first ALWAYS_RUN levels always may; a higher one only once every lower
    level has 2 sound repeats and none of them is a knee. Returns None, or raises ValueError saying why not."""
    ladder = PT.FAMILIES[family]["levels"]
    lower = ladder[:ladder.index(level)]
    if len(lower) < PT.ALWAYS_RUN:
        return
    rows = [x for x in R.read_index(root) if x["phase"] == "ladder"]
    if rows:
        _status, _named, _h, _families, harms, _missing, _controls = _ladder(root, record_path)
        harms = harms.get(family, {})
    else:
        harms = {}
    short = [n for n in lower if len(harms.get(n, ())) < REPEATS]
    if short:
        raise ValueError(f"{family} {level} runs only once every lower level has {REPEATS} sound repeats and none is a knee (D-073 (1)): "
                         f"{short} {'has' if len(short) == 1 else 'have'} not")
    k = CAL.knee(sorted((n, harms[n]) for n in lower), 1.0, REPEATS)
    if k["level"] is not None:
        raise ValueError(f"{family} {level}: {int(k['level'])} is the knee, and a level above the knee does not run (D-073 (1))")


def _result(f, harms, missing, gone, controls=()):
    """One family's knee and status (see the module docstring), or ValueError for a reading D-067 refuses."""
    ladder = PT.FAMILIES[f]["levels"]
    reachable = [n for n in ladder if n not in gone]
    ran = sorted(set(harms) | set(missing))
    if not ran:
        raise ValueError(f"the ladder holds no run of {f}")
    k = CAL.knee(sorted(harms.items()), 1.0, REPEATS)
    level = None if k["level"] is None else int(k["level"])
    holes = [(n, seed, label) for n in ran if level is None or n <= level for seed, label in missing.get(n, ())]
    if holes:
        n, seed, label = holes[0]
        sick = next((c["reasons"][0] for c in reversed(controls) if (c.get("family"), c.get("level"), c["seed"], c["label"]) == (f, n, seed, label)
                     and c["reasons"]), None)
        raise ValueError(f"{f} {n}: repeat {label} on seed {seed} has no sound attempt, so no knee is read across it: re-run it, with its "
                         f"reason (D-067)" + (f"; its C was unhealthy (D-073 (3)): {sick}" if sick else "")
                         + (f"; also {[(h[0], h[2], h[1]) for h in holes[1:]]}" if holes[1:] else ""))
    short = [n for n in ran if level is None and len(harms.get(n, ())) < REPEATS]
    if short:
        raise ValueError(f"{f}: no level passes, but level(s) {short} have fewer than {REPEATS} sound repeats, so no knee is not read either (D-067)")
    skipped = [n for n in ladder if level is not None and n < level and len(harms.get(n, ())) < REPEATS]
    if skipped:
        raise ValueError(f"{f}: the knee would be {level}, but level(s) {skipped} under it have not run {REPEATS} repeats")
    out = {"status": "knee", "level": level, "next_level": None, "top": None, "not_reachable": sorted(gone)}
    if level is None:
        not_run = [n for n in reachable if n not in harms]
        if not_run:
            out.update(status="incomplete", next_level=not_run[0])
        else:
            out.update(status="no knee", top=reachable[-1])
    return out, k


def check_unreachable(unreachable, family_set, harms, missing):
    """D-073 (5): --unreachable names only a ladder's top, above its always-run levels, that has not run, with a dated reading."""
    for f, spec in unreachable.items():
        if f not in family_set:
            raise ValueError(f"--unreachable: {f} is not a family of this ladder {list(family_set)}")
        ladder = PT.FAMILIES[f]["levels"]
        for n in spec["levels"]:
            if n != ladder[-1] or len(ladder) <= PT.ALWAYS_RUN:
                raise ValueError(f"--unreachable {n}: only {f}'s top, {ladder[-1]}, above its first {PT.ALWAYS_RUN} levels, can be named not "
                                 "reachable, by P4-S s2's feasibility reading (D-073 (5))")
            if n in harms.get(f, {}) or n in missing.get(f, {}):
                raise ValueError(f"--unreachable {n}: {f} {n} has run, so it is not 'not reachable' (D-073 (5))")
        if not re.search(r"\d{4}-\d{2}-\d{2}", spec.get("why") or ""):
            raise ValueError("--unreachable needs --why naming the dated reading that found the level not reachable (D-073 (5))")


def knees(root, record_path, unreachable=None):
    """The record --out writes, or ValueError: what stops it is named. `unreachable`: {family: {"levels": [top], "why": text}} (D-073 (5)).
    See the module docstring."""
    unreachable = unreachable or {}
    status, named, halvings, family_set, harms, missing, controls = _ladder(root, record_path)
    check_unreachable(unreachable, family_set, harms, missing)
    levels, no_knee, families, results = {}, {}, {}, {}
    for f in family_set:
        gone = tuple(unreachable.get(f, {}).get("levels", ()))
        res, k = _result(f, harms[f], missing[f], gone, controls)
        if gone:
            res["why_not_reachable"] = unreachable[f]["why"]
        results[f] = res
        levels[f] = res["level"]
        if res["level"] is None:
            no_knee[f] = {"why": k["why"], "top_level_run": PT.FAMILIES[f]["levels"][-1] in harms[f], "status": res["status"]}
        families[f] = {"rows": sorted(harms[f].items()), "passing": k["passing"], "monotone": k["monotone"],
                       "unsound_above_knee": sorted((n, seed, label) for n, rs in missing[f].items() for seed, label in rs)}
    return {"format": FORMAT, "levels": levels, "no_knee": no_knee, "results": results, "halvings": halvings, "family_set": list(family_set),
            "calibration_sha256": named, "calibration_status": status, "families": families, "controls": controls,
            "unreachable": unreachable}


def said(f, res):
    """One family's line of the tool's report."""
    name = OUT.FAMILY_NAMES[f]
    gone = f"; {', '.join(map(str, res['not_reachable']))} not reachable ({res.get('why_not_reachable')})" if res["not_reachable"] else ""
    if res["status"] == "knee":
        return f"  {f}: the knee is {res['level']} sources"
    if res["status"] == "incomplete":
        return f"  {f}: no knee yet: level {res['next_level']} runs next (D-073 (1)){gone}"
    return (f"  {f}: no knee up to {res['top']} sources: {name} below the default rules' thresholds did not harm profile R up to {res['top']} "
            f"sources (D-074, rule A): no validation and no campaign{gone}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root", help="the runner's root: index.jsonl and the ladder's runs")
    ap.add_argument("--calibration", required=True, help="the record the ladder ran under")
    ap.add_argument("--out", required=True)
    ap.add_argument("--unreachable", type=int, action="append", default=[], metavar="LEVEL",
                    help="loris's top, not reachable by P4-S s2's feasibility reading (D-073 (5)); needs --why")
    ap.add_argument("--family", default="loris", choices=OUT.FAMILIES, help="the family of --unreachable")
    ap.add_argument("--why", help="the dated reading that found --unreachable's level not reachable")
    args = ap.parse_args(argv)
    unreachable = {args.family: {"levels": sorted(set(args.unreachable)), "why": args.why}} if args.unreachable else {}
    if args.why and not args.unreachable:
        ap.error("--why goes with --unreachable")
    try:
        rec = knees(args.root, args.calibration, unreachable)
    except (ValueError, OSError, KeyError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"knees {rec['levels']}; halvings {rec['halvings']}; calibration {rec['calibration_status']}")
    for f, res in rec["results"].items():
        print(said(f, res))
    return max(EXIT[res["status"]] for res in rec["results"].values())


if __name__ == "__main__":
    sys.exit(main())

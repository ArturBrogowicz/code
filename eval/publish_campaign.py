#!/usr/bin/env python3
"""Copy a campaign into the repository (results/<id>/) so it can be committed.

    venv/bin/python eval/publish_campaign.py <campaign_dir> [--name ID] [--force]
    venv/bin/python eval/publish_campaign.py <run_contract_dir> [<run_contract_dir> ...] --name ID
        [--calibration FILE] [--with PATH ...] [--force]

A suite campaign (eval/run_campaign.py: a provenance.json per run). Copies campaign.json (if any) and, per run,
provenance.json, scenario_results.csv, availability.csv, availability_raw.csv, metrics.csv, server_requests.csv (the load
the server received), ban_events.jsonl, daemon.log, console.log (ANSI colour codes stripped) and DONE; then regenerates
analysis/ in the copy with eval/analyze_campaign.py and eval/plot_campaign.py and writes SHA256SUMS. If the source
already had an analysis/, the regenerated one must match it byte for byte (proof that the published numbers come from the
published data). The figures are the only step that needs matplotlib; without it the copy has no analysis/figures/ and
says so.

A run-contract directory (bench/executor.py, bench/calibrate.py, bench/gate_campaign.py: plan.json, run.json,
environment.json and DONE per run, no provenance.json). Each one given is copied as it is, every file, into
results/<id>/<its name>/: the runs cut before their run.json, the runs kept aside (U.failed1) and empty files included.
`--with` copies a further file or directory as it is beside them (a README.md, step logs, pre-registration texts). The
provenance is what the runs record: analysis/runs.json lists, per run, its state (complete, ended without DONE, failed with
the executor's FAILED, cut), the executor's verdict, and the commit, tree state, host and calibration hash of its
environment.json, run.json and plan.json.
A drift check (<dir>/drift/drift.json, judging drift/legit/C and drift/attack_<family>/U) is judged again from the
published runs with bench/calibrate.py's own functions against the frozen record the runs name (found under
bench/calibration/ by its sha256, or --calibration), and analysis/drift.json holds both verdicts and says whether they
agree apart from created_utc, waits and smoke. A drift directory without drift.json has no verdict (the step was cut);
the Q and p95 of its complete runs are reported as descriptive only, never as a verdict. No other kind of run is judged.

Nothing outside results/<id>/ is touched; committing is left to you.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import campaign as C

REPO = os.path.dirname(HERE)                 # where results/ is written
CODE = os.path.dirname(HERE)                 # where bench/ and the frozen records are read
RUN_FILES = ["provenance.json", "scenario_results.csv", "availability.csv",
             "availability_raw.csv", "metrics.csv", "server_requests.csv", "ban_events.jsonl",
             "daemon.log", "console.log", "DONE"]
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
WARN_BYTES, MAX_BYTES = 20 << 20, 100 << 20
RUN_MARKERS = ("plan.json", "run.json", "FAILED")   # only the run contract writes these
RESERVED = ("analysis", "SHA256SUMS")
DRIFT_NOT_COMPARED = ("created_utc", "waits", "smoke")
HOST_FACTS = ("uname", "cpus", "mem_mib", "nginx", "gunicorn", "python")


def tree_hashes(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root)
            if rel != "SHA256SUMS":
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return dict(sorted(out.items()))


def regenerate(campaign_dir, out_dir):
    """analysis/ of a suite campaign: the tables, then the figures, which alone need matplotlib. False when they could not
    be made."""
    from analyze_campaign import analyse
    analyse(campaign_dir, out_dir)
    try:
        from plot_campaign import plot_all
    except ImportError as exc:
        print(f"[!] no figures ({exc}): analysis/figures/ is missing from this copy; regenerate it where matplotlib "
              "is installed before committing")
        return False
    plot_all(campaign_dir, os.path.join(out_dir, "figures"))
    return True


def finish(dst, force):
    """SHA256SUMS over the copy and the size limits; returns (files, bytes), or exits when the copy is too large."""
    hashes = tree_hashes(dst)
    with open(os.path.join(dst, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.writelines(f"{h}  {rel}\n" for rel, h in hashes.items())
    size = sum(os.path.getsize(os.path.join(dst, rel)) for rel in hashes)
    if size > MAX_BYTES and not force:
        shutil.rmtree(dst)
        sys.exit(f"{size / 2**20:.1f} MB is too large to commit (use --force to keep it)")
    if size > WARN_BYTES:
        print(f"[!] {size / 2**20:.1f} MB — consider Git LFS or publishing a subset")
    rel = os.path.relpath(dst, REPO)
    print(f"[+] published {len(hashes)} files ({size / 2**20:.2f} MB) to {rel}/\n"
          f"    review, then: git add {rel} && git commit")
    return len(hashes), size


def publish_suite(src, dst, force):
    runs = C.find_runs(src)
    if not runs:
        sys.exit(f"no runs (provenance.json) under {src}")
    single = len(runs) == 1 and os.path.isfile(os.path.join(src, "provenance.json"))
    os.makedirs(dst)
    for extra in ("campaign.json", "README.md"):
        if os.path.isfile(os.path.join(src, extra)):
            shutil.copy2(os.path.join(src, extra), dst)
    for _, run, rdir in runs:
        target = dst if single else os.path.join(dst, os.path.relpath(rdir, src))
        os.makedirs(target, exist_ok=True)
        for f in RUN_FILES:
            p = os.path.join(rdir, f)
            if not os.path.isfile(p):
                continue
            if f == "console.log":
                with open(p, encoding="utf-8", errors="replace") as fh:
                    text = ANSI.sub("", fh.read())
                with open(os.path.join(target, f), "w", encoding="utf-8") as fh:
                    fh.write(text)
            else:
                shutil.copy2(p, target)
    regenerate(dst, os.path.join(dst, "analysis"))
    src_analysis = os.path.join(src, "analysis")
    if os.path.isdir(src_analysis):
        a, b = tree_hashes(src_analysis), tree_hashes(os.path.join(dst, "analysis"))
        differ = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        if differ:
            print("[!] analysis/ of the source differs from the one regenerated from the "
                  "published data (stale source analysis?):\n    " + "\n    ".join(differ))
        else:
            print(f"[+] analysis/ reproduces byte for byte from the published data ({len(a)} files)")
    finish(dst, force)


# --- run-contract directories ---------------------------------------------------------------------------------------

def is_run_contract(path):
    """A tree the run contract wrote: no run of the suite layout, and a plan.json, run.json or FAILED somewhere in it."""
    if not os.path.isdir(path) or C.find_runs(path):
        return False
    return any(m in files for _, _, files in os.walk(path) for m in RUN_MARKERS)


def read_json(path):
    """(object, None), or (None, why): absent, or unreadable (a file cut by a host reset can be empty)."""
    if not os.path.isfile(path):
        return None, "absent"
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as exc:
        return None, f"unreadable ({os.path.getsize(path)} bytes, {exc.__class__.__name__})"


def harm_tools():
    """bench/calibrate.py, bench/calibration.py and eval/harm_gate.py, imported only for a drift check."""
    for sub in ("eval", "bench"):
        path = os.path.join(CODE, sub)
        if path not in sys.path:
            sys.path.insert(0, path)
    import calibrate as K
    import calibration as CAL
    import harm_gate as H
    return K, CAL, H


def run_dirs(root):
    """Every run directory under `root`: a directory that holds a plan.json, a run.json or a FAILED."""
    return sorted(d for d, _, files in os.walk(root) if any(m in files for m in RUN_MARKERS))


def run_record(run_dir, root):
    """What a run records about itself, read from its own files: its provenance in place of provenance.json."""
    got = {name: read_json(os.path.join(run_dir, name)) for name in ("environment.json", "plan.json", "run.json", "DONE")}
    env, plan, meta = (got[n][0] or {} for n in ("environment.json", "plan.json", "run.json"))
    has_run, has_done = got["run.json"][0] is not None, os.path.isfile(os.path.join(run_dir, "DONE"))
    failed = None
    if os.path.isfile(os.path.join(run_dir, "FAILED")):          # the executor's record of a run it could not carry out
        with open(os.path.join(run_dir, "FAILED"), encoding="utf-8", errors="replace") as fh:
            failed = fh.read().strip()
    state = ("complete" if has_run and has_done else "ended without DONE" if has_run else
             "failed before run.json" if failed is not None else "cut before run.json")
    executor, git, facts = meta.get("executor") or {}, env.get("git") or {}, env.get("facts") or {}
    named = sorted({h for h in (meta.get("calibration_sha256"), plan.get("calibration_sha256"),
                                env.get("calibration_sha256")) if h})
    return {"dir": os.path.relpath(run_dir, root),
            "state": state, "failed": failed, "executor_ok": executor.get("ok"), "executor_reasons": executor.get("reasons"),
            "role": meta.get("role"), "started_utc": meta.get("started_utc"),
            "kind": plan.get("kind"), "scenario": plan.get("scenario"), "seed": plan.get("seed"), "level": plan.get("level"),
            "timeline": plan.get("timeline"), "calibration_sha256": named,
            "commit": git.get("commit"), "dirty": git.get("dirty"), "dirty_files": git.get("dirty_files"),
            "checked_utc": env.get("checked_utc"), "host": {k: facts.get(k) for k in HOST_FACTS if k in facts},
            "files_missing_or_unreadable": {n: why for n, (_, why) in got.items() if why}}


def provenance_of(records):
    """What every run of a source has in common, and where they differ: the commits, the tree state, the hosts."""
    def values(get):
        return sorted({json.dumps(get(r), sort_keys=True) for r in records if get(r) is not None})
    return {"runs": len(records),
            "states": {s: sum(r["state"] == s for r in records) for s in sorted({r["state"] for r in records})},
            "commits": [json.loads(v) for v in values(lambda r: r["commit"])],
            "dirty": [json.loads(v) for v in values(lambda r: r["dirty"])],
            "calibration_sha256": sorted({h for r in records for h in r["calibration_sha256"]}),
            "host": {k: [json.loads(v) for v in values(lambda r, k=k: r["host"].get(k))] for k in HOST_FACTS},
            "checked_utc": [min((r["checked_utc"] for r in records if r["checked_utc"]), default=None),
                            max((r["checked_utc"] for r in records if r["checked_utc"]), default=None)]}


def named_records(sources):
    """The calibration hashes the runs and the drift verdicts of the copied sources name."""
    names = set()
    for src in sources:
        for d in run_dirs(src):
            names.update(run_record(d, src)["calibration_sha256"])
        recorded, _ = read_json(os.path.join(src, "drift", "drift.json"))
        if recorded and recorded.get("calibration_sha256"):
            names.add(recorded["calibration_sha256"])
    return names


def frozen_record(names, path=None):
    """(record, path) of the frozen calibration record the runs name: `path`, or the one under bench/calibration/ whose
    sha256 is that name. Exits when the runs name none or several, or when no frozen record has that hash."""
    _, CAL, _ = harm_tools()
    if len(names) != 1:
        sys.exit(f"the runs name {len(names)} calibration records ({', '.join(sorted(names)) or 'none'}); "
                 "a drift check is judged against exactly one")
    want = next(iter(names))
    candidates = [path] if path else sorted(glob.glob(os.path.join(CODE, "bench", "calibration", "*.json")))
    for p in candidates:
        try:
            cal = CAL.load(p)
        except (OSError, ValueError, KeyError, TypeError) as exc:       # calibration.RecordError is a ValueError
            if path:
                sys.exit(f"{p}: not a valid calibration record ({exc})")
            continue
        if cal.get("status") == "frozen" and cal.get("sha256") == want:
            return cal, p
        if path:
            sys.exit(f"{p} has sha256 {cal.get('sha256')} and status {cal.get('status')}; the runs name the frozen {want}")
    sys.exit(f"no frozen record with sha256 {want} under {os.path.join(CODE, 'bench', 'calibration')} (give --calibration)")


def same(a, b):
    if isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return a == b
    return abs(a - b) <= 1e-9 * max(1.0, abs(a), abs(b))


def drift_differences(recorded, judged):
    """The fields of a recorded drift.json that the verdict judged again from the runs does not reproduce."""
    out = [k for k in ("ok", "reasons", "calibration_sha256") if recorded.get(k) != judged.get(k)]
    out += [f"legit.{k}" for k in ("Q", "p95_s", "requests") if not same((recorded.get("legit") or {}).get(k), judged["legit"][k])]
    have = recorded.get("attacks") or {}
    for family in sorted(set(have) | set(judged["attacks"])):
        if family not in have or family not in judged["attacks"]:
            out.append(f"attacks.{family}")
            continue
        out += [f"attacks.{family}.{k}" for k in ("level", "Q", "p95_s", "requests")
                if not same(have[family].get(k), judged["attacks"][family].get(k))]
    return out


def run_metrics(run_dir, kind, cal):
    """Q, p95 and the number of requests of one run, by the calibration runner's own functions; (None, why) when the run
    cannot be read as the run contract."""
    K, _, H = harm_tools()
    try:
        if kind == "legit":
            return K.probe_metrics(H.read_run(run_dir), cal), None
        plan, why = read_json(os.path.join(run_dir, "plan.json"))
        if why:
            return None, f"plan.json {why}"
        return K.attack_metrics(types.SimpleNamespace(out=run_dir, timeline=plan["timeline"]), cal), None
    except (H.GateError, OSError, ValueError, KeyError, TypeError) as exc:
        return None, f"{exc.__class__.__name__}: {exc}"


def judge_drift(src, cal):
    """The drift verdict of one copied directory, judged again from its runs, beside the recorded one."""
    K, _, _ = harm_tools()
    base = os.path.join(src, "drift")
    recorded, why = read_json(os.path.join(base, "drift.json"))
    runs, problems = {}, []
    parts = [("legit", "legit", os.path.join(base, "legit", "C"))]
    parts += [(name[len("attack_"):], "attack", os.path.join(base, name, "U"))
              for name in sorted(os.listdir(base)) if name.startswith("attack_")]
    for key, kind, d in parts:
        complete = os.path.isfile(os.path.join(d, "run.json")) and os.path.isfile(os.path.join(d, "DONE"))
        m, err = run_metrics(d, kind, cal) if complete else (None, "no complete run (run.json and DONE)")
        if m is not None and kind == "attack":
            plan, _ = read_json(os.path.join(d, "plan.json"))
            m = {"level": plan.get("level"), **m}
        runs[key] = m
        if err:
            problems.append(f"{key}: {err}")
    out = {"dir": os.path.basename(src), "recorded": recorded, "recorded_file": "absent" if why == "absent" else why}
    if recorded is None:
        out.update(verdict="no verdict (the step was cut: no drift.json)", judged=None,
                   descriptive_not_a_verdict={k: v for k, v in runs.items() if v is not None}, problems=problems)
        return out
    if problems or runs.get("legit") is None:
        out.update(verdict="recorded, but it cannot be judged again from the published runs", judged=None,
                   problems=problems, agree=False, differences=["runs"])
        return out
    legit = {k: runs["legit"][k] for k in ("Q", "p95_s", "requests")}
    attacks = {f: m for f, m in runs.items() if f != "legit"}
    judged = {"calibration_sha256": cal["sha256"], "legit": legit, "attacks": attacks,
              **K.drift_check(cal, legit, {f: {"Q": m["Q"], "p95_s": m["p95_s"]} for f, m in attacks.items()})}
    differences = drift_differences(recorded, judged)
    out.update(verdict=f"recorded ok={recorded.get('ok')}", judged=judged, agree=not differences,
               differences=differences, not_compared=list(DRIFT_NOT_COMPARED), problems=problems)
    return out


def drift_markdown(name, cal_path, cal, drifts, records):
    def qp(m):
        return f"{m['Q']:.2f} / {m['p95_s']:.3f} s (n {m['requests']})" if m else "–"
    lines = [f"# {name}: run-contract directories, judged again from the published runs", "",
             f"Record: `{cal_path}` (sha256 field `{cal['sha256']}`)." if cal else "No drift check, no record.", ""]
    if drifts:
        families = sorted({f for d in drifts for f in [*((d.get("judged") or {}).get("attacks") or {}),
                                                        *((d.get("recorded") or {}).get("attacks") or {}),
                                                        *(d.get("descriptive_not_a_verdict") or {})] if f != "legit"})
        lines += ["| directory | verdict | judged again | agree | legit Q / p95 | " + " | ".join(families) + " |",
                  "|---|---|---|---|---|" + "---|" * len(families)]
        for d in drifts:
            j = d.get("judged")
            src = j or d.get("descriptive_not_a_verdict") or {}
            att = (j or {}).get("attacks") or {k: v for k, v in src.items() if k != "legit"}
            lines.append(f"| {d['dir']} | {d['verdict']} | {'ok=' + str(j['ok']) if j else 'none'} | "
                         f"{d.get('agree', '–')} | {qp(src.get('legit'))} | " +
                         " | ".join(qp(att.get(f)) for f in families) + " |")
        lines += ["", ("Q in %, p95 in s. A row without a verdict lists its complete runs as descriptive only."
                       f" Not compared: {', '.join(DRIFT_NOT_COMPARED)}."), ""]
        for d in drifts:
            if d.get("judged"):
                lines.append(f"- {d['dir']}: reasons judged again: " + ("; ".join(d["judged"]["reasons"]) or "none"))
            if d.get("differences"):
                lines.append(f"- {d['dir']}: DIFFERS from the recorded verdict in {', '.join(d['differences'])}")
            for p in d.get("problems") or []:
                lines.append(f"- {d['dir']}: {p}")
        lines.append("")
    lines += ["| run | state | executor ok | commit | dirty | kernel | mem_mib |", "|---|---|---|---|---|---|---|"]
    for r in records:
        kernel = (r["host"].get("uname") or "").split(" ")[2:3]
        lines.append(f"| {r['dir']} | {r['state']} | {r['executor_ok']} | {(r['commit'] or '–')[:7]} | {r['dirty']} | "
                     f"{kernel[0] if kernel else '–'} | {r['host'].get('mem_mib', '–')} |")
    return "\n".join(lines) + "\n"


def publish_run_contract(sources, extras, dst, force, calibration=None):
    names = [os.path.basename(os.path.normpath(p)) for p in sources + extras]
    clash = sorted({n for n in names if names.count(n) > 1 or n in RESERVED})
    if clash:
        sys.exit(f"these names would collide in the copy: {', '.join(clash)}")
    for p in sources + extras:
        if not os.path.exists(p):
            sys.exit(f"{p} does not exist")
        links = [os.path.join(d, n) for d, dirs, files in os.walk(p) for n in dirs + files if os.path.islink(os.path.join(d, n))]
        if os.path.islink(p) or links:
            sys.exit(f"{p} holds symbolic links ({', '.join(links[:3]) or p}); publish plain files")
    drift_sources = [s for s in sources if os.path.isdir(os.path.join(s, "drift"))]
    cal, cal_path = frozen_record(named_records(drift_sources), calibration) if drift_sources else (None, None)
    os.makedirs(dst)
    for p in sources + extras:
        target = os.path.join(dst, os.path.basename(os.path.normpath(p)))
        if os.path.isdir(p):
            shutil.copytree(p, target)
        else:
            shutil.copy2(p, target)
    copied = [os.path.join(dst, os.path.basename(os.path.normpath(s))) for s in sources]
    records, per_source = [], {}
    for src in copied:
        mine = [run_record(d, dst) for d in run_dirs(src)]
        records += mine
        per_source[os.path.basename(src)] = provenance_of(mine)
        p = per_source[os.path.basename(src)]
        print(f"[+] {os.path.basename(src)}: {p['runs']} runs ({', '.join(f'{n} {s}' for s, n in p['states'].items())}); "
              f"commit {', '.join(c[:7] for c in p['commits']) or 'none recorded'}; dirty {p['dirty'] or 'not recorded'}; "
              f"kernel {', '.join(sorted({u.split(' ')[2] for u in p['host']['uname'] if len(u.split(' ')) > 2})) or '–'}; "
              f"mem_mib {', '.join(map(str, p['host']['mem_mib'])) or '–'}")
    drifts = [judge_drift(src, cal) for src in copied if os.path.isdir(os.path.join(src, "drift"))]
    for d in drifts:
        if d["judged"] is None and d["recorded"] is None:
            print(f"[!] {d['dir']}: {d['verdict']}; complete runs reported as descriptive only: "
                  f"{', '.join(sorted(d['descriptive_not_a_verdict'])) or 'none'}")
        elif d["judged"] is None:
            print(f"[!] {d['dir']}: {d['verdict']}: {'; '.join(d['problems'])}")
        elif d["agree"]:
            print(f"[+] {d['dir']}: {d['verdict']}; judged again from the published runs: ok={d['judged']['ok']}; "
                  f"the two agree apart from {', '.join(DRIFT_NOT_COMPARED)}")
        else:
            print(f"[!] {d['dir']}: {d['verdict']}; judged again: ok={d['judged']['ok']}; they DIFFER in "
                  f"{', '.join(d['differences'])}")
    analysis = os.path.join(dst, "analysis")
    os.makedirs(analysis)
    cal_note = None
    if cal is not None:
        with open(cal_path, "rb") as fh:
            file_sha256 = hashlib.sha256(fh.read()).hexdigest()
        inside = os.path.abspath(cal_path).startswith(CODE + os.sep)
        cal_note = {"path": os.path.relpath(cal_path, CODE) if inside else cal_path, "sha256_field": cal["sha256"],
                    "file_sha256": file_sha256}
    with open(os.path.join(analysis, "runs.json"), "w", encoding="utf-8") as fh:
        json.dump({"sources": per_source, "runs": records}, fh, indent=1, sort_keys=True)
        fh.write("\n")
    if drifts:
        with open(os.path.join(analysis, "drift.json"), "w", encoding="utf-8") as fh:
            json.dump({"calibration": cal_note, "rule": "bench/calibrate.py drift_check (docs/HG1C_DESIGN.md departure 33)",
                       "not_compared": list(DRIFT_NOT_COMPARED), "attempts": drifts}, fh, indent=1, sort_keys=True)
            fh.write("\n")
    with open(os.path.join(analysis, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(drift_markdown(os.path.basename(dst), cal_note and cal_note["path"], cal, drifts, records))
    return finish(dst, force)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("campaign", nargs="+", help="a suite campaign; or one or more run-contract directories")
    ap.add_argument("--name", help="results/<name> (default: the campaign directory name)")
    ap.add_argument("--force", action="store_true", help="replace an existing results/<name>, "
                    "or publish more than 100 MB")
    ap.add_argument("--calibration", help="run-contract directories: the frozen record the runs name "
                    "(default: the one under bench/calibration/ with that sha256)")
    ap.add_argument("--with", dest="extras", action="append", default=[], metavar="PATH",
                    help="run-contract directories: a file or directory copied as it is beside them")
    args = ap.parse_args()
    sources = [os.path.abspath(s) for s in args.campaign]
    contract = [is_run_contract(s) for s in sources]
    if any(contract) and not all(contract):
        sys.exit("give either one suite campaign or run-contract directories, not both: " +
                 ", ".join(s for s, c in zip(sources, contract, strict=True) if not c))
    if not any(contract) and (len(sources) > 1 or args.extras or args.calibration):
        sys.exit("several directories, --with and --calibration are for run-contract directories")
    if len(sources) > 1 and not args.name:
        sys.exit("several directories need --name")
    name = args.name or os.path.basename(sources[0])
    dst = os.path.join(REPO, "results", name)
    if os.path.exists(dst):
        if not args.force:
            sys.exit(f"{dst} exists (use --force to replace it)")
        shutil.rmtree(dst)
    if all(contract):
        publish_run_contract(sources, [os.path.abspath(p) for p in args.extras], dst, args.force, args.calibration)
    else:
        publish_suite(sources[0], dst, args.force)


if __name__ == "__main__":
    main()

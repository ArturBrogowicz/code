#!/usr/bin/env python3
"""Run an evaluation campaign: every mode x N runs of test_distributed_suite.py,
interleaved in seeded random blocks, each run in its own results directory.

    sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 \\
        --modes xdp,iptables,nginxlimits,unprotected --runs 3 [--attack-duration 30]

Block b runs every mode once, in a random order drawn from --order-seed, with
PROFILE_SEED = --seed-base + b, so the runs of a block share their client-profile plan
and can be compared pairwise. Each run's console goes to <run>/console.log.

--loads wrk,loadgen:50,loadgen:100 makes the HTTP flood's load model a factor of the block
(EXP-C): every (mode, load) pair runs once per block, in a random order, as <mode>@<tool><rate>
(requests/s per bot; a cell is `wrk`, the closed-loop default, or a verified open-loop tool and
its rate). Without it the plan is exactly what it always was.
Re-running the same command resumes the campaign: runs with a DONE file are skipped.

Evaluation variables inherited from the environment are cleared, so every setting is
explicit and recorded in campaign.json (overrides: --set NAME=VALUE). The campaign
refuses to start on uncommitted changes to tracked files (unless --allow-dirty) or
while a previous testbed is still present. Standard library only. See
docs/EVALUATION.md.
"""
import argparse
import datetime
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = os.path.join(REPO, "test_distributed_suite.py")
MODE_ENV = {
    "xdp": {},
    "iptables": {"MITIGATION_BACKEND": "iptables"},
    "nginxlimits": {"MITIGATION_MODE": "none", "NGINX_PROTECTED": "1"},
    "unprotected": {"MITIGATION_MODE": "none"},
}
EVAL_VARS = ("MITIGATION_MODE", "MITIGATION_BACKEND", "NGINX_PROTECTED", "OPERATING_POINT",
             "GUNICORN_WORKERS", "GUNICORN_THREADS", "WRK_CONNS", "WRK_THREADS",
             "BOTNET_COUNT", "SERVER_CPUS", "ATTACK_CPUS", "ATTACK_DURATION", "PROFILE_SEED",
             "FLOOD_TOOL", "FLOOD_RATE", "RESULTS_DIR", "RESULTS_ROOT", "ONLY_SCENARIOS", "GRU_ONLY",
             "BAN_EVENTS")
SETTABLE = ("GUNICORN_WORKERS", "GUNICORN_THREADS", "WRK_CONNS", "WRK_THREADS",
            "BOTNET_COUNT", "SERVER_CPUS", "ATTACK_CPUS", "GRU_ONLY", "FLOOD_TOOL", "FLOOD_RATE")
LOAD_TOOLS = ("wrk", "loadgen", "k6")     # the suite's FLOOD_TOOLS (a test pins that they agree)


def utc_now():
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def git(*args):
    """git output for the repository, or None (marked safe for this call: we run as root)."""
    try:
        r = subprocess.run(["git", "-c", f"safe.directory={REPO}", "-C", REPO, *args],
                           capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def leftovers():
    """Testbed remains that would contaminate the next run (namespaces, processes)."""
    found = []
    r = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True, check=False)
    found += [f"netns {ln.split()[0]}" for ln in r.stdout.splitlines()
              if ln.strip() and re.match(r"(server_ns|legit_|bot_)", ln)]
    for pattern in ("nginx: (master|worker) process", "control_plane.py", "hping3",
                    "bench/loadgen.py"):
        r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False)
        found += [f"process '{pattern}' pid {p}" for p in r.stdout.split()]
    for name in ("wrk", "k6"):
        r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True, check=False)
        found += [f"process {name} pid {p}" for p in r.stdout.split()]
    return found


def chown_tree(path):
    """Hand results to the user who ran sudo, so analysis/publishing need no root."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (uid and gid and os.path.exists(path)):
        return
    for root, dirs, files in os.walk(path):
        for p in [root] + [os.path.join(root, n) for n in dirs + files]:
            try:
                os.chown(p, int(uid), int(gid))
            except OSError:
                pass


def parse_loads(text):
    """The load-model cells of --loads: [{"spec", "tool", "rate", "suffix"}]. A cell is `wrk` (the
    closed-loop default, no rate) or `<tool>:<requests/s per bot>` for an open-loop tool; the
    suffix is what the suite adds to the mode label (test_distributed_suite._flood_suffix)."""
    cells = []
    for item in (x.strip() for x in text.split(",") if x.strip()):
        tool, _, raw = item.partition(":")
        tool, raw = tool.strip(), raw.strip()
        if tool not in LOAD_TOOLS:
            raise ValueError(f"--loads {item!r}: unknown tool (known: {', '.join(LOAD_TOOLS)})")
        if tool == "wrk":
            if raw:
                raise ValueError(f"--loads {item!r}: wrk is closed-loop and takes no rate")
            cells.append({"spec": "wrk", "tool": "wrk", "rate": 0.0, "suffix": ""})
            continue
        try:
            rate = float(raw)
        except ValueError:
            rate = 0.0
        if not 0 < rate < float("inf"):
            raise ValueError(f"--loads {item!r}: {tool} needs a rate, requests/s per bot")
        cells.append({"spec": f"{tool}:{rate:g}", "tool": tool, "rate": rate,
                      "suffix": f"@{tool}{rate:g}"})
    if not cells:
        raise ValueError("--loads: no cell")
    if len({c["spec"] for c in cells}) != len(cells):
        raise ValueError(f"--loads {text!r}: a cell is listed twice")
    return cells


def check_loads(loads):
    """Exit unless every open-loop tool of the cells is `verified` in bench/loadtools.json and its
    binary is the pinned one: the rule the suite applies before it starts."""
    tools = sorted({c["tool"] for c in loads if c["tool"] != "wrk"})
    if not tools:
        return
    sys.path.insert(0, os.path.join(REPO, "bench"))
    import loadtools
    try:
        manifest = loadtools.load_manifest()
        for tool in tools:
            loadtools.resolve_tool(manifest, tool)
    except (loadtools.ToolError, OSError, ValueError) as exc:
        sys.exit(f"--loads: {exc}")


def build_plan(modes, runs, order_seed, seed_base, loads=None):
    """The runs of the campaign. With `loads` (parse_loads cells) every block runs every
    (mode, load) pair once; without, every mode once, exactly as before."""
    rng = random.Random(order_seed)
    plan = []
    for block in range(1, runs + 1):
        if loads is None:
            order = list(modes)
            rng.shuffle(order)
            plan += [{"block": block, "mode": m, "profile_seed": seed_base + block,
                      "dir": f"{m}/run{block}"} for m in order]
            continue
        cells = [(m, c) for m in modes for c in loads]
        rng.shuffle(cells)
        plan += [{"block": block, "mode": m, "load": c["spec"], "profile_seed": seed_base + block,
                  "dir": f"{m}{c['suffix']}/run{block}"} for m, c in cells]
    return plan


def make_settings(args, overrides, loads=None):
    """The campaign's settings as recorded in campaign.json (a resume must match them). `loads`
    is recorded only when it is not the default, so earlier campaigns still resume."""
    settings = {"modes": [m.strip() for m in args.modes.split(",") if m.strip()], "runs": args.runs,
                "scenarios": args.scenarios, "operating_point": args.operating_point,
                "attack_duration": args.attack_duration, "seed_base": args.seed_base,
                "order_seed": args.order_seed, "set": overrides}
    if loads is not None:
        settings["loads"] = [c["spec"] for c in loads]
    return settings


def run_env(args, overrides, item, run_dir):
    env = {k: v for k, v in os.environ.items() if k not in EVAL_VARS}
    env.update(MODE_ENV[item["mode"]])
    env.update({"OPERATING_POINT": args.operating_point,
                "PROFILE_SEED": str(item["profile_seed"]),
                "RESULTS_DIR": run_dir})
    if item.get("load"):
        cell = parse_loads(item["load"])[0]
        env["FLOOD_TOOL"] = cell["tool"]
        if cell["rate"]:
            env["FLOOD_RATE"] = f"{cell['rate']:g}"
    if args.scenarios:
        env["ONLY_SCENARIOS"] = args.scenarios
    if args.attack_duration:
        env["ATTACK_DURATION"] = f"{args.attack_duration:g}"
    env.update(overrides)
    return env


def write_json(path, obj):
    with open(path + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)
        fh.write("\n")
    os.replace(path + ".tmp", path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--modes", default="xdp,iptables,nginxlimits,unprotected",
                    help="comma-separated: " + ", ".join(MODE_ENV))
    ap.add_argument("--runs", type=int, default=3, help="runs (blocks) per mode")
    ap.add_argument("--scenarios", default="", help="ONLY_SCENARIOS, e.g. 4 or 4,7,8,9 (default all)")
    ap.add_argument("--operating-point", default="default", help="default | knee")
    ap.add_argument("--attack-duration", type=float, default=0.0,
                    help="ATTACK_DURATION in s (0 = historical: stop on ban)")
    ap.add_argument("--seed-base", type=int, default=0, help="PROFILE_SEED = seed-base + block")
    ap.add_argument("--order-seed", type=int, default=0, help="seed of the mode order per block")
    ap.add_argument("--set", action="append", default=[], metavar="NAME=VALUE",
                    help="override a setting for every run: " + ", ".join(SETTABLE))
    ap.add_argument("--loads", default="", metavar="CELLS",
                    help="load models of the HTTP flood, as cells of the block: wrk (closed-loop, "
                         "the default) and TOOL:RATE per bot, e.g. wrk,loadgen:50,loadgen:100")
    ap.add_argument("--out", help="campaign directory (default /var/tmp/ddos_campaigns/<UTC>_...)")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run despite uncommitted changes to tracked files (recorded)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exit")
    args = ap.parse_args()

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    unknown = [m for m in modes if m not in MODE_ENV]
    if unknown or not modes or args.runs < 1:
        sys.exit(f"bad --modes/--runs (unknown modes: {unknown}; known: {', '.join(MODE_ENV)})")
    overrides = {}
    for item in args.set:
        name, sep, value = item.partition("=")
        if not sep or name not in SETTABLE:
            sys.exit(f"--set {item!r}: expected NAME=VALUE with NAME in {', '.join(SETTABLE)}")
        overrides[name] = value
    loads = None
    if args.loads:
        try:
            loads = parse_loads(args.loads)
        except ValueError as exc:
            sys.exit(str(exc))
        if {"FLOOD_TOOL", "FLOOD_RATE"} & set(overrides):
            sys.exit("--loads sets the flood of every run; do not combine it with --set FLOOD_*")
        if [c["spec"] for c in loads] == ["wrk"]:
            loads = None                     # the default cell: the plan stays what it always was
        else:
            check_loads(loads)
    plan = build_plan(modes, args.runs, args.order_seed, args.seed_base, loads)
    settings = make_settings(args, overrides, loads)
    if {"FLOOD_TOOL", "FLOOD_RATE"} & set(overrides):    # one load model for every run
        tool, rate = overrides.get("FLOOD_TOOL", "wrk"), overrides.get("FLOOD_RATE", "").strip()
        try:
            cell = parse_loads(tool if tool == "wrk" and rate in ("", "0") else f"{tool}:{rate}")
        except ValueError as exc:
            sys.exit(f"--set FLOOD_TOOL/FLOOD_RATE: {exc}")
        check_loads(cell)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    label = f"{args.operating_point}_s{(args.scenarios or 'all').replace(',', '-')}"
    out = os.path.abspath(args.out or os.path.join("/var/tmp/ddos_campaigns", f"{stamp}_{label}"))

    if args.dry_run:
        print(f"campaign: {out}\nsettings: {json.dumps(settings)}")
        for it in plan:
            env = run_env(args, overrides, it, os.path.join(out, it["dir"]))
            shown = {k: env[k] for k in EVAL_VARS if k in env}
            print(f"  block {it['block']:>2} {it['dir'].split('/')[0]:<12} {shown}")
        return

    if os.geteuid() != 0:
        sys.exit("run_campaign.py needs root (it runs the suite): sudo python3 eval/run_campaign.py ...")
    dirty = git("status", "--porcelain", "--untracked-files=no")
    if dirty and not args.allow_dirty:
        sys.exit(f"uncommitted changes to tracked files:\n{dirty}\ncommit them (results must map "
                 f"to a commit) or pass --allow-dirty")
    if left := leftovers():
        sys.exit("a previous testbed is still present (run the suite's cleanup or reboot):\n  "
                 + "\n  ".join(left))

    manifest_path = os.path.join(out, "campaign.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        if manifest.get("settings") != settings:
            sys.exit(f"{out} holds a campaign with different settings; use another --out")
        print(f"[*] Resuming campaign {out}")
    else:
        os.makedirs(out, exist_ok=True)
        manifest = {"schema": 1, "campaign_id": os.path.basename(out), "created_utc": utc_now(),
                    "command": sys.argv, "python": sys.executable, "settings": settings,
                    "plan": plan, "runs": {}}
    manifest.update(status="running", updated_utc=utc_now(),
                    git={"commit": git("rev-parse", "HEAD"),
                         "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                         "dirty": None if dirty is None else bool(dirty)})
    write_json(manifest_path, manifest)

    try:
        for i, it in enumerate(plan, 1):
            run_dir = os.path.join(out, it["dir"])
            if os.path.isfile(os.path.join(run_dir, "DONE")):
                print(f"[=] {i}/{len(plan)} {it['dir']}: done, skipping")
                continue
            if os.path.exists(run_dir):
                shutil.rmtree(run_dir)            # partial earlier attempt: start clean
            os.makedirs(run_dir)
            print(f"\n[*] {i}/{len(plan)} {it['dir']} (block {it['block']}, "
                  f"PROFILE_SEED={it['profile_seed']})", flush=True)
            t0 = time.time()
            env = run_env(args, overrides, it, run_dir)
            with open(os.path.join(run_dir, "console.log"), "w", encoding="utf-8") as log, \
                    subprocess.Popen([sys.executable, SUITE], cwd=REPO, env=env, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     errors="replace") as proc:
                try:
                    for line in proc.stdout:
                        sys.stdout.write(line)
                        log.write(line)
                except KeyboardInterrupt:
                    # Ctrl-C reached the suite too; keep reading its output until its own
                    # cleanup has finished (a closed pipe would break that cleanup).
                    print("\n[!] Interrupted: waiting for the suite to clean up...", flush=True)
                    for line in proc.stdout:
                        sys.stdout.write(line)
                        log.write(line)
                    proc.wait()
                    raise
                code = proc.wait()
            left = leftovers()
            done = {"exit_code": code, "seconds": round(time.time() - t0, 1),
                    "finished_utc": utc_now(), "leftovers": left}
            write_json(os.path.join(run_dir, "DONE"), done)
            manifest["runs"][it["dir"]] = done
            manifest["updated_utc"] = utc_now()
            write_json(manifest_path, manifest)
            chown_tree(run_dir)
            if left:
                sys.exit("testbed remains after the run; stopping:\n  " + "\n  ".join(left))
        manifest["status"] = "completed"
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
        print("\n[!] Interrupted; re-run the same command to resume.")
    finally:
        if manifest.get("status") == "running":
            manifest["status"] = "incomplete"
        manifest["updated_utc"] = utc_now()
        write_json(manifest_path, manifest)
        chown_tree(out)
    print(f"\n[+] Campaign {manifest['status']}: {out}\n    next:"
          f"\n      venv/bin/python eval/analyze_campaign.py {out}"
          f"\n      venv/bin/python eval/plot_campaign.py {out}"
          f"\n      venv/bin/python eval/publish_campaign.py {out}")


if __name__ == "__main__":
    main()

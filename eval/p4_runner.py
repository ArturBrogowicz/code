#!/usr/bin/env python3
"""The P4 runner (docs/P4_SLOW_DESIGN.md §4.3, §8, §10, §11, §13; T-023 report §6): the runs of P4 on profile R.

THIS IS A VM WORKLOAD (T3): it builds network namespaces, starts nginx, gunicorn, the mitigation daemon and the
generators, as root. Run it only with the user's approval of a VM step. `--plan` prints what it would do and touches
nothing; the tests drive it with a fake host (tests/p4_fake_host.py), as bench/executor.py's tests drive SimHost.

One run, per arm (eval/p4_outcome.ARMS; the validation runs are slow_pc.VALIDATION_RUNS):
  * the population of the seed (ml/p4_traffic.py build_plan: the benign mix of §4.2 and the sources of the families at
    the level given), the run's entities being the benign ones and the sources of the arm's family;
  * client namespaces grouped by netem profile (at most MAX_ALIASES addresses each, l7_pools's rule), each slow uploader
    on a 16 kbit/s link of its own (p4_traffic.NETEM_SLOW_ARGV);
  * nginx with nginx_profile_r.conf (C, C', U and the validation runs) or nginx_profile_r_limits.conf (M arms, C_M), and
    gunicorn -c gunicorn_profile_r.py (the costed app with the streamed upload, L7_CALIBRATION the record in use), both
    in server_ns on CPUs 0-1; the sha256 of the three files and of the record in the provenance;
  * the daemon (control_plane.py, in server_ns on CPU 2, the variables that select its mode set) per arm: M_def the default
    profile without the per-connection rule; M_pc the tolerant profile with SLOW_PC=1 SLOW_PC_ENFORCE=1, the
    committed T, F, K and SLOW_PC_RECORD; C_M (D-041) M_pc's configuration, with no attack; the validation runs (and the smoke runs) the tolerant profile with the rule
    in shadow (SLOW_PC=1, SLOW_PC_RECORD), as M_pc without enforcement. C, C' and U run without a daemon. The kill
    file (SLOW_PC_KILL_FILE, /run/l7v2/kill) must be absent for an enforcing run, before and during it;
  * the timeline 30 + 210 + 30 s (eval/p4_outcome.TIMELINE): the benign generators (ml/l7_gen.py, one per entity,
    from its own address, the plan kinds writing their client-side records) from 0 s to 270 s, the attack's from
    30 s to 240 s; nginx's stub_status sampled every second, recorded and never a validity rule (D-050, §8): its listener
    shares the worker connections an attack exhausts, so judging it would make the harm itself invalid;
  * the per-run labels (p4_traffic.roles: attack, slow_uploader, cgnat, the kind) in manifest.json and in
    slow_pc_manifest.json, the input of eval/p4_validation.py;
  * checks: the stack answered, every generator started and ended cleanly, the daemon was ready before the traffic
    and alive to the end with XDP attached, the attack ran (review T-047 P-06: its generators' stats, attack_summary()), the
    record exists, the kill file stayed absent, and (D-035, V-08 of review
    T-039) in an M_pc or validation run the rule's slow_pc_poll
    events that report a successful read are never more than SLOW_PC_POLL_GAP_S = 10 s apart, from the traffic's start to
    the run's end, and in an M_pc run they all say it enforced (review T-047 P-05: the daemon logs the event with polls 0
    and ss_failed N when every read fails, so counting events would call a blind rule alive). A run that
    fails one is invalid, with its reasons.

Re-registration record (T-052, 2026-11-03T15:01Z, the orchestrator's brief, before any data; reviews T-047 and T-050; labelled,
not a decision of the user), committed before the code it judges: a campaign block needs --selection, the validation's record, and its T, F and K (P-08); a
validation run needs a readable socket of each benign role (P-09); a ban-event line that cannot be read, or a daemon run whose ban
file is gone, is a reason (P-17 (4)); a benign device's view more than STALL_BOUND_S = 10 s after its intended start, or a generator
launched more than that late, is a reason, and run.json's `stall` always holds the readings (T-050).

Re-registration record (D-050, 2026-11-02T08:48Z, the user's "Approve as recommended", before any data; review T-047),
committed before the code it judges: this runner refuses --attempt N unless the index shows that attempt N-1 of the block had
an invalid needed arm or an unhealthy C, and the campaign holds at most 2 re-run blocks; stub_status is recorded, never a
validity rule.

Re-registration record (D-035, 2026-10-31T12:44Z, the user's "Approve all four", before any data): an M_pc run is
valid only if the per-connection rule logged slow_pc_poll at least every 10 s (the daemon logs one every
SLOW_PC_REPORT_INTERVAL = 5 s, control_plane.py, so 10 s is two missed reports): no gap between the traffic's start
(t0) and the first poll, between two polls, or between the last poll and t0 + 270 s, longer than 10.0 s. The runner
applies the same bound to the validation runs, whose record the rule writes in the same thread (a reading the user
accepted, D-041, 2026-10-31T16:06Z, as "seeded order" = each block's runs in a seeded order).
A block is one seed's runs in a seeded order: the 9 arms of an evaluation block (seeds 3101-3110), the 3 runs of a
validation seed (4001-4002), (C, U) at one ladder level of a pilot seed (9101-9106), or the runs a smoke test names.
Every attempt, valid or not, is in ROOT/index.jsonl with its reasons (§13 row 6), by two lines: one written and synced before
the run begins, one when it ends (review T-047 P-07), so that a run whose runner died still counts, with its bans. An attempt
is a directory
ROOT/<phase>/b<seed>_a<attempt>[_<label>]/<arm>/, with block.json beside its runs.

What the runs write feeds eval/p4_validation.py (slow_pc_manifest.json, slow_pc.jsonl.gz) and eval/p4_outcome.py
(run_record(): the client-side figures of eval/l7v2_harm.py over the attack window and LEVEL_WINDOW_S, the ban events,
the closes, and nginx's refusals by role from the access log, for the limits' own cost of D-041) unchanged; `--summarize ROOT OUT.jsonl` writes the run records of every evaluation attempt of the
run index, valid or not (D-035, V-03).

    ./venv/bin/python eval/p4_validation.py ROOT --json selection.json
    sudo ./venv/bin/python eval/p4_runner.py --phase campaign --seed 3101 --loris 175 --post 10 --thresholds 20,64,2 --selection selection.json
    ./venv/bin/python eval/p4_runner.py --phase validation --seed 4001 --loris 175 --post 10 --plan
    ./venv/bin/python eval/p4_runner.py --summarize ROOT runs.jsonl --calibration bench/calibration/placeholder.json
"""
import argparse
import datetime
import hashlib
import itertools
import json
import math
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), HERE, os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_outcome as OUT
import p4_traffic as PT

import slow_pc

FORMAT = "p4-run/1"
PHASES = ("smoke", "ladder", "validation", "campaign")
SERVER_NS, SERVER_IP, BRIDGE, SERVER_VETH_HOST_END = "server_ns", "10.0.0.1", "ddos_br0", "veth_srv_br"
NS_PREFIX, MAX_ALIASES, SUBNET_MASK = "p4n", 80, "/16"
# The runner too (review T-050 T050-17): its popen, curl and reads, and the ip and curl processes it starts, keep off the CPUs of the
# server and the daemon, as bench/population.PIN_PLAN_DAEMON's executor CPU does. P4's plan has no CPU to spare, so it shares the clients'.
PINS = {"server": "0-1", "daemon": "2", "clients": "3-7", "runner": "3-7"}
CONF_R = "nginx_profile_r.conf"
CONF_LIMITS = "nginx_profile_r_limits.conf"
GUNICORN_CONF = "gunicorn_profile_r.py"
PROFILE_FILES = (CONF_R, CONF_LIMITS, GUNICORN_CONF)
# What a verdict's runs depend on, hashed in every run's provenance (review T-047 P-08): the daemon under test included.
CODE_FILES = ("control_plane.py", "slow_pc.py", "ban_events.py", "xdp_ddos_filter.c", "l7_backend.py", "l7_webapp.py",
              "bench/origin.py", "ml/l7_benign.py", "ml/l7_gen.py", "ml/p4_traffic.py")
GEN = os.path.join(REPO, "ml", "l7_gen.py")
DAEMON = os.path.join(REPO, "control_plane.py")
PYTHON = os.path.join(REPO, "venv", "bin", "python")
PLACEHOLDER = os.path.join(REPO, "bench", "calibration", "placeholder.json")
KILL_FILE = "/run/l7v2/kill"
NGINX_LOGS = {"access.log": "/var/log/nginx/l7_capture.log", "error.log": "/var/log/nginx/error.log",
              "ddos_ml_access.log": "/var/log/nginx/ddos_ml_access.log"}      # nginx_profile_r*.conf's paths
STUB_STATUS_URL = "http://127.0.0.1:8081/nginx_status"
READY_URL = f"http://{SERVER_IP}/"
DAEMON_READY_LINE = "Listening for Nginx logs"          # bench/executor.py DAEMON_READY_LINE
XDP_ATTACHED_LINE = "Successfully attached XDP program"
DAEMON_READY_TIMEOUT_S, STACK_READY_TIMEOUT_S = 60.0, 30.0
STOP_GRACE_S = 10.0
# The attack ran: no open failed for a local reason, and at least this share of its connections was opened at least once. Not
# 90 %: slots run out as the attack harms (at the ladder's top ~1,800 connections meet ~1,065 free slots and a backlog of 511),
# so a higher floor would call the harm itself invalid, the trap of stub_status (D-050, P-02).
ATTACK_MIN_OPENED_SHARE = 0.5
SLOW_PC_POLL_GAP_S = 10.0          # D-035 (V-08): the longest silence of the rule in an M_pc or validation run
# the variables that select the daemon's mode, set, so that the operator's environment cannot change it (bench/executor.py
# DAEMON_ENV); MITIGATION_BACKEND is XDP in every P4 arm
DAEMON_BASE_ENV = {"XDP_GRU": "0", "GRU_ONLY": "0", "L7_SHADOW": "0", "L7_MODEL": "", "L7_RECORD": "",
                   "MITIGATION_BACKEND": "xdp", "SLOW_PC_KILL_FILE": KILL_FILE}
DAEMON_MODE_KEYS = ("HEURISTIC_PROFILE", "SLOW_PC", "SLOW_PC_ENFORCE")   # recorded in slow_pc_manifest.json
DAEMON_MODES = {
    "default": {"HEURISTIC_PROFILE": "default", "SLOW_PC": "0"},
    "pc": {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "1"},
    "shadow": {"HEURISTIC_PROFILE": "tolerant", "SLOW_PC": "1", "SLOW_PC_ENFORCE": "0"},
}


def _recorded_kinds():
    """The benign plan kinds (ml/l7_benign.py), whose generators write client-side records."""
    import l7_benign
    return tuple(l7_benign.KINDS) + tuple(l7_benign.L7V2_KINDS)


class PlanError(ValueError):
    """The run or block cannot be planned as asked."""


# --- arms ----------------------------------------------------------------------------------------

def arm_spec(arm, phase):
    """(nginx configuration, daemon mode or None, family or None) of an arm in a phase."""
    family = next((f for f in OUT.FAMILIES if arm.endswith("_" + f)), None)
    if arm == OUT.PROTECTED and phase in ("campaign", "smoke"):
        return CONF_LIMITS, "pc", None                # D-041: R + the deployed limits + M_pc's daemon, no attack
    if phase in ("validation", "smoke"):
        if arm not in slow_pc.VALIDATION_RUNS:
            raise PlanError(f"{phase} runs are {slow_pc.VALIDATION_RUNS}, not {arm!r}")
        return CONF_R, "shadow", family
    if phase == "ladder":
        if arm not in ("C", "U_loris", "U_post"):
            raise PlanError(f"a ladder runs C and U_<family>, not {arm!r}")
        return CONF_R, None, family
    if arm not in OUT.ARMS:
        raise PlanError(f"unknown arm {arm!r} (have {OUT.ARMS})")
    if arm.startswith("M_def_"):
        return CONF_LIMITS, "default", family
    if arm.startswith("M_pc_"):
        return CONF_LIMITS, "pc", family
    return CONF_R, None, family


def block_order(phase, seed, arms, label=""):
    """The block's runs in a seeded random order (§10: each block's runs in a seeded order)."""
    order = list(arms)
    random.Random(f"p4-order|{phase}|{seed}|{label}").shuffle(order)
    return order


def phase_arms(phase, family=None):
    if phase == "campaign":
        return OUT.ARMS
    if phase in ("validation", "smoke"):
        return slow_pc.VALIDATION_RUNS
    if family not in OUT.FAMILIES:
        raise PlanError(f"a ladder needs --family {' or '.join(OUT.FAMILIES)}")
    return ("C", f"U_{family}")


def check_phase(phase, seed, sources, thresholds, family=None):
    """What each phase needs, so that no run judges data on a setting that was not frozen."""
    role = {"smoke": "pilot", "ladder": "pilot", "validation": "val", "campaign": "eval"}[phase]
    PT.check_seed(seed, role)
    if phase == "ladder" and family not in OUT.FAMILIES:
        raise PlanError(f"a ladder needs --family {' or '.join(OUT.FAMILIES)}")
    if phase in ("validation", "campaign"):
        for f in OUT.FAMILIES:
            if sources[f] not in PT.FAMILIES[f]["levels"]:
                raise PlanError(f"{phase}: --{f} must be a level of the ladder {PT.FAMILIES[f]['levels']} (the knee)")
    if phase == "ladder" and sources[family] not in PT.FAMILIES[family]["levels"]:
        raise PlanError(f"ladder: --{family} must be a level of {PT.FAMILIES[family]['levels']}")
    if phase == "campaign":
        if thresholds is None or tuple(thresholds) not in slow_pc.GRID:
            raise PlanError("campaign: --thresholds T,F,K must be the committed point of slow_pc.GRID (§13 row 4)")
    elif thresholds is not None:
        raise PlanError(f"{phase}: the thresholds are the campaign's (the shadow runs record for every point)")
    return role


# --- one run's plan ------------------------------------------------------------------------------

def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def namespaces(entities, prefix=NS_PREFIX):
    """Client namespaces: the entities grouped by netem profile, at most MAX_ALIASES addresses each. A slow uploader has a
    namespace of its own: netem belongs to an interface, and two on one 16 kbit/s qdisc would get about 908 B/s each, under the
    grid's F = 1024 and not the link of §4.2 (review T-047 P-12)."""
    out, profiles = [], []
    for e in entities:
        if e["netem"] not in profiles:
            profiles.append(e["netem"])
    for prof in sorted(profiles):
        members = [e for e in entities if e["netem"] == prof]
        size = 1 if prof == PT.NETEM_SLOW else MAX_ALIASES
        for c in range(0, len(members), size):
            name = f"{prefix}{len(out)}_{prof}"
            out.append({"name": name, "profile": prof, "addresses": [e["address"] for e in members[c:c + size]]})
            for e in members[c:c + size]:
                e["namespace"] = name
    return out


def records_path(out, entity):
    """Where a benign plan-kind entity writes its client-side rows (eval/l7v2_harm.py run_rows reads them)."""
    return os.path.join(out, "records", entity["entity_id"].replace(":", "_") + ".csv")


def stats_path(out, entity):
    """Where an attack generator writes what it did (ml/l7_gen.py --stats)."""
    return os.path.join(out, "attack_stats", entity["entity_id"].replace(":", "_") + ".json")


def gen_argv(entity, out, python, cpus=PINS["clients"]):
    role = "benign" if entity["role"] == "benign" else "attack"
    dur = entity["schedule"]["stop_s"] - entity["schedule"]["start_s"]
    argv = ["taskset", "-c", cpus, python, GEN, "--role", role, "--host", SERVER_IP,
            "--port", str(entity["port"]), "--duration", f"{dur:.1f}", "--seed", str(entity["client_seed"]),
            "--params", json.dumps(entity["params"], sort_keys=True), "--source", entity["address"]]
    argv += ["--kind" if role == "benign" else "--family", entity["kind_or_family"]]
    if role == "benign" and entity["kind_or_family"] in _recorded_kinds():
        argv += ["--records", records_path(out, entity)]
    if role == "attack":
        argv += ["--stats", stats_path(out, entity)]
    return argv


def daemon_env(mode, out, thresholds):
    env = {**DAEMON_BASE_ENV, **DAEMON_MODES[mode], "BAN_EVENTS": os.path.join(out, "ban_events.jsonl")}
    if mode in ("pc", "shadow"):
        env["SLOW_PC_RECORD"] = os.path.join(out, "slow_pc.jsonl.gz")
    if mode == "pc":
        env["SLOW_PC_T"], env["SLOW_PC_F"], env["SLOW_PC_K"] = (str(x) for x in thresholds)
    return env


def plan_run(pop, phase, arm, out, *, thresholds=None, calibration=PLACEHOLDER, python=PYTHON):
    """One run as data: everything execute_run() does, and nothing it does not."""
    conf, mode, family = arm_spec(arm, phase)
    if mode == "pc" and thresholds is None:
        raise PlanError(f"{arm} runs M_pc's daemon: it needs --thresholds T,F,K")
    ents = [dict(e) for e in pop["entities"]
            if e["role"] == "benign" or (family is not None and e["schedule"]["phase"] == family)]
    nss = namespaces(ents)
    files = {name: sha256_file(os.path.join(REPO, name)) for name in PROFILE_FILES}
    launches = [{"entity_id": e["entity_id"], "role": e["role"], "ns": e["namespace"],
                 "start_s": e["schedule"]["start_s"], "argv": gen_argv(e, out, python)}
                for e in sorted(ents, key=lambda e: (e["schedule"]["start_s"], e["index"]))]
    conf_path = os.path.join(REPO, conf)
    daemon = None
    if mode is not None:
        daemon = {"mode": mode, "argv": ["taskset", "-c", PINS["daemon"], python, "-u", DAEMON],
                  "env": daemon_env(mode, out, thresholds), "cwd": REPO, "log": os.path.join(out, "daemon.log")}
    return {
        "format": FORMAT, "phase": phase, "seed": pop["seed"], "seed_role": pop["seed_role"], "arm": arm,
        "family": family, "out": out, "timeline": dict(PT.TIMELINE), "sources": dict(pop["sources"]),
        "halvings": pop["halvings"], "thresholds": list(thresholds) if mode == "pc" else None,
        "nginx": {"conf": conf, "conf_path": conf_path,
                  "start": ["taskset", "-c", PINS["server"], "nginx", "-c", conf_path],
                  "stop": ["nginx", "-c", conf_path, "-s", "quit"]},
        "gunicorn": {"argv": ["taskset", "-c", PINS["server"], python, "-m", "gunicorn", "-c",
                              os.path.join(REPO, GUNICORN_CONF), "--chdir", REPO],
                     "env": {"L7_CALIBRATION": calibration}, "log": os.path.join(out, "gunicorn.log")},
        "daemon": daemon, "kill_file": KILL_FILE, "enforcing": mode == "pc",
        "namespaces": nss, "launches": launches, "entities": ents, "roles": PT.roles(ents),
        "provenance": {"files_sha256": files, "calibration": {"path": calibration,
                                                              "sha256": sha256_file(calibration)},
                       "slow_pc_sha256": sha256_file(os.path.join(REPO, "slow_pc.py")),
                       "p4_traffic_sha256": sha256_file(os.path.join(REPO, "ml", "p4_traffic.py")),
                       "l7_gen_sha256": sha256_file(GEN), "pins": dict(PINS), "population": pop["version"],
                       "code_sha256": {name: sha256_file(os.path.join(REPO, name)) for name in CODE_FILES}},
    }


def plan_block(phase, seed, root, *, attempt=1, sources=None, halvings=0, thresholds=None, family=None,
               arms=None, label="", calibration=PLACEHOLDER, python=PYTHON, selection=None):
    """One block's runs, in their seeded order, as data. `selection`: the campaign's record of the validation, which run_block
    checks (check_selection); a plan can be printed without it."""
    sources = {"loris": 0, "post": 0, **(sources or {})}
    if phase not in PHASES:
        raise PlanError(f"unknown phase {phase!r}")
    if selection and phase != "campaign":
        raise PlanError(f"{phase}: --selection is the campaign's: the validation's choice of T, F and K")
    if label and phase in ("campaign", "validation"):
        raise PlanError(f"{phase}: no --label: it would give another arm order in another directory (review T-047 P-13)")
    role = check_phase(phase, seed, sources, thresholds, family) if phase != "smoke" else "pilot"
    if phase == "smoke":
        PT.check_seed(seed, "pilot")
        if thresholds is not None and tuple(thresholds) not in slow_pc.GRID:
            raise PlanError("smoke: --thresholds T,F,K must be a point of slow_pc.GRID")
    if phase == "ladder":                        # the ladder's runs carry only the family under test
        sources = {f: (n if f == family else 0) for f, n in sources.items()}
    pop = PT.build_plan(seed, role, halvings=halvings, loris=sources["loris"], post=sources["post"])
    wanted = tuple(arms) if arms else phase_arms(phase, family)
    order = block_order(phase, seed, wanted, label)
    name = f"b{seed}_a{attempt}" + (f"_{label}" if label else "")
    bdir = os.path.join(root, phase, name)
    runs = [plan_run(pop, phase, arm, os.path.join(bdir, arm), thresholds=thresholds, calibration=calibration,
                     python=python) for arm in order]
    return {"phase": phase, "seed": seed, "attempt": attempt, "label": label, "dir": bdir, "root": root,
            "order": order, "sources": sources, "halvings": halvings, "thresholds": thresholds,
            "calibration": calibration, "selection": selection, "runs": runs}


def describe(block):
    """The text of --plan."""
    lines = [f"P4 {block['phase']} block {block['seed']} attempt {block['attempt']}: {block['dir']}",
             (f"order {block['order']}; sources {block['sources']}; halvings {block['halvings']}; "
              f"thresholds {block['thresholds']}; calibration {block['calibration']}"
              + (f"; selection {block['selection']}" if block["phase"] == "campaign" else ""))]
    for r in block["runs"]:
        d = r["daemon"]
        lines.append(f"  run {r['arm']}: nginx {r['nginx']['conf']}, daemon "
                     + (f"{d['mode']} {' '.join(f'{k}={v}' for k, v in sorted(d['env'].items()))}" if d else "none")
                     + f"; {len(r['namespaces'])} namespaces, {sum(len(n['addresses']) for n in r['namespaces'])} "
                       f"addresses, {len(r['launches'])} generators "
                       f"({sum(1 for x in r['launches'] if x['role'] == 'attack')} attacking from "
                       f"{r['timeline']['baseline_s']} s)")
    return "\n".join(lines)


# --- executing -----------------------------------------------------------------------------------

def _utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True, default=str)
        fh.write("\n")


def parse_stub_status(text):
    """nginx's stub_status page as numbers, or None."""
    try:
        lines = [x.split() for x in text.strip().splitlines()]
        acc, han, req = (int(x) for x in lines[2])
        return {"active": int(lines[0][2]), "accepts": acc, "handled": han, "requests": req,
                "reading": int(lines[3][1]), "writing": int(lines[3][3]), "waiting": int(lines[3][5])}
    except (IndexError, ValueError):
        return None


def _events(path):
    out = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def read_ban_events(path):
    """(events, garbled lines) of a run's ban events, for what judges them (review T-047 P-17 (4)): a line that cannot be read could
    be a ban, so it is counted, where _events, for what only waits on the file, skips it. (None, 0): there is no file."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return None, 0
    events, garbled = [], 0
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            event = None
        if isinstance(event, dict):
            events.append(event)
        else:
            garbled += 1
    return events, garbled


def _wait(host, cond, timeout_s, step=0.5):
    t_end = host.monotonic() + timeout_s
    while host.monotonic() < t_end:
        if cond():
            return True
        host.sleep(step)
    return cond()


def _text(host, path):
    try:
        return host.read_text(path)
    except OSError:
        return ""


def topology(host, plan):
    host.prim("bridge")
    host.prim("server_ns")
    for ns in plan["namespaces"]:
        host.prim("client_ns", ns["name"], ns["addresses"][0])
        if ns["addresses"][1:]:
            host.run(["ip", "-batch", "-"], ns=ns["name"],
                     stdin="".join(f"addr add {a}{SUBNET_MASK} dev veth_in\n" for a in ns["addresses"][1:]))
        if ns["profile"] == PT.NETEM_SLOW:
            host.run(list(PT.NETEM_SLOW_ARGV), ns=ns["name"])
        else:
            host.prim("netem", ns["name"], ns["profile"])


def teardown(host, plan):
    names = [ns["name"] for ns in plan["namespaces"]] + [SERVER_NS]
    for n in names:
        for pid in host.run(["ip", "netns", "pids", n]).out.split():
            host.run(["kill", "-KILL", pid])
        host.run(["ip", "netns", "del", n])
    for link in [f"vo_{ns['name'][:12]}" for ns in plan["namespaces"]] + [SERVER_VETH_HOST_END, BRIDGE]:
        host.run(["ip", "link", "del", link])


def leftovers(host, plan, prefix=NS_PREFIX):
    ours = {ns["name"] for ns in plan["namespaces"]} | {SERVER_NS}
    listed = {line.split()[0] for line in host.run(["ip", "netns", "list"]).out.splitlines() if line.strip()}
    return sorted(n for n in listed if n in ours or n.startswith(prefix))


def execute_run(host, plan):
    """Run one planned run on `host` and write its directory. Returns {"ok", "reasons", "started", "ended"}."""
    out, t = plan["out"], plan["timeline"]
    reasons, procs, launched = [], [], []
    os.makedirs(os.path.join(out, "records"), exist_ok=True)
    os.makedirs(os.path.join(out, "attack_stats"), exist_ok=True)
    started = host.time()
    write_json(os.path.join(out, "plan.json"), plan)
    if not host.is_root():
        return finish(host, plan, ["not root: nothing was started"], started, None, [], {}, [])
    left = leftovers(host, plan)
    if left:
        return finish(host, plan, [f"leftover namespaces {left}: nothing was started"], started, None, [], {}, [])
    if plan["enforcing"] and host.exists(plan["kill_file"]):
        return finish(host, plan, [(f"the kill file {plan['kill_file']} exists: an enforcing run would run in shadow; "
                                    "nothing was started")], started, None, [], {}, [])
    logs, stub, t0 = {}, [], None
    try:
        procs.append(("topology", None))                # from here on the teardown runs, whatever happens
        topology(host, plan)
        host.run(["mkdir", "-p", "/var/log/nginx", os.path.join(out, "feed_before")])
        for name, path in NGINX_LOGS.items():          # nginx starts its logs afresh; nothing of the host's is lost
            host.run(["mv", "-f", path, os.path.join(out, "feed_before", name)])
        logs["gunicorn"] = open(plan["gunicorn"]["log"], "w", encoding="utf-8")       # noqa: SIM115 (closed in finish)
        procs.append(("gunicorn", host.popen(plan["gunicorn"]["argv"], ns=SERVER_NS, env=plan["gunicorn"]["env"],
                                             stdout=logs["gunicorn"], stderr=logs["gunicorn"], cwd=REPO)))
        if host.run(plan["nginx"]["start"], ns=SERVER_NS).code != 0:
            reasons.append("nginx did not start")
        ready = _wait(host, lambda: host.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2",
                                              READY_URL], ns=SERVER_NS).out.strip() == "200", STACK_READY_TIMEOUT_S)
        if not ready:
            reasons.append(f"the stack did not answer {READY_URL} with 200 within {STACK_READY_TIMEOUT_S:g} s")
        daemon = None
        if plan["daemon"] and not reasons:
            d = plan["daemon"]
            logs["daemon"] = open(d["log"], "w", encoding="utf-8")                   # noqa: SIM115
            daemon = host.popen(d["argv"], ns=SERVER_NS, env=d["env"], stdout=logs["daemon"], stderr=logs["daemon"],
                                cwd=d["cwd"])
            procs.append(("daemon", daemon))
            events = d["env"]["BAN_EVENTS"]
            if not _wait(host, lambda: DAEMON_READY_LINE in _text(host, d["log"])
                         and any(e.get("kind") == "start" for e in _events(events)), DAEMON_READY_TIMEOUT_S):
                reasons.append(f"the daemon was not ready within {DAEMON_READY_TIMEOUT_S:g} s")
        if reasons:
            return finish(host, plan, reasons, started, None, procs, logs, stub)
        t0 = host.time()
        total = sum(t.values())
        pending = list(plan["launches"])
        kill_seen = None
        while True:
            now = host.time() - t0
            while pending and pending[0]["start_s"] <= now:
                x = pending.pop(0)
                try:
                    launched.append((x, host.popen(x["argv"], ns=x["ns"], cwd=REPO)))
                except OSError as exc:
                    reasons.append(f"{x['entity_id']} did not start: {exc}")
            r = host.run(["curl", "-s", "--max-time", "1", STUB_STATUS_URL], ns=SERVER_NS)
            stub.append({"t": round(now, 3), **(parse_stub_status(r.out) or {"error": r.code})})
            if plan["enforcing"] and kill_seen is None and host.exists(plan["kill_file"]):
                kill_seen = now
                reasons.append(f"the kill file appeared at {now:.0f} s: the rule ran in shadow from then on")
            if daemon is not None and daemon.poll() is not None:
                reasons.append(f"the daemon exited at {now:.0f} s (code {daemon.poll()})")
                daemon = None
            if now >= total:
                break
            elapsed = host.time() - t0                                    # on the second, whatever the sample took
            host.sleep(max(0.0, min(math.floor(now) + 1, total) - elapsed))
        return finish(host, plan, reasons, started, t0, procs, logs, stub, launched)
    except Exception as exc:  # noqa: BLE001 - whatever failed, the run is recorded and the teardown runs
        reasons.append(f"the runner failed: {type(exc).__name__}: {exc}")
        return finish(host, plan, reasons, started, t0, procs, logs, stub, launched)


def _stop(host, proc, grace=STOP_GRACE_S, interrupt=False):
    if proc.poll() is None:
        (proc.interrupt if interrupt else proc.terminate)()
        if not _wait(host, lambda: proc.poll() is not None, grace, step=0.2):
            proc.kill()


def finish(host, plan, reasons, started, t0, procs, logs, stub, launched=()):
    """Stop everything, take the logs into the run, tear the testbed down, check and write the run's records."""
    out = plan["out"]
    reasons = list(reasons)
    try:
        for x, proc in launched:                          # the generators end on their own at their duration
            if not _wait(host, lambda p=proc: p.poll() is not None, STOP_GRACE_S, step=0.5):
                reasons.append(f"{x['entity_id']} was still running {STOP_GRACE_S:g} s after its end: stopped")
                _stop(host, proc)
            elif proc.poll() != 0:
                reasons.append(f"{x['entity_id']} exited with code {proc.poll()}")
        for name, proc in procs:
            if name == "daemon":
                _stop(host, proc, interrupt=True)          # SIGINT runs its finally, which detaches XDP
        if any(name == "gunicorn" for name, _p in procs):
            host.run(plan["nginx"]["stop"], ns=SERVER_NS)
        for name, proc in procs:
            if name == "gunicorn":
                _stop(host, proc)
        if procs:
            for name, path in NGINX_LOGS.items():
                host.run(["mv", "-f", path, os.path.join(out, name)])
    finally:
        for fh in logs.values():
            fh.close()
        if procs or t0 is not None:
            teardown(host, plan)
    ended = host.time()
    reasons += checks(host, plan, t0, launched)
    import executor
    daemon_prov = executor.daemon_provenance(host) if plan["daemon"] else None
    if daemon_prov and t0 is not None and not daemon_prov["h01"]["has_fix"]:
        reasons.append("the daemon lacks the H-01 fix, the prerequisite of every daemon arm (§4.3)")
    if stub:
        with open(os.path.join(out, "stub_status.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(s, sort_keys=True) + "\n" for s in stub)
    ok = not reasons
    roles = {"C": "control", "Cp": "placebo", OUT.PROTECTED: "protected_control"}
    meta = {"role": roles.get(plan["arm"], "attack" if plan["arm"].startswith("U_") else "mitigated"),
            "class": plan["family"], "arm": plan["arm"], "phase": plan["phase"], "seed": plan["seed"],
            "checks": {"ok": ok, "reasons": reasons}, "started_utc": _utc(started), "ended_utc": _utc(ended),
            "daemon": None if plan["daemon"] is None else {"mode": plan["daemon"]["mode"],
                                                           "env": plan["daemon"]["env"]},
            "thresholds": plan["thresholds"], "provenance": plan["provenance"],
            "attack": attack_summary(plan) if t0 is not None else None, "daemon_provenance": daemon_prov,
            "git": executor.git_state(host)}
    write_json(os.path.join(out, "run.json"), meta)
    write_json(os.path.join(out, "manifest.json"), manifest(plan, t0))
    if plan["daemon"] and plan["daemon"]["mode"] in ("pc", "shadow"):
        write_json(os.path.join(out, "slow_pc_manifest.json"),
                   {"seed": plan["seed"], "arm": plan["arm"], "record": "slow_pc.jsonl.gz", "roles": plan["roles"],
                    "daemon": {k: plan["daemon"]["env"][k] for k in DAEMON_MODE_KEYS}})
    return {"ok": ok, "reasons": reasons, "started": started, "ended": ended}


def attack_summary(plan):
    """What the attack generators of a run did (their --stats), or None for a run without an attack."""
    entities = [e for e in plan["entities"] if e["role"] == "attack"]
    if not entities:
        return None
    out = {"planned": sum(e["params"]["conns"] for e in entities), "generators": len(entities), "no_stats": 0, "opened": 0,
           "reopened": 0, "failed_opens": 0, "local_errors": 0, "sent_bytes": 0}
    for e in entities:
        try:
            with open(stats_path(plan["out"], e), encoding="utf-8") as fh:
                stats = json.load(fh)
        except (OSError, ValueError):
            out["no_stats"] += 1
            continue
        for key in ("opened", "reopened", "failed_opens", "local_errors", "sent_bytes"):
            out[key] += stats.get(key, 0)
    return out


def checks(host, plan, t0, launched):
    """The validity checks of a run that ran (see the module docstring)."""
    if t0 is None:
        return []
    reasons = []
    total = sum(plan["timeline"].values())
    if len(launched) != len(plan["launches"]):
        reasons.append(f"{len(plan['launches']) - len(launched)} of {len(plan['launches'])} generators never started")
    attack = attack_summary(plan)
    if attack:
        if attack["no_stats"]:
            reasons.append(f"{attack['no_stats']} of {attack['generators']} attack generators left no stats")
        if attack["local_errors"]:
            reasons.append(f"the attack could not open connections on this machine: {attack['local_errors']} local errors")
        if attack["opened"] < ATTACK_MIN_OPENED_SHARE * attack["planned"]:
            reasons.append(f"the attack opened {attack['opened']} of its {attack['planned']} connections")
    d = plan["daemon"]
    if d:
        log = _text(host, d["log"])
        if XDP_ATTACHED_LINE not in log:
            reasons.append("the daemon's log does not show XDP attached")
        events, garbled = read_ban_events(d["env"]["BAN_EVENTS"])
        if events is None:
            reasons.append("the daemon's ban events are gone: no ban can be excluded")
        elif garbled:
            reasons.append(f"{garbled} lines of the ban events cannot be read: each could be a ban")
        if d["mode"] in ("pc", "shadow"):
            rec = d["env"]["SLOW_PC_RECORD"]
            if not os.path.isfile(rec) or os.path.getsize(rec) == 0:
                reasons.append("the per-connection rule's record is missing or empty")
            polls = [e for e in events or () if e.get("kind") == "slow_pc_poll" and t0 <= e["t_wall"] <= t0 + total]
            edges = [t0, *sorted(e["t_wall"] for e in polls if e.get("polls", 0) > 0), t0 + total]
            gap = max(b - a for a, b in itertools.pairwise(edges))
            if gap > SLOW_PC_POLL_GAP_S:
                reasons.append(f"the per-connection rule logged no successful poll for {gap:.1f} s (more than "
                               f"{SLOW_PC_POLL_GAP_S:g} s, D-035)")
            if d["mode"] == "pc" and any(e.get("mode") != "enforce" for e in polls):
                reasons.append("the per-connection rule did not enforce throughout an enforcing run")
            if plan["phase"] == "validation" and os.path.isfile(rec):
                import p4_validation
                missing = p4_validation.roles_without_a_socket(slow_pc.read_record(rec), plan["roles"])
                if missing:
                    reasons.append(f"no socket of {', '.join(missing)} in the rule's record: the constraints on them would hold "
                                   "by construction (review T-047 P-09)")
    return reasons


def manifest(plan, t0):
    """The run manifest: the entities (with the L7 v2 fields eval/l7v2_harm.py reads), the time origin, the ip_map of
    l7_dataset (eval/l7v2_harm.server_q labels the access log by it) and the P4 labels."""
    import l7_dataset
    return {"format": FORMAT, "phase": plan["phase"], "seed": plan["seed"], "arm": plan["arm"],
            "timeline": {**plan["timeline"], "t0_wall": t0}, "entities": plan["entities"],
            "ip_map": l7_dataset.ip_map_from_entities(plan["entities"]), "roles": plan["roles"],
            "namespaces": plan["namespaces"], "sources": plan["sources"], "halvings": plan["halvings"],
            "provenance": plan["provenance"]}


def index_line(block, run, event, **fields):
    return {"event": event, "phase": block["phase"], "block": block["seed"], "attempt": block["attempt"],
            "label": block["label"], "arm": run["arm"], "dir": os.path.relpath(run["out"], block["root"]),
            "block_dir": os.path.relpath(block["dir"], block["root"]), **fields}


def _append(fh, line):
    fh.write(json.dumps(line, sort_keys=True) + "\n")
    fh.flush()
    os.fsync(fh.fileno())


def read_index(root):
    """Every run of ROOT/index.jsonl, one dict each, in the order they began: a run with no "ended" line is an invalid
    run whose runner died ("ended": False). A last line cut in the middle is what such a death leaves; any other line that
    cannot be read is refused."""
    path = os.path.join(root, "index.jsonl")
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    rows, by = [], {}
    for k, raw in enumerate(lines):
        try:
            x = json.loads(raw)
        except ValueError:
            if k == len(lines) - 1:
                break
            raise ValueError(f"{path}: line {k + 1} cannot be read") from None
        key = (x["phase"], x["block"], x["attempt"], x["label"], x["arm"])
        if x["event"] == "started":
            by[key] = {**x, "ended": False, "valid": False, "reasons": ["the index holds no end of this run: the runner died"]}
            rows.append(by[key])
        else:
            by[key].update(ended=True, valid=x["valid"], reasons=x["reasons"], ended_utc=x["ended_utc"])
    return rows


def block_settings(block):
    """What every block of a campaign, and every attempt of a block, must share (review T-047 P-08): the scale, the halvings,
    the thresholds, the calibration record, the validation's record and the code."""
    prov = block["runs"][0]["provenance"]
    code = hashlib.sha256(json.dumps([prov["files_sha256"], prov["code_sha256"]], sort_keys=True).encode()).hexdigest()
    return {"sources": block["sources"], "halvings": block["halvings"],
            "thresholds": list(block["thresholds"]) if block["thresholds"] else None,
            "calibration_sha256": sha256_file(block["calibration"]), "code_sha256": code,
            "selection_sha256": sha256_file(block["selection"]) if block.get("selection") else None}


def check_selection(block):
    """§13 row 4 (review T-047 P-08): a campaign's T, F and K are what the validation chose, under the detector it scored, at its
    scale and halvings and under its calibration record. The record is what eval/p4_validation.py --json wrote."""
    if block["phase"] != "campaign":
        return
    path = block["selection"]
    if not path:
        raise PlanError("campaign: --selection must name the validation's record (eval/p4_validation.py --json, §13 row 4)")
    try:
        with open(path, encoding="utf-8") as fh:
            sel = json.load(fh)
        point, detector, theirs = sel["selection"]["point"], sel["slow_pc_sha256"], sel["settings"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PlanError(f"{path} is not a record of eval/p4_validation.py --json: {exc!r}") from None
    if point is None:
        raise PlanError(f"{path}: the validation chose no point: the rule fails its budget (§6.4), and no campaign follows")
    if tuple(point) != tuple(block["thresholds"]):
        raise PlanError(f"campaign: --thresholds {tuple(block['thresholds'])} are not the validation's selection {tuple(point)}")
    if detector != sha256_file(os.path.join(REPO, "slow_pc.py")):
        raise PlanError(f"{path}: the validation scored another slow_pc.py (§13 row 3)")
    mine = block_settings(block)
    differ = sorted(k for k in ("sources", "halvings", "calibration_sha256") if mine[k] != theirs.get(k))
    if differ:
        raise PlanError(f"campaign: {', '.join(differ)} differ from the validation's ({path})")


def check_settings(block):
    """A campaign, or a validation, at one setting: refuse a block whose settings differ from an earlier one's."""
    if block["phase"] not in ("campaign", "validation"):
        return
    base = os.path.join(block["root"], block["phase"])
    mine = block_settings(block)
    for name in sorted(os.listdir(base)) if os.path.isdir(base) else ():
        path = os.path.join(base, name, "block.json")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            theirs = json.load(fh)["settings"]
        differ = sorted(k for k in mine if mine[k] != theirs.get(k))
        if differ:
            raise PlanError(f"{block['phase']} block {block['seed']}: {', '.join(differ)} differ from {name}'s")


def check_attempt(block):
    """D-050 (review T-047 P-03): the attempt must be the next one the index shows, and a re-run needs a reason: attempt N-1 of
    the block had an invalid or missing needed arm (a run whose runner died is invalid), or, in the campaign, an unhealthy
    C. The campaign holds at most OUT.MAX_RERUNS re-runs. Smoke runs judge nothing and need no reason."""
    phase, seed = block["phase"], block["seed"]
    rows = read_index(block["root"])
    mine = [x for x in rows if (x["phase"], x["block"], x["label"]) == (phase, seed, block["label"])]
    next_attempt = max((x["attempt"] for x in mine), default=0) + 1
    if block["attempt"] != next_attempt:
        raise PlanError(f"{phase} block {seed}: attempt {block['attempt']}, and the index says the next is {next_attempt}")
    if next_attempt == 1 or phase == "smoke":
        return
    last = {x["arm"]: x for x in mine if x["attempt"] == next_attempt - 1}
    needed = OUT.NEEDED_ARMS if phase == "campaign" else block["order"]
    why = [arm for arm in needed if arm not in last or not last[arm]["valid"]]
    if phase == "campaign" and not why:
        import l7_backend
        cal = l7_backend.load_record(block["calibration"])[0]
        control = last[OUT.CONTROL]
        if run_record(os.path.join(block["root"], control["dir"]), cal, seed, control["attempt"])["control_reasons"]:
            why = ["an unhealthy C"]
    if not why:
        raise PlanError(f"{phase} block {seed}: attempt {next_attempt - 1} had every needed arm valid and a healthy C, and "
                        "D-050 allows no re-run of it")
    if phase == "campaign":
        reruns = {(x["block"], x["attempt"]) for x in rows if x["phase"] == "campaign" and x["attempt"] > 1}
        if len(reruns) >= OUT.MAX_RERUNS:
            raise PlanError(f"the campaign already holds {len(reruns)} re-runs, at most {OUT.MAX_RERUNS} (D-050)")


def run_block(host, block):
    """Every run of a block in its order; each in ROOT/index.jsonl before it begins and when it ends, valid or not."""
    check_attempt(block)
    check_selection(block)
    check_settings(block)
    if os.path.exists(block["dir"]):
        raise PlanError(f"{block['dir']} exists: an attempt is never overwritten (use the next --attempt)")
    os.makedirs(block["dir"])
    host.pin(PINS["runner"])
    cal = block["calibration"]
    write_json(os.path.join(block["dir"], "block.json"),
               {"block": block["seed"], "attempt": block["attempt"], "seed": block["seed"], "phase": block["phase"],
                "calibration_sha256": sha256_file(cal), "timeline": dict(PT.TIMELINE), "order": block["order"],
                "sources": block["sources"], "halvings": block["halvings"], "thresholds": block["thresholds"],
                "settings": block_settings(block)})
    results = []
    with open(os.path.join(block["root"], "index.jsonl"), "a", encoding="utf-8") as idx:
        for run in block["runs"]:
            write_json(os.path.join(run["out"], "plan.json"), run)
            _append(idx, index_line(block, run, "started", started_utc=_utc(host.time())))
            res = execute_run(host, run)
            _append(idx, index_line(block, run, "ended", valid=res["ok"], reasons=res["reasons"],
                                    ended_utc=_utc(res["ended"])))
            results.append((run["arm"], res))
    return results


# --- the records eval/p4_outcome.py judges ----------------------------------------------------------

def refusals(path, man, window):
    """What nginx refused over `window` of the run (status 429 or 503, what limit_req and limit_conn answer:
    eval/harm_gate.REFUSED_STATUSES), from the run's access log and labels, for the limits' own cost of D-041:
    {"by_role": {role: {"requests", "refused"}}, "cgnat": {"CGNAT-12": {"address", "requests", "refused"}, ...}}. A request
    is placed at its start ($msec - $request_time), as eval/l7v2_harm.server_q does; a line that cannot be read is
    skipped; an address without a label is counted as "unlabelled", never dropped."""
    import l7_dataset
    import l7_ingest
    t0, roles = man["timeline"]["t0_wall"], man["roles"]
    pools = {e["address"]: f"CGNAT-{e['params']['users']}" for e in man["entities"]
             if e["kind_or_family"] == "cgnat_browsers"}
    out = {"by_role": {}, "cgnat": {name: {"address": ip, "requests": 0, "refused": 0} for ip, name in pools.items()}}
    with l7_dataset.open_log(path) as fh:
        for line in fh:
            obj = l7_ingest.parse_l7_line(line)
            if obj is None or not obj.get("ip"):
                continue
            t_rel = l7_ingest._num(obj.get("msec")) - l7_ingest._num(obj.get("rt")) - t0
            if not window[0] <= t_rel < window[1]:
                continue
            ip, hit = obj["ip"], int(l7_ingest._num(obj.get("status"))) in OUT.HG.REFUSED_STATUSES
            rows = [out["by_role"].setdefault(roles.get(ip, "unlabelled"), {"requests": 0, "refused": 0})]
            if ip in pools:
                rows.append(out["cgnat"][pools[ip]])
            for row in rows:
                row["requests"] += 1
                row["refused"] += hit
    return out


def run_record(run_dir, cal, block=None, attempt=1):
    """eval/p4_outcome.summarize of one run directory: the client-side figures of eval/l7v2_harm.py over the attack
    window and over LEVEL_WINDOW_S, the ban events, the closes the rule enforced, the run's labels and its attempt; a
    run of C also its health under `cal` (D-046), which the run index does not know, and every run the settings of its
    block (block.json, review T-047 P-08), which the outcome compares: `--summarize`, and the outcome, say
    which attempts it invalidates. A run that never started (refused before its traffic), or whose runner died in it
    (no manifest, P-07), is an invalid record without figures, with whatever bans and closes its daemon had logged."""
    import l7v2_harm as LH
    if os.path.isfile(os.path.join(run_dir, "manifest.json")):
        with open(os.path.join(run_dir, "manifest.json"), encoding="utf-8") as fh:
            man = json.load(fh)
        with open(os.path.join(run_dir, "run.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
    else:
        with open(os.path.join(run_dir, "plan.json"), encoding="utf-8") as fh:
            plan = json.load(fh)
        man, meta = {"seed": plan["seed"], "arm": plan["arm"], "roles": plan["roles"], "timeline": {}}, None
    t = man["timeline"]
    events, garbled = read_ban_events(os.path.join(run_dir, "ban_events.jsonl"))
    ban_problem = f"{garbled} lines cannot be read" if garbled else None
    if events is None:              # no daemon, or none that got as far as its start event, wrote no ban; else the file is gone
        events = []
        if t.get("t0_wall") is not None and meta["daemon"] is not None:
            ban_problem = "the file is gone"
    closes = [e for e in events if e.get("kind") == "slow_pc_close" and e.get("enforced")]
    seed = man["seed"] if block is None else block
    with open(os.path.join(os.path.dirname(run_dir), "block.json"), encoding="utf-8") as fh:
        settings = json.load(fh)["settings"]
    if t.get("t0_wall") is None:
        empty = {"Q": None, "p95_s": None, "q_per_s": [None] * OUT.RUN_S, "by_class": {}}
        return OUT.summarize(seed, man["arm"], False, empty, {"Q": None}, events, man["roles"], closes,
                             level_window=OUT.LEVEL_WINDOW_S, attempt=attempt, cal=cal, settings=settings, ban_problem=ban_problem,
                             reasons=meta["checks"]["reasons"] if meta else ["the runner died in this run"])
    total = sum(t[k] for k in ("baseline_s", "attack_s", "recovery_s"))
    attack = (t["baseline_s"], t["baseline_s"] + t["attack_s"])
    rows, t0, _cover = LH.run_rows(run_dir, man, attack)
    m = LH.metrics(rows, cal, (t0 + attack[0], t0 + attack[1]), t0, total)
    lw = OUT.LEVEL_WINDOW_S
    rows_l, _t0, _c = LH.run_rows(run_dir, man, lw)
    level = LH.metrics(rows_l, cal, (t0 + lw[0], t0 + lw[1]), t0, total)
    log = os.path.join(run_dir, "access.log")
    refused = refusals(log, man, attack) if os.path.isfile(log) else None
    return OUT.summarize(seed, man["arm"], meta["checks"]["ok"], m, level, events, man["roles"], closes,
                         level_window=lw, attempt=attempt, refused=refused, cal=cal, settings=settings, ban_problem=ban_problem,
                         reasons=meta["checks"]["reasons"])


def summarize_root(root, calibration, out_path):
    """The run records of EVERY evaluation attempt of ROOT/index.jsonl, valid or not, a run whose runner died included
    (D-035, V-03; P-07), under the calibration record `calibration` (a path), which must be the one the blocks name (P-08).
    A run directory the index does not hold is refused: it could hide a ban."""
    import l7_backend
    cal = l7_backend.load_record(calibration)[0]
    named = sha256_file(calibration)
    rows = [x for x in read_index(root) if x["phase"] == "campaign"]
    known = {x["dir"] for x in rows}
    base = os.path.join(root, "campaign")
    tree = [os.path.join("campaign", b, a) for b in (sorted(os.listdir(base)) if os.path.isdir(base) else ())
            for a in sorted(os.listdir(os.path.join(base, b))) if os.path.isdir(os.path.join(base, b, a))]
    strays = [d for d in tree if d not in known]
    if strays:
        raise ValueError(f"runs the index does not hold: {strays[:5]}")
    for block_dir in sorted({x["block_dir"] for x in rows}):
        with open(os.path.join(root, block_dir, "block.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        if meta["calibration_sha256"] != named:
            raise ValueError(f"{block_dir} ran under calibration {meta['calibration_sha256'][:8]}, not {calibration}")
        if meta["order"] != block_order("campaign", meta["block"], [a for a in OUT.ARMS if a in meta["order"]]):
            raise ValueError(f"{block_dir}: the runs are not in the block's seeded order")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(run_record(os.path.join(root, x["dir"]), cal, x["block"], x["attempt"])) + "\n" for x in rows)


# --- the command line --------------------------------------------------------------------------------

def _thresholds(text):
    if text is None:
        return None
    try:
        return tuple(int(x) for x in text.split(","))
    except ValueError:
        raise argparse.ArgumentTypeError(f"T,F,K: {text!r}") from None


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phase", choices=PHASES)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--attempt", type=int, default=1)
    ap.add_argument("--loris", type=int, default=0, help="Slowloris sources (a ladder level; the knee)")
    ap.add_argument("--post", type=int, default=0, help="slow-POST sources (a ladder level; the knee)")
    ap.add_argument("--family", choices=OUT.FAMILIES, help="the ladder's family")
    ap.add_argument("--label", default="", help="a ladder's level and repeat, a smoke run's name; refused elsewhere")
    ap.add_argument("--arms", help="smoke only: the runs, comma-separated (C, U_loris, U_post, C_M)")
    ap.add_argument("--halvings", type=int, default=0, help="how often the halving rule of §4.2 has fired")
    ap.add_argument("--thresholds", type=_thresholds, help="campaign: the committed T,F,K; a smoke C_M: a grid point")
    ap.add_argument("--selection", help="campaign: the validation's record (eval/p4_validation.py --json)")
    ap.add_argument("--calibration", default=PLACEHOLDER)
    ap.add_argument("--root", default="/var/tmp/p4_runs")
    ap.add_argument("--python", default=PYTHON)
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (offline)")
    ap.add_argument("--summarize", nargs=2, metavar=("ROOT", "OUT_JSONL"))
    args = ap.parse_args(argv)
    if args.summarize:
        try:
            summarize_root(args.summarize[0], args.calibration, args.summarize[1])
        except ValueError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        return 0
    if args.phase is None or args.seed is None:
        ap.error("--phase and --seed are required")
    if args.arms and args.phase != "smoke":
        ap.error("--arms is for smoke runs only")
    try:
        block = plan_block(args.phase, args.seed, args.root, attempt=args.attempt,
                           sources={"loris": args.loris, "post": args.post}, halvings=args.halvings,
                           thresholds=args.thresholds, family=args.family,
                           arms=args.arms.split(",") if args.arms else None, label=args.label,
                           calibration=args.calibration, python=args.python, selection=args.selection)
    except (PlanError, PT.PlanError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    print(describe(block))
    if args.plan:
        return 0
    if host is None:
        import executor
        host = executor.RealHost()
    try:
        results = run_block(host, block)
    except PlanError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    for arm, res in results:
        print(f"  {arm}: {'valid' if res['ok'] else 'INVALID: ' + '; '.join(res['reasons'])}")
    return 0 if all(res["ok"] for _a, res in results) else 1


if __name__ == "__main__":
    sys.exit(main())

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
  * checks: the stack answered and stayed up (D-063: gunicorn alive to the run's end, nginx there to be told to quit), every generator started on time and ended cleanly, no client stalled in mid-life (stall_reading()),
    the daemon was ready before the traffic
    and alive to the end with XDP attached, the attack ran (review T-047 P-06: its generators' stats, attack_summary()), the
    record exists, the kill file stayed absent, and (D-035, V-08 of review
    T-039) in an M_pc or validation run the rule's slow_pc_poll
    events that report a successful read are never more than SLOW_PC_POLL_GAP_S = 10 s apart, from the traffic's start to
    the run's end, and in an M_pc run they all say it enforced (review T-047 P-05: the daemon logs the event with polls 0
    and ss_failed N when every read fails, so counting events would call a blind rule alive). A run that
    fails one is invalid, with its reasons.

Re-registration record (D-063, 2026-11-04T13:04Z, the orchestrator's decision, before any data; the user may overrule), committed
before the code it judges: gunicorn exiting during a run is a reason, named as a calibration refusal or a failed worker boot when
gunicorn.log shows one, and so is nginx not running at the run's end.

Re-registration record (T-052b, 2026-11-04T12:16Z, the orchestrator's brief, before any data; the rule of eval/harm_gate.py and
eval/l7v2_harm.py), committed before the code it judges: a campaign block refuses a calibration record that is not frozen before anything runs,
and so does --summarize; only a simulated host, or --dry-run on --summarize, is exempt, and labelled. Smoke, ladder and validation may
name any record, and each block.json says which.

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

    ./venv/bin/python eval/p4_ladder.py ROOT --calibration FROZEN.json --out knees.json
    sudo ./venv/bin/python eval/p4_runner.py --phase validation --seed 4001 --loris 175 --post 10 --knees knees.json --calibration FROZEN.json
    ./venv/bin/python eval/p4_validation.py ROOT --json selection.json
    sudo ./venv/bin/python eval/p4_runner.py --phase campaign --seed 3101 --loris 175 --post 10 --thresholds 20,64,2 --selection selection.json --knees knees.json --calibration FROZEN.json
    ./venv/bin/python eval/p4_runner.py --phase validation --seed 4001 --loris 175 --post 10 --plan
    ./venv/bin/python eval/p4_runner.py --summarize ROOT runs.jsonl --calibration FROZEN.json    # --dry-run: a simulated campaign
"""
import argparse
import contextlib
import datetime
import hashlib
import itertools
import json
import math
import os
import random
import sys
import types

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
# "timer": the CPU the timer gate probes (review T-057 T057-06), the legit CPU of bench/population.PIN_PLAN_DAEMON, on which the record's limit was
# measured. P4's clients stay on 3-7, so the gate says that the host is calm, not that their CPUs are; the view slips read those.
PINS = {"server": "0-1", "daemon": "2", "clients": "3-7", "runner": "3-7", "timer": "7"}
TIMER_WAIT_MIN = 30.0              # bench/executor.py timer_gate's default wait, as eval/p1_runner.py: every run may use it in full
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
# What gunicorn.log names when gunicorn stops by itself (D-063): the first found goes in the reason.
GUNICORN_REFUSALS = (("CalibrationError", "the origin refused its calibration record"), ("Worker failed to boot", "a worker failed to boot"))
SLOW_PC_POLL_GAP_S = 10.0          # D-035 (V-08): the longest silence of the rule in an M_pc or validation run
STALL_BOUND_S = 10.0               # T-052: never_sent_after_s (ml/l7v2_prereg.json), past which a late view fails in Q; and STOP_GRACE_S
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


LADDER_REPEATS = 2           # §5: "the lowest level that harms in 2 of 2 repeats"


def ladder_labels(level):
    """The labels of a ladder level's repeats (review T-063 T063-05; the spelling the tests and eval/p4_ladder.py used). A level names its
    family too, since the two families' ladders share no level."""
    return [f"l{level}r{repeat}" for repeat in range(1, LADDER_REPEATS + 1)]


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


def stderr_path(out, entity_id):
    """Where a generator's stderr goes (review T-057 T057-07); finish() removes the empty ones."""
    return os.path.join(out, "gen_stderr", entity_id.replace(":", "_") + ".log")


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


def read_record(path):
    """(record, status) of a calibration record, its schema and hash checked (l7_backend.load_record), or PlanError."""
    import l7_backend
    try:
        rec, status, _tag = l7_backend.load_record(path)
    except (OSError, ValueError) as exc:
        raise PlanError(f"the calibration record {path}: {exc}") from None
    return rec, status


def plan_block(phase, seed, root, *, attempt=1, sources=None, halvings=0, thresholds=None, family=None,
               arms=None, label="", calibration=PLACEHOLDER, python=PYTHON, selection=None, knees=None):
    """One block's runs, in their seeded order, as data. `selection`: the campaign's record of the validation, which run_block
    checks (check_selection); `knees`: the validation's and the campaign's record of the ladder (check_knees); a plan can be printed
    without them."""
    sources = {"loris": 0, "post": 0, **(sources or {})}
    if phase not in PHASES:
        raise PlanError(f"unknown phase {phase!r}")
    if selection and phase != "campaign":
        raise PlanError(f"{phase}: --selection is the campaign's: the validation's choice of T, F and K")
    if knees and phase not in ("validation", "campaign"):
        raise PlanError(f"{phase}: --knees is the validation's and the campaign's: the ladder's record")
    record, status = read_record(calibration)
    if label and phase in ("campaign", "validation"):
        raise PlanError(f"{phase}: no --label: it would give another arm order in another directory (review T-047 P-13)")
    role = check_phase(phase, seed, sources, thresholds, family) if phase != "smoke" else "pilot"
    if phase == "smoke":
        PT.check_seed(seed, "pilot")
        if thresholds is not None and tuple(thresholds) not in slow_pc.GRID:
            raise PlanError("smoke: --thresholds T,F,K must be a point of slow_pc.GRID")
    if phase == "ladder":                        # the ladder's runs carry only the family under test
        sources = {f: (n if f == family else 0) for f, n in sources.items()}
        if label not in ladder_labels(sources[family]):
            raise PlanError(f"ladder: the label {label!r} is not one of {ladder_labels(sources[family])}: eval/p4_ladder.py reads the repeat "
                            f"from it, and §5's ladder has {LADDER_REPEATS} repeats a level (review T-063 T063-05)")
    pop = PT.build_plan(seed, role, halvings=halvings, loris=sources["loris"], post=sources["post"])
    wanted = tuple(arms) if arms else phase_arms(phase, family)
    order = block_order(phase, seed, wanted, label)
    name = f"b{seed}_a{attempt}" + (f"_{label}" if label else "")
    bdir = os.path.join(root, phase, name)
    runs = [plan_run(pop, phase, arm, os.path.join(bdir, arm), thresholds=thresholds, calibration=calibration,
                     python=python) for arm in order]
    for run in runs:
        run["timer_limit_ms"] = record["validity"]["timer_p99_ms"]
    return {"phase": phase, "seed": seed, "attempt": attempt, "label": label, "dir": bdir, "root": root,
            "order": order, "sources": sources, "halvings": halvings, "thresholds": thresholds,
            "calibration": calibration, "calibration_status": status, "selection": selection, "knees": knees, "runs": runs}


def describe(block):
    """The text of --plan."""
    lines = [f"P4 {block['phase']} block {block['seed']} attempt {block['attempt']}: {block['dir']}",
             (f"order {block['order']}; sources {block['sources']}; halvings {block['halvings']}; "
              f"thresholds {block['thresholds']}; calibration {block['calibration']} ({block['calibration_status']})"
              + (f"; selection {block['selection']}" if block["phase"] == "campaign" else "")
              + (f"; knees {block['knees']}" if block["phase"] in ("validation", "campaign") else ""))]
    if block["calibration_status"] != "frozen" and block["phase"] in ("validation", "campaign"):
        lines.append(f"  NOT FROZEN: {'a real host refuses this campaign' if block['phase'] == 'campaign' else 'no campaign can follow this validation'}"
                     " (T-052b; the campaign must name the validation's record, and a frozen one)")
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
    """The run's testbed. Returns what failed, for the run's reasons (review T-057 T057-03): an alias that was not added fails its generator's
    every request, which reads as harm, and a netem that failed leaves a slow uploader fast. Only these two are the runner's own commands: the
    suite's primitives run theirs unchecked and return nothing, so a failure inside one is not seen here."""
    problems = []

    def step(what, argv, name, stdin=""):
        r = host.run(argv, ns=name, stdin=stdin)
        if r.code != 0:
            problems.append(f"{what} in {name} exited {r.code}: {(r.err or r.out).strip()[:200]}")

    host.prim("bridge")
    host.prim("server_ns")
    for ns in plan["namespaces"]:
        host.prim("client_ns", ns["name"], ns["addresses"][0])
        if ns["addresses"][1:]:
            step("ip -batch", ["ip", "-batch", "-"], ns["name"],
                 "".join(f"addr add {a}{SUBNET_MASK} dev veth_in\n" for a in ns["addresses"][1:]))
        if ns["profile"] == PT.NETEM_SLOW:
            step("netem", list(PT.NETEM_SLOW_ARGV), ns["name"])
        else:
            host.prim("netem", ns["name"], ns["profile"])
    return problems


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
    os.makedirs(os.path.join(out, "gen_stderr"), exist_ok=True)
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
    timer, refused = timer_gate(host, plan)
    if refused:
        return finish(host, plan, [f"{refused}: nothing was started"], started, None, [], {}, [], timer=timer)
    logs, stub, t0, logs_at_start = {}, [], None, None
    try:
        procs.append(("topology", None))                # from here on the teardown runs, whatever happens
        reasons += topology(host, plan)
        if reasons:
            return finish(host, plan, reasons, started, None, procs, logs, stub, timer=timer, logs_at_start=logs_at_start)
        host.run(["mkdir", "-p", "/var/log/nginx", os.path.join(out, "feed_before")])
        for name, path in NGINX_LOGS.items():          # nginx starts its logs afresh; nothing of the host's is lost
            host.run(["mv", "-f", path, os.path.join(out, "feed_before", name)])
        logs["gunicorn"] = open(plan["gunicorn"]["log"], "w", encoding="utf-8")       # noqa: SIM115 (closed in finish)
        gunicorn = host.popen(plan["gunicorn"]["argv"], ns=SERVER_NS, env=plan["gunicorn"]["env"],
                              stdout=logs["gunicorn"], stderr=logs["gunicorn"], cwd=REPO)
        procs.append(("gunicorn", gunicorn))
        refused = start_nginx(host, plan)
        if refused:
            reasons.append(refused)
        else:
            logs_at_start = log_stats(host)
        ready = _wait(host, lambda: gunicorn.poll() is not None
                      or host.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2",
                                   READY_URL], ns=SERVER_NS).out.strip() == "200", STACK_READY_TIMEOUT_S)
        if gunicorn.poll() is not None:
            reasons.append(gunicorn_gone(host, plan, gunicorn, "before the traffic"))
        elif not ready:
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
            return finish(host, plan, reasons, started, None, procs, logs, stub, timer=timer, logs_at_start=logs_at_start)
        t0 = host.time()
        total = sum(t.values())
        pending = list(plan["launches"])
        kill_seen = None
        while True:
            now = host.time() - t0
            while pending and pending[0]["start_s"] <= now:
                x = pending.pop(0)
                try:
                    with open(stderr_path(out, x["entity_id"]), "ab") as err:
                        launched.append(({**x, "lag_s": host.time() - t0 - x["start_s"]},
                                         host.popen(x["argv"], ns=x["ns"], cwd=REPO, stderr=err)))
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
            if gunicorn is not None and gunicorn.poll() is not None:
                reasons.append(gunicorn_gone(host, plan, gunicorn, f"at {now:.0f} s"))
                gunicorn = None
            if now >= total:
                break
            elapsed = host.time() - t0                                    # on the second, whatever the sample took
            host.sleep(max(0.0, min(math.floor(now) + 1, total) - elapsed))
        return finish(host, plan, reasons, started, t0, procs, logs, stub, launched, timer=timer, logs_at_start=logs_at_start)
    except KeyboardInterrupt as exc:     # Ctrl-C, or TERM or HUP in main: the testbed comes down, the generators with it, and the block stops
        with host.shielded():          # D-068, as P1's: only this pass is shielded, so a second interrupt cannot cut it short (T063-02)
            finish(host, plan, [*reasons, f"the run was interrupted ({exc})"], started, t0, procs, logs, stub, launched, timer=timer,
                   logs_at_start=logs_at_start, interrupted=True)
        raise
    except Exception as exc:  # noqa: BLE001 - whatever failed, the run is recorded and the teardown runs
        reasons.append(f"the runner failed: {type(exc).__name__}: {exc}")
        return finish(host, plan, reasons, started, t0, procs, logs, stub, launched, timer=timer, logs_at_start=logs_at_start)


def timer_gate(host, plan):
    """The harm benchmark's gate before a run, as eval/p1_runner.py takes it (review T-057 T057-06): the timer of the CPU the record's limit was
    measured on, at that limit, with its wait. Returns (the record of its probes, for run.json; the refusal's text, or None)."""
    import executor
    gate = types.SimpleNamespace(pins={"legit": PINS["timer"]}, timer_limit_ms=plan["timer_limit_ms"], overrides={})
    try:
        return executor.timer_gate(host, gate, TIMER_WAIT_MIN)[1], None
    except executor.EnvironmentRefused as exc:
        return getattr(exc, "record", None), f"the timer gate refused the run: {exc}"


def log_stats(host, paths=None):
    """{path: (inode, size) or None} of nginx's logs, or of `paths` (P1 passes its own), for replaced_logs(): taken once nginx has started
    (review T-063 T063-07)."""
    return {path: host.stat(path) for path in (NGINX_LOGS.values() if paths is None else paths)}


def replaced_logs(host, at_start):
    """Review T-057 T057-09, HG's check (bench/executor.py, T-028 F-04): nginx's logs sit in logrotate's glob, and a rotation in a run leaves its copy
    only what came after, and the daemon without what nginx wrote until it reopened. `at_start` is log_stats() at nginx's start, and this is called
    once its last writer has stopped and before the logs are moved, so no stretch of the run is left out (T063-07). A log that was not there at the
    start has nothing to compare. Only the inode: logrotate's rule for these logs renames and creates, which the inode sees; a truncation in place
    would keep it, and two sizes, one at a fresh start, cannot tell one from a log that grew."""
    out = []
    for path, then in at_start.items():
        now = host.stat(path)
        if then is not None and (now is None or now[0] != then[0]):
            out.append(f"{path} was replaced or removed during the run (inode {then[0]} at nginx's start, {now and now[0]} before the logs were moved): "
                       "logrotate?")
    return out


def start_nginx(host, plan):
    """Nginx as the harm benchmark starts it (bench/executor.py start_daemon; review T-057 T057-01): a process of its own with no pipe for
    its daemon to hold. `host.run` captures its output, and a call like that came back only at its 120-s timeout, so no run would have got past
    this line. A failed start keeps its message in the run's nginx_start.log. Returns the reason, or None. P1 calls it too."""
    import executor
    step = executor.Cmd(tuple(plan["nginx"]["start"]), SERVER_NS, detach=True)
    try:
        executor.start_daemon(host, step, types.SimpleNamespace(out=plan["out"]), lambda _said: None)
    except executor.SetupFailed as exc:
        return f"nginx did not start: {exc}"
    return None


def gunicorn_gone(host, plan, proc, when):
    """The reason a run gives for a gunicorn that exited by itself (D-063): a dead backend must not read as harm."""
    log = _text(host, plan["gunicorn"]["log"])
    named = next((f": {what} (gunicorn.log)" for line, what in GUNICORN_REFUSALS if line in log), "")
    return f"gunicorn exited {when} (code {proc.poll()}){named}"


def nginx_gone(code):
    """The reason a run gives when `nginx -s quit` fails at its end (D-063). That a master that has died gives a non-zero exit is [CLAIMED], NOT RUN."""
    return f"nginx was not running at the run's end: its quit exited {code}"


def _stop(host, proc, grace=STOP_GRACE_S, interrupt=False):
    if proc.poll() is None:
        (proc.interrupt if interrupt else proc.terminate)()
        if not _wait(host, lambda: proc.poll() is not None, grace, step=0.2):
            proc.kill()


def finish(host, plan, reasons, started, t0, procs, logs, stub, launched=(), timer=None, logs_at_start=None, interrupted=False):
    """Stop everything, take the logs into the run, tear the testbed down, check and write the run's records. As in P1 (D-068, review T-067
    T067-01), only the `interrupted` finish runs inside host.shielded(), from execute_run's handler: a Ctrl-C, TERM or HUP during an ordinary
    finish reaches that handler, whose shielded pass completes the stop and the teardown, and the block stops; a second interrupt in that pass is
    lost (T063-02). So an interrupted pass may follow an ordinary one cut short, and repeats what it did harmlessly. An `interrupted` run keeps
    its t0 and its generators, so its record keeps its figures (T063-08): they are stopped at once, not waited for, and the reasons a run's end
    and checks would add are left out, gunicorn's exit, nginx's quit and the logs' inodes included, which a first pass may already have taken,
    so that the interrupt is its reason."""
    import executor
    out = plan["out"]
    reasons = list(reasons)
    try:
        for _x, proc in launched if interrupted else ():
            if proc.poll() is None:
                proc.terminate()
        for x, proc in launched:                          # the generators end on their own at their duration
            if not _wait(host, lambda p=proc: p.poll() is not None, STOP_GRACE_S, step=0.5):
                if not interrupted:
                    reasons.append(f"{x['entity_id']} was still running {STOP_GRACE_S:g} s after its end: stopped")
                _stop(host, proc)
            elif proc.poll() != 0 and not interrupted:
                said = executor._tail(stderr_path(out, x["entity_id"]))
                reasons.append(f"{x['entity_id']} exited with code {proc.poll()}" + (f": {said[:200]}" if said else ""))
        for name, proc in procs:
            if name == "gunicorn" and t0 is not None and proc.poll() is not None and not interrupted and \
                    not any(r.startswith("gunicorn exited") for r in reasons):
                reasons.append(gunicorn_gone(host, plan, proc, f"at {host.time() - t0:.0f} s"))    # after the loop's last look
            if name == "daemon":
                _stop(host, proc, interrupt=True)          # SIGINT runs its finally, which detaches XDP
        if any(name == "gunicorn" for name, _p in procs):
            quit_code = host.run(plan["nginx"]["stop"], ns=SERVER_NS).code
            if quit_code != 0 and t0 is not None and not interrupted:   # stub_status judges nothing (D-050), so only this says it had gone
                reasons.append(nginx_gone(quit_code))
        for name, proc in procs:
            if name == "gunicorn":
                _stop(host, proc)
        if logs_at_start and t0 is not None and not interrupted:   # nginx and gunicorn have stopped: nothing writes these logs any more
            reasons += replaced_logs(host, logs_at_start)
        if procs:
            for name, path in NGINX_LOGS.items():
                host.run(["mv", "-f", path, os.path.join(out, name)])
    finally:
        for fh in logs.values():
            fh.close()
        if procs or t0 is not None:
            teardown(host, plan)
    ended = host.time()
    reasons += [] if interrupted else checks(host, plan, t0, launched)
    stall = stall_reading(plan, t0, launched, stub) if t0 is not None else None
    reasons += stall_reasons(stall) if stall and not interrupted else []
    for x, _proc in launched:
        with contextlib.suppress(OSError):
            if os.path.getsize(stderr_path(out, x["entity_id"])) == 0:
                os.remove(stderr_path(out, x["entity_id"]))
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
            "attack": attack_summary(plan) if t0 is not None else None, "stall": stall, "timer": timer, "daemon_provenance": daemon_prov,
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


def view_slips(rows, planned, origin, end):
    """{(user, view): seconds late} of one generator's views against each device's own closed-loop schedule, the intended start of
    eval/l7v2_harm.with_never_sent: the completion of the device's previous view plus that one's pause (the first view's is its
    nominal start). A slow or refusing server moves that completion, so it does not raise a slip: only the client's own lateness
    does. A view that never started and was due before the generator's end is late by at least what was left of it. A view that
    never completed leaves nothing to read the device's later views against: it was still busy with that view, as one hanging on
    a banned address is at its generator's end, and that must not read as a stall (review T-050 T050-16)."""
    sent = {}
    for r in rows:
        if not math.isnan(r["t_sent"]):
            sent.setdefault((r["user"], r["view"]), []).append(r)
    slips = {}
    for user in sorted({u for u, _v in planned}):
        intended = None
        for key in sorted(k for k in planned if k[0] == user):
            t_rel, classes, pause = planned[key]
            intended = origin + t_rel if intended is None else intended
            if intended >= end:
                break
            got = sent.get(key, [])
            slips[key] = (min(r["t_sent"] for r in got) if got else end) - intended
            done = [r["t_done"] for r in got if not math.isnan(r["t_done"])]
            if classes and len(done) < len(classes):
                break
            intended = (max(done) if classes else intended) + pause
    return slips


def stall_reading(plan, t0, launched, stub):
    """What a stall in mid-life leaves (review T-050, post-verdict): over the generators whose rows are in Q (an uploader writes none
    and is in no Q), the largest view slip and how many views passed STALL_BOUND_S; the largest launch lag; and the largest gap of
    the runner's own loop, which judges nothing: the stack's samples are never a validity rule (D-050), and a runner that stalled after
    its launches changed no client's traffic."""
    import l7v2_harm as LH
    out = {"bound_s": STALL_BOUND_S, "largest_view_slip_s": None, "entity": None, "view": None, "views": 0, "views_over_bound": 0,
           "no_records": [], "largest_launch_lag_s": max((x["lag_s"] for x, _p in launched), default=None), "late_launch": None,
           "largest_loop_gap_s": max((b["t"] - a["t"] for a, b in itertools.pairwise(stub)), default=None)}
    if launched:
        out["late_launch"] = max(launched, key=lambda item: item[0]["lag_s"])[0]["entity_id"]
    for e in plan["entities"]:
        if e["role"] != "benign" or e["kind_or_family"] not in _recorded_kinds():
            continue
        try:
            rows = LH.read_client_records(records_path(plan["out"], e))
        except (OSError, ValueError, TypeError):
            out["no_records"].append(e["entity_id"])
            continue
        dur = e["schedule"]["stop_s"] - e["schedule"]["start_s"]
        origin = rows[0]["t_origin"] if rows else t0 + e["schedule"]["start_s"]
        slips = view_slips(rows, LH.planned_views(e, dur), origin, origin + dur)
        out["views"] += len(slips)
        out["views_over_bound"] += sum(1 for s in slips.values() if s > STALL_BOUND_S)
        for key, slip in slips.items():
            if out["largest_view_slip_s"] is None or slip > out["largest_view_slip_s"]:
                out.update(largest_view_slip_s=slip, entity=e["entity_id"], view=list(key))
    return out


def stall_reasons(stall):
    """What of stall_reading() makes a run invalid: a loss in Q that nothing else would name."""
    reasons = []
    if stall["views_over_bound"]:
        reasons.append(f"a client stalled: {stall['views_over_bound']} views more than {STALL_BOUND_S:g} s late, the latest "
                       f"{stall['largest_view_slip_s']:.1f} s ({stall['entity']}, user {stall['view'][0]} view {stall['view'][1]})")
    if stall["no_records"]:
        reasons.append(f"{len(stall['no_records'])} benign generators left no readable records, the first {stall['no_records'][0]}")
    if (stall["largest_launch_lag_s"] or 0) > STALL_BOUND_S:
        reasons.append(f"{stall['late_launch']} was launched {stall['largest_launch_lag_s']:.1f} s late (more than {STALL_BOUND_S:g} s)")
    return reasons


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
            "calibration_sha256": sha256_file(block["calibration"]), "calibration_status": block["calibration_status"],
            "code_sha256": code,
            "selection_sha256": sha256_file(block["selection"]) if block.get("selection") else None,
            "knees_sha256": sha256_file(block["knees"]) if block.get("knees") else None}


def check_frozen(block, host):
    """T-052b, the rule of eval/harm_gate.py and eval/l7v2_harm.py: no campaign on a calibration record that is not frozen. Only a
    host that measures nothing is exempt (executor.Host.simulated: the tests, a simulated campaign); smoke, ladder and validation
    runs may name any record, and block.json says which."""
    if block["phase"] != "campaign" or getattr(host, "simulated", False):
        return
    import l7_backend
    try:
        l7_backend.require_frozen(l7_backend.load_record(block["calibration"])[0])
    except (OSError, ValueError) as exc:
        raise PlanError(f"campaign: {block['calibration']}: {exc}") from None


def check_knees(block, host):
    """§5 (review T-057 T057-04): a validation's and a campaign's level and halvings are the ladder's, read by eval/p4_ladder.py, under the same
    calibration record. A family with no knee stops here: what that means is not decided (T-060). Only a host that measures nothing may go
    without the file, as with check_frozen."""
    if block["phase"] not in ("validation", "campaign"):
        return
    path = block["knees"]
    if not path:
        if getattr(host, "simulated", False):
            return
        raise PlanError(f"{block['phase']}: --knees must name the ladder's record (eval/p4_ladder.py --out, §5)")
    try:
        with open(path, encoding="utf-8") as fh:
            rec = json.load(fh)
        levels, halvings, record = rec["levels"], rec["halvings"], rec["calibration_sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PlanError(f"{path} is not a record of eval/p4_ladder.py: {exc!r}") from None
    none = sorted(f for f in OUT.FAMILIES if levels.get(f) is None)
    if none:
        raise PlanError(f"{block['phase']}: {', '.join(none)} has no knee in {path}: what that means is not decided, so nothing runs (T-060)")
    typed = {f: block["sources"][f] for f in OUT.FAMILIES}
    if typed != {f: levels[f] for f in OUT.FAMILIES}:
        raise PlanError(f"{block['phase']}: the sources {typed} are not the ladder's knees { {f: levels[f] for f in OUT.FAMILIES} } ({path})")
    if block["halvings"] != halvings:
        raise PlanError(f"{block['phase']}: --halvings {block['halvings']}, and the ladder ran at {halvings} ({path})")
    if record != sha256_file(block["calibration"]):
        raise PlanError(f"{block['phase']}: {path} was read under another calibration record than {block['calibration']}")


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
    differ = sorted(k for k in ("sources", "halvings", "calibration_sha256", "knees_sha256") if mine[k] != theirs.get(k))
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
    if phase == "ladder":                       # a repeat stays on its seed: on another it would be attempt 1, with no reason asked
        other = sorted({x["block"] for x in rows if x["phase"] == "ladder" and x["label"] == block["label"] and x["block"] != seed})
        if other:
            raise PlanError(f"ladder {block['label']} ran on seed {other[0]}: a repeat is re-run on its own seed, with a reason, not rolled "
                            f"again on {seed} (review T-063 T063-05)")
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
    check_frozen(block, host)
    check_attempt(block)
    check_knees(block, host)
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
    slip = ((meta or {}).get("stall") or {}).get("largest_view_slip_s")
    seed = man["seed"] if block is None else block
    with open(os.path.join(os.path.dirname(run_dir), "block.json"), encoding="utf-8") as fh:
        settings = json.load(fh)["settings"]
    if t.get("t0_wall") is None:
        empty = {"Q": None, "p95_s": None, "q_per_s": [None] * OUT.RUN_S, "by_class": {}}
        return OUT.summarize(seed, man["arm"], False, empty, {"Q": None}, events, man["roles"], closes,
                             level_window=OUT.LEVEL_WINDOW_S, attempt=attempt, cal=cal, settings=settings, ban_problem=ban_problem,
                             reasons=meta["checks"]["reasons"] if meta else ["the runner died in this run"], view_slip_s=slip)
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
                         reasons=meta["checks"]["reasons"], view_slip_s=slip)


def summarize_root(root, calibration, out_path, dry_run=False):
    """The run records of EVERY evaluation attempt of ROOT/index.jsonl, valid or not, a run whose runner died included
    (D-035, V-03; P-07), under the calibration record `calibration` (a path), which must be the one the blocks name (P-08), and
    frozen unless `dry_run` (T-052b). A run directory the index does not hold is refused: it could hide a ban."""
    import l7_backend
    cal = l7_backend.load_record(calibration)[0]
    if not dry_run:
        l7_backend.require_frozen(cal)
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
    ap.add_argument("--knees", help="validation, campaign: the ladder's record (eval/p4_ladder.py --out)")
    ap.add_argument("--calibration", default=PLACEHOLDER)
    ap.add_argument("--root", default="/var/tmp/p4_runs")
    ap.add_argument("--python", default=PYTHON)
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (offline)")
    ap.add_argument("--summarize", nargs=2, metavar=("ROOT", "OUT_JSONL"))
    ap.add_argument("--dry-run", action="store_true", help="--summarize only: allow a record that is not frozen, for a simulated campaign")
    args = ap.parse_args(argv)
    if args.dry_run and not args.summarize:
        ap.error("--dry-run is for --summarize: a real campaign has no exemption, and a simulated host needs none")
    if args.summarize:
        try:
            summarize_root(args.summarize[0], args.calibration, args.summarize[1], dry_run=args.dry_run)
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
                           calibration=args.calibration, python=args.python, selection=args.selection, knees=args.knees)
    except (PlanError, PT.PlanError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    print(describe(block))
    if args.plan:
        return 0
    if host is None:
        import executor
        host = executor.RealHost()
        executor._install_signal_handlers()        # TERM and HUP end the run as Ctrl-C does
    try:
        results = run_block(host, block)
    except PlanError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt as exc:
        print(f"[-] interrupted ({exc}): the testbed is down; the run is invalid, and the index holds no end of it", file=sys.stderr)
        return 130
    for arm, res in results:
        print(f"  {arm}: {'valid' if res['ok'] else 'INVALID: ' + '; '.join(res['reasons'])}")
    return 0 if all(res["ok"] for _a, res in results) else 1


if __name__ == "__main__":
    sys.exit(main())

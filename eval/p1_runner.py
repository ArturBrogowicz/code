#!/usr/bin/env python3
"""The P1 runner (docs/L7V2_DESIGN.md 4.3, 5.3, 5.4, 9, 10, 11, 14): the runs of P1 on the costed backend.

THIS IS A VM WORKLOAD (T3): it builds network namespaces and starts nginx, gunicorn, the mitigation daemon and the
generators, as root. Run it only with the user's approval of a VM step. `--plan` prints what it would do and touches
nothing; the tests drive it with a fake host (tests/p1_fake_host.py), as eval/p4_runner.py's tests do.

A block is one seed (ml/p1_traffic.py build_block): its pool, role map, parameters, netem and schedules are the same in
every run. Its runs, in a seeded order, are the live set of ml/l7v2_verdict_prereg_v2.json: C, C' and, per class, U and
its live arms (13 runs; `--cut` is section 14's minimum cut, 9 runs). Every attempt, valid or not, is a line of
ROOT/index.jsonl with its reasons (section 13 row 6); an attempt is a directory ROOT/<phase>/b<seed>_a<attempt>[_<label>]/
<run>/ beside block.json, the run contract of eval/l7v2_harm.py.

The halving rule (ml/p1_prereg.json, D-049), before the ladder: phase `health` runs C and C' on the rule's pilot seed at
`--halvings`; eval/p1_analysis.py --health reads them into the next step, the frozen factor or a refusal, in a file bound to the
record. A ladder and a campaign refuse without a frozen factor in that file (--health), say why, and run every block at it.

What each arm runs is one table, ARM_TABLE, and nothing else decides it:
  * C, C' and U: no daemon, l7_conf.unprotected(nginx_unprotected.conf), with the file sink;
  * every M arm: l7_conf.protected(nginx.conf, key_map=True) and a deny directory with both maps (T-025e's report F8: one
    conf for every M arm, or R* alone pays the second map's lookup; an empty map answers its default);
  * default_rules (C3b, the status quo): the daemon's default profile and nginx.conf's limits as deployed, no L7 engine;
  * hgb, view_gru, R*: the tolerant profile (P5c.2, the heuristics that realistic benign traffic does not trip) and its nginx
    limits, and the enforcing arm (L7_ENFORCE=1, L7_SHADOW=1, the arm from its frozen selection, T-025e's env per arm).
The second map and R*'s live path are T-025e's (feat/l7v2-rstar, a parallel branch): until it is merged here (m_arms_pending),
an M arm's conf is planned without the map and a real run of it is refused.
Every conf is the run's own copy, the tracked files are only read (D-028): l7_conf for the arm, capture_l7.render_limits
for the profile's limits, file_sink for the l7json file sink, capture_l7.render_l7_sink for the daemon's socket,
executor.render_nginx_conf for the run's log paths. The deny run directory comes from l7_denymap.prepare_run_dir.

The stack (design 4.3): gunicorn 2 x 8, bound to loopback, with the costed backend and the record in use, on the server
CPUs; pins are the harm benchmark's daemon plan in every run (bench/population.PIN_PLAN_DAEMON), so an arm differs from U
only by what the table says. A campaign checks the frozen items before its first run: the record is frozen, the knees
are bound to it (L7V2-08) and the block runs at them, and both selections are the recorded ones and valid for claims
(train_l7v2.load_selection, l7v2_replay.load_rules); their sha256s go into block.json and every run's provenance.

Checks of a run (design 5.4): the stack answered; every planned client started and ended cleanly; in an M run the daemon was
ready before the traffic, alive to the end, with XDP attached, its start event says what the table says and the arm armed;
its l7_enforce_arm event names the arm, the selection's sha256 and R*'s rule; the kill file stayed absent; the file sink has no silence longer than LOG_GAP_MAX_S [ASSUMPTION] over the run. A run that
fails one is invalid, with its reasons. CPU per core is sampled every second (cpu.jsonl).

    sudo ./venv/bin/python eval/p1_runner.py --phase campaign --seed 3001 --calibration REC --knees KNEES \\
        --health HEALTH --selection SEL/selection.json --selection-sha256 H --rules RULES/rules_selection.json --rules-sha256 H
    ./venv/bin/python eval/p1_runner.py --phase health --seed 9001 --halvings 0 --plan
    ./venv/bin/python eval/p1_runner.py --phase ladder --seed 9001 --class C2 --level 2 --repeat 1 --health HEALTH --plan
    ./venv/bin/python eval/p1_runner.py --phase smoke --seed 9001 --levels C3b=50 --runs C,U_C3b --plan
"""
import argparse
import gzip
import hashlib
import inspect
import itertools
import json
import os
import random
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (REPO, os.path.join(REPO, "ml"), HERE, os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import capture_l7 as CAP
import executor as X
import l7v2_verdict_prereg as VP
import p1_traffic as PT
import p4_runner as P4
import population as POP

import ban_events
import l7_conf
import l7_dataset
import l7_denymap
import l7_ingest

FORMAT = "p1-run/1"
PHASES = ("smoke", "health", "ladder", "campaign")
HEALTH_FORMAT = "p1-health/1"
PINS = dict(POP.PIN_PLAN_DAEMON)           # the harm benchmark's plan with a daemon, in every run of a block
NS_PREFIX = "p1n"
SERVER_NS, SERVER_IP = P4.SERVER_NS, P4.SERVER_IP
GEN, DAEMON, PYTHON = P4.GEN, P4.DAEMON, P4.PYTHON
KILL_FILE = "/run/l7v2/kill"
SOCKET_PATH = l7_ingest.DEFAULT_SOCKET_PATH
HOST_LOGS = ("/var/log/nginx/ddos_ml_access.log", "/var/log/nginx/error.log")    # what the daemon's heuristic tails
READY_URL = f"http://{SERVER_IP}/"
DAEMON_READY_TIMEOUT_S, STACK_READY_TIMEOUT_S = 90.0, 30.0
LOG_GAP_MAX_S = 10.0                       # [ASSUMPTION] design 5.4's "the file-sink log has no gaps"
SETUP_S = 45                               # [ESTIMATE] design 14: a run's set-up and teardown
GUNICORN = {"backend": "costed", "gunicorn_workers": 2, "gunicorn_threads": 8}     # design 4.3
PROVENANCE_FILES = ("nginx.conf", "nginx_unprotected.conf", "control_plane.py", "l7_enforce.py", "l7_arms.py", "l7_conf.py",
                    "l7_denymap.py", "l7_engine.py", "l7_backend.py", "l7_webapp.py", "ml/l7_gen.py", "ml/l7_bots.py",
                    "ml/l7_benign.py", "ml/l7_pools.py", "ml/p1_traffic.py", "ml/l7v2_prereg.json",
                    "ml/l7v2_verdict_prereg_v2.json", "eval/p1_runner.py")
BAN_ENGINES = (*ban_events.ENGINES, ban_events.L7V2_ENGINE)     # D-037: the arm's engine sits outside ENGINES

# The one table: what each arm runs (T-025e's report, "Env per arm for the P1 runner", feat/l7v2-rstar c6028ce). Everything an
# arm's conf or daemon needs changes here only. L7_ALLOWLIST is empty: the runner's only monitoring is the readiness probe from
# the server's own 10.0.0.1, which the arm's built-in list holds. "budget" says what a flag on a benign key costs in the live
# reading (D-043, D-044; an XDP ban costs everyone behind the address in every arm).
_M_CONF = {"conf": "protected", "conf_kw": {"key_map": True}, "deny_kw": {"key_level": True}}
_ENFORCING = {"HEURISTIC_PROFILE": "tolerant", "L7_SHADOW": "1", "L7_ENFORCE": "1", "L7_KILL_FILE": KILL_FILE,
              "L7_SOCKET_PATH": SOCKET_PATH, "L7_ALLOWLIST": ""}
ARM_TABLE = {
    "C": {"conf": "unprotected", "daemon": None},
    "C'": {"conf": "unprotected", "daemon": None},
    "U": {"conf": "unprotected", "daemon": None},
    "default_rules": {**_M_CONF, "limits": "default", "daemon": {"HEURISTIC_PROFILE": "default", "L7_SHADOW": "0", "L7_ENFORCE": "0"}},
    "R*": {**_M_CONF, "limits": "tolerant", "selection": "rules", "budget": "rule_key", "daemon": {**_ENFORCING, "L7_ARM": "R*"}},
    "hgb": {**_M_CONF, "limits": "tolerant", "selection": "learned", "budget": "view_key", "daemon": {**_ENFORCING, "L7_ARM": "hgb"}},
    "view_gru": {**_M_CONF, "limits": "tolerant", "selection": "learned", "budget": "view_key",
                 "daemon": {**_ENFORCING, "L7_ARM": "view_gru"}},
}
SLUG = {"default_rules": "default_rules", "R*": "rstar", "hgb": "hgb", "view_gru": "gru"}


class PlanError(ValueError):
    """The run or block cannot be planned as asked."""


# --- runs ------------------------------------------------------------------------------------------

def run_name(arm, cls=None):
    """The run's directory, the names of eval/l7v2_harm.py's contract: C, Cp, U_<class>, M_<arm>_<class>."""
    if arm == "C":
        return "C"
    if arm == "C'":
        return "Cp"
    return f"U_{cls}" if arm == "U" else f"M_{SLUG[arm]}_{cls}"


def parse_run(name):
    """(arm, class) of a run's directory name."""
    if name == "C":
        return "C", None
    if name == "Cp":
        return "C'", None
    if name.startswith("U_"):
        return "U", name[2:]
    for arm, slug in SLUG.items():
        if name.startswith(f"M_{slug}_"):
            return arm, name[len(f"M_{slug}_"):]
    raise PlanError(f"not a run name: {name!r}")


def live_runs(cut=False, pre=None):
    """Every run of a block as (arm, class), from the pre-registered live set (or its minimum cut)."""
    live = (pre or VP.load())["live_set"]
    per_class = live["minimum_cut"]["per_class"] if cut else live["per_class"]
    out = [("C", None), ("C'", None)]
    for cls in sorted(per_class):
        out += [(arm, cls) for arm in per_class[cls]]
    want = live["minimum_cut"]["runs_per_block"] if cut else live["runs_per_block"]
    if len(out) != want:
        raise PlanError(f"{len(out)} runs in a block, the pre-registration says {want}")
    return out


def block_order(phase, seed, names, label=""):
    """The block's runs in a seeded random order (design 5.3); a re-run keeps it."""
    order = list(names)
    random.Random(f"p1-order|{phase}|{seed}|{label}").shuffle(order)
    return order


def m_arms_pending():
    """Why this checkout cannot run the M arms as the table says, or None: the second deny map comes with T-025e."""
    if "key_map" in inspect.signature(l7_conf.protected).parameters \
            and "key_level" in inspect.signature(l7_denymap.prepare_run_dir).parameters:
        return None
    return "the M arms' key map and R*'s live path are T-025e's (feat/l7v2-rstar), not merged in this checkout"


# --- the conf ----------------------------------------------------------------------------------------

def file_sink(text, path):
    """The conf with the lossless l7json file sink written next to the marker, which stays for the daemon's socket sink."""
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.strip().startswith(CAP.L7_SINK_MARKER)]
    if len(hits) != 1:
        raise PlanError(f"nginx conf: expected exactly one {CAP.L7_SINK_MARKER!r} line, found {len(hits)}")
    i = hits[0]
    indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
    lines.insert(i, f"{indent}access_log {path} l7json;\n")
    return "".join(lines)


def render_conf(spec, out, deny_dir):
    """The run's own nginx conf, from the tracked files, which are only read (D-028)."""
    if spec["conf"] == "unprotected":
        text = l7_conf.unprotected(l7_conf.read(l7_conf.UNPROTECTED_CONF))
    else:
        text = CAP.render_limits(l7_conf.read(l7_conf.PROTECTED_CONF), spec["limits"])
        text = l7_conf.protected(text, deny_dir, **(spec["conf_kw"] if m_arms_pending() is None else {}))
    text = file_sink(text, os.path.join(out, l7_dataset.ACCESS_LOG))
    if (spec["daemon"] or {}).get("L7_SHADOW") == "1":
        text = CAP.render_l7_sink(text, SOCKET_PATH)        # only with a daemon bound to it (audit G-23)
    return X.render_nginx_conf(text, os.path.join(out, "ddos_ml_access.log"), os.path.join(out, "error.log"),
                               feed=spec["daemon"] is not None)


class _Stack:
    PYTHON_VENV = None

    @staticmethod
    def _srv(cmd):
        return ["taskset", "-c", PINS["server"], *cmd]


def gunicorn_argv(record, python):
    _Stack.PYTHON_VENV = python
    return CAP.gunicorn_argv(_Stack, {**GUNICORN, "calibration": {"path": record}})


# --- frozen items ------------------------------------------------------------------------------------

def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def load_knees(path):
    if path is None:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_factor(frozen):
    """The frozen factor of the halving rule, from the health file (eval/p1_analysis.py --health), bound to the record in use; a
    file without a factor is refused, and the refusal says why (ml/p1_prereg.json halving.at_the_floor)."""
    import l7_backend
    path = frozen.get("health")
    if not path:
        raise PlanError("a ladder or a campaign needs the halving rule's frozen factor (--health, from eval/p1_analysis.py --health; "
                        "ml/p1_prereg.json halving)")
    try:
        with open(path, encoding="utf-8") as fh:
            health = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PlanError(f"the health file {path}: {exc}") from exc
    if health.get("format") != HEALTH_FORMAT:
        raise PlanError(f"{path} is not a {HEALTH_FORMAT} file")
    rec = l7_backend.load_record(frozen["calibration"])[0]
    if health.get("record_sha256") != rec.get("sha256"):
        raise PlanError(f"the health file was read on the calibration record {str(health.get('record_sha256'))[:12]}..., not on "
                        f"the record in use ({str(rec.get('sha256'))[:12]}...)")
    if health.get("decision") != "frozen":
        raise PlanError(f"the benign mix has no frozen factor ({health.get('decision')}): {health.get('why')}")
    return PT.check_halvings(health["benign_halvings"])


def plan_halvings(phase, frozen, knees, halvings):
    """A block's halvings: a smoke's or a health step's own; a ladder's and a campaign's the frozen factor, which a campaign's knees
    must name too, since they were measured at it."""
    if phase in ("smoke", "health"):
        return halvings or 0
    if halvings is not None:
        raise PlanError(f"a {phase} runs at the frozen factor (--health), not at --halvings")
    factor = load_factor(frozen)
    if phase == "campaign" and knees.get("benign_halvings") != factor:
        raise PlanError(f"the knees were measured at {knees.get('benign_halvings')} halvings, the frozen factor is {factor}")
    return factor


def check_frozen(frozen, *, need_frozen_record, arms):
    """What must be frozen before a run judges anything, each checked by its sha256: the record, the knees and the selections
    that the block's arms read. Returns their sha256s, or raises PlanError."""
    import l7v2_replay as RP
    import train_l7v2 as V

    import l7_backend
    out = {}
    path = frozen["calibration"]
    try:
        rec, status, _tag = l7_backend.load_record(path)
    except (OSError, ValueError) as exc:
        raise PlanError(f"the calibration record {path}: {exc}") from exc
    out["calibration"] = {"path": path, "sha256": sha256_file(path), "status": status, "digest": rec.get("sha256")}
    if need_frozen_record and status != "frozen":
        raise PlanError(f"the calibration record is {status!r}: only a frozen one gives a verdict "
                        "(ml/l7v2_prereg.json harm.verdict_record)")
    if frozen.get("knees"):
        out["knees"] = {"path": frozen["knees"], "sha256": sha256_file(frozen["knees"])}
    if frozen.get("health"):
        out["health"] = {"path": frozen["health"], "sha256": sha256_file(frozen["health"])}
    selections = {ARM_TABLE[a].get("selection") for a in arms} - {None}
    if "learned" in selections:
        try:
            sel = V.load_selection(frozen.get("selection") or "", frozen.get("selection_sha256"))
        except V.SelectionError as exc:
            raise PlanError(str(exc)) from exc
        if not sel.get("valid_for_claims"):
            raise PlanError(f"{frozen['selection']} is not valid for claims: the enforcing arm refuses it (T-042 E05)")
        out["selection"] = {"path": frozen["selection"], "sha256": frozen["selection_sha256"]}
    if "rules" in selections:
        try:
            _arms, r_star = RP.load_rules(frozen.get("rules") or "", frozen.get("rules_sha256"))
        except (OSError, RP.ReplayError) as exc:
            raise PlanError(f"the rule selection: {exc}") from exc
        with open(frozen["rules"], encoding="utf-8") as fh:
            sel = json.load(fh)
        if r_star is None:
            raise PlanError("the rule selection has no R*: no rule fits the budget")
        if not sel.get("valid_for_claims"):
            raise PlanError(f"{frozen['rules']} is not valid for claims")
        if sel.get("calibration", {}).get("sha256") != rec.get("sha256"):
            raise PlanError("the rule selection's class costs come from another calibration record")
        out["rules"] = {"path": frozen["rules"], "sha256": frozen["rules_sha256"], "r_star": r_star}
    return out


# --- one run's plan ----------------------------------------------------------------------------------

def gen_argv(entity, out, python):
    return P4.gen_argv(entity, out, python, cpus=PINS["legit"] if entity["role"] == "benign" else PINS["attack"])


def daemon_env(spec, out, deny_dir, conf_path, frozen):
    """Every variable the daemon reads, set (bench/executor.py DAEMON_ENV, off), then the arm's row of ARM_TABLE."""
    env = {**dict(X.DAEMON_ENV), "MITIGATION_BACKEND": "xdp", "BAN_EVENTS": os.path.join(out, "ban_events.jsonl"),
           **spec["daemon"]}
    if spec.get("selection"):
        key, sha = ("rules", "rules_sha256") if spec["selection"] == "rules" else ("selection", "selection_sha256")
        env.update({"L7_ENFORCE_DIR": deny_dir, "L7_NGINX_CONF": conf_path, "L7_SELECTION": frozen.get(key) or "",
                    "L7_SELECTION_SHA256": frozen.get(sha) or "", "L7_RECORD": os.path.join(out, "l7_record.jsonl")})
    return env


def plan_run(pop, phase, arm, cls, out, frozen, *, python=PYTHON):
    """One run as data: everything execute_run() does, and nothing it does not."""
    spec = ARM_TABLE[arm]
    name = run_name(arm, cls)
    ents = PT.run_entities(pop, cls)
    nss = P4.namespaces(ents, prefix=NS_PREFIX)
    launches = [{"entity_id": e["entity_id"], "role": e["role"], "ns": e["namespace"], "start_s": e["schedule"]["start_s"],
                 "argv": gen_argv(e, out, python)}
                for e in sorted(ents, key=lambda e: (e["schedule"]["start_s"], e["index"]))]
    conf_path = os.path.join(out, "nginx.conf")
    deny_dir = os.path.join(out, "l7v2_deny") if spec["conf"] == "protected" else None
    daemon = None
    if spec["daemon"] is not None:
        daemon = {"argv": ["taskset", "-c", PINS["daemon"], python, "-u", DAEMON], "cwd": REPO,
                  "env": daemon_env(spec, out, deny_dir, conf_path, frozen), "log": os.path.join(out, "daemon.log")}
    role = {"C": "control", "C'": "placebo", "U": "attack"}.get(arm, "mitigated")
    return {
        "format": FORMAT, "phase": phase, "seed": pop["seed"], "seed_role": pop["seed_role"], "name": name, "arm": arm,
        "class": cls, "role": role, "out": out, "timeline": dict(PT.TIMELINE), "levels": dict(pop["levels"]),
        "halvings": pop["halvings"],
        "budget": spec.get("budget"), "spec": {k: v for k, v in spec.items() if k != "daemon"},
        "pending": m_arms_pending() if spec["conf"] == "protected" else None,
        "nginx": {"conf_path": conf_path, "deny_dir": deny_dir,
                  "start": ["taskset", "-c", PINS["server"], "nginx", "-c", conf_path],
                  "stop": ["nginx", "-c", conf_path, "-s", "quit"]},
        "gunicorn": {"argv": gunicorn_argv(frozen["calibration"], python), "log": os.path.join(out, "gunicorn.log")},
        "daemon": daemon, "kill_file": KILL_FILE, "enforcing": bool(spec.get("selection")),
        "namespaces": nss, "launches": launches, "entities": ents,
    }


def plan_block(phase, seed, root, *, frozen, levels=None, attempt=1, label="", runs=None, cut=False, python=PYTHON,
               benign_specs=None, max_sources=None, halvings=None):
    """One block's runs, in their seeded order, as data. A campaign's levels are the knees, and its runs the live set; a health
    step is the rule's two controls on its seed (ml/p1_prereg.json halving)."""
    if phase not in PHASES:
        raise PlanError(f"unknown phase {phase!r}")
    role = "eval" if phase == "campaign" else "pilot"
    knees = load_knees(frozen.get("knees"))
    if phase == "campaign":
        if knees is None:
            raise PlanError("a campaign needs the frozen knees (--knees)")
        if runs is not None:
            raise PlanError("a campaign runs the live set")
        pairs = live_runs(cut)
        levels = {c: knees.get(c) for c in sorted({c for _a, c in pairs} - {None})}
    elif phase == "health":
        rule = PT.prereg()["halving"]
        if runs is not None or levels:
            raise PlanError("a health step runs the rule's two controls, without attack")
        if seed != rule["seed"]:
            raise PlanError(f"a health step runs on the rule's pilot seed {rule['seed']}, not on {seed} (ml/p1_prereg.json)")
        pairs, levels = [parse_run(n) for n in rule["controls"]], {}
        label = label or f"h{halvings or 0}"
    else:
        if runs is None:
            raise PlanError(f"{phase}: name the runs")
        pairs = [parse_run(n) for n in runs]
        levels = dict(levels or {})
    try:
        factor = plan_halvings(phase, frozen, knees, halvings)
        pop = PT.build_block(seed, role, levels, record_path=frozen["calibration"], knees=knees if phase == "campaign" else None,
                             benign_specs=benign_specs, max_sources=max_sources, halvings=factor)
    except PT.PlanError as exc:
        raise PlanError(str(exc)) from exc
    arms = {a for a, _c in pairs}
    sums = check_frozen(frozen, need_frozen_record=phase == "campaign", arms=arms)
    names = {run_name(a, c): (a, c) for a, c in pairs}
    order = block_order(phase, seed, names, label)
    name = f"b{seed}_a{attempt}" + (f"_{label}" if label else "")
    bdir = os.path.join(root, phase, name)
    try:
        planned = [plan_run(pop, phase, *names[n], os.path.join(bdir, n), frozen, python=python) for n in order]
    except PT.PlanError as exc:
        raise PlanError(str(exc)) from exc
    return {"phase": phase, "seed": seed, "attempt": attempt, "label": label, "dir": bdir, "root": root, "order": order,
            "levels": levels, "halvings": factor, "sources": pop["sources"], "cut": bool(cut), "frozen": sums,
            "calibration": frozen["calibration"],
            "intensity": pop["intensity"], "flash": pop["flash"], "dropped": pop["dropped"],
            "age_check": PT.age_report(pop) if phase == "campaign" else None, "runs": planned}


def vm_minutes(n_runs, setup_s=SETUP_S):
    """The VM time of `n_runs` runs [ESTIMATE of the set-up, design 14]."""
    return n_runs * (PT.run_seconds() + setup_s) / 60.0


def describe(block):
    """The text of --plan."""
    lines = [f"P1 {block['phase']} block {block['seed']} attempt {block['attempt']}: {block['dir']}",
             f"order {block['order']}; levels {block['levels']}; sources {block['sources']}",
             f"benign halvings {block['halvings']}; record {block['intensity']['label']}",
             f"VM time of this block: {vm_minutes(len(block['runs'])):.0f} min [ESTIMATE]"]
    for r in block["runs"]:
        d = r["daemon"]
        env = " ".join(f"{k}={v}" for k, v in sorted(d["env"].items())) if d else "none"
        lines.append(f"  run {r['name']}: conf {r['spec']['conf']} limits {r['spec'].get('limits')}, daemon {env}; "
                     f"{len(r['namespaces'])} namespaces, {sum(len(n['addresses']) for n in r['namespaces'])} addresses, "
                     f"{len(r['launches'])} generators ({sum(1 for x in r['launches'] if x['role'] == 'attack')} attacking)"
                     + (f"; PENDING: {r['pending']}" if r.get("pending") else ""))
    return "\n".join(lines)


# --- executing -----------------------------------------------------------------------------------

def _cpu_times(text):
    """{cpu number: (busy, total) jiffies} of /proc/stat."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"cpu(\d+)\s+(.*)", line)
        if m:
            v = [int(x) for x in m.group(2).split()]
            out[m.group(1)] = (sum(v) - v[3] - (v[4] if len(v) > 4 else 0), sum(v))
    return out


def provenance(plan, frozen_sums):
    return {"files_sha256": {f: sha256_file(os.path.join(REPO, f)) for f in PROVENANCE_FILES},
            "frozen": frozen_sums, "pins": dict(PINS), "population": PT.VERSION, "gunicorn": dict(GUNICORN)}


def start_problems(plan, events, frozen_sums=None):
    """What the daemon's start and arm events say against what the table asks (design 5.4; T-025e's "run validity")."""
    env = plan["daemon"]["env"]
    start = next((e for e in events if e.get("kind") == "start"), None)
    if start is None:
        return ["the daemon wrote no start event"]
    want = {"heuristic_profile": env["HEURISTIC_PROFILE"], "l7_enforce": env.get("L7_ENFORCE") == "1",
            "l7_shadow": env.get("L7_SHADOW") == "1", "l7_arm": env.get("L7_ARM") or None,
            "l7_selection_sha256": env.get("L7_SELECTION_SHA256") or None}
    out = [f"the daemon's start event says {k}={start.get(k)!r}, the run asks {v!r}" for k, v in want.items()
           if start.get(k) != v]
    if plan["enforcing"]:
        arm = next((e for e in events if e.get("kind") == "l7_enforce_arm"), None)
        if arm is None or not arm.get("armed"):
            out.append(f"the enforcing arm is not armed: {arm.get('reason') if arm else 'no l7_enforce_arm event'}")
        else:
            asked = {"arm": env["L7_ARM"], "selection_sha256": env["L7_SELECTION_SHA256"]}
            if env["L7_ARM"] == "R*":
                asked["rule_arm"] = ((frozen_sums or {}).get("rules") or {}).get("r_star")
            out += [f"the l7_enforce_arm event says {k}={arm.get(k)!r}, the run asks {v!r}" for k, v in asked.items()
                    if arm.get(k) != v]
    return out


def log_gap(path, t0, total):
    """The longest silence of the file sink over [t0, t0 + total] (design 5.4), from its $msec."""
    times = [t0, t0 + total]
    with l7_dataset.open_log(path) as fh:
        for line in fh:
            obj = l7_ingest.parse_l7_line(line)
            if obj is not None:
                msec = l7_ingest._num(obj.get("msec"))
                if t0 <= msec <= t0 + total:
                    times.append(msec)
    times.sort()
    return max(b - a for a, b in itertools.pairwise(times))


def execute_run(host, plan, frozen_sums):
    """Run one planned run on `host` and write its directory. Returns {"ok", "reasons", "started", "ended"}."""
    out = plan["out"]
    reasons, procs, launched, logs, cpu = [], [], [], {}, []
    os.makedirs(os.path.join(out, "records"), exist_ok=True)
    started = host.time()
    P4.write_json(os.path.join(out, "plan.json"), plan)
    ctx = {"started": started, "t0": None, "procs": procs, "logs": logs, "launched": launched, "cpu": cpu, "sums": frozen_sums}
    if not host.is_root():
        return finish(host, plan, ["not root: nothing was started"], ctx)
    if plan.get("pending") and not host.simulated:
        return finish(host, plan, [f"{plan['pending']}: nothing was started"], ctx)
    left = P4.leftovers(host, plan, prefix=NS_PREFIX)
    if left:
        return finish(host, plan, [f"leftover namespaces {left}: nothing was started"], ctx)
    if plan["enforcing"] and host.exists(plan["kill_file"]):
        return finish(host, plan, [f"the kill file {plan['kill_file']} exists: nothing was started"], ctx)
    try:
        if plan["nginx"]["deny_dir"]:               # nginx refuses an include of a missing file
            l7_denymap.prepare_run_dir(plan["nginx"]["deny_dir"], **(plan["spec"]["deny_kw"] if m_arms_pending() is None else {}))
        with open(plan["nginx"]["conf_path"], "w", encoding="utf-8") as fh:
            fh.write(render_conf(plan["spec"] | {"daemon": plan["daemon"]}, out, plan["nginx"]["deny_dir"]))
        procs.append(("topology", None))                # from here on the teardown runs, whatever happens
        P4.topology(host, plan)
        host.run(["mkdir", "-p", "/var/log/nginx", os.path.join(out, "feed_before")])
        for path in HOST_LOGS:                          # the daemon tails the host's log: nothing of an earlier run reaches it
            host.run(["mv", "-f", path, os.path.join(out, "feed_before", os.path.basename(path))])
        logs["gunicorn"] = open(plan["gunicorn"]["log"], "w", encoding="utf-8")       # noqa: SIM115 (closed in finish)
        procs.append(("gunicorn", host.popen(plan["gunicorn"]["argv"], ns=SERVER_NS, stdout=logs["gunicorn"],
                                             stderr=logs["gunicorn"], cwd=REPO)))
        if host.run(plan["nginx"]["start"], ns=SERVER_NS).code != 0:
            reasons.append("nginx did not start")
        ready = P4._wait(host, lambda: host.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2",
                                                 READY_URL], ns=SERVER_NS).out.strip() == "200", STACK_READY_TIMEOUT_S)
        if not ready:
            reasons.append(f"the stack did not answer {READY_URL} with 200 within {STACK_READY_TIMEOUT_S:g} s")
        daemon = None
        if plan["daemon"] and not reasons:
            d = plan["daemon"]
            logs["daemon"] = open(d["log"], "w", encoding="utf-8")                   # noqa: SIM115
            daemon = host.popen(d["argv"], ns=SERVER_NS, env=d["env"], stdout=logs["daemon"], stderr=logs["daemon"], cwd=d["cwd"])
            procs.append(("daemon", daemon))
            events = d["env"]["BAN_EVENTS"]
            if not P4._wait(host, lambda: P4.DAEMON_READY_LINE in P4._text(host, d["log"])
                            and any(e.get("kind") == "start" for e in P4._events(events)), DAEMON_READY_TIMEOUT_S):
                reasons.append(f"the daemon was not ready within {DAEMON_READY_TIMEOUT_S:g} s")
        if reasons:
            return finish(host, plan, reasons, ctx)
        ctx["t0"] = t0 = host.time()
        total = PT.run_seconds()
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
            cpu.append({"t": round(now, 3), "cpu": _cpu_times(P4._text(host, "/proc/stat"))})
            if plan["enforcing"] and kill_seen is None and host.exists(plan["kill_file"]):
                kill_seen = now
                reasons.append(f"the kill file appeared at {now:.0f} s: the arm stopped acting")
            if daemon is not None and daemon.poll() is not None:
                reasons.append(f"the daemon exited at {now:.0f} s (code {daemon.poll()})")
                daemon = None
            if now >= total:
                break
            host.sleep(min(1.0, max(0.0, total - now)))
        return finish(host, plan, reasons, ctx)
    except Exception as exc:  # noqa: BLE001 - whatever failed, the run is recorded and the teardown runs
        reasons.append(f"the runner failed: {type(exc).__name__}: {exc}")
        return finish(host, plan, reasons, ctx)


def finish(host, plan, reasons, ctx):
    """Stop everything, tear the testbed down, check and write the run's records."""
    out, procs, launched, t0 = plan["out"], ctx["procs"], ctx["launched"], ctx["t0"]
    reasons = list(reasons)
    try:
        for x, proc in launched:                          # the generators end on their own at their duration
            if not P4._wait(host, lambda p=proc: p.poll() is not None, P4.STOP_GRACE_S, step=0.5):
                reasons.append(f"{x['entity_id']} was still running {P4.STOP_GRACE_S:g} s after its end: stopped")
                P4._stop(host, proc)
            elif proc.poll() != 0:
                reasons.append(f"{x['entity_id']} exited with code {proc.poll()}")
        for name, proc in procs:
            if name == "daemon":
                P4._stop(host, proc, interrupt=True)       # SIGINT runs its finally, which detaches XDP and empties the map
        if any(name == "gunicorn" for name, _p in procs):
            host.run(plan["nginx"]["stop"], ns=SERVER_NS)
        for name, proc in procs:
            if name == "gunicorn":
                P4._stop(host, proc)
    finally:
        for fh in ctx["logs"].values():
            fh.close()
        if procs:
            P4.teardown(host, plan)
    ended = host.time()
    reasons += checks(host, plan, t0, launched, ctx["sums"])
    log = os.path.join(out, l7_dataset.ACCESS_LOG)
    if os.path.isfile(log):                               # a run's sink is tens of MB; the readers take either form
        with open(log, "rb") as src, gzip.open(log + ".gz", "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.remove(log)
    if ctx["cpu"]:
        with open(os.path.join(out, "cpu.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(c, sort_keys=True) + "\n" for c in ctx["cpu"])
    ok = not reasons
    meta = {"format": FORMAT, "role": plan["role"], "class": plan["class"], "arm": plan["arm"], "phase": plan["phase"],
            "seed": plan["seed"], "levels": plan["levels"], "halvings": plan["halvings"], "budget": plan["budget"],
            "checks": {"ok": ok, "reasons": reasons},
            "started_utc": P4._utc(ctx["started"]), "ended_utc": P4._utc(ended),
            "daemon": None if plan["daemon"] is None else {"env": plan["daemon"]["env"]},
            "provenance": provenance(plan, ctx["sums"])}
    P4.write_json(os.path.join(out, "run.json"), meta)
    P4.write_json(os.path.join(out, l7_dataset.MANIFEST_FILE), manifest(plan, t0))
    return {"ok": ok, "reasons": reasons, "started": ctx["started"], "ended": ended}


def checks(host, plan, t0, launched, frozen_sums=None):
    """The validity checks of a run that ran (design 5.4)."""
    if t0 is None:
        return []
    reasons = []
    total = PT.run_seconds()
    if len(launched) != len(plan["launches"]):
        reasons.append(f"{len(plan['launches']) - len(launched)} of {len(plan['launches'])} generators never started")
    log = os.path.join(plan["out"], l7_dataset.ACCESS_LOG)
    if not os.path.isfile(log):
        reasons.append("the file sink is missing")
    else:
        gap = log_gap(log, t0, total)
        if gap > LOG_GAP_MAX_S:
            reasons.append(f"the file sink has a silence of {gap:.1f} s (more than {LOG_GAP_MAX_S:g} s, design 5.4)")
    d = plan["daemon"]
    if d:
        if P4.XDP_ATTACHED_LINE not in P4._text(host, d["log"]):
            reasons.append("the daemon's log does not show XDP attached")
        reasons += start_problems(plan, P4._events(d["env"]["BAN_EVENTS"]), frozen_sums)
    return reasons


def manifest(plan, t0):
    """The run manifest, in schema 3's form so that l7_dataset labels it (l7v2_harm, l7v2_replay.RunLabels): the entities with
    their plans' fields, the time origin, the ip_map and the address map."""
    return {"format": l7_dataset.DATASET_FORMAT_V3, "run_format": FORMAT, "phase": plan["phase"], "seed": plan["seed"],
            "seed_role": plan["seed_role"], "run": plan["name"], "arm": plan["arm"], "class": plan["class"],
            "levels": plan["levels"], "halvings": plan["halvings"], "timeline": {**plan["timeline"], "t0_wall": t0},
            "entities": plan["entities"],
            "ip_map": l7_dataset.ip_map_from_entities(plan["entities"]),
            "address_map": l7_dataset.address_map_from_entities(plan["entities"]), "namespaces": plan["namespaces"]}


def run_bans(events):
    """The bans of a run's event log by engine (D-037: the arm's engine counts, though it sits outside ENGINES); an engine
    this runner does not know is kept under its own name, never dropped."""
    out = {}
    for e in events:
        if e.get("kind") == "ban":
            out.setdefault(str(e.get("engine", "unknown")), []).append(e)
    return out


def index_line(block, run, res):
    return {"phase": block["phase"], "block": block["seed"], "attempt": block["attempt"], "label": block["label"],
            "run": run["name"], "arm": run["arm"], "class": run["class"], "dir": os.path.relpath(run["out"], block["root"]),
            "valid": res["ok"], "reasons": res["reasons"], "started_utc": P4._utc(res["started"]),
            "ended_utc": P4._utc(res["ended"]), "block_dir": os.path.relpath(block["dir"], block["root"])}


def run_block(host, block):
    """Every run of a block in its order; each attempt appended to ROOT/index.jsonl, valid or not."""
    if os.path.exists(block["dir"]):
        raise PlanError(f"{block['dir']} exists: an attempt is never overwritten (use the next --attempt)")
    os.makedirs(block["dir"])
    P4.write_json(os.path.join(block["dir"], "block.json"),
                  {"block": block["seed"], "attempt": block["attempt"], "seed": block["seed"], "phase": block["phase"],
                   "calibration_sha256": block["frozen"]["calibration"]["digest"], "timeline": dict(PT.TIMELINE),
                   "order": block["order"], "levels": block["levels"], "halvings": block["halvings"],
                   "sources": block["sources"], "cut": block["cut"],
                   "frozen": block["frozen"], "intensity": block["intensity"], "flash": block["flash"],
                   "dropped": block["dropped"], "age_check": block["age_check"]})
    results = []
    with open(os.path.join(block["root"], "index.jsonl"), "a", encoding="utf-8") as idx:
        for run in block["runs"]:
            res = execute_run(host, run, block["frozen"])
            idx.write(json.dumps(index_line(block, run, res), sort_keys=True) + "\n")
            idx.flush()
            results.append((run["name"], res))
    return results


# --- the command line --------------------------------------------------------------------------------

def _levels(text):
    out = {}
    for part in (text or "").split(","):
        if part:
            cls, _eq, value = part.partition("=")
            out[cls] = float(value) if cls != "C3b" else int(value)
    return out


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phase", choices=PHASES, required=True)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--attempt", type=int, default=1)
    ap.add_argument("--class", dest="cls", help="ladder: the class")
    ap.add_argument("--level", type=float, help="ladder: the level (C3b: the number of bots)")
    ap.add_argument("--repeat", type=int, default=1, help="ladder: the repeat")
    ap.add_argument("--levels", help="smoke: CLASS=LEVEL,... (C3b: the number of bots)")
    ap.add_argument("--runs", help="smoke: run names, comma-separated (C, Cp, U_C3b, M_gru_C3b, ...)")
    ap.add_argument("--label", default="")
    ap.add_argument("--cut", action="store_true", help="campaign: section 14's minimum cut")
    ap.add_argument("--calibration", default=P4.PLACEHOLDER)
    ap.add_argument("--knees", help="campaign: the frozen knees (JSON: status, record_sha256, benign_halvings, C2, C3a, C3b)")
    ap.add_argument("--halvings", type=int, help="smoke, health: how often the halving rule has fired (ml/p1_prereg.json)")
    ap.add_argument("--health", help="ladder, campaign: the rule's frozen factor (eval/p1_analysis.py --health)")
    ap.add_argument("--selection")
    ap.add_argument("--selection-sha256")
    ap.add_argument("--rules")
    ap.add_argument("--rules-sha256")
    ap.add_argument("--root", default="/var/tmp/p1_runs")
    ap.add_argument("--python", default=PYTHON)
    ap.add_argument("--plan", action="store_true", help="print the plan and exit (offline)")
    args = ap.parse_args(argv)
    frozen = {"calibration": args.calibration, "knees": args.knees, "health": args.health, "selection": args.selection,
              "selection_sha256": args.selection_sha256, "rules": args.rules, "rules_sha256": args.rules_sha256}
    label, runs, levels = args.label, args.runs.split(",") if args.runs else None, _levels(args.levels)
    if args.phase == "ladder":
        if not args.cls or args.level is None:
            ap.error("a ladder needs --class and --level")
        lv = int(args.level) if args.cls == "C3b" else args.level
        levels, runs = {args.cls: lv}, ["C", f"U_{args.cls}"]
        label = label or f"{args.cls}_L{lv:g}_r{args.repeat}"
    try:
        block = plan_block(args.phase, args.seed, args.root, frozen=frozen, levels=levels, attempt=args.attempt, label=label,
                           runs=runs, cut=args.cut, python=args.python, halvings=args.halvings)
    except PlanError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    print(describe(block))
    if args.plan:
        return 0
    if host is None:
        host = X.RealHost()
    results = run_block(host, block)
    for name, res in results:
        print(f"  {name}: {'valid' if res['ok'] else 'INVALID: ' + '; '.join(res['reasons'])}")
    return 0 if all(res["ok"] for _n, res in results) else 1


if __name__ == "__main__":
    sys.exit(main())

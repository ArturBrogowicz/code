#!/usr/bin/env python3
"""The gate campaign of the harm benchmark: the blocks of one scenario, each block the control C, the placebo Cp and the attack U
in a drawn order, run by the executor and judged by eval/harm_gate.py (docs/HG1C_DESIGN.md 7, docs/HG1B_MINIMAL_DESIGN.md 5).

    python3 bench/gate_campaign.py plan SPEC --calibration FILE [--blocks N]
    sudo ./venv/bin/python bench/gate_campaign.py run SPEC --calibration FILE --out DIR [--dry-run] [--blocks N]
    sudo ./venv/bin/python bench/gate_campaign.py run SPEC --calibration FILE --out DIR --dry-run --timer-limit-ms 50   # a smoke test
    python3 bench/gate_campaign.py run SPEC --calibration FILE --out DIR --simulate pass       # no root, no namespace
    sudo ./venv/bin/python bench/gate_campaign.py run SPEC --calibration FILE --out DIR --modes xdp    # with the protected arm M_xdp
    python3 bench/gate_campaign.py status DIR

A campaign directory holds `campaign.json`, an unscored `warmup/C`, and one directory `bNN_aM` per block attempt with its
`block.json` and the runs `C`, `Cp` and `U` (and `M_<mode>` for each `--modes`), each in the run contract (bench/executor.py). `DONE` marks a finished run; the same
command resumes an interrupted campaign and refuses to resume with other settings. After a block the decision to re-run it is
made by harm_gate.assess_block, so the rule cannot be applied differently here and in the analysis; harm_gate.analyse re-checks the
whole directory and has the last word. `--simulate` runs the whole campaign on the simulated host (bench/sim_host.py), with a harm of
a known size, and lets harm_gate give a verdict: the protocol seen working offline, and nothing about any server.

`--rho`, `--timeline` and `--timer-limit-ms` are for smoke tests (a lighter load, a short run, a timer limit other than the
calibration's). They are recorded as overrides in every plan, run and block, and harm_gate gives no verdict on a campaign that
carries any: it says INVALID and why. Only the simulated host's campaigns get one, and gate.md says that it is no result.
`--timer-limit-ms` needs `--dry-run`, so that a campaign meant to count is not run with it.
"""
import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import random
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "eval"))
import calibration as C
import executor as X
import harm_gate as H
import loadtools as LT
import population as P
import scenario as SC
import sim_host as S

DONE, CAMPAIGN, SIMULATED, WARMUP = "DONE", "campaign.json", "SIMULATED", "warmup"
RUN_ESTIMATE_S = 150.0                      # one run, docs/HG1C_DESIGN.md 6.2; S4 replaces it with a measurement
# refusals and failures of the setting-up end the campaign; they say nothing about the block and are not re-run
STOP_ERRORS = (X.PreflightRefused, X.EnvironmentRefused, X.SetupFailed, X.LeftoverError, X.TableUnreadable)
KEPT_OF_UNFINISHED = ((H.BAN_FILE, "ban file"), ("environment.json", "gate's record"), ("executor.log", "log"))
EXIT_OK, EXIT_USAGE, EXIT_STOPPED, EXIT_INTERRUPTED = 0, 1, 2, 130


class CampaignError(RuntimeError):
    """The campaign cannot be started, continued or trusted as it is."""


@dataclasses.dataclass(frozen=True)
class Options:
    blocks: int | None = None               # fewer blocks than the scenario's, for a smoke test
    dry_run: bool = False                   # allow a placeholder calibration; everything is labelled
    warmup: bool = True
    allow_dirty: bool = False
    clean: bool = False
    wait_gate_min: float = 30.0
    keep_going: bool = False                # go on although the gate can no longer reach its minimum of valid blocks
    rho: float | None = None                # smoke test: the benign load
    timeline: tuple | None = None           # smoke test: baseline, attack, recovery
    timer_limit_ms: float | None = None     # smoke test: the limit for the timer on the legit CPU, instead of the calibration's
    settings: tuple = ()                    # executor settings changed, as (name, value) pairs
    simulate: str | None = None             # the name of an effect preset of bench/sim_host.py
    modes: tuple = ()                       # the protected arms, M_<mode> in every block beside C, Cp and U (HG4)
    confirm_2x_knee: bool = False           # the one further confirmation of design 7.2 step 6, after one at the knee has failed


def kinds_of(opts):
    """The runs of a block: C, Cp, U and one M_<mode> for each protected mode."""
    return [*X.KINDS, *(X.MITIGATED + m for m in opts.modes)]


def pins_text(pins):
    return ", ".join(f"{k} {v}" for k, v in pins.items())


def pins_of(opts):
    """The pin plan of every run of the campaign (the warm-up's too): the daemon's as soon as one mode has a daemon."""
    return X.pins_for(kinds_of(opts))


def now():
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def timeline_of(scn, opts):
    t = scn.timeline if opts.timeline is None else P.Timeline(*opts.timeline)
    return {"baseline_s": t.baseline_s, "attack_s": t.attack_s, "recovery_s": t.recovery_s}


def block_count(scn, opts):
    planned = scn.gate["blocks"] if scn.gate else 1
    if opts.blocks is not None and not 1 <= opts.blocks <= planned:
        raise CampaignError(f"--blocks: between 1 and the scenario's {planned}, got {opts.blocks}")
    return planned if opts.blocks is None else opts.blocks


def run_order(scn, block, attempt, modes=()):
    """The order of C, Cp, U and the protected runs M_<mode> in an attempt, drawn from the scenario, the block and the attempt, so
    that it can be recomputed when a campaign resumes. The order recorded in block.json is the one that counts. Without modes the
    draw is the one it always was."""
    runs = [*X.KINDS, *(X.MITIGATED + m for m in modes)]
    random.Random(f"{scn.id}|{scn.first_seed}|{block}|{attempt}").shuffle(runs)
    return runs


def block_dir(out, block, attempt):
    return os.path.join(out, f"b{block:02d}_a{attempt}")


def sha256_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def fingerprint(scn, cal, scenario_sha, opts):
    """What a campaign was started with; a resumed one must have the same."""
    return {"scenario": scn.id, "scenario_sha256": scenario_sha, "calibration_sha256": cal.get("sha256") or C.digest(cal),
            "calibration_status": cal["status"], "seed_namespace": scn.seed_namespace, "first_seed": scn.first_seed,
            "blocks": block_count(scn, opts), "timeline": timeline_of(scn, opts), "rho_rps": opts.rho,
            "timer_limit_ms": opts.timer_limit_ms, "settings": {**X.SETTINGS, **dict(opts.settings)}, "gate": cal["gate"],
            "warmup": opts.warmup, "simulate": opts.simulate, "modes": list(opts.modes), "pins": pins_of(opts),
            "confirmation": confirmation_of(opts)}


# --- the plan ---------------------------------------------------------------------------------

def describe(scn, cal, scenario_sha, opts):
    """What the campaign would do, as text. Pure."""
    scn = at_campaign_level(scn, cal, opts)
    n = block_count(scn, opts)
    gate = cal["gate"]
    per_block = len(kinds_of(opts))
    runs = per_block * n + (1 if opts.warmup else 0)
    out = [f"== gate campaign: {scn.id} ({scn.seed_namespace}), {n} blocks =="]
    out.append(f"calibration  sha256:{(cal.get('sha256') or C.digest(cal))[:8]} "
               + ("PLACEHOLDER: a dry run, nothing it makes is a result" if cal["status"] != "frozen" else "frozen"))
    level = "none" if scn.is_control else SC.resolve_level(scn, cal)
    out.append(f"scenario     sha256:{scenario_sha[:8]}, {scn.family} ({scn.threat_class}), attack level {level}")
    if opts.confirm_2x_knee:
        out.append("CONFIRMATION at 2 x the knee, asked for by hand: the design's one further confirmation, for after one at the knee has "
                   "failed; every run's manifest records it, and both outcomes are reported")
    if not scn.is_control:
        if cal["status"] != "frozen":
            rule = "no frozen record: a dry run may take any level, and the gate gives it no verdict"
        elif opts.modes:
            times = HG4_KNEE_MULTIPLE.get(scn.family, 1)
            rule = ("with protected arms (HG4) " + (f"{scn.family} runs at {times} x the frozen knee (D-071)" if times != 1 else
                                                    "the frozen knee") + "; `run` refuses any other level")
        else:
            rule = ("the design allows the frozen knee and, as the one further confirmation after a failure, 2 x the knee; "
                    "`run` refuses any other level on a frozen record")
        out.append("level rule   " + rule)
    out.append("timeline     " + ", ".join(f"{k} {v:g}" for k, v in timeline_of(scn, opts).items()))
    smoke = {k: v for k, v in (("rho", opts.rho), ("timeline", opts.timeline), ("timer limit ms", opts.timer_limit_ms)) if v}
    if smoke:
        out.append("OVERRIDES    " + ", ".join(f"{k} {v}" for k, v in smoke.items()) + ": a smoke test, not a result")
    if opts.simulate:
        out.append(f"SIMULATED    the simulated host, preset {opts.simulate}: no namespace, no traffic, nothing about any server")
    out.append(f"blocks       seeds {scn.first_seed}-{scn.first_seed + n - 1} in {scn.seed_namespace}; a block is "
               + ", ".join(kinds_of(opts)) + " in the order shown; a failed block is re-run once with its seed and a new order")
    out.append(f"re-runs      at most {gate['max_reruns']} in the campaign; a valid block is never re-run"
               + ("; a block whose protected run is not valid is not valid either" if opts.modes else ""))
    if opts.modes:
        pins = pins_of(opts)
        o = H.P2_OUTCOME
        out.append(f"arms         {', '.join(X.MITIGATED + m for m in opts.modes)}: {'; '.join(X.MODE_TEXT[m] for m in opts.modes)}")
        out.append("pins         " + pins_text(pins) + f" for every run (the executor on CPU "
                   f"{P.executor_cpus(pins)})")
        out.append(f"P2 outcome   pre-registered (harm_gate.P2_OUTCOME): unprotected fails in {o['block_share']:.0%} of the blocks "
                   f"(dQ >= {o['unprotected_floor_pp']:g} pp or p95 >= {o['unprotected_p95_ratio']:g} x C); protected works when "
                   f"Q(M) >= {o['protected_q_ratio']:g} x Q(C) in as many and no legit identity is blocked; TTM reported")
    out.append(f"timer gate   every run, on CPU {pins_of(opts)['legit']}: {X.timer_wait_text(opts.wait_gate_min)}; a last refusal stops the "
               "campaign, and the same command resumes it; waits are not in the VM time below")
    out.append(f"the gate     needs {gate['min_blocks']} valid blocks; floors {gate['floor_pp']:g} pp and "
               f"{gate['floor_log2_p95']:g} in log2 p95; interval {gate['ci_level']:g}, same sign {gate['same_sign_share']:.0%}")
    out.append("warm-up      " + (f"one unscored C run at seed {scn.first_seed}, in {WARMUP}/" if opts.warmup
                                  else "none (--no-warmup)"))
    out.append(f"VM time      {runs} runs at about {RUN_ESTIMATE_S:.0f} s = {runs * RUN_ESTIMATE_S / 3600:.1f} h; each re-run adds "
               f"{per_block * RUN_ESTIMATE_S / 60:.1f} min" + (f" ({per_block} runs); at most {gate['max_reruns']} re-runs, "
                                                               f"{gate['max_reruns'] * per_block * RUN_ESTIMATE_S / 60:.1f} min"
                                                               if per_block != 3 else ""))
    out.append("")
    warned = SC.plan(scn, cal, pins=pins_of(opts))["warnings"]        # the scenario plan's own, so that the two plans cannot disagree
    problem = level_problem(scn, cal, opts)
    out += [f"WARNING: {w}." for w in warned] + ([f"WARNING: `run` refuses this: {problem}."] if problem else [])
    if warned or problem:
        out.append("")
    if n < gate["min_blocks"]:
        out.append(f"WARNING: {n} blocks are fewer than the {gate['min_blocks']} the gate needs: the verdict would be INVALID.\n")
    out.append("block  seed  order of attempt 1")
    for b in range(1, n + 1):
        out.append(f"{b:>5}  {scn.first_seed + b - 1:>4}  " + ", ".join(run_order(scn, b, 1, opts.modes)))
    return "\n".join(out) + "\n"


# --- the state of a campaign ------------------------------------------------------------------

def load_state(out, fp):
    """campaign.json of `out`, checked against `fp`; None if the campaign is new. The pin plan is part of `fp`. A record without
    one was made before the campaigns recorded their pins (HG4), possibly under D14's first plan (`population.PIN_PLAN_BEFORE_D032`:
    the legit streams and the timer gate on CPU 6), which no plan of this code is: it is read as that plan and refused, so that one
    campaign never mixes two layouts (T-039 V-22). Fails closed: such a campaign is not resumed; another directory starts anew."""
    path = os.path.join(out, CAMPAIGN)
    if not os.path.exists(path):
        if os.path.isdir(out) and os.listdir(out):
            raise CampaignError(f"{out} holds something that is not a campaign (no {CAMPAIGN})")
        return None
    state = read_json(path)
    if "pins" not in state["fingerprint"]:
        raise CampaignError(f"{out} records no pin plan: it was started before campaigns recorded theirs, and is read as the plan "
                            f"of before 2026-10-31 (D-032), {pins_text(P.PIN_PLAN_BEFORE_D032)}, while this campaign would run "
                            f"with {pins_text(fp['pins'])}; a campaign resumes only as it began. Use another directory for "
                            "another campaign.")
    before = {"modes": [], "confirmation": None, **state["fingerprint"]}      # a campaign of before HG4 had no modes (nor pins: refused above)
    differ = sorted(k for k in fp if before.get(k) != fp[k])
    if differ:
        raise CampaignError(f"{out} was started with other settings ({', '.join(differ)}); a campaign resumes only as it "
                            "began. Use another directory for another campaign.")
    return state


def save_state(out, state):
    X.write_json(os.path.join(out, CAMPAIGN), state)


def run_record(result):
    return {"ok": result.ok, "reasons": result.reasons, "seconds": round(result.seconds, 1),
            "setup_retries": result.setup_retries, "timer_refused_probes": result.timer_refused_probes,
            "timer_waited_s": result.timer_waited_s}


def mark_done(run_path, record):
    X.write_json(os.path.join(run_path, DONE), {**record, "finished_utc": now()})


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_done(run_path):
    path = os.path.join(run_path, DONE)
    return read_json(path) if os.path.exists(path) else None


# --- one attempt ------------------------------------------------------------------------------

def plans_of(scn, cal, cal_path, scenario_sha, out_dir, seed, opts):
    """The plans of the runs of a block (C, Cp, U and the protected ones), with the campaign's pin plan; their legit streams must
    be the same."""
    plans = {kind: X.plan_run(scn, cal, kind, seed, os.path.join(out_dir, kind), cal_path, scenario_sha,
                              settings=dict(opts.settings), rho=opts.rho, timeline=opts.timeline,
                              timer_limit_ms=opts.timer_limit_ms, pins=pins_of(opts), confirmation=confirmation_of(opts))
             for kind in kinds_of(opts)}
    hashes = {p.plan_sha256 for p in plans.values()}
    if len(hashes) != 1:
        names = list(plans)
        raise CampaignError(f"the legit streams of {', '.join(names[:-1])} and {names[-1]} differ (plan hashes "
                            f"{sorted(h[:8] for h in hashes)}): "
                            "a block compares runs that must have the same clients")
    return plans


def keep_unfinished(parent, name, run_path):
    """What must outlive an unfinished run about to be removed, copied beside it as <name>.unfinished.<k>.<file>, one k for one run:
    its ban file (a legit identity its daemon banned still counts against the protected arm, harm_gate.campaign_benign_bans), and its
    gate's record and log (every timer probe stays on record, D-045, and a resume starts a new wait: docs/HG1C_DESIGN.md departure 32).
    Says what it kept, for the message about the removal."""
    files = [(f, what) for f, what in KEPT_OF_UNFINISHED if os.path.isfile(os.path.join(run_path, f))]
    if not files:
        return ""
    k, there, said = 1, os.listdir(parent), []
    while any(f.startswith(f"{name}{H.UNFINISHED}{k}.") for f in there):
        k += 1
    for f, what in files:
        kept = f"{name}{H.UNFINISHED}{k}.{f}"
        shutil.copy2(os.path.join(run_path, f), os.path.join(parent, kept))
        said.append(f"; its {what} is kept as {kept}")
    return "".join(said)


def run_attempt(scn, cal, cal_path, scenario_sha, out, block, attempt, host, opts, gate, say):
    """Make the runs of one attempt that are not made yet, write its block.json, and return the gate's assessment of it and
    the gate mode the next run should use. A run that fails or is found unsound ends the attempt: the block is invalid
    whatever the other runs say, and finishing it would spend VM time on nothing."""
    seed = scn.first_seed + block - 1
    d = block_dir(out, block, attempt)
    meta_path = os.path.join(d, "block.json")
    if os.path.exists(meta_path) and read_json(meta_path).get("complete"):
        say(f"block {block} attempt {attempt}: made already")
        return H.assess_block(d, cal), gate
    plans = plans_of(scn, cal, cal_path, scenario_sha, d, seed, opts)
    os.makedirs(d, exist_ok=True)
    planned, made, records, aborted = run_order(scn, block, attempt, opts.modes), [], {}, None
    for kind in planned:
        run_path = plans[kind].out
        record = read_done(run_path)
        if record is None:
            if os.path.exists(run_path):
                say(f"block {block} attempt {attempt} {kind}: removing the unfinished run{keep_unfinished(d, kind, run_path)}")
                shutil.rmtree(run_path)
            say(f"block {block} attempt {attempt} seed {seed}: run {kind}")
            try:
                result = X.execute(plans[kind], host, gate, opts.allow_dirty, opts.clean, opts.wait_gate_min, say)
            except STOP_ERRORS:
                raise
            except X.RunFailed as exc:
                record = {"ok": False, "failed": str(exc), "reasons": [str(exc)]}
            else:
                record = run_record(result)
            mark_done(run_path, record)
            gate = "timer"
        records[kind] = record
        if os.path.exists(os.path.join(run_path, "run.json")):
            made.append(kind)
        if not record["ok"]:
            aborted = kind
            say(f"block {block} attempt {attempt}: run {kind} is not sound ({'; '.join(record['reasons'])[:200]}): "
                "the attempt ends here")
            break
    t = timeline_of(scn, opts)
    X.write_json(meta_path, {
        "scenario": scn.id, "block": block, "attempt": attempt, "seed_namespace": scn.seed_namespace, "seed": seed,
        "calibration_sha256": cal.get("sha256") or C.digest(cal), "timeline": t, "order": made,
        "scenario_sha256": scenario_sha, "plan_sha256": next(iter(plans.values())).plan_sha256, "planned_order": planned,
        "aborted": aborted, "runs": records, "overrides": plans[planned[0]].overrides, "confirmation": confirmation_of(opts), "complete": True,
        "finished_utc": now()})
    return H.assess_block(d, cal), gate


# --- the campaign -----------------------------------------------------------------------------

def attempt_row(a):
    return {"block": a["block"], "attempt": a["attempt"], "seed": a["seed"], "valid": a["valid"], "reasons": a["reasons"],
            "order": a["order"], "dQ": a["dQ"], "dL": a["dL"], "dQ_placebo": a["dQ_placebo"],
            "valid_all": a["valid_all"], "arm_reasons": a["arm_reasons"], "waits": a.get("waits")}


def warm_up(scn, cal, cal_path, scenario_sha, out, host, opts, gate, say):
    """One unscored C run at the first block's seed, apart from the blocks (HG1c D25): the first run on a cold stack is not like
    the others and must not be the control of a block. Returns its record and the gate mode of the next run."""
    path = os.path.join(out, WARMUP, "C")
    record = read_done(path)
    if record is not None:
        return record, gate
    if os.path.exists(path):
        say(f"warm-up: removing the unfinished run{keep_unfinished(os.path.dirname(path), os.path.basename(path), path)}")
        shutil.rmtree(path)
    plan = X.plan_run(scn, cal, "C", scn.first_seed, path, cal_path, scenario_sha, settings=dict(opts.settings),
                      rho=opts.rho, timeline=opts.timeline, timer_limit_ms=opts.timer_limit_ms, pins=pins_of(opts),
                      confirmation=confirmation_of(opts))
    say(f"warm-up run C at seed {scn.first_seed}")
    try:
        record = run_record(X.execute(plan, host, gate, opts.allow_dirty, opts.clean, opts.wait_gate_min, say))
    except STOP_ERRORS:
        raise
    except X.RunFailed as exc:
        raise CampaignError(f"the warm-up run failed ({exc}); a stack that cannot do that is not ready for blocks") from exc
    mark_done(path, record)
    return record, "timer"


def check_calibration(cal, opts):
    if cal["status"] != "frozen" and not opts.dry_run:
        raise CampaignError("the calibration is a placeholder: its numbers are illustrations. Freeze one (bench/calibrate.py), "
                            "or pass --dry-run to run the protocol and label everything a dry run.")


def confirmation_of(opts):
    """What a run's manifest says of its level: None, or the design's one further confirmation."""
    return "2x_knee" if opts.confirm_2x_knee else None


def at_campaign_level(scn, cal, opts):
    """The scenario at the campaign's level: its own, or with --confirm-2x-knee twice the record's knee (design 7.2 step 6). That is asked
    for by hand and recorded in every run's manifest; nothing starts it after a failure (docs/HG1C_DESIGN.md departure 38)."""
    if not opts.confirm_2x_knee:
        return scn
    knee = None if scn.is_control else cal["knees"].get(scn.family)
    if not isinstance(knee, (int, float)):
        raise CampaignError(f"--confirm-2x-knee needs a knee for {scn.family or scn.id} in the calibration; it holds {knee!r}")
    return dataclasses.replace(scn, intensity={**scn.intensity, "level": 2 * float(knee)})


# docs/HG1C_DESIGN.md departure 39 (D-071, the user's, 2026-11-06, before any HG4 data; R-020): a campaign with protected arms (HG4) runs
# these families at this multiple of the frozen knee, which their HG4 spec states as a number; every other family at the knee
HG4_KNEE_MULTIPLE = {"cheap_static_flood": 2}


def level_problem(scn, cal, opts):
    """Why a campaign on a frozen record may not run at the scenario's level, or None (docs/HG1C_DESIGN.md departure 37): design 7.2 step
    6 allows 'Ten paired blocks at the frozen kappa_f' and, if that fails, one further confirmation at 2 x kappa_f; 'no other level is
    tried'. A record that is not frozen makes no result at any level, and a dry run may take any."""
    if cal["status"] != "frozen" or scn.is_control:
        return None
    knee = cal["knees"].get(scn.family)
    if not isinstance(knee, (int, float)):
        return f"the frozen record holds no knee for {scn.family} ({knee!r}), so no level of {scn.id} is one the design allows"
    level = SC.resolve_level(scn, cal)
    if opts.modes:
        if opts.confirm_2x_knee:
            return ("--confirm-2x-knee is HG3's one further confirmation (design 7.2 step 6); a campaign with protected arms (HG4) takes "
                    "its own level (departure 39)")
        times = HG4_KNEE_MULTIPLE.get(scn.family, 1)
        if level == times * knee:
            return None
        return (f"{scn.id} is at level {level:g}; with protected arms (HG4) {scn.family} runs at "
                + (f"{times} x its frozen knee of {knee:g}, so {times * knee:g} (D-071)" if times != 1 else f"its frozen knee, {knee:g}"))
    if level == knee or (opts.confirm_2x_knee and level == 2 * knee):
        return None
    return (f"{scn.id} is at level {level:g}, and the frozen knee of {scn.family} is {knee:g}: the design (7.2 step 6) allows only the knee "
            "and, as the one further confirmation after a failure, 2 x the knee, which --confirm-2x-knee asks for"
            + (f"; with protected arms (--modes) this family runs at {HG4_KNEE_MULTIPLE[scn.family]} x the knee (D-071)"
               if scn.family in HG4_KNEE_MULTIPLE else ""))


def check_options(opts):
    """A timer limit other than the calibration's is a smoke test's, and the harm gate gives no verdict on runs that carry it:
    a campaign meant to count would spend its VM hours for nothing, so it is refused before any starts."""
    if opts.timer_limit_ms is not None and not opts.dry_run:
        raise CampaignError("--timer-limit-ms: a smoke test's override, so the campaign is a dry run: pass --dry-run, or run it "
                            "with the calibration's limit")
    check_modes(opts)


def check_modes(opts):
    """Each protected mode once, and one that is built (the L7 GRU's are named and refused until they are)."""
    if len(set(opts.modes)) != len(opts.modes):
        raise CampaignError(f"--modes: each mode once, got {', '.join(opts.modes)}")
    for mode in opts.modes:
        try:
            X.mode_of(X.MITIGATED + mode)
        except X.PlanError as exc:
            raise CampaignError(f"--modes: {exc}") from exc


def run_campaign(scn, cal, cal_path, scenario_sha, out, host, opts=None, say=print):
    """Carry out the campaign in `out`, or resume it. Returns the campaign record (also campaign.json) with the gate's analysis
    in `gate`. Raises CampaignError for a campaign that cannot be run, and lets the executor's refusals and KeyboardInterrupt
    through after recording that the campaign stopped; the same command resumes it."""
    opts = opts or Options()
    check_calibration(cal, opts)
    check_options(opts)
    scn = at_campaign_level(scn, cal, opts)
    problem = level_problem(scn, cal, opts)
    if problem:
        raise CampaignError(problem)
    fp = fingerprint(scn, cal, scenario_sha, opts)
    state = load_state(out, fp)
    os.makedirs(out, exist_ok=True)
    if state is None:
        state = {"fingerprint": fp, "created_utc": now(), "git": X.git_state(host), "simulated": opts.simulate,
                 "state": "running", "stopped": None, "warmup": None, "attempts": [], "reruns": 0}
        if opts.simulate:
            with open(os.path.join(out, SIMULATED), "w", encoding="utf-8") as fh:
                fh.write("this directory was made by the simulated host: nothing in it was measured\n")
    state.update(state="running", stopped=None)
    save_state(out, state)
    gate_mode, gate, reruns, valid, attempts = "full", cal["gate"], 0, 0, []
    n = fp["blocks"]
    try:
        if opts.warmup:
            state["warmup"], gate_mode = warm_up(scn, cal, cal_path, scenario_sha, out, host, opts, gate_mode, say)
            save_state(out, state)
        for block in range(1, n + 1):
            attempt = 1
            while True:
                a, gate_mode = run_attempt(scn, cal, cal_path, scenario_sha, out, block, attempt, host, opts, gate_mode, say)
                attempts.append(attempt_row(a))
                state.update(attempts=attempts, reruns=reruns)
                save_state(out, state)
                if a["valid_all"]:                  # C, Cp, U and every protected run: a block missing an arm is made again
                    valid += 1
                    break
                say(f"block {block} attempt {attempt} is not valid: {'; '.join(a['reasons'])[:300]}")
                if attempt == 1 and reruns < gate["max_reruns"]:
                    reruns += 1
                    attempt += 1
                    continue
                break
            if block < n and valid + (n - block) < gate["min_blocks"] and not opts.keep_going:
                state.update(state="stopped", stopped=f"{valid} valid blocks and {n - block} to go cannot reach the "
                             f"{gate['min_blocks']} the gate needs; --keep-going continues anyway")
                break
        else:
            state["state"] = "complete"
    except KeyboardInterrupt:
        state.update(state="interrupted", stopped="interrupted; the same command resumes it")
        save_state(out, state)
        raise
    except (CampaignError, *STOP_ERRORS) as exc:
        state.update(state="stopped", stopped=f"{type(exc).__name__}: {exc}")
        save_state(out, state)
        raise
    state["reruns"] = reruns
    state["gate"] = analyse_into(out, cal, state, say, allow_overrides=bool(getattr(host, "simulated", False)))
    save_state(out, state)
    return state


def analyse_into(out, cal, state, say, allow_overrides=False):
    """harm_gate's verdict on the directory, written next to it as gate.json and gate.md; a short summary for the record.
    A campaign that carries overrides gets none unless it was made by the simulated host (`allow_overrides`)."""
    try:
        result = H.analyse(out, cal, dry_run=cal["status"] != "frozen", allow_overrides=allow_overrides)
    except H.GateError as exc:
        say(f"the gate could not read the campaign: {exc}")
        return {"verdict": None, "error": str(exc)}
    banner = ""
    if state.get("simulated"):
        banner = ("> **SIMULATED.** Made by the simulated host (bench/sim_host.py) with a harm of a known size: it shows the "
                  "protocol working and says nothing about any server.\n\n")
    with open(os.path.join(out, "gate.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    with open(os.path.join(out, "gate.md"), "w", encoding="utf-8") as fh:
        fh.write(banner + H.to_markdown(result))
    say(f"gate: {result['verdict']}" + (" (dry run)" if result["dry_run"] else "") + (" (simulated)" if banner else "")
        + f", {result['blocks_valid']} valid blocks of {result['blocks_total']}, {result['reruns']} re-run(s)")
    if result["overrides"]:
        say(f"OVERRIDES {result['overrides']}: a smoke test, not a result"
            + ("" if allow_overrides else "; the gate gives no verdict on it"))
    for p in result["protected"]:
        say(f"P2 outcome of {X.MITIGATED}{p['mode']}: {p['verdict']}" + (f" ({'; '.join(p['reasons'])[:200]})" if p["reasons"] else ""))
    return {"verdict": result["verdict"], "reasons": result["reasons"], "blocks_valid": result["blocks_valid"],
            "blocks_total": result["blocks_total"], "reruns": result["reruns"], "dry_run": result["dry_run"],
            "overrides": result["overrides"],
            "protected": [{"mode": p["mode"], "verdict": p["verdict"], "reasons": p["reasons"]} for p in result["protected"]]}


def status_text(out):
    """The state of a campaign directory, for `status`."""
    path = os.path.join(out, CAMPAIGN)
    if not os.path.exists(path):
        raise CampaignError(f"{out}: no {CAMPAIGN}")
    state = read_json(path)
    fp = state["fingerprint"]
    lines = [f"campaign {fp['scenario']} ({fp['seed_namespace']}), {fp['blocks']} blocks, calibration "
             f"{fp['calibration_sha256'][:8]} {fp['calibration_status']}" + (", SIMULATED" if state.get("simulated") else "")
             + (f", arms {', '.join(X.MITIGATED + m for m in fp['modes'])}" if fp.get("modes") else ""),
             f"state {state['state']}" + (f": {state['stopped']}" if state.get("stopped") else "") + f"; re-runs {state['reruns']}"]
    if fp.get("confirmation"):
        lines.append(f"confirmation {fp['confirmation']}: asked for by hand, after one at the knee")
    for a in state["attempts"]:
        lines.append(f"  block {a['block']:>2} attempt {a['attempt']} seed {a['seed']}: " + ("valid" if a["valid"] else "NOT valid")
                     + f"  order {', '.join(a['order'])}" + ("" if a["valid"] else "  " + "; ".join(a["reasons"])[:160]))
        if H.waited(a.get("waits")):
            lines.append("    timer waits, recorded and not judged: " + H.waits_text(a["waits"], a["order"]))
    if state.get("gate"):
        g = state["gate"]
        lines.append(f"gate {g['verdict']}: {g.get('blocks_valid')} valid blocks of {g.get('blocks_total')}")
    return "\n".join(lines) + "\n"


# --- the command line -------------------------------------------------------------------------

def parse_faults(items):
    """`name` or `name:count` for the simulated host's faults."""
    faults = {}
    for item in items or ():
        name, _, count = item.partition(":")
        faults[name] = int(count) if count else None
    return faults


def _add_common(p):
    p.add_argument("spec", help="a scenario record (bench/scenarios/*.json)")
    p.add_argument("--calibration", default=C.PLACEHOLDER, help="the calibration record (default: the placeholder, which has no knee, so an attack spec needs another)")
    p.add_argument("--blocks", type=int, default=None, help="fewer blocks than the scenario's: a smoke test")
    p.add_argument("--rho", type=float, default=None, help="smoke test: the benign load in requests/s")
    p.add_argument("--timeline", type=X._timeline_arg, default=None, metavar="B,A,R", help="smoke test: baseline, attack, recovery seconds")
    p.add_argument("--timer-limit-ms", type=float, default=None, metavar="MS",
                   help="smoke test: refuse a run if the timer on the legit CPU has p99 of this many ms or more, instead of the "
                        "calibration's validity.timer_p99_ms; needs --dry-run")
    p.add_argument("--no-warmup", action="store_true", help="skip the unscored warm-up run")
    p.add_argument("--confirm-2x-knee", action="store_true",
                   help="the one further confirmation at 2 x the frozen knee (design 7.2 step 6), for after one at the knee has failed; never automatic")
    p.add_argument("--modes", type=_modes_arg, default=(), metavar="MODE[,MODE]",
                   help="the protected arms: an M_<mode> run in every block (limits, xdp; l7shadow and l7 are not built yet)")


def _modes_arg(text):
    return tuple(m.strip() for m in text.split(",") if m.strip())


def options_of(args):
    return Options(blocks=args.blocks, dry_run=getattr(args, "dry_run", False), warmup=not args.no_warmup,
                   allow_dirty=getattr(args, "allow_dirty", False), clean=getattr(args, "clean", False),
                   wait_gate_min=getattr(args, "wait_gate", 30.0), keep_going=getattr(args, "keep_going", False),
                   confirm_2x_knee=args.confirm_2x_knee,
                   rho=args.rho, timeline=args.timeline, timer_limit_ms=args.timer_limit_ms,
                   simulate=getattr(args, "simulate", None), modes=args.modes)


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    wait_help = "minutes to wait for uptime and load at the start and, from each run's first probe, for a refused timer probe to pass; 0: one probe"
    p = sub.add_parser("plan", help="print the campaign: seeds, orders, VM time (offline, no root)")
    _add_common(p)
    p.add_argument("--wait-gate", type=float, default=30.0, metavar="MIN", help=wait_help)
    p = sub.add_parser("run", help="carry out the campaign, or resume it (root; or --simulate)")
    _add_common(p)
    p.add_argument("--out", required=True, help="the campaign directory")
    p.add_argument("--dry-run", action="store_true", help="allow a placeholder calibration; everything is labelled")
    p.add_argument("--allow-dirty", action="store_true", help="run with uncommitted changes; they are recorded")
    p.add_argument("--clean", action="store_true", help="take down the namespaces and links of an earlier testbed first")
    p.add_argument("--wait-gate", type=float, default=30.0, metavar="MIN", help=wait_help)
    p.add_argument("--keep-going", action="store_true", help="go on although the gate can no longer reach its valid blocks")
    p.add_argument("--simulate", choices=sorted(S.EFFECT_PRESETS), help="run on the simulated host with this effect")
    p.add_argument("--simulate-fault", action="append", metavar="NAME[:N]", help="a fault of the simulated host, N times")
    p = sub.add_parser("status", help="print the state of a campaign directory")
    p.add_argument("out")
    args = ap.parse_args(argv)
    try:
        if args.command == "status":
            print(status_text(args.out), end="")
            return EXIT_OK
        scn, cal = SC.load(args.spec), C.load(args.calibration)
        opts = options_of(args)
        check_modes(opts)
        scenario_sha = sha256_of(args.spec)
        if args.command == "plan":
            print(describe(scn, cal, scenario_sha, opts), end="")
            return EXIT_OK
        if scn.is_control:
            raise CampaignError(f"{scn.id} is attack-free: a gate campaign needs an attack scenario")
        if opts.simulate:
            t = timeline_of(scn, opts)
            host = host or S.SimHost(server=S.SyntheticServer(cal, (t["baseline_s"], t["attack_s"], t["recovery_s"]),
                                                              S.EFFECT_PRESETS[opts.simulate]),
                                     faults=parse_faults(args.simulate_fault), tag=S.origin_tag(cal))
        else:
            host = host or X.RealHost()
            host.pin(P.executor_cpus(pins_of(opts)))
            X._install_signal_handlers()
        state = run_campaign(scn, cal, args.calibration, scenario_sha, args.out, host, opts)
        return EXIT_OK if state["state"] == "complete" else EXIT_STOPPED
    except KeyboardInterrupt:
        print("interrupted; the testbed was taken down. The same command resumes the campaign.", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (CampaignError, X.RunFailed) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_STOPPED
    except (X.PlanError, SC.ScenarioError, C.RecordError, LT.ToolError, LT.ScopeError, H.GateError, OSError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

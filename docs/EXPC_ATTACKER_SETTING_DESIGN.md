# EXP-C prerequisites: the HTTP flood's load model as a setting (design note)

**Status (2026-10-23, after the refinement ramp): implemented as recommended and run in the testbed.** Commits on
`feat/expc-attacker-setting` (off `feat/loadtools-harness`, which holds `bench/loadtools.py` and the verified
generators): `6df18a9` the suite settings (2.1), `bc8adc4` the runner's `--loads` (2.2), `76a66b4`
`server_requests.csv` (2.3); then what the first real runs needed: `3f4feea` the CSV bins by arrival, `8235d39`
the suite kills `wrk` by its exact name (it had killed its own runner), `78122bc` the flood counts as "during"
from its launch, `e1e8247` and `2efb7e4` the table helper with `--r50`. The data are
`results/2026-10-22_expc-r50-probe/` and `results/2026-10-23_expc-r50-refinement/`; amendment A (section 6, `cdf5606`)
reads R50 on the nominal axis; 736 tests pass. Taken as recommended: the engine is the primary open-loop tool
and k6 is supported, scenario 4 only, the ~35-byte request-shape difference is accepted and recorded, the
label scheme is `<mode>@<tool><rate>`. The settings rule moved into `loadtools.limits_for`. Checked offline: the
default `wrk` command is pinned by a test, the default `--dry-run` is byte-identical to the previous runner's,
and the dry-run of the EXP-C plan (3 modes x 4 loads x 10 blocks) lists 120 runs. **The probe** (unprotected, one run
per rate, 30 s): the open-loop path works in the testbed; the legit clients see 100 % up to 190 requests/s per bot and
65.3, 36.0, 19.7 and 1.8 % at 230, 270, 320 and 640, so **R50 is 2,501 requests/s in total, 250 per bot**, and the
default cells (0.5, 1 and 2 x) are 125, 250 and 500 per bot. The server answers at least 1.84 k requests/s, and the
transition is a slope, not the cliff the first part's two points suggested. **Findings:** the launch check's seconds were
labelled "before" (fixed in `78122bc`; "before" is 100 % in the refinement runs); the server log holds 97 % of the nominal
count at 190 per bot and 82, 63, 49 and 20 % at 230, 270, 320 and 640, so the check that 2.3 planned works only below the
limit (not changed). Not done: fixing the three rates (the user's), the analysis by cell, and `publish_campaign.py`
copying `server_requests.csv`. Tags: **[FACT]** read from the code or a published file; **[PROPOSAL]** for you to
confirm; **[RISK]** a hazard with its mitigation. The experiment itself is `docs/BENCHMARK_HARM_DESIGN.md`
8.5 on `design/benchmark-harm`: EXP-A's design with only the attacker's load model changed, in the same
campaign: the closed-loop `wrk -c400` reference arm and open-loop arms at 0.5, 1 and 2 x R50 split over the
10 bots, for three modes (unprotected, Nginx limits, daemon + XDP), 10 paired blocks, 120 runs.

## 1. What the code does today [FACT]

* **The flood is `wrk`, fixed.** `scenario_http_flood` (S4) runs `wrk -t{WRK_THREADS} -c{WRK_CONNS}
  -d{_wrk_seconds()}s {HTTP_URL}` in every bot namespace through `run(..., ns=ns, bg=True)`, which prefixes
  `ip netns exec <ns>` and, for `bot_*`, `taskset -c ATTACK_CPUS`. wrk is also used by Yo-Yo (S9, inside a
  shell script) and multi-vector (S10).
* **The generator is always killed.** `capture_metrics("... Phase 3")` first holds the attack to
  `ATTACK_DURATION` (`_hold_attack`), then `kill_procs` sends SIGKILL (and `pkill wrk`). A generator never
  ends by itself, so any end-of-run summary of its own is lost.
* **Settings are environment variables**, defaults pinned by `tests/test_suite_harness.py`, recorded in
  `provenance.json` (`operating_point`, `settings`, `inputs_sha256` of `_PROVENANCE_INPUTS`).
* **The runner** (`eval/run_campaign.py`) clears `EVAL_VARS` from the inherited environment, builds each
  run's environment in `run_env`, shuffles the modes inside each block (`--order-seed`), pairs the modes of
  a block by `PROFILE_SEED`, and refuses to resume a campaign whose `settings` differ.
* **The analysis groups runs by `provenance.json["mode"]["label"]`** and pairs by profile seed
  (`eval/campaign.py`: `find_runs`, `delta_vs_reference(reference=...)`, so a contrast per load model needs
  no change there as long as the labels differ).
* **The offered load at the server is recorded nowhere.** The Nginx access log
  (`/var/log/nginx/ddos_ml_access.log`: time, client IP, status, request time and length per request) is
  truncated at the start of each scenario and never archived; a published run directory (EXP-A: 332 files,
  2.7 MB) holds the availability, metrics and scenario CSVs, provenance, the console and the ban events.
* **The request shapes differ.** wrk sends `Host` only; the engine sends `User-Agent: loadgen/1` and
  `Accept: */*`; k6 adds its own User-Agent. The User-Agent is never an L7 feature; it only keys the
  shadow engine's windows, which are off by default (`l7_features.py`).
* **Manifest:** the engine and k6 are `verified` (k6: no millisecond-precision latency claims, irrelevant for
  an attacker); vegeta is `smoke-tested`, so not runnable; wrk is `installed` (the closed-loop control).

## 2. Proposal

### 2.1 Two suite settings; the defaults reproduce today's run [PROPOSAL]

* `FLOOD_TOOL` = `wrk` (default) | `loadgen` | `k6`. `FLOOD_RATE` = requests/s **per bot**, constant
  schedule; empty or 0 for wrk, which is closed-loop; a rate with wrk, or no rate with an open-loop tool, is an
  error, never ignored. Anything else is refused (`vegeta`, `wrk2`).
* **Verified generators only.** Before the testbed is built (like the venv check), an open-loop tool must
  pass `loadtools.resolve_tool`: status `verified` and the pinned sha256, and the target must pass the scope
  lock. A generator the verification did not clear cannot drive EXP-C.
* **Scope: S4 only**, the scenario named "HTTP flood". S9 and S10 keep wrk; the docs say so.
* **The command** comes from `loadtools.build_plan` with the settings the verification used (`limits_for`:
  workers = rate x 0.3 s between 100 and 2,000, at most 5,000 in flight, idle pool = workers, request timeout
  10 s; the rule moves into `loadtools.py` as its single definition, the verification harness delegates to it
  and a test pins that both give the same numbers), run through the same `run()` as `ip netns exec <bot> [taskset -c ATTACK_CPUS] <argv>`, for
  `_wrk_seconds()` as wrk is. A killed generator leaves no summary, so none is relied on.
* **Launch check.** Two seconds after launch every generator must be alive, otherwise the run stops with an
  error: an attacker that never started would read as "the attack does no harm".
* **Provenance.** `settings.FLOOD_TOOL` and `FLOOD_RATE`, the tool's manifest entry (version, sha256, status),
  the hashes of `bench/loadtools.py`, `bench/loadtools.json` and `bench/loadgen.py` in `inputs_sha256`, and the
  bots' open-file limit.
* **The mode label** gets a suffix for open-loop runs, `unprotected@loadgen100` (per-bot rate 100); the
  default label is unchanged. Reason: the analysis groups by label, and two loads under one label would
  collide in `find_runs`.

### 2.2 Runner: the load model is a factor of the block [PROPOSAL]

* `--loads wrk,loadgen:50,loadgen:100,loadgen:200`: each block runs every (mode x load) pair once, in a
  random order from `--order-seed`, all with the block's `PROFILE_SEED`, so every cell of a block is paired.
  Run directories are `<label>/run<b>`; `campaign.json` records `loads` only when it is not the default, so
  campaigns recorded before still resume. `FLOOD_TOOL` and `FLOOD_RATE` join `EVAL_VARS`, so an inherited
  value cannot leak in; `--set FLOOD_*` keeps working for a single-load campaign and is refused together with
  `--loads`.
* With the default (`wrk` only) the plan, the shuffle and the directories are identical to today's; a test
  pins it. `--dry-run` shows the cells, and the runner validates them (tool, rate, manifest status) before
  anything starts.
* **Not here:** the three rates (they follow from the R50 probe, a later session), and the analysis by cell.

### 2.3 Server-side offered load, as a separate commit [PROPOSAL, recommended]

At the end of each scenario, before the log is truncated, aggregate the access log into
`server_requests.csv` in the run directory: second since attack start x client class (bot, legit, other) x
status -> requests and mean request time. A few hundred rows per run. Why: the design makes the effective
offered rate a measurement (8.3), the closed-loop arm's offered rate is "whatever the server allows" and is
visible nowhere else, and a killed generator cannot report. It is also what lets V7-style schedule adherence
be checked on the attack itself. One function and one hook, unit-tested on a synthetic log.

## 3. Tests (offline; the suite and ruff gate every commit)

The S4 command for the default environment is the exact historical `wrk` string; settings parsing and
refusals; an unverified, missing or changed tool is refused; the open-loop command is
`ip netns exec ... taskset ...` with the expected flags; label, provenance and `EVAL_VARS`; the runner's
plan for the default is byte-identical and for `--loads` has the right cells, order and directories; resume
compatibility; `--dry-run`; the access-log aggregation on a synthetic log.

## 4. Risks and choices

1. **Request shape [RISK].** The open-loop arms send about 35 bytes more per request than wrk. Options:
   (a) accept and record it, since the server work for two extra headers is negligible and the daemon does not
   use them (recommended); (b) a bare mode in the engine, which changes a pinned, verified file and forces a
   new verification; (c) the same two headers on wrk in the reference arm, which loses comparability with
   EXP-A. A short wrk-with-headers cell can test (a) later.
2. **Open-file limit and in-flight requests [RISK].** After a ban an open-loop generator keeps scheduling:
   at 100 requests/s with a 10 s timeout it holds up to 1,000 pending connections per bot. The bots must have
   an open-file limit above that; the setting checks it and records it. The verification ran with 524,288.
3. **The engine's slip gate fires on this VM** (design F.7, point 5), so a generator-side validity check
   would be noise; the server-side counts (2.3) are the check. `--spin-ms` is untested.
4. **Start-up:** a Python bot starts about 0.2 s later than wrk; negligible against a 30 s window.
5. **Tool:** the engine is the primary (lightest, exact schedules, passes V1-V6 including V3); k6 is
   supported as a cross-check cell, not part of the default EXP-C.

## 5. Plan

Commits on this branch, each gated on the full suite and ruff: (1) suite settings, tests and the table in
`docs/EVALUATION.md`; (2) runner `--loads`, tests; (3) the server-side CSV, if you agree. Then a `--dry-run`
of the EXP-C campaign (no VM) and, separately approved, the R50 probe session. No VM workload before that.

## 6. Reading R50: amendment A (post hoc, 2026-10-23)

**Pre-registered (proposal of 2026-10-22, approved before the first open-loop run).** R50 is the *measured* total
offered rate at which the legit success crosses 50 %, interpolated in log-rate between the two bracketing runs; if
those differ by more than 40 pp, a three-rate refinement ramp follows; EXP-C's rates are 0.5, 1 and 2 x R50.

**What the probe showed** (`results/2026-10-22_expc-r50-probe/`, 8 runs). The bracketing runs, 160 per bot (100 %) and
320 per bot (19.7 %), differ by 80 pp, so the refinement rule applies. The logged rate cannot be the axis: it is 1,587
and 1,569 requests/s at the two, and above the limit it is a floor of the offered load (49 % of nominal at 320, 20 % at
640).

**Amendment A.** Written after the eight probe runs and before any refinement run; the pre-registered reading stands
in the published probe, and where it differs this one is labelled post hoc. Approved 2026-10-23.

1. The axis is the **nominal** total rate (per-bot rate x 10 bots), which is the setting, not a measurement. The logged
   rate is reported next to it and not used.
2. The outcome is the legit success in the first 30 s from `Attack_Start`, from `availability_raw.csv` (HTTP 200 within
   10 s), as `eval/expc_probe.py` tabulates it; not the suite's period labels.
3. R50 is interpolated linearly in log-rate between the two adjacent rates of the ladder 20, 40, 80, 160, 190, 230, 270,
   320, 640 per bot, the lower with success at or above 50 % and the higher below it. If the success is not monotone along
   the ladder (a rate above one that is below 50 % is back at 50 % or more), no R50 is computed and that is reported.
4. One run per rate: R50 places the cells and carries no interval. The EXP-C cells, ten blocks each, are what measure.
5. The three rates are fixed by the user after the ramp. 0.5, 1 and 2 x R50, split over the 10 bots and rounded to a whole
   per-bot rate, stay the default proposal.

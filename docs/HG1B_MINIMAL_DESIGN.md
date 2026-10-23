# HG1b minimal cut: design delta (written before the code)

**Status (2026-10-23): built, offline, unmerged and unpushed; section 9 says how it differs from this note.** The user
approved deltas 1-10, O4 as D14 and the full cut (D17) on 2026-10-23: eight commits on `feat/hg1b-minimal`, off
`feat/expc-attacker-setting`, offline only (ten were made, section 9). The base is
`docs/BENCHMARK_HARM_DESIGN.md` on `design/benchmark-harm`; its section numbers are cited as "design N". This file is its
delta, to be folded into it by whoever merges that branch. Nothing here changes `bench/loadgen.py` (its sha256 stays as
pinned in `bench/loadtools.json`), `test_distributed_suite.py`, the Nginx configurations, the daemon, or a published result.
Tags: **[FACT]** read from a file; **[ARITHMETIC]** computed from facts; **[PROPOSAL]** a value fixed here and frozen before
the data it will judge; **[RISK]** a hazard with its mitigation.

## 1. Scope

| In (this cut) | Out (named, not forgotten) |
|---|---|
| `bench/origin.py`: the cost-calibrated origin | the executor that runs a scenario in the namespaces, and the calibration runner (HG1c, section 7) |
| `bench/calibration.py`: the calibration record, its hash, and the pure rules (knee, drift) | POST routes: C4 login and C6 upload (the engine is GET/HEAD only) |
| `bench/population.py`: seed namespaces, identities, traffic families, class-pure stream specs, alias plan | session structure, heavy-tailed think times, page asset waves (delta 4) |
| `bench/scenario.py` and three specs: the scenario record and `--plan` | an Nginx benchmark profile, TLS, HTTP/2, the SYN and cookie arms |
| `eval/harm_gate.py`: the harm-gate analysis, with the placebo and the HRR | L3/L4 floods, slow connections, ML detection studies, any VM workload |
| `bench/loadtools.py`: the wrapper builds multi-identity engine commands (commit 1) | |

## 2. Decisions recorded

| # | Decision | State |
|---|---|---|
| D14 | O4: the legit streams run on vCPU 6 (the healthy one), generator validity is relative to the control (a gross ceiling and a difference), no `--spin-ms` for populations (allowed on at most four attack streams), the environment gate judges the timers on the vCPU of the legit streams | approved 2026-10-23 |
| D15 | Deltas 1-10 of section 3 | approved 2026-10-23 |
| D16 | The executor and the calibration runner are HG1c, with their own design note and approval | acknowledged |
| D17 | The full cut: commits 0-7 | approved 2026-10-23 |

## 3. The ten deltas

| # | Delta | Why | Consequence |
|---|---|---|---|
| 1 | The executor (topology, origin, Nginx, streams, records, tear-down) and the calibration runner are HG1c. This cut fixes the contracts it must meet (section 5) and tests them with a synthetic end-to-end block. | The design names no component that runs a scenario spec in the namespaces. [FACT: design 12.1 lists `bench/calibrate.py` and no executor] | HG2 cannot start on this cut alone. |
| 2 | Routes C0, C1, C2, C3 and C5, all GET. C4 login and C6 upload are deferred. | `bench/loadgen.py` sends GET and HEAD only (line 227); adding POST changes its pinned hash and forces a new verification. | The cheapest dynamic route to the dearest is 2 ms to 150 ms: 75 times, above the 50 the design requires (5.2). [ARITHMETIC, placeholder costs] |
| 3 | A population is a set of **class-pure streams**: one engine process per (kind, route class, process, netem profile, rate group), with its source addresses, one User-Agent and a path list (a repeated path is a weight). | The engine has one schedule per process, picks a path uniformly, splits its requests round-robin over its identities (`i % len(idents)`), and its records carry no route. | The route class of a request is its stream's. Per-entity rate differences come from rate groups. The process count is printed by `--plan`. |
| 4 | Heavy-tailed per-entity think times and page asset waves are approximated by per-stream Poisson, constant or pulse schedules. | Follows from 3. | Fit for Gate A (service harm); not for ML evaluation, which is outside this cut. |
| 5 | C0 is served by the origin, not by Nginx. | Avoids a new Nginx profile in an offline cut. | The unloaded cost of C0 is a few microseconds more than a static file. |
| 6 | SLO-success is judged on the latency from the actual send. The latency from the intended time and the slip are recorded and reported next to it. | The same rule as A2 of the generator verification. A timer that wakes late must not turn a healthy control into an invalid block. | A generator that falls behind is caught by the slip checks of 4, not hidden. |
| 7 | The scenario format is JSON. | No new dependency. | |
| 8 | `bench/calibration.py` holds the schema, the hash and the pure rules only. | The measuring runner is HG1c. | `--plan` and the gate read a placeholder or a frozen file. |
| 9 | The gate gives no verdict on a calibration whose status is not `frozen` (a flag allows a labelled dry run). `--plan` prints a banner on a placeholder one. | A verdict on illustrative costs would look like a result. | The placeholder file holds the design's Appendix A numbers. |
| 10 | The origin's service-time spread is keyed by a hash of the URL. | The engine sends no request id. | The same URL costs the same, which replays a schedule. |

## 4. O4 as decided (D14)

**Facts.** The VM wakes sleepers late, per vCPU (design F.5): with eight pinned probes at once, vCPUs 0-5 and 7 had p50 25.5-30.7 ms
and p99 102.8-113.6 ms; **vCPU 6 had p50 1.4 ms, p99 6.1 ms, max 7.6 ms**. The engine's slip flag (p99 above 50 ms) fired at every
rate in the corrected verification run, 100/s included (F.7). Design 7.2 step 0 asks for timer p99 below 10 ms and 8.3 for slip p99
below 50 ms; neither can be met on most vCPUs.

**Rules, frozen before any gate data.**

1. **Pinning [PROPOSAL, replaces design 7.4].** Server stack CPUs 0-1, daemon CPU 2, **legit streams CPU 6**, attack streams CPUs 3, 4, 5 and 7.
2. **Environment gate.** The timer probe (200 x 10 ms) is judged on the CPU of the legit streams: p99 below 10 ms. The other CPUs are
   recorded, not judged. The probe is repeated before every run, as the harness already does.
3. **Generator validity, profile `relative` (the default).** A stream is invalid when its CPU share exceeds 0.70, when it sent fewer
   than 99 % of its intended requests, when it ran out of descriptors or ports, or, for a legit stream, when it dropped a request. Slip is a
   difference, not an absolute: the p99 slip of the legit streams in a run may exceed the control's by at most 50 ms, and no stream's
   p99 slip may exceed 250 ms. The profile `strict` is design 8.3 as written (every engine flag clear, slip p99 below 50 ms); it is computed and
   reported for every run and judges nothing unless chosen.
4. **No `--spin-ms` for populations** (a core per stream). An attack stream may use it; the plan counts those cores.
5. **V7.** Closed as a ceiling: 5,000 requests/s per stream, the highest rate at which no CPU flag fired (the corrected run, F.7). The 10 s steps
   are not repeated.

**Not decided here.** Whether idle-priority busy loops on the other vCPUs would remove the lateness at its root (it needs a short VM probe and
changes the system under test). It is the fallback if the environment gate of 2 fails on vCPU 6 in HG2.

## 5. Contracts

### 5.1 The origin (`bench/origin.py`)

* A WSGI app; stdlib only (`sqlite3`, `hashlib`, `json`, `csv`). For gunicorn: `--chdir bench origin:app`; `app` is built on first access from the
  environment (`ORIGIN_CALIBRATION` a path, `ORIGIN_SEED`, `ORIGIN_KNOBS` a JSON override for tests); a missing calibration means the placeholder.
* Routes: `GET /static/<n>` (C0), `GET /page/<id>` (C1), `GET /api/item/<id>` (C2), `GET /search?q=<term>` (C3), `GET /export` (C5). HEAD
  as GET without a body; any other method is 405; an unknown path 404; a bad parameter 400.
* **Real work, not sleeps.** Each route does its natural work (a point lookup, a range render, a scan with ranking, a CSV build) and then
  `burn(units)`, a deterministic hash chain, for the part the knobs add. An explicit I/O wait (`io_wait_ms`, default 0) is the only sleep.
* **Determinism.** Bytes and the work count depend only on (route, parameters, data seed, knobs). The count is returned in `X-Work`. The
  spread factor `f = exp(sigma z - sigma^2/2)`, `z` drawn from a generator seeded by a hash of the URL, scales the work (delta 10).
* **Headers.** `X-Route-Class`, `X-Work`, `X-Origin-Calibration` (`placeholder` or `frozen:<sha8>`), `Cache-Control: no-store`.
* **Self-check.** `measure_unloaded` times every route with an injectable clock; `self_check` raises when any route is more than 25 % off the
  frozen cost; a frozen calibration triggers it at start-up, the calibrate mode (and a placeholder) skips it.

### 5.2 The calibration record (`bench/calibration.py`)

A JSON object with: `schema` (1), `status` (`placeholder` or `frozen`), `created_utc`, `host`, `route_costs_ms`, `knobs`, `spread_sigma`,
`capacity` (`c_slo_rps`, `c_sat_rps`), `mix` (the legit route mix), `slo_ms` (per class), `gate` (`floor_pp` 10, `floor_log2_p95` 1,
`min_blocks` 10, `same_sign_share` 0.8, `ci_level` 0.95, `control_q_min` 99, `max_reruns` 2), `validity` (section 4), `knees`, `sha256`.
The hash is that of the canonical JSON (sorted keys, no whitespace) without the `sha256` key. Derived, never stored: `rho = 0.5 c_slo`, the mean
cost of the mix, and the spare capacity `S = (c_slo - rho) x mean cost` in CPU-seconds per second. The knee rule is the design's (7.2 step 4): the lowest
level whose harm reaches the floor in both repeats; none means "cannot harm this server within the generator limit". The drift check
reproduces `Q` within 2 pp and p95 within 25 % (7.2 step 7).

### 5.3 Populations (`bench/population.py`)

* **Seed namespaces** are disjoint ranges of the seed: `calib` 1-99, `train` 100-199, `val` 200-299, `test` 300-399. The entity seed is the first 8 bytes of
  `sha256("namespace|seed|role|index")`. A seed outside its namespace's range is an error (G-03).
* **One netem distribution for every class**, attackers included: the suite's own mix, perfect 0.30, broadband 0.35, mobile_3g 0.25, mobile_bad 0.10
  (`test_distributed_suite.py`, assumed, not sourced), realised by namespaces that carry the profile. Default: **four, one per profile**, each holding the aliases of its identities
  (the design's 24 namespaces would multiply the streams by six: a stream binds addresses of one namespace only). An identity draws its profile from the mix, whatever its role.
* **Benign classes (8)**, each a share of the legit rate, an identity share, a route mix and an arrival process (all *assumed*, tuned so the aggregate route
  mix is within 3 pp of the calibration's): `page_browser`, `spa_burst`, `api_steady`, `api_bursty`, `search_user`, `crawler_polite`, `nat_pool`, `downloader`.
* **Attack families (3)**, intensity as a cost rate in units of `S`: `costly_search_flood` (C3), `costly_export_flood` (C5), `cheap_static_flood` (C1, the
  control where rules win). Sources 5, 20 or 100; the total cost rate stays at the level while the number of sources changes.
* **Addresses:** benign 10.0.1.0/24 (then 10.0.3.0/24), attackers 10.0.2.0/24, all inside the scope lock of `bench/loadtools.py`; the suite's own convention
  (10.0.1.x legit, 10.0.2.x bots), so its false-positive and class logic keeps working.
* **A stream spec** is: `id`, `kind` (`legit` or `attack`), `class`, `route_class`, `process` and its `period`/`duty`, `rate`, `seed`, `netem`, `ns_index`,
  `addresses`, `paths`, `start_s`, `duration_s`, `cpu` (`legit` or `attack`), and the engine's `pool`. It converts to a `LoadSpec` for the wrapper.
  There is no `ua`: the engine sends `User-Agent: loadgen/1` on every request (section 9).

### 5.4 The scenario record and `--plan` (`bench/scenario.py`)

The fields of design Appendix B in JSON. `--plan` prints, offline and without root: a calibration banner; the entity-to-seed map; per benign class the identities, rate,
cost rate and utilisation, and the aggregate route mix against the calibration's; per attack family the total rate, per-source rate, cost rate in units of `S`; per source
the rate against 30 r/s (`limit_req`, burst 100) and 50 rps (the L7 rule), and the number of sources at which a source falls below each; the generator load (streams,
expected CPU at 0.1 ms per request, descriptors, memory at 30 MB per process) against the ceiling of 5,000 requests/s per stream; the expected gate class from the cost-rate
model (A >= 2 likely PASS, A <= 0.5 likely FAIL, else cannot say; first order, the ladder finds the knee). **Thresholds are printed, never used to choose an intensity**; a test
changes them and checks that the intensity does not move.

### 5.5 What HG1c must write (the run contract)

```
<block>/block.json          scenario id, block number, attempt, seed namespace and seed, calibration sha256,
                            timeline {baseline_s, attack_s, recovery_s}, the order the three runs were made in
<block>/<run>/run.json      role (control | placebo | attack | mitigated), mode, started_utc, the streams:
                            {id, kind, route_class, summary, records, offset_s}
<block>/<run>/streams/<id>.summary.json     the engine's --summary
<block>/<run>/streams/<id>.records.csv.gz   the engine's --records (i,t_intended,t_sent,t_done,status,bytes,err,ident,reused)
```

`<run>` is `C`, `Cp` (the placebo) or `U`; later `M_<mode>`. Times in a stream's records are on that stream's own axis (zero at its start); the legit streams start with the
run, so the windows are [baseline, baseline + attack) on their axis, the same seconds in all three runs.

### 5.6 The harm gate (`eval/harm_gate.py`)

Per run: `Q` is the share of the legit requests whose intended time falls in the window that completed 2xx within their class's SLO (service time from the actual send; a request that
was never sent, dropped, timed out or answered non-2xx fails); p95 is that of the successful ones. Per block: `dQ = Q(C) - Q(U)` in pp, `dL = log2(p95(U) / p95(C))`, `dQ' = Q(C) - Q(C')`.
A block is valid iff its runs pass the validity profile (section 4) and the control is healthy (`Q(C) >= 99 %` and every class's p95 within its SLO). A failed block is re-run once with the same
seed, at most twice per gate; fewer than ten valid blocks is INVALID. PASS iff the mean `dQ` reaches the floor with its 95 % t-interval excluding 0 and at least 80 % of the blocks of that sign, or the
same for `dL >= 1`; otherwise FAIL. The same rule on `dQ'` is the placebo and must not pass. HRR `= (Q(m) - Q(U)) / (Q(C) - Q(U))` from block means, defined only after a PASS. Also per run: 1-s bins,
degraded seconds (`Q` below 95 %), the time to the first degraded second, and the recovery time (five bins at 99 % or more). The t-interval and the sign share are `eval/run_level_stats.py`'s.

## 6. Tests per commit (all offline)

| Commit | Tests |
|---|---|
| 1 wrapper | the default engine argv unchanged (golden); the new fields reach the argv; a non-testbed address is refused; the other tools refuse what they cannot honour |
| 2 origin | bytes and work counts identical for a repeated (route, seed); the seed changes the bytes; the route table is complete; GET/HEAD/405/404/400; knobs monotone; the spread is deterministic with mean 1; the self-check passes at 10 % and fails at 30 % off on a fake clock; no sleep with the I/O wait off; threads give the sequential bytes |
| 3 calibration | the schema; the hash is stable and changes with any field; the knee rule on monotone, noisy and never-passing ladders; the drift check; the placeholder is valid and not frozen |
| 4 population | determinism per namespace and seed; no seed shared across namespaces; counts and class mix; the aggregate route mix within 3 pp; one netem distribution for benign and attackers; no address collision, all in scope; streams convert to engine commands |
| 5 scenario | schema errors; three golden plans; thresholds never move the intensity; the ceiling and the placeholder warnings |
| 6 harm gate | synthetic PASS, FAIL and INVALID; the floor, the interval and the sign share at their boundaries; the re-run rule; the placebo; HRR only after PASS; the 1-s bins; the validity profiles; an end-to-end block built through the population and the run contract |

## 7. HG1c: what is left, and the options

The executor must: build the topology (the suite's `create_host_bridge`, `create_server_ns`, `create_client_ns`, `apply_tc` exist; a client namespace with many address aliases does not),
start the origin under gunicorn (`gthread`, 2 x 8 slots) and Nginx, launch the streams with the timeline of section 5.5 (`ip netns exec`, `taskset`, `prlimit`), keep the engine's `--records` and `--summary`,
collect the server counters, and tear down, with the suite's leftover checks. Two options, to be decided in its own note: **(a)** a new scenario type inside `test_distributed_suite.py`, driven by
`eval/run_campaign.py` through a setting (additive, reuses the testbed and the cleanup, and touches the suite); **(b)** a separate runner that imports the suite's testbed functions (no change to the
suite, but the suite registers `atexit` and signal handlers and keeps module state, which is why its tests mock them on import). The calibration runner then drives the executor.

## 8. Limits of this cut

* The costs are placeholders until HG2 measures them; every conclusion is conditional on the cost model (design principle 4).
* A population of class-pure streams is coarser than the design's sessions; the number of processes it implies is part of the plan output and may need the reduction rule of D5.
* Nothing here has run on the VM. The first contact with it is HG1c, then HG2.

## 9. As built (2026-10-23)

Branch `feat/hg1b-minimal`, off `feat/expc-attacker-setting` (f96c30c); unmerged, unpushed. Offline only: no VM workload,
no sudo run, no namespace, no traffic. Ten commits, because two defects found while writing the tests and the plan each
got a commit of their own.

| Commit | What |
|---|---|
| e73da79 | this note |
| 4ec6b45 | `bench/loadtools.py`: the wrapper builds multi-identity commands for the engine (`local_addrs`, `paths`, `process`, `seed`, `period`, `duty`, `ramp_to`, `spin_ms`); the default argv is unchanged and the other tools refuse these options |
| fa31372 | `bench/origin.py`, the cost-calibrated origin |
| 36ce15f | `bench/calibration.py` and `bench/calibration/placeholder.json` |
| 0a037fc | `bench/population.py` |
| 9ecc4df | fix: an attack group is split evenly and never past the engine's ceiling |
| 217f42a | `bench/scenario.py`, three specs, three golden plans |
| e501121 | the plan prints the worst-case in-flight requests of each stream against the engine's cap |
| 91491cc | `eval/harm_gate.py` |
| the one that adds this section | `docs/EVALUATION.md` and this section |

Tests: 7 new in `test_loadtools` (69), 23 origin, 19 calibration, 28 population, 54 scenario, 73 harm gate; the whole
suite was 958 tests OK at 91491cc, and ruff was clean on every new file at every commit.

### 9.1 Where the build differs from sections 3 to 6

* **No `ua` in a stream.** [FACT: `bench/loadgen.py` sends `User-Agent: loadgen/1` on every request.] The daemon's L7 engine
  keys on (IP, User-Agent); in this population the second part is one constant. Gate A does not read it; a study of
  detectors that does would need an engine change, which changes its pinned hash and its verification.
* **Streams are per namespace.** An engine process runs in one network namespace and a namespace carries one link profile, so
  a stream is a (process, route class, profile) combination: 29 legit and 4 attack streams at 200 identities (33 processes, about
  1 GB at 30 MB each) with four namespaces. An identity in several streams has one idle pool in each: the printed idle-pool
  figure (2,892 for 200 identities) is an upper bound on idle connections, not on concurrency.
* **A pulse sends whole requests per period**: `rate = max(1, round(rate x 15 s)) / 15 s`, so the smallest pulse stream sends one
  request every 15 s, and the legit total is 90.07 req/s for a rho of 90.
* **Rates inside a stream are equal.** The engine splits a stream's schedule round-robin over its addresses, so the per-identity
  spread of rates survives between classes and streams and is lost inside one.
* **`/export` takes `?r=<digits>`** (at most six; anything else is a 400), so that the C5 URLs differ: a single URL would
  have a single work factor.
* **The split of an attack group.** The first version took every n-th address and left streams without an address, or above
  the ceiling, when one address alone exceeded 5,000 req/s or the addresses divided unevenly (9ecc4df). A group is now cut into
  balanced streams of at most floor(ceiling / per-source rate) addresses; one address above the ceiling is carried by several
  processes that share it.
* **The scenario record** has `first_seed`, `benign {identities, per_profile}`, `intensity.level` as a number or `"knee"` (the
  calibration's recorded knee, an error if it has none), and `controls {control, placebo: "repeat"}`. The SLOs and floors stay in
  the calibration. `gate.metrics` is honoured by `eval/harm_gate.py --metrics`.

### 9.2 What the build found [ARITHMETIC on placeholder numbers, not results]

* With rho = 90 req/s and a mean cost of 6.14 ms, S is 0.5523 CPU-s/s. The shipped sub-threshold scenario (level 2 on C3, 100
  sources) is 36.8 req/s in total and **0.37 req/s per source: 81 times below `limit_req`'s 30 r/s and 136 times below the L7
  rule's 50**. The cheap flood (level 4 on C1, 5 sources) is 147 req/s per source: 4.9 times and 2.9 times above them, and
  it takes 25 sources to bring a source below `limit_req`.
* **Validity must not read the attack's effect.** The relative profile counts a legit stream's drop and any stream's `sent` below
  99 %; the engine drops only when its in-flight cap is full, which is when the server stalls. The plan therefore prints the
  largest stream's rate times the request timeout against the cap: legit 118 of 2,000; attack 140 of 5,000 for the search
  scenario and **4,418 of 5,000 for the cheap flood at level 4**, and a warning at level 8.
* **Both shipped attack scenarios are "likely PASS" under the cost-rate model** (A = 2 and 4). There is no negative control for
  Gate A among them (a level of 0.25 would be one); whether to ship one is open.
* The legit route mix drawn from the classes is within 1.8 pp of the calibration's (C1 +1.8, C2 -1.2).

### 9.3 Decided in the gate's code, beyond 5.6

* A run's slip is judged twice: the gross ceiling on each stream's summary, and the difference to the control on the p99 pooled from
  the legit records.
* The p95 criterion is *not evaluable* when a valid block has no p95 (an attack run without a single success); Q then carries the
  verdict, and `--metrics p95` alone is INVALID with that reason.
* The placebo is reported with the verdict and does not change it; a placebo that passes is stated in the report as making the
  verdict unreliable. `dL'` is computed with `dQ'`.
* A mitigated run that is not valid is left out of its HRR and does not spoil its block. The block's `order` lists C, Cp and U only.
* `slo_scale` exists in the analysis for the design's x0.5 and x2 sensitivity and is not on the command line.
* An exit status of 0 means a verdict was reached, whatever it is; 1 is an error in the data or the calibration.

### 9.4 How it was tested, and what was not

* A mutation check of 24 single-line edits to the gate's rule, validity, re-run, placebo, HRR and dry-run lines: 23 are caught.
  The survivor turns `lo > 0` into `lo >= 0`, which differs only when a t-interval's lower end is exactly 0.0.
* One older test, `test_loadtool_validate.ScriptedOriginTest.test_a_response_that_falls_inside_the_stall_is_held_to_its_end`, failed
  once in a full run with a 5 s socket timeout while the VM stalled, and passed alone and in every later run. Its skip logic covers
  a late arrival and not a stalled read. It was not changed here. [RISK]
* **Nothing has run on the VM.** The origin's real costs, the engine's 0.1 ms of CPU per request and 30 MB per process (figures from the
  HG1a verification), 33 processes together, about 300 address aliases, the per-process descriptor limit the plan prints (5,216 for the
  search scenario), and the records of a real multi-stream run are all untested. The first contact is HG1c.

### 9.5 What HG1c still has to do

The executor: four client namespaces with the aliases the plan counts (106, 102, 68 and 24 at seed 1), the server stack with the origin
under gunicorn and the Nginx profile, `prlimit`, `taskset` and start times as printed, the run contract of 5.5, tear-down and the suite's leftover
checks. The calibration runner: the capacity probe, the ladders, the knee, and the freeze (`calibration.freeze` and `dump`) with the drift
check before every later campaign. The choice between the options (a) and (b) of section 7 is still open and needs its own note.

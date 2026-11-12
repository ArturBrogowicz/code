# Design plan: a benchmark in which attacks cause measurable harm

**Status (2026-10-22): the design is approved; HG1a is written; its first run (a pilot) found faults in
the harness, the harness was corrected, and the corrected run was approved and made the same day:
k6 and the in-repo engine pass V1-V6, vegeta fails V3 and V5; on your decision the manifest now marks
k6 and the engine `verified` and leaves vegeta `smoke-tested` (Appendix F.7); a V3 repeat session
(3 repeats per tool, with a warm-up) then showed that only the engine meets V3 at p99 on this VM
(Appendix F.8).**
Decisions: D4 decided (both generators); D1-D3 and D5-D12 approved at the recommended defaults; D13
(two post hoc amendments to the verification criteria) adopted. Stage 1 of Appendix E was run:
vegeta and k6 are installed and smoke-tested, wrk2 is unavailable on this OS. HG1a (the wrapper, the
verification harness and the engine, `bench/loadtools.py`, `bench/loadtool_validate.py`,
`bench/loadgen.py`) is on the branch `feat/loadtools-harness`; its first full run is published as a
pilot whose verdicts are not used. Nothing else described here exists yet. The usual
protocol applies: feature branch, static analysis first, approval of the
design before code, approval of every VM workload with its duration and side effects, one concern
per commit gated on `unittest` + ruff, you merge and push.

**Tags.** **[FACT]** read from a file or a published result (path given). **[INFERENCE]** reasoned,
not measured. **[PROPOSAL]** a value or choice for you to confirm or change (decisions D1-D12,
section 15). **[RISK]** a hazard with its mitigation. **[CLAIMED]** stated elsewhere without data.
Citations are from memory and carry **[verify before citing]**.

**Scope.** This plan designs the *evaluation*: how harm is defined and gated, what the backend and the
workloads must look like, how operating points are calibrated, how load is generated, and how entity
populations and statistics are organised. It does not specify new attacks or ways of avoiding a
detector, and it does not change any detector, threshold or model.

## Summary

1. **Why.** Apart from one HTTP flood at one hand-found operating point, no scenario in the record
   is shown to hurt the server it targets. G-01, G-05, G-10 and G-13 are four faces of that: a
   backend too cheap to hurt, populations too small to vary, no calibrated load, and generators
   whose offered load depends on the answers.
2. **What.** A *harm gate*: before a scenario counts as a threat, a frozen rule must show, on
   paired blocks of the unprotected stack, that it lowers SLO-success by at least 10 pp or doubles
   p95 (section 10). A failing scenario is reported as "no measurable harm", never retuned until it
   passes.
3. **How, in five parts.** (A) a deterministic origin whose route costs span about three orders of
   magnitude, from a static asset to a report export, as real applications do; (B) a workload at
   half of measured capacity, with attack intensity expressed as a cost rate against the remaining
   spare capacity; (C) per-resource calibration on service impact only, frozen in a hashed file,
   with a drift check and a transferability probe for L3/L4 floods on veth; (D) open-loop scheduled
   load with intended-time latency and generator-validity gates; (E) entities drawn per seed from
   parametric families, with seed namespaces and one netem distribution for every class.
4. **Order.** The external load tools first (D4; vegeta and k6 are installed, wrk2 is unavailable),
   then EXP-C: it needs no new origin, answers G-13 on its own, and a verified external driver is
   enough, so it does not wait for the in-repo engine, which everything else needs (section 12).
5. **Cost.** 14-19 working days of code (9-11 for the minimum version) and about 18 VM hours in
   sessions you approve one by one (7 h for the smallest useful cut).
6. **Limits, stated up front.** The cost model is a design choice, so conclusions are conditional
   on it and tested against it (x0.5 / x2); L3/L4 harm may be unproducible on veth;
   slow-connection harm needs a regime far above today's socket counts (6.4); nothing here is
   built to make a learned model win.
7. **What I need.** Decisions D1-D12 (section 15); D4 is decided (2026-10-22). The two that
   move cost most: D6 (first-wave scope) and D11 (EXP-C first, on the legacy origin).

## 1. The problem

### 1.1 The four findings and what a fix must deliver

| ID | What the audit found | Evidence [FACT] | A fix must deliver |
|---|---|---|---|
| G-01 (High) | The "attackers" cause no harm, so mitigation claims reduce to label checks | The suite's origin `dummy_app.py` returns the same 31 bytes for every request; `l7_webapp.py` has a few cheap routes and one `time.sleep(0.04)` route. In P5c.4 benign success was 1.0 and the median server time 2.0 ms (p95 10-42 ms) with and without the fast attackers (`results/2026-10-20_audit-derived/l7_harm_p5c4.md`) | a backend whose route costs differ by orders of magnitude, and a *harm gate* applied to the unprotected system before any scenario counts as a threat |
| G-05 (Medium) | The entity pools are tiny and repeated | 20 benign and 4 attacker roles, identical in every seed; "20 attackers / 100 benign IPs" are 4 and 20 roles x 5 seeds (`l7_roles_p5c4.md`) | populations drawn per seed from parametric role families, seed namespaces that never overlap, cluster-aware statistics |
| G-10 (Medium) | No CPU-bound operating point for floods | `default` is 8 x 4 gunicorn workers, unpinned; the only "knee" is one hand-found configuration for the HTTP flood (`test_distributed_suite.py:68-73`; `docs/EVALUATION.md`, Settings). At the default point no attack lowered success in any mode, although 1.46 M packets/s of UDP flood reached the unprotected server's stack (`results/2026-10-12_exp1-default-4modes_prototype/README.md`) | a calibration *procedure* per resource, a frozen calibration file, a drift check, and a probe that says whether floods can harm the server on this topology at all |
| G-13 (Medium) | Closed-loop generators distort the rate-limiting evaluation | The HTTP flood is `wrk -t2 -c400` per bot (`test_distributed_suite.py:1487`), whose rate depends on the server's answers; the L7 generators wait for each response before sleeping (`ml/l7_gen.py:260-277`), so planned rates were not realised: the fast attackers sustained 11-25 rps against a nominal 20-45, and the benign `api_bulk` hard negative 2.5-4.4 rps on mobile profiles against 15-20 specified (`l7_rates_p5c4.md`). Nginx limits only served 44.4 % against 66.8 % unprotected (EXP-A) while its Nginx CPU was 96 % against 33 % | an open-loop generator with intended-time latency accounting, a validity gate, and the matched-offered-load experiment (EXP-C) |

Parts of G-03 (seed reuse), G-04 (netem confound), G-08 (rate conformance) and G-22 (`limit_req`
rejections are invisible to the error ratio) are handled where they touch this design; they are
named where they occur.

### 1.2 Where harm exists today [FACT]

| Scenario family | Default operating point | Knee operating point | Source |
|---|---|---|---|
| HTTP flood (S4) | none | **unprotected 66.8 %, limits only 44.4 %, daemon 100 %** (10 blocks) | `results/2026-10-20_expa-knee-10-blocks/` |
| L3/L4 floods (S1, S3, S5, S6, S10) | none: 6,107 unprotected requests during all ten scenarios, 1 failed | never run | `results/2026-10-12_exp1-default-4modes_prototype/` |
| Slow connections (S7, S8) | none | never run | Nginx keeps 5-s header and body timeouts in the unprotected config too (`nginx_unprotected.conf` differs from `nginx.conf` only in the `limit_req` / `limit_conn` zones and directives, comments aside); EXP-B (`2026-10-20_expb-tolerant-profile-suite`): legit success 100 % before, during and after while both attacks ran unbanned |
| Pulsing HTTP (S9) | none | never run | prototype benchmark |
| L7 families of P5 / P5c (sub-threshold floods, scraper, padded flood, credential stuffing, slow-read) | none | not applicable | `l7_harm_p5c4.md` |

The whole record contains one harmful configuration: the HTTP flood at one operating point, found
by a five-point, single-run, unseeded sweep with unpinned generators
(`results/2026-10-12_exp1d-calibration-sweep_raw/README.md`: only 1 x 1 workers with `wrk -c400` x
10 bots degraded, to 76.7 %).

## 2. Principles and non-goals

1. **Harm first.** A scenario is not called a threat, and is not used as mitigation evidence, until
   the harm gate passes on the *unprotected* system, with no daemon and no model in the loop. This
   is rule (b) of `docs/L7_GRU_DESIGN.md` section 7, made operational.
2. **Offered load is exogenous.** Whatever the server does, the load an attacker or a legitimate
   client *intends* to send is fixed by a schedule. Modes are compared at the same offered load.
3. **Calibrate on service impact and resource saturation only.** Never on a detector's or a
   model's output. Everything is frozen in a commit before the data it will judge.
4. **Conditional claims.** Every conclusion names the cost model and the server profile it rests
   on, and the plan includes sensitivity runs. A result that holds only if the backend is built a
   certain way says so.
5. **Every candidate is reported.** Failing the gate is a result ("no measurable harm"), not a
   reason to retune until it passes. Stopping rules are in 7.5.
6. **Additive.** `dummy_app.py`, `l7_webapp.py`, `nginx.conf`, the daemon, the published campaigns
   and their analyses stay as they are. New pieces are selected by name (a new operating point,
   a new origin) so every old command still reproduces.
7. **Isolation.** All traffic stays inside the namespaces. Every new generator carries the scope
   lock of `ml/l7_gen.py` (it refuses a target outside the testbed subnet); external tools run only
   through the wrapper of 8.4, which applies the same lock.

**Non-goals.** New attack techniques or an adaptive-adversary study (to be scoped with the
supervisor); evasion of any detector; TLS/HTTP-2 realism and real-browser sessions; a second VM or
a physical NIC; changes to detection thresholds, the daemon or the models; production hardening.

## 3. Definitions

| Term | Definition |
|---|---|
| **Legit workload** `W(rho)` | An open-loop stream of legitimate sessions at `rho` requests/s with a fixed mix of route classes (section 6.1) |
| **SLO-success** | The fraction of legit requests that complete with a 2xx *within the SLO of their route class*. A timeout or a slow answer is a failure. The primary quality-of-service (QoS) number `Q` |
| **Control (C)** | The same block with the attack switched off: the legit workload only, on the unprotected stack |
| **Unprotected (U)** | The attack on the stack without the daemon and without Nginx limits |
| **Cost rate** | CPU-seconds the server spends per second of wall time on a class of requests: `rate x cost per request` |
| **SLO capacity `C_slo`** | The largest legit load (requests/s) at which `Q` >= 99 % (capacity probe, 7.2) |
| **Spare capacity `S`** | `(C_slo - rho) x mean cost of W`: the cost rate the server can still absorb before SLO-success falls below 99 % (a first-order model; the screening ladder measures the real knee) |
| **Intensity** | Per family, in a native unit on a geometric ladder: cost rate for L7 families, packets/s for L3/L4 floods, held connections for slow connections |
| **Knee `kappa_f`** | The lowest ladder level at which the screening gate passes in both repeats (7.2) |
| **Harm (per block)** | `Q(C) - Q(U)` in percentage points, and `log2(p95(U) / p95(C))` for requests that succeed |
| **Harm gate** | The frozen rule of section 10 that turns paired blocks into PASS, FAIL or INVALID |
| **Harm-reduction ratio (HRR)** | `(Q(m) - Q(U)) / (Q(C) - Q(U))` for a mitigated mode `m`, computed from block means; defined only where the gate passed |
| **Degraded seconds** | One-second bins of a run in which SLO-success is below 95 % |
| **Placebo** | A second control run per block, compared with the first as if it were an attack: it estimates how often the gate passes by chance |

## 4. Architecture

```
scenario spec ──► population generator ──► load generators (open-loop, closed-loop)
 (families,        (identities, UAs,           │  legit W(rho) + attack, intended-time
  levels, seeds)    netem, IP aliases)         ▼  schedules, scope-locked
                                        benchmark origin  ◄── Nginx bench profile
                                        (cost-calibrated routes)
                                               │
 calibration runner ─► calibration.json        ▼
 (capacity, ladders,   (frozen, hashed)   run directory: per-request records, 1-s bins,
  knee, drift check)                      server counters, generator validity, provenance
                                               │
                                               ▼
                                   harm-gate / QoS analysis (eval/) ─► gate verdicts, HRR,
                                                                        published campaigns
```

Only the suite, `eval/run_campaign.py` and the daemon exist today; they are reused and gain
settings only after your approval. The origin, generators, populations, calibration runner and gate
analysis are new code (section 12). Every new runner writes the provenance record of the suite's
`_write_provenance` (commit, dirty state, settings, hashes) and refuses a dirty tracked tree, as
`eval/run_campaign.py` does.

## 5. Workstream A: a cost-calibrated origin (G-01)

### 5.1 Why a flat cost cannot support a threat model [INFERENCE, arithmetic]

The rate an attacker needs to consume the server's spare capacity is `S / cost of the attacked
route`. With every route costing microseconds, that rate is enormous and necessarily far above any
per-source threshold, so a rate rule catches everything that can harm and nothing sub-threshold can
exist. Real applications do not look like that: search, report export and authentication are
routinely two orders of magnitude dearer than a static asset (OWASP API Security Top 10 2023, API4
*Unrestricted Resource Consumption*; OWASP Automated Threats OAT-008 [verify before citing]).
Appendix A works one example with illustrative numbers.

### 5.2 Route classes

A new origin module (working name `bench/origin.py`) serves the following classes. Costs are
**[PROPOSAL]** placeholders; the real values come from the calibration of 7.2 and are then frozen.
What is fixed by design is the *ratio structure*: at least a factor of 50 between the
cheapest dynamic route and the dearest (about 3,000 from a static asset to the export).

| Class | Example route | Work (deterministic, stdlib) | Unloaded cost, CPU | Stands for |
|---|---|---|---|---|
| C0 | `GET /static/..` | none (served by Nginx) | < 0.1 ms | assets |
| C1 | `GET /page/<id>` | template render of a 20-50 KB page | ~3 ms | dynamic page |
| C2 | `GET /api/item/<id>` | indexed SQLite lookup, JSON | ~2 ms | API read |
| C3 | `GET /search?q=` | SQLite scan of ~50 k rows with ranking | ~30 ms | search |
| C4 | `POST /login` | password-hash verification (`hashlib.scrypt` or `pbkdf2_hmac`) | ~60 ms | authentication |
| C5 | `GET /export` | build a 1-2 MB CSV | ~150 ms + bandwidth | report |
| C6 | `POST /upload` | read a body up to 64 KB, write to tmpfs | ~3 ms + body time | upload |

### 5.3 Constraints

* **Real work, not sleeps, for CPU classes.** A `sleep` costs no CPU and would hide the very
  saturation the gate must see. A separate, explicit *I/O wait* component (short blocking sleep on
  C2/C3) models blocked worker slots; it is documented and can be switched off.
* **Deterministic.** Response bytes and work amount depend only on `(route, parameters, cost
  seed)`; a per-request service-time spread (log-normal, sigma documented) is drawn from a seed
  derived from the request id, so a replayed schedule replays the same costs.
* **Calibrated, then self-checked.** The knobs (rows scanned, hash cost, template size) are set once
  per host class in the calibration; at start-up the origin measures each route unloaded and refuses
  to serve if any route is more than 25 % off the frozen value (host drift or a different CPU); a
  calibration mode, which produces the table, skips the check.
* **Stdlib only.** `sqlite3`, `hashlib`, `json`: nothing new to install; the data set is generated
  from a seed, small enough to stay in the page cache.
* **Benign.** No authentication state, no real secrets, no vulnerabilities: only cost.

### 5.4 Server profiles

The suite's gunicorn (8 x 4 or 1 x 1) and Nginx stay available. The benchmark adds named profiles,
each fully recorded in the run's provenance:

| Profile | Nginx | gunicorn | Pinning | Use |
|---|---|---|---|---|
| `bench-testbed` | the deployed `nginx.conf` / `nginx_unprotected.conf` (5-s timeouts, 16384 connections) | `gthread`, W x T slots **[PROPOSAL: 2 x 8]** | server on CPUs 0-1, daemon CPU 2, generators CPUs 4-7 | the main profile; modes are the existing four plus a control |
| `bench-stock` | same limits, distro-default timeouts (60 s) | same | same | sensitivity: does the testbed's own hardening hide harm? (D3) |

Transport is plain HTTP/1.1 on port 80, as in the suite (`HTTP_URL`). `nginx.conf` also listens on
443 with TLS, which the generator can use (stdlib `ssl`), but TLS handshake load is a separate
resource and is left to a later wave; there is no HTTP/2 client in the venv.

A response micro-cache for C1 is a later variant (it changes how URI-diverse requests cost), not
part of the first wave.

### 5.5 Verification

Offline unit tests (Appendix C): determinism, route table, cost self-check on a fake clock. On the VM
(HG2): the unloaded cost per route, its spread, and a saturation curve against the queueing
expectation (an M/G/c estimate computed from the measured costs); a mismatch of more than 25 %
stops the phase.

## 6. Workstream B: workload, intensity and harm metrics

### 6.1 The legit workload

* Open-loop sessions (section 8), not `curl` loops: the suite's 20 clients issue about 7 requests/s
  in total (`test_distributed_suite.py:828-850`), far below any capacity worth saturating, and
  each client is a closed loop that starts one process per request.
* A fixed mix over the route classes, **[PROPOSAL]** C0 30 %, C1 20 %, C2 30 %, C3 10 %, C4 4 %,
  C5 1 %, C6 5 %, so the mean cost is about 8 ms with the placeholder costs of 5.2.
* **Nominal load `rho` = 50 % of `C_slo`**, the largest load with SLO-success >= 99 % in the
  capacity probe (7.2). Half-loaded is typical of a production service and leaves a finite `S`;
  an idle server (5 % load) would make every sub-saturating attack harmless by construction (D2).
* SLO per class **[PROPOSAL]**: C0 100 ms, C1 and C2 300 ms, C3 and C4 1 s, C5 3 s, C6 1 s (an
  Apdex-style satisfaction threshold, Apdex Alliance, *Technical Specification* 1.1; and the
  percentage of failed transactions against per-application QoS thresholds of Mirkovic et al.,
  ExpCS 2007 [verify both]) (D1).
* The same engine also supplies the hard negatives of the benign side: heavy legitimate users of
  C3-C5 and NAT pools, so that "uses an expensive route" is not a label proxy.

### 6.2 Attack intensity as a cost rate

For L7 families the intensity is the cost rate `A` in units of `S` (ladder `S x {1/8, 1/4, 1/2, 1,
2, 4, 8}`), realised as `rate x cost of the attacked routes`. This makes families comparable and
makes "sub-threshold" a *derived* property: the per-source request rate that the cost rate implies,
compared afterwards with the deployed thresholds exactly as the engine matrix does (REPORT
section 3.5). Intensities are never chosen by looking at a threshold or a detector. This is a
first-order model: the ladder, not the model, finds the knee. Low-and-slow in the request-rate
sense is the same family spread over many sources: the total cost rate stays at the ladder level
while the number of sources grows, which lowers every source's rate; the number of sources is a
recorded factor (9.1).

For L3/L4 floods the native units are packets/s (and the SYN backlog for SYN floods); for slow
connections, held connections per source. Ladders are geometric with factor 2 from a floor to the
generator limit.

### 6.3 Metrics (all computed per run from per-request records and 1-s bins)

| Metric | Why |
|---|---|
| SLO-success `Q`, overall and per route class | the primary harm number; a flood of cheap requests can leave C0 fine and starve C3 |
| p50 / p95 / p99 of successful requests, per class | tail latency is the first thing to degrade (*The Tail at Scale*, CACM 2013 [verify]) |
| Degraded seconds, time to first degraded second, recovery time (5 consecutive bins >= 99 %) | a mitigation that bans in 0.3 s and one that bans in 4 s differ in *how long* the harm lasts, which a window mean hides |
| Lost requests = failures + SLO violations over the exposure | the integral of harm, in requests |
| Server side: CPU per process (psutil), accept-queue overflows and listen drops (`nstat`), Nginx `stub_status`, Nginx 5xx and 503 counts, gunicorn queue | tells *which* resource saturated and verifies offered rate at the server |
| Collateral: legit requests rejected by a limit (access-log field `lreq`, i.e. `$limit_req_status`; G-22), legit sources banned, per client-hour | a mitigation's own harm; HRR alone can reward over-blocking |

### 6.4 Mapping the existing scenarios, and expectations written down before any data

| Class | Existing scenarios | Primary resource | Expected under the gate (HYP) |
|---|---|---|---|
| L3/L4 volumetric | S1 SYN, S3 UDP, S5 ACK, S6 fragmentation, S10 multi-vector | softirq / kernel stack / SYN backlog | HYP-3 |
| L7 volumetric on cheap routes | S4 HTTP flood, S9 pulsing flood | app CPU | passes at the knee only at rates above the per-source thresholds (HYP-2) |
| L7 on costly routes | the sub-threshold floods, scraper, padded flood of P5 / P5c, aimed at C3-C5 | app CPU | passes at per-source rates below the thresholds *if the cost asymmetry of 5.2 holds* (HYP-2) |
| Authentication abuse | `credstuff` against C4 | app CPU (hash) | passes; also covered by the error-ratio branch (a control where rules win) |
| Slow connections | S7, S8, slow-read | worker slots, connections | harm only near the connection limit (HYP-4) |
| Controls and hard negatives | plain floods; flash crowd; NAT pools; heavy legitimate users | any | rules win; the benign side must not be banned |

Pre-registered expectations **[PROPOSAL]**:

* **HYP-1.** On the old flat origin only S4 at the knee passes the gate (what the record already
  shows in EXP-A, EXP-1d and the default-point campaign; the gate itself was never applied to them).
* **HYP-2.** On the calibrated origin, cheap-route floods pass only at above-threshold rates; at
  least one costly-route family passes below them; the count of passing families changes with the
  cost scale (x0.5 in the minimum version, x2 if the budget allows; section 11).
* **HYP-3.** L3/L4 floods fail on the veth topology at any server CPU budget unless the probe of 7.3
  shows the receive work is charged to the server's CPUs.
* **HYP-4.** Slow connections cause no measurable harm at the suite's 8-10 held sockets per bot in
  either profile (Nginx absorbs them with its own timeouts and buffers), and harm only when the
  held connections approach `worker_connections` (16,384) or the descriptor limit. With the
  per-IP limits off in the unprotected stack that is a regime of thousands of held connections;
  whether it is reachable below the per-source SlowConn thresholds depends on the number of
  sources, which `--plan` prints. If the population cannot supply them, the class is recorded as
  "harm not producible below the per-source thresholds with this population".
* **HYP-5** (the report's). At the same open-loop offered rate, limits-only is no worse than
  unprotected. If the -22.5 pp of EXP-A came from the closed-loop generator speeding up when
  rejected (`PPS_Rx` 33,440 against 3,303, mean over the attack phases), it disappears; if it
  persists, Nginx's own cost under that load is the cause.
* **HYP-6.** The daemon's advantage persists under open-loop load in every cell where the per-bot
  rate exceeds its L7 rule (50 rps), because bans act on sources; below that rate it has no reason
  to ban, and the cell shows whether the flood harms at all.

## 7. Workstream C: operating-point calibration (G-10)

### 7.1 Resource model

An attack harms by saturating a *resource*; calibration is per resource, not per scenario name.

| Resource | Saturated by | Operating-point knobs (recorded in provenance) |
|---|---|---|
| App CPU | costly-route L7 load | server CPU set, workers x threads |
| Worker slots / connections | long or held requests | threads, `worker_connections`, timeouts |
| Accept / SYN queue | connection-rate floods | `somaxconn`, `tcp_max_syn_backlog`, `tcp_syncookies` (a stock Linux has cookies on) |
| Packet processing | L3/L4 floods | pinned CPUs for softirq, RPS masks, generator CPUs |
| Bandwidth | large responses | veth link rate |

### 7.2 Procedure (offline plan; each VM step needs your approval)

0. **Environment gate.** Clean tree, `uptime` above 30 minutes (the full-suite run of 2026-10-20
   started three minutes after a restart and its HTTP-flood time to mitigate was 1.08 s against
   0.55-0.69 s in warm runs; one run could not separate warm-up from phase), load average below
   0.3, governor and steal time recorded, and the timer wake-up lateness (`time.sleep(10 ms)`,
   200 samples; the harness measures it before and after every run) with p99 below 10 ms. On
   2026-10-22 the VM gave p50 12 ms and a maximum of 389 ms in a 20-sample probe, with no steal time
   and no scheduling gap in a busy loop: its idle vCPUs are woken late.
1. **Origin check.** Unloaded cost per route against the frozen table (5.3).
2. **Capacity probe.** Legit workload only, open-loop ramp in 10 steps of 20 s, three repeats:
   `C_slo` (largest load with `Q` >= 99 %) and `C_sat` (`Q` < 50 %). `rho` = 0.5 x `C_slo`.
3. **Screening ladders.** For each family, the unprotected system at `rho`, the ladder of 6.2, two
   repeats per level, an attack-free control after every fourth run. Screening gate: block harm >=
   the floor of section 10 in both repeats.
4. **Knee.** `kappa_f` = lowest level that passes screening. If no level passes up to the generator
   limit, the family is recorded as **"cannot harm this server within the generator limit"**, which
   is a finding, and nothing is tuned further.
5. **Freeze (end of HG2).** `bench/calibration/<host>-<date>.json` (capacity curve, `rho`,
   `kappa_f`, route costs, pilot spreads, host and kernel, boot time), committed before any
   confirmation or evaluation data. The probes and ladders are published as ordinary campaigns,
   one per (family, level), so the existing layout and `SHA256SUMS` apply; the EXP-1d lesson (five
   points that did not fit the layout) is the reason.
6. **Confirmation (HG3).** Ten paired blocks at the frozen `kappa_f` with the full gate (section
   10), including the placebo. If that fails, one further confirmation at `2 x kappa_f`; no other
   level is tried and both outcomes are reported. The dose-response from the ladder (mean harm
   non-decreasing with the level) is reported next to the verdict as supporting evidence.
7. **Drift check before every later campaign.** A 2-minute legit-only probe plus one calibrated
   attack level must reproduce `Q` within 2 pp and p95 within 25 %; otherwise the campaign does not
   start.

### 7.3 L3/L4 floods: a transferability probe first [RISK]

The audit inferred (REPORT section 9.4) that on a veth pair the receive work of a packet runs in the
*sender's* context. If so, a packet flood loads the attacker's CPUs, not the server's, and no
pinning of the server can make the flood harmful; that would also make XDP-versus-iptables CPU
numbers non-transferable to a real NIC. Step 3 for L3/L4 therefore starts with a **probe**: run a
UDP and an ACK flood against the unprotected server and attribute softirq time per CPU
(`/proc/softirqs`, `mpstat`; `metrics.csv` already holds `HotCore_ID`, `HotCore_CPU_Pct` and the
NET_RX counters) to server-side and attacker-side CPUs. Outcomes: (a) the server's CPUs carry the
work, so the ladder proceeds with them pinned; (b) they do not, so L3/L4 floods are recorded as
**harm not producible on this topology** (HYP-3) and the plan states the limit: a second VM or a
physical NIC.
SYN floods are different: the SYN backlog is kernel state in the server's namespace and does not
depend on whose CPU ran the receive path, but stock Linux enables SYN cookies, so the ladder runs
with the stock setting and, as a sensitivity arm, with cookies off and a small backlog (D3).

### 7.4 Pinning plan [PROPOSAL]

Server stack on CPUs 0-1, daemon on CPU 2, legit generators on CPU 3, attack generators on CPUs
4-7 (`taskset`, as `SERVER_CPUS` / `ATTACK_CPUS` already do). A run is INVALID if any generator
process exceeds 70 % of one core or the server's non-bottleneck CPUs are saturated.

### 7.5 Stopping rules

Stop and report instead of tuning when: no family passes the gate within the generator limit; the
drift check fails twice after re-running the environment gate; the open-loop generator cannot hold
the intended rate at the knee (then the generator, not the server, is the bottleneck: split it across
processes, and if that fails, the second-VM option of D8).

## 8. Workstream D: open-loop and closed-loop load (G-13)

### 8.1 Why the distinction decides the rate-limiting result [INFERENCE]

A closed-loop client sends its next request only after the previous one is answered. Against
`limit_req`, a rejection is cheap and arrives fast, so a closed-loop client *speeds up* when it is
rejected; against a saturated server it slows down. Either way the load it offers depends on the
mode under test, so modes are compared at different offered loads. `limit_req` is designed for a
fixed arrival rate above its limit. This is the open-versus-closed distinction of Schroeder,
Wierman and Harchol-Balter (NSDI 2006 [verify before citing]). The campaigns record packets/s and
established connections at the server (`PPS_Rx`, `TCP_Estab` in `metrics.csv`) but no request count
at Nginx, so the offered request rate of EXP-A's closed-loop arms is known only indirectly (`PPS_Rx`
33,440 for limits-only against 3,303 unprotected, mean over the attack phases).

### 8.2 Required semantics

* **Open-loop arrivals** follow a precomputed schedule (constant rate, Poisson, on/off pulses, or a
  ramp), independent of any response. Concurrency is bounded by a documented cap; a request that
  cannot be started because the cap is reached is *counted as dropped by the generator* and the
  run is flagged.
* **Intended-time latency** (the correction for coordinated omission, Tene, "How NOT to measure
  latency" [verify]): a request's latency runs from its scheduled send time, so a stalled server
  or a late generator shows up as latency instead of vanishing.
* **Closed-loop** stays available as a separate, labelled model (`wrk`, fixed connections): it is a
  fair model of a connection-limited client. The two are never mixed in one comparison.
* **Sources and connections.** Each identity binds its source address; keep-alive pools are
  capped per identity (legit: browser-like; flood: documented).
* **Output.** One record per request (intended time, actual send time, completion, status, bytes,
  error class) plus 1-s bins; written compactly (a few thousand requests/s is under 1 MB/s).

### 8.3 Validity rules (a run failing any is INVALID and reported; its block is re-run, section 10)

* schedule slip (actual minus intended send time): p99 below 50 ms;
* achieved sends at least 99 % of intended;
* generator CPU below 70 % of its pinned core(s); no fd or ephemeral-port exhaustion;
* **server-side check**: requests counted by Nginx (access log, including `limit_req` 503s,
  which `nginx.conf` already logs as `$limit_req_status`) within 5 % of requests sent, so the
  *effective* offered rate is a measurement, not an assumption (this also closes G-08 for new
  scenarios).

### 8.4 Generators, their roles and how they are verified (D4: decided 2026-10-22)

**Decision: both.** The in-repo asyncio engine is the primary generator. `wrk2`, `vegeta` and `k6`
were to be installed, pinned and verified as well (Appendix E), as independent cross-checks of the
in-repo engine and of each other, and as alternative drivers where the in-repo ceiling is too low.
Stage 1 (2026-10-22) installed and smoke-tested vegeta and k6; **wrk2 builds but panics in Lua at
the start of a run and is recorded as unavailable on this OS** (E.3). The closed-loop `wrk` already
on the VM (Ubuntu package 4.1.0) stays the closed-loop model and serves as the *negative control* of
the verification: it must fail the coordinated-omission test. The reference for the correction is
the analytic value of V4, which does not depend on any tool.

| Generator | Role | For | Against |
|---|---|---|---|
| **In-repo asyncio** (`bench/loadgen.py`, new; stdlib) | primary: legit populations, L7 families, one source address per identity, seeds, scope lock, our per-request record schema | one engine for legit and attack load; deterministic schedules; reviewable | Python: a ceiling of a few thousand requests/s per core (to be measured); must itself pass the verification |
| **wrk2** (`giltene/wrk2` @ `44a94c1`; Apache-2.0): **unavailable on this OS** | was: high-rate constant-throughput driver, the reference implementation of the correction | `-R` total rate, HdrHistogram latency, efficient C | builds (GCC 15.2, OpenSSL 3.5.5) but exits at the start of every run with `PANIC: unprotected error in call to Lua API (attempt to index a nil value)`; its bundled LuaJIT is 2.0.3 (2014) and the default-branch head is a 2019 merge; cause not diagnosed, no retry made (E.3) |
| **vegeta** (v12.13.0, release binary; MIT [verify]) | open-loop constant-rate driver with many targets | `-laddr`, JSON and HDR reports, PGP-signed checksum file | its README defines latency as the time taken for a response to be read, so the correction semantics are for the verification to establish |
| **k6** (v2.3.0, release binary; AGPL-3.0 [verify]) | scenario-rich open-model driver (`constant-arrival-rate`, `ramping-arrival-rate`) | arrival-rate executors, thresholds, JS scripting for sessions | heaviest per request; v2 is a recent major version; checksums but no signature; reports anonymous usage on every run unless given `--no-usage-report` |

**Provisioning rules for every external tool.**

* Pinned versions (above), each in its own new directory under `/home/artur/loadtools/`, outside
  the repository; binaries are never committed. No external tool is put on `PATH` under the
  name `wrk` (the suite calls `wrk`); `/usr/bin/wrk` was checksummed before and after Stage 1 and
  is unchanged.
* Integrity: the sha256 of every download is compared with the release's checksum file and with
  the digest GitHub reports for the asset; for vegeta also the PGP signature of its checksum file
  (the key ships in the same release, so this shows consistency, not independent authenticity; the
  fingerprint is recorded); for wrk2 the commit hash after checkout. Any mismatch stops the
  procedure. Building wrk2 executes upstream Makefile code, as the unprivileged user, never as root.
* A manifest (`tools.json`: name, version, source URL, sha256, install path, status; wrk2 is
  listed as `unavailable` with its build-log hash and the panic as the reason) is committed with
  the results. The verification load
  runs unprivileged on loopback; only later, inside the testbed namespaces, do the tools run as
  root.
* Execution goes through a thin wrapper (`bench/loadtools.py`) that builds the command line from a
  schedule, refuses a target outside the testbed subnet (or loopback, for the verification), pins
  CPUs, never follows redirects (a redirect could leave the subnet), starts k6 with
  `--no-usage-report`, and records the exact command, version and sha256 in the run's provenance.
  Direct invocation is for the verification only.

**Verification protocol.** The acceptance criteria are written down here, before any measurement,
and apply to every generator including the in-repo one. Two loopback origins: S1, a user-level
Nginx returning a fixed body (rate and ceiling tests), and S2, a scripted Python server with a
known service-time distribution, a scripted stall and a status mix (latency, stall and accounting
tests).

| Test | What is run | Pass criterion |
|---|---|---|
| V0 integrity | checksums, signature, commit hash | all match |
| V1 smoke | `--version`; 10 s at 100 requests/s | version as pinned; zero errors; sent within 2 % of intended |
| V2 rate accuracy | 200, 1,000 and 5,000 requests/s, 20 s each, 3 repeats | requests counted by the origin within 1 % of rate x duration |
| V3 latency accuracy | 500 requests/s, 30 s, S2 with known service times | reported p50 and p99 within the larger of 1 ms and 10 % of the origin-side ground truth |
| V4 coordinated omission | 500 requests/s, 40 s, S2 stalls every response for 3 s starting at t = 15 s | reported p99 within 15 % of the analytic value, 2.6 s: 1,500 of the 20,000 requests arrive during the stall, uniformly over its 3 s, so p99 = 3 s x (1 - 1/7.5); the closed-loop `wrk` must report about the service time |
| V5 overload honesty | offered rate 2x the origin's capacity, 20 s | arrivals at the origin follow the intended rate, or the tool reports every dropped or late send; no silent slip |
| V6 status accounting | S2 answers 10 % of requests with 503 | the tool's non-2xx count is within 1 % of the origin's |
| V7 ceiling and cost | ramp 1k, 2k, 5k, 10k, 20k requests/s, 10 s each, one pinned core | highest rate with at least 99 % schedule adherence and no errors; CPU per 1,000 requests/s recorded |

**Criteria version 2 (added 2026-10-22).** The table above is criteria version 1, fixed before any
measurement and used for the first run. Version 2 adds two amendments adopted *after* that run, each
labelled **post hoc** wherever it appears (A1: the V4 control is judged by its arrivals in the stall,
not by its reported p99; A2: V3 latency is judged from the actual send for every tool), and applies
this table's own V7 criterion, schedule adherence, which the first run did not (C1, not an
amendment). Every results directory records the version that judged it. Appendix F.4.

Each tool gets the documented settings a test needs (for V4 enough workers or VUs to cover 3 s of
arrivals, at least 1,500 plus margin); the settings are recorded, and a tool that passes only with
settings the benchmark cannot afford (CPU, descriptors) is reported with that restriction. A
generator that fails V0-V2 is unfit and reported as such; one that fails only V4 or V5 is not used
for latency or overload claims; none is tuned until it passes. The thesis names, for each number,
the generator and the verification result it rests on.

### 8.5 EXP-C: the rate-limiting experiment (REPORT section 15, EXP-C)

**Design.** EXP-A's design on EXP-A's server (knee operating point, existing origin and Nginx
configurations), so that the *only* change is the attacker's load model and the result is directly
comparable with `results/2026-10-20_expa-knee-10-blocks/`. Three modes (unprotected, Nginx limits
only, daemon + XDP), each under four load models in the *same* campaign, so that host drift cannot
separate them:

| Load model | Offered load | Reading |
|---|---|---|
| closed-loop (`wrk -c400`, as in EXP-A) | whatever the server allows; measured at the server (8.3) | the reference arm |
| open-loop, 0.5 x R50 | split evenly over the 10 bots | below the saturation of the unprotected server |
| open-loop, 1 x R50 | same | at it |
| open-loop, 2 x R50 | same | above it |

`R50` is the offered rate at which the *unprotected* knee server serves about half of the legit
requests. A short open-loop capacity probe (one ramp, about 10 minutes) finds it, on service impact
only; the three rates, and the per-bot rate each implies relative to the two per-IP rules (30 r/s
`limit_req` with burst 100, 50 rps L7 rule), are written down before the blocks run. The report
suggests rates below, near and above the per-IP rule; with 10 bots and an `R50` near 1,000
requests/s the three cells fall near and above the rules, so this experiment answers the
*amplification* question (G-13) and not the *sub-threshold* question, which needs more sources
(section 9). Ten blocks per cell, `PROFILE_SEED`-paired as in EXP-A, block order shuffled.

**Outputs.** Success during the attack and in its first 10 s, tail latency, Nginx CPU, `PPS_Rx`,
`lreq` counts, and the offered rate measured at the server for every cell.

**Pre-registered hypotheses.** HYP-5 and HYP-6 (6.4), the first being the report's: with an
open-loop attacker the closed-loop amplification (`PPS_Rx` 33,440 against 3,303 in EXP-A) does not
occur and limits-only is no worse than unprotected. Either outcome is reported, and so is any cell
in which the unprotected server is not harmed (that cell tests nothing about mitigation).

**What it needs.** An open-loop driver that passed V0-V5 of 8.4 (the verified external tools
qualify, so it does not wait for the in-repo engine) and a per-bot rate and tool setting in the
HTTP-flood scenario (default unchanged). It does not need the calibrated origin, the populations or
the gate: the flood is the one EXP-A already showed to be harmful at this operating point, which is
why it can run first.

**Cost.** 120 runs (3 modes x 4 load models x 10 blocks) at EXP-A's 93 s per run is about 3.2 h,
plus the probe. The report's version, with no closed-loop arm in the same campaign, is 90 runs;
reusing EXP-A as the closed-loop reference would save 30 runs at the price of comparing across two
campaigns on different days (D11). Optional: repeat the 1 x R50 cell with a second verified
generator (3 modes x 10 blocks = 30 runs, about 0.8 h) to show that the result is not
generator-specific.

## 9. Workstream E: entity populations (G-05)

### 9.1 Design

* **Identity** = source IP + User-Agent + cookie jar + behaviour parameters + netem class. An
  *entity* is drawn, not hand-written.
* **Benign population** per seed: at least 200 identities from at least 10 behaviour classes
  (page browsers with 10-150 assets, single-page-app bursts, mobile API pollers, steady and bursty
  API clients, polite crawlers, flash-crowd visitors, NAT pools of k users, downloaders, uploaders,
  heavy search users). Per-entity parameters are sampled from documented distributions (think times
  heavy-tailed, SURGE-style; Barford and Crovella 1998 [verify]); each distribution is labelled
  *sourced* or *assumed*. The benign kinds of `ml/l7_gen.py` (`browser_page`, `api_poll`,
  `api_bulk`, `crawler_polite`, `cgnat_browsers`, `nat_gateway`, `downloader`, `uploader`,
  `keepalive`) are the starting inventory; the new engine re-expresses them as open-loop session
  schedules, because the existing ones are blocking `requests` loops.
* **Attacker pools** per family and seed: at least 8 distinct instantiations for the harm gate and
  at least 50 per family for any detection study (the audit's number); source addresses re-drawn per
  seed; total cost rate held at the ladder level while the number of sources is a recorded factor
  (5, 20, 100).
* **One netem distribution for every class**, attackers included, over a shared set of
  namespaces, which removes the link-quality label proxy (G-04).
* **Seed namespaces** `calib`, `train`, `val`, `test`: the entity seed is `hash(namespace, seed, role,
  index)`, namespaces never share a seed, and the harm-gate calibration may only use `calib`
  (G-03).

### 9.2 Realisation

Namespaces are costly, addresses are not. Use IP aliases (or macvlan with unique MACs) on a few
client namespaces: about 24 namespaces, each carrying roughly ten identities, each generator process
multiplexing its identities and binding their source addresses. The daemon and XDP key on source
IP and the L7 engine on (IP, UA), so nothing downstream changes. Memory and CPU are the limit
(about 250 identities at a few hundred requests/s in total is within the 8-vCPU / 9.4 GiB VM
[INFERENCE]; the generator-validity rules of 8.3 are the proof). If it is not, the fallback is 120
benign and 40 attacker identities with the reduction stated.

### 9.3 Units and statistics

The unit for service metrics is the **block**; for detection metrics it is the **entity**, nested
in blocks (cluster bootstrap by entity within block, as the audit's section 11.6). No pooled
Fisher or McNemar tests over replicates.

## 10. The harm gate

Applied to the unprotected stack, no model and no daemon, on paired blocks.

**Block** = control `C`, placebo `C'`, attack `U`, run in shuffled order, same entity draw, same
`rho`, same timeline of baseline, attack window and recovery (the window is empty in `C` and `C'`).
`Q` and p95 are computed over the attack window, the same seconds in all three runs; the baseline
and recovery windows feed the health check and the recovery time.

**Per block**: `dQ = Q(C) - Q(U)` (pp), `dL = log2(p95(U) / p95(C))`, `dQ' = Q(C) - Q(C')`.

**Verdict** over `B >= 10` blocks (screening uses 2 repeats and the floor only):

1. **INVALID** if fewer than 10 valid blocks remain after re-running a failed block once with the
   same seed (at most two re-runs per gate). A block is valid iff its three runs pass the validity
   rules (8.3) and the control is healthy (`Q(C)` >= 99 % and p95 within its class SLO); both are
   independent of the attack's effect. Reported, not repaired by dropping blocks or relaxing
   rules.
2. **PASS** iff, on valid blocks, either (a) the mean of `dQ` is at least the floor **[PROPOSAL] 10
   pp**, its 95 % t-interval excludes 0 and at least 80 % of the blocks have its sign; or (b) the
   mean of `dL` is at least **1** (p95 doubles), with the same interval and sign conditions. The
   floor is the harm that 10 blocks detect with 80 % power at the spread seen in EXP-A (section
   11), so that it is a promise the design can keep; smaller effects are reported as "degradation
   below the floor", not as harm.
3. **FAIL** otherwise. A FAIL is reported as *no measurable harm at this level*, not as "attack
   absent".
4. **Specificity.** The same rule applied to `dQ'` must not pass; over the whole programme the
   fraction of placebo passes is reported (target: none).

The rule is the run-level rule of `eval/run_level_stats.py` (it needs at least 10 blocks, the
interval and the same-sign share) plus a magnitude floor, so that a significant but trivial effect
is not called harm. It is committed, with the floor and the SLO table, before the confirmation data.

**What a verdict licenses.** PASS: the scenario at that level may be used as a mitigation scenario
and its HRR is defined. FAIL: it may appear in the thesis only as a *label-detection* scenario,
with that wording. INVALID: re-run after fixing the cause, with the failure published.

**Relation to the audit's admissibility gate (REPORT section 11.2).** The audit lists six
conditions for admitting a threat class. This design supplies the measurable ones and says where
the others live:

| Condition of 11.2 | Where it is handled |
|---|---|
| 1. External grounding cited | the `grounding` field of the scenario specification (Appendix B); `assumed` is allowed and reported |
| 2. Harm measured against a pre-registered margin | **Gate A, this section**, on the unprotected stack. The audit words the condition for the deterministic-only system; that second measurement (**Gate B**: the harm that remains with the rules and XDP active and the GRU off) is the daemon's HRR in HG4. A scenario is a candidate target for a learned model only if Gate A passes and Gate B leaves a residual above the margin (D12) |
| 3. Not already covered by the deterministic engines | `--plan` against the engine matrix (REPORT 3.5), confirmed by Gate B |
| 4. Calibrated on thresholds and service impact only | principle 3; the knee rule of 7.2 uses service impact only |
| 5. Not separable through a fingerprint | outside this plan (the invariance probes of the ML track); the populations here, with one netem distribution for every class, remove the netem and pacing proxies by construction |
| 6. Frozen in a commit before any data | the freeze file (7.2) and the gate rule (this section) are committed first |

## 11. Statistics

* **Blocks** are the independent units; seeds come from the `test` namespace for evaluation and
  `calib` for calibration. Mode order inside a block is shuffled (`--order-seed`).
* **Sample size.** In EXP-A the spread of the unprotected arm across blocks was about 10 pp
  (recomputed from the block table in its README: SD 9.8 pp for the daemon-minus-unprotected
  differences, 13 pp for limits-only minus unprotected). `blocks_for_power`
  (`eval/run_level_stats.py:124`) gives the blocks needed for 80 % power at an SD of 10 pp:
  **15 pp: 6; 10 pp: 10; 7 pp: 19; 5 pp: 34** [FACT, computed offline]. So 10 blocks certify a
  harm of about 10 pp, 20 blocks about 7 pp, and a 5 pp floor would need 34. The floor of section
  10 is therefore the harm the planned number of blocks can detect, and it is re-derived from the
  pilot SD (the HG2 screening repeats) before the confirmation data (D1).
* **Two stages.** Screening (2 repeats) is allowed to be liberal because confirmation (10 blocks) is
  the only stage whose verdict is reported as a gate result.
* **Multiplicity.** Each gate is an admission decision for one scenario and level, not a test of
  a shared hypothesis; the magnitude floor, the sign share and the placebo are the guard. The
  number of gates run is reported in full.
* **HRR** is reported with a block bootstrap interval and only where its denominator is the
  gate-passed harm; otherwise absolute differences in pp are reported, as in EXP-A.
* **Sensitivity.** Offline, from the same per-request records: the SLO table at x0.5 and x2, and
  the success-versus-p95 criterion. On the VM, limited to the costly-route family: cost scale x0.5
  (5.3 knobs; the arm in which a low-rate niche is most likely to close), x2 if the budget allows,
  each with its own capacity probe; `rho` = 0.4 and 0.6 of `C_slo` only if a verdict is borderline.
  Verdicts that flip are reported as fragile. The cost-rate model of 6.2 predicts the direction of
  each flip, so the arm also tests the model.

## 12. Plan, budget and approvals

### 12.1 Phases

| Phase | Work | Files (working names) | Effort | VM time | Gate to proceed |
|---|---|---|---|---|---|
| **HG0** | this review | `docs/BENCHMARK_HARM_DESIGN.md` | - | none | your decisions D1-D12 |
| **HG1a-0** external tools | Stage 1 of Appendix E: packages, pinned downloads, wrk2 build, V0 and V1. **Done 2026-10-22**: vegeta and k6 installed and smoke-tested, wrk2 unavailable (E.3) | `/home/artur/loadtools/` (outside the repo), manifest | S, no repo code | done: about 3 min | your go on the exact commands (given) |
| **HG1a** generators | wrapper with scope lock and provenance; verification harness (two loopback origins, V2-V7, analysis); in-repo asyncio engine (schedules, intended-time latency, validity flags, records); a per-bot rate and tool setting for the HTTP flood (default unchanged) | `bench/loadtools.py`, `bench/loadtool_validate.py`, `bench/loadgen.py`, a setting in `test_distributed_suite.py` and `eval/run_campaign.py`, tests | 6-8 days | V2-V7 for vegeta, k6 and `wrk`, then for the in-repo engine: about 0.65 h | tests and ruff green; every generator verified or documented as unfit |
| **EXP-C** | section 8.5, driven by a verified generator | a campaign | S | about 3.5 h | HYP-5 and HYP-6 reported |
| **HG1b** offline build | cost-calibrated origin; populations and seed namespaces; scenario specification and `--plan`; harm-gate analysis (time-resolved metrics, placebo, HRR); calibration runner and freeze file | `bench/origin.py`, `bench/population.py`, `bench/calibrate.py`, `eval/harm_gate.py`, tests | 8-11 days | none | tests and ruff green; golden `--plan` files |
| **HG2** calibration | steps 0-5 of 7.2: gates, origin check, capacity, transferability probe, ladders, freeze | `bench/calibration/*.json`, campaigns | - | about 3 h in 1-2 sessions | frozen file committed |
| **HG3** harm gate | confirmation of every candidate (7.2 step 6), sensitivity arm | campaigns, `harm_gate.md` | S | about 5-6.5 h in 2 sessions | verdicts published |
| **HG4** mitigation benchmark | admitted scenarios x (control + 4 modes) | campaigns | S-M | about 4 h | HRR, collateral, degraded seconds |
| **HG5** analysis and text | `docs/THESIS_CLAIMS.md`, errata, derived tables | docs, `results/..._derived` | S | none | numbers regenerate from `results/` |

Code effort is 14-19 working days in full (HG1a + HG1b) and 9-11 for the minimum viable version.
Order: HG1a-0, then the harness and wrapper of HG1a, then EXP-C with a verified external driver
while the in-repo engine and HG1b are built. Mapping to the audit's phases (REPORT 11.7): G0 (seed
namespaces, same netem, rate conformance) is 9.1 and 8.3 here; G1 (backend and harm gate) is
HG1b-HG3; G2 (entities, scenario language, open loop) is HG1a, section 9 and Appendix B.

### 12.2 VM time, derived

A new-harness run is assumed to take 2.5 min (30 s baseline, 45 s attack, 30 s recovery, about 45 s
of set-up and tear-down); EXP-C uses the existing harness at EXP-A's measured 93 s per run (62 min
for 40 runs). Both are recomputed from the first real run.

| Step | Runs | Min/run | Hours |
|---|---|---|---|
| External tools: packages, downloads, wrk2 build, V0, V1 (Stage 1, done: about 3 min) | - | - | 0.1 |
| vegeta, k6 and `wrk` as negative control: V2-V7 on loopback | - | - | 0.4 |
| In-repo engine: V1-V7 on loopback | - | - | 0.25 |
| EXP-C: capacity probe + 3 modes x 4 load models x 10 blocks | 1 + 120 | 1.6 | 0.25 + 3.2 |
| HG2: environment gate, origin check, capacity probe, transferability probe | - | - | 0.7 |
| HG2: screening, 3 families x (7 levels x 2 repeats + 4 controls) | 54 | 2.5 | 2.25 |
| HG3: confirmation, 3 families x 10 blocks x (control, placebo, attack) | 90 | 2.5 | 3.75 |
| HG3: second-level confirmation for one family whose first level failed (contingency) | 30 | 2.5 | 1.25 |
| HG3: sensitivity arm, costly-route family at cost x0.5 (probe + 10 blocks x 3 runs) | 30 | 2.5 | 1.5 |
| HG4: 2 admitted L7 scenarios x (control + 4 modes) x 10 blocks | 100 | 2.5 | 4.2 |
| **Minimum viable version** | | | **about 18 h** (16.5 h without the contingency) |

Smaller cuts (D10), each including the 0.75 h for the load tools: the two L7 families through
HG2-HG4 plus EXP-C, with no L3/L4 family and no sensitivity arm, is about 13 h; EXP-C plus one
costly-route family through HG2-HG3 is about 7 h. Not included: the `bench-stock` and SYN-cookie
arms (about 1.5 h each, D3), re-runs of invalid blocks (at most 6 runs per gate), a cross-tool
repeat of EXP-C's 1 x R50 cell (30 runs, about 0.8 h), and the second-wave families.

### 12.3 Approvals and side effects

Each VM session is proposed separately with its exact command, duration and side effects, as for
EXP-A and EXP-B. Campaign sessions: root; namespaces, Nginx, the origin and generators started and
stopped; XDP programs attached and removed; traffic inside the testbed only; results written under
`/var/tmp/ddos_campaigns` and published afterwards (`docs/EVALUATION.md`, "Side effects of a suite
run"). HG1b runs nothing on the VM except offline unit tests. Stage 1 of Appendix E was different
in kind (run 2026-10-22): root for `apt-get` only; it added 24 packages, downloaded from GitHub
and the Ubuntu mirrors, and generated loopback traffic for about a minute; its side effects and
the way to undo them are in Appendix E.

## 13. Validity threats and risks

| Threat | Why it matters | Mitigation |
|---|---|---|
| The cost model *creates* the niche for low-rate harm [RISK] | a backend built so that cheap requests can hurt makes any rule-evading story easy | classes anchored to external grounding; ratios, not tuning; sensitivity at x0.5 / x2; controls where rules win and hard negatives that use expensive routes; conclusions stated as conditional (principle 4) |
| Goodhart: tuning the gate until a scenario passes | an admitted scenario would mean nothing | frozen floor and SLOs; stopping rules (7.5); all candidates and the placebo reported |
| Generator is the bottleneck | harm would be measured on the client, not the server | validity rules (8.3); CPU pinning; server-side count check |
| Late timer wake-ups on the VM | a generator that sleeps until its next send slips by tens or hundreds of milliseconds; every tool's schedule suffers, and so does a daemon that polls once a second | the probe above, before and after every run; the validity gates (slip p99 below 50 ms) catch the effect; `bench/loadgen.py --spin-ms` busy-waits and the CPU flag ignores that time; if the VM cannot meet the gates, say so and move the generators to a host that can (D8) |
| Host drift, cold start | the run of 2026-10-20 started 3 minutes after a restart; its HTTP-flood time to mitigate was 1.08 s against 0.55-0.69 s warm, and warm-up could not be separated from phase | environment gate and drift check (7.2); boot time in provenance |
| Veth charges the receive work to the sender | L3/L4 CPU harm and XDP-vs-iptables CPU may not transfer | transferability probe; the limit stated; second VM as future work |
| The unprotected stack is already hardened | slow-connection and SYN harm may be invisible | `bench-stock` and SYN sensitivity arms (D3); a FAIL is reported as such |
| Switching the legit measurement tool | latencies are not comparable with campaigns that used `curl` | new campaigns are labelled; old ones are not re-analysed with the new tool |
| Calibration overfits one host state | thresholds drift | calibration dated and hashed; drift check; recalibrate when the check fails |
| Time budget | the full plan is several weeks | MVP (D6); the thesis does not depend on it; the negative result of `docs/THESIS_CLAIMS.md` L2 stands without it |
| Safety | load generators can be pointed anywhere | scope lock in every generator and in the wrapper of 8.4; only namespace addresses; no external targets |
| External binaries (supply chain) | third-party code runs on the testbed host: unprivileged for the verification, as root inside the namespaces later | pinned versions and commit; sha256 against the checksum file and GitHub's digest; PGP where offered (the key ships in the same release: consistency, not independent authenticity); dedicated directory, never on `PATH`; scope-locking wrapper; manifest committed |
| wrk2 does not build or run here | its default branch ends in 2019; OpenSSL 3.5 and GCC 15 are newer than anything it was tested with | **Realised 2026-10-22:** it builds but panics in Lua at the start of every run. Recorded as "unavailable", not patched or retried; vegeta and k6 remain, so the plan loses one cross-check and one efficient C driver, not the design |
| Tools measure latency differently | wrk2 reports intended-time latency; vegeta and k6 time from the actual send, which equals the intended time only while their worker pools keep up | V3-V5 measure each tool against the origin's ground truth; the thesis states which metric of which tool each number uses |
| A second `wrk` on `PATH` would change the suite | the suite calls `wrk` | wrk2 is installed as `wrk2` in its own directory; `/usr/bin/wrk` is checksummed before and after |

## 14. Effect on claims and existing artifacts

No published campaign, analysis or verdict is edited. New work is new campaigns and new derived
files; corrections, if any, go in the errata of `results/README.md`. `docs/THESIS_CLAIMS.md` gains,
per scenario, one of: *harm demonstrated at level X (Gate A pass)*, *no measurable harm (Gate A
fail): label-detection only*, or *not producible on this topology*. Claim by claim:

| Claim (`docs/THESIS_CLAIMS.md`) | Today | What this plan adds |
|---|---|---|
| M1 rules ban all 10 attack types, XDP enforces the bans | Supported with scope | nothing changes: it is about bans, not harm; the gate says for which scenarios a ban matters |
| M2 XDP outperforms iptables | Partly supported | CPU numbers carry the veth caveat; the transferability probe (7.3) says whether a CPU advantage can be measured here at all |
| M3 daemon preserves availability under an HTTP flood | Supported with scope (EXP-A) | restated at open-loop offered load (EXP-C), and as HRR with collateral on the calibrated origin |
| M4 rate limiting alone is harmful | Supported with scope | EXP-C tests HYP-5; the claim narrows to closed-loop generators if it does not survive open-loop load |
| M6 time to mitigate | Supported as bounds | degraded seconds and recovery time add how long the harm lasts |
| M7 slow attacks are mitigated | Not supported | becomes a measured statement: no harm at the suite's socket counts, or harm at level X and its HRR (HYP-4) |
| L1, L2 the GRU adds value | Contradicted / not supported | learned-model evaluations draw only from scenarios that pass Gate A (and, for a niche claim, Gate B; D12) |
| L4 collateral-versus-evasion dilemma | Partly supported | with a harm measure, "evasion that harms" is separable from "evasion that does nothing" |

The P5d plan on the branch `design/l7-sequence-benchmark` is independent of this one and would
need Gate A as a prerequisite (REPORT 11.8).

## 15. Decisions needed from you

| # | Decision | Recommendation |
|---|---|---|
| D1 | Harm definition: SLO table (6.1); floor 10 pp or p95 x 2; 10 blocks; 95 % interval excluding 0 and 80 % same-sign share (10) | Accept. 10 pp is what 10 blocks detect at the EXP-A spread; a 5 pp floor would need 34 blocks per gate (about three times the HG3 time). The pilot SD re-derives the floor before any confirmation data |
| D2 | Nominal legit load at 50 % of the SLO capacity (6.1) | Accept; vary to 40 / 60 % only if a verdict is borderline |
| D3 | Server profiles: `bench-testbed` only, or also `bench-stock` (60-s timeouts) and a SYN arm (cookies off, small backlog) as sensitivity | `bench-testbed` first; add the other two in HG3 if time allows (about 1.5 h each) |
| D4 | Open-loop generator: in-repo asyncio, or install `wrk2` / `vegeta` / `k6` (needs network, a compiler for `wrk2`, and your approval); a one-off cross-check install? | **Decided 2026-10-22: both.** In-repo asyncio is primary; external tools are installed, pinned and verified (8.4, Appendix E). Stage 1 done: vegeta and k6 installed and smoke-tested; wrk2 unavailable on this OS (E.3), no retry |
| D5 | Population size: 200+ benign, 8+ attacker instantiations per family; reduced to 120 / 40 if the VM cannot hold it | Accept, with the reduction rule |
| D6 | First wave: cheap-route L7 flood, costly-route family (C3/C4), L3/L4 transferability probe + one packet flood. Second wave: slow connections, credential stuffing, pulsing and low-rate variants | Accept |
| D7 | Where code lives: new modules in `bench/` (it holds two component micro-benchmarks today, run as scripts) and `eval/harm_gate.py`, or a new package `harm/` | `bench/` + `eval/`; `ml/` stays for the L7 model track |
| D8 | Second VM or physical NIC for L3/L4 | Out of scope; revisit only if the probe says CPU harm is not producible here |
| D9 | How a gate FAIL appears in the thesis: labelled "label-detection only", or dropped | Report it, labelled |
| D10 | VM budget ceiling: minimum viable version about 18 h; two L7 families + EXP-C about 13 h; EXP-C + one costly-route family about 7 h (each includes 0.75 h for the load tools) | Stage it: tools and EXP-C first, then HG2 for the costly-route family, look at the result, then decide. Each session is approved separately anyway; the ceiling is for planning |
| D11 | EXP-C: first, on the legacy origin (comparable with EXP-A), with a closed-loop arm in the same campaign (120 runs, about 3.5 h); or reuse EXP-A as the closed-loop reference (90 runs, about 2.7 h, comparing across days); or wait for the calibrated origin | First option |
| D12 | Gate B (harm that remains under the deterministic daemon): reported here as the daemon's HRR in HG4, with the ML admissibility rule left to the ML track; or implemented now as a second gate with its own floor | Report HRR; decide the ML rule when the ML track resumes |
| D13 | Two changes to pre-registered verification criteria after the first run: A1 (the V4 control judged by its arrivals in the stall) and A2 (V3 latency judged from the actual send for every tool) | **Adopted 2026-10-22**, labelled post hoc wherever they appear; the first run keeps its original verdicts (Appendix F.4) |

## Appendix A: worked example with illustrative numbers

Cost per class (ms CPU, illustrative): C0 0.05, C1 3, C2 2, C3 30, C4 60, C5 150, C6 3. The legit
mix of 6.1 gives a mean cost of about 8.3 ms. Server on 2 pinned CPUs: 2.0 CPU-s/s of capacity;
suppose the capacity probe finds `C_slo` at about 180 requests/s (1.5 CPU-s/s, 75 % of the CPUs).
`rho` = 50 % of `C_slo` = 90 requests/s, a legit cost rate of 0.74 CPU-s/s, so `S` = (180 - 90)
x 8.3 ms is about 0.75 CPU-s/s.

| Attacked class | Cost | Total rate that consumes `S` | One source alone, against the per-source thresholds (30 r/s `limit_req`, 50 rps L7 rule) |
|---|---|---|---|
| C0 static | 0.05 ms | 15,000 /s | far above |
| C1 page | 3 ms | 250 /s | above |
| C2 API read | 2 ms | 375 /s | above |
| C3 search | 30 ms | 25 /s | below |
| C4 login | 60 ms | 12.5 /s | below |
| C5 export | 150 ms | 5 /s | below |

The point is structural, not a recipe: with a flat cost every row would sit at the top, and the
benchmark could not contain a harmful low-rate class; with realistic asymmetry it can, and then the
question the thesis asks (does a learned detector add anything the rules lack?) has a testable
subject. The numbers above are placeholders; HG2 replaces them with measurements, and the
sensitivity arms show how far the conclusion depends on them. With N sources the per-source rate is
the total divided by N; `--plan` prints, per class, the N at which a source falls below each
threshold.

## Appendix B: scenario specification and `--plan`

A scenario is a declarative record (YAML or JSON; the format is an implementation choice) with the
fields below. Nothing in it describes how a client avoids a detector; a source's behaviour is a
rate, a route mix and a schedule.

| Field | Meaning |
|---|---|
| `id`, `family`, `class` | name; family (flood, scraper, credential abuse, slow connection, packet flood, benign); class A-G of REPORT 11.2 where it applies |
| `grounding` | the external reference that motivates the class (admissibility condition 1); `assumed` if none |
| `resource` | the resource it is meant to saturate (7.1) |
| `routes` | route classes and their weights (5.2) |
| `intensity` | unit (cost rate, packets/s, held connections), the ladder, the level used |
| `sources` | number of sources and how the intensity is split; identity classes drawn from the population |
| `arrival` | process: constant, Poisson, on/off pulses, ramp; open- or closed-loop (8) |
| `netem` | the shared distribution (9.1) |
| `timeline` | baseline, attack and recovery durations |
| `seed_namespace` | `calib`, `train`, `val` or `test` |
| `gate` | SLO table, floor, number of blocks, which metrics (10) |
| `controls` | the control and the placebo it is paired with |

`--plan` (offline, no root, no traffic) prints for every scenario: the entity-to-seed mapping; per
class the expected request rate, the expected cost rate and the utilisation implied by the frozen
calibration; per source the rate and connection count against each deployed threshold (30 r/s
`limit_req`, 50 rps L7 rule, SlowConn, volumetric); the generator load (expected CPU, descriptors);
the expected gate outcome from the cost-rate model (likely PASS, likely FAIL, cannot say); and a
warning when the planned intensity exceeds the generator ceiling. Thresholds are printed, never
used to pick an intensity.

## Appendix C: unit tests to write in HG1a and HG1b (all offline)

* **load generator** (HG1a): seeded schedules identical across runs; intended-time latency on a
  fake server with a scripted stall; validity flags (slip, drops, cap); scope lock refuses a target
  outside the testbed subnet; keep-alive pool caps; timeout and error classification; the per-bot
  rate setting leaves the default command line of the HTTP flood unchanged (golden command).
* **external tools** (HG1a): command construction per tool for a given schedule (golden command
  lines); scope-lock refusal for a non-testbed target; manifest schema and hash check; parsers for
  each tool's report against canned samples; the V-test analysis on synthetic outputs, including the
  pass and fail sides of the analytic V4 value (2.6 s).
* **origin**: byte-identical responses and identical work counts for a repeated `(route, seed)`;
  cost knobs monotone; route table complete; start-up self-check fails on a fake clock that is
  30 % off.
* **population**: determinism per seed namespace; no seed shared by `calib`, `train`, `val` and
  `test`; counts and class mix; one netem distribution for all classes (distribution test); alias
  plan has no address collision.
* **harm gate**: synthetic blocks for PASS, FAIL and INVALID; the floor, the interval and the sign
  share at their boundaries; re-run rule for invalid blocks; the placebo; HRR defined only after a
  PASS; time-resolved metrics from synthetic bins.
* **calibration**: the knee rule on monotone, noisy and never-passing ladders; freeze-file schema
  and hash; drift check pass and fail.
* **harness**: `--plan` golden output (expected utilisation, cost rates, per-source rates against
  thresholds, expected gate class) for each scenario.

## Appendix D: references [verify before citing]

OWASP API Security Top 10 (2023), API4 Unrestricted Resource Consumption; OWASP Automated Threats
to Web Applications, OAT-008; Mirkovic and Reiher, "A taxonomy of DDoS attack and DDoS defense
mechanisms", ACM CCR 2004; Mirkovic et al., user-centric metrics for denial-of-service measurement
(percentage of failed transactions against per-application QoS thresholds), ExpCS 2007; Schroeder,
Wierman and Harchol-Balter, "Open versus closed: a cautionary tale", NSDI 2006; Tene, "How NOT to
measure latency" (talk) and the `wrk2` documentation on coordinated omission; Apdex Alliance,
Technical Specification 1.1; Dean and Barroso, "The Tail at Scale", CACM 2013; Barford and
Crovella, "Generating representative web workloads for network and server performance evaluation"
(SURGE), SIGMETRICS 1998; Jain, *The Art of Computer Systems Performance Analysis* (1991), on
blocking and replication; Ranjan et al., DDoS-Shield (INFOCOM 2006); the READMEs of wrk2 (`-R`,
corrected latency) and vegeta (constant rate, coordinated omission), and the k6 documentation of
the arrival-rate executors.

## Appendix E: installing and verifying the external load tools (D4)

Two stages. Stage 1 needed your go on the exact commands below and wrote no repository code; it was
run on 2026-10-22 (outcome in E.3). Stage 2 is part of HG1a and needs the design approved, because
it is code.

### E.1 Stage 1: provision, check integrity, smoke-test (planned 0.5 h; took about 3 min)

Pins found on 2026-10-22 from the GitHub API and the repository pages. The VM recomputes every
hash; any mismatch stops the procedure.

| Tool | Pin | Asset | Lookup sha256 (prefix) | Integrity evidence |
|---|---|---|---|---|
| vegeta | v12.13.0 (2025-10-31) | `vegeta_12.13.0_linux_amd64.tar.gz` | e8759ce45c14... | checksum file, GitHub digest, PGP signature of the checksum file |
| k6 | v2.3.0 (2026-09-21) | `k6-v2.3.0-linux-amd64.tar.gz` | 39c3117b6af8... | checksum file, GitHub digest (no signature is published) |
| wrk2 (unavailable, E.3) | `44a94c17d8e6a0bac8559b53da76848e430cb7a7` (master, 2019-09-24) | source by `git clone` | - | commit hash |

Commands, run one block at a time and stopped at the first failure. `$T` is a scratch directory
outside the repository (the session scratchpad), `$L` the tools directory.

```bash
T=<scratch directory>; L=/home/artur/loadtools

# 0. preflight: baseline of the existing wrk, package list, two HEAD requests
uptime
command -v wrk && sha256sum /usr/bin/wrk | tee $T/wrk.sha256
dpkg-query -W -f='${Package} ${Version}\n' | sort > $T/pkgs.before
curl -sSI --max-time 20 https://github.com | head -1
curl -sSI --max-time 20 https://api.github.com | head -1

# 1. system packages (root, network): 24 new, 0 upgraded, 0 removed (apt simulation, 2026-10-22)
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
  apt-get install -y --no-install-recommends gcc make libssl-dev zlib1g-dev
dpkg-query -W -f='${Package} ${Version}\n' | sort > $T/pkgs.after
diff $T/pkgs.before $T/pkgs.after > $T/pkgs.diff      # the exact list to remove again

# 2. vegeta (unprivileged; own directory)
mkdir -p $L/vegeta-12.13.0 && cd $L/vegeta-12.13.0
B=https://github.com/tsenart/vegeta/releases/download/v12.13.0
for f in vegeta_12.13.0_linux_amd64.tar.gz vegeta_12.13.0_checksums.txt \
         vegeta_12.13.0_checksums.txt.asc vegeta_12.13.0_pubkey.asc; do
  curl -fsSLO --proto '=https' --proto-redir '=https' --max-time 300 "$B/$f"; done
grep -F ' vegeta_12.13.0_linux_amd64.tar.gz' vegeta_12.13.0_checksums.txt | sha256sum -c -
curl -fsS --max-time 30 https://api.github.com/repos/tsenart/vegeta/releases/tags/v12.13.0 > release.json
python3 -I -c 'import json,hashlib,sys; n="vegeta_12.13.0_linux_amd64.tar.gz"; h=hashlib.sha256(open(n,"rb").read()).hexdigest(); a=[x for x in json.load(open("release.json"))["assets"] if x["name"]==n][0]; print(h, a.get("digest")); sys.exit(0 if a.get("digest")=="sha256:"+h else 1)'
export GNUPGHOME=$(mktemp -d)                         # throwaway keyring; ~/.gnupg is not touched
gpg --batch --import vegeta_12.13.0_pubkey.asc
gpg --batch --verify vegeta_12.13.0_checksums.txt.asc vegeta_12.13.0_checksums.txt
gpg --batch --fingerprint                             # recorded in the manifest
tar -tzf vegeta_12.13.0_linux_amd64.tar.gz            # member names first
tar -xzf vegeta_12.13.0_linux_amd64.tar.gz vegeta
./vegeta -version

# 3. k6 (unprivileged; own directory)
mkdir -p $L/k6-2.3.0 && cd $L/k6-2.3.0
B=https://github.com/grafana/k6/releases/download/v2.3.0
for f in k6-v2.3.0-linux-amd64.tar.gz k6-v2.3.0-checksums.txt; do
  curl -fsSLO --proto '=https' --proto-redir '=https' --max-time 300 "$B/$f"; done
grep -F ' k6-v2.3.0-linux-amd64.tar.gz' k6-v2.3.0-checksums.txt | sha256sum -c -
curl -fsS --max-time 30 https://api.github.com/repos/grafana/k6/releases/tags/v2.3.0 > release.json
python3 -I -c 'import json,hashlib,sys; n="k6-v2.3.0-linux-amd64.tar.gz"; h=hashlib.sha256(open(n,"rb").read()).hexdigest(); a=[x for x in json.load(open("release.json"))["assets"] if x["name"]==n][0]; print(h, a.get("digest")); sys.exit(0 if a.get("digest")=="sha256:"+h else 1)'
tar -tzf k6-v2.3.0-linux-amd64.tar.gz                 # member names first
tar -xzf k6-v2.3.0-linux-amd64.tar.gz --strip-components=1 k6-v2.3.0-linux-amd64/k6
./k6 version

# 4. wrk2 (builds as the unprivileged user; installed as "wrk2", never on PATH)
mkdir -p $L/wrk2-44a94c1 && cd $L/wrk2-44a94c1
git clone --quiet https://github.com/giltene/wrk2.git src
git -C src checkout --quiet --detach 44a94c17d8e6a0bac8559b53da76848e430cb7a7
test "$(git -C src rev-parse HEAD)" = 44a94c17d8e6a0bac8559b53da76848e430cb7a7 && echo pinned-commit-ok
ls src/deps/luajit | head -3                          # LuaJIT sources must be present
{ gcc --version | head -1; make --version | head -1; openssl version; } > build.env
make -C src -j4 > build.log 2>&1; echo "make exit code: $?"
sha256sum build.log > build.log.sha256
cp src/wrk wrk2 && ./wrk2 2>&1 | head -3

# 5. nothing else changed
sha256sum -c $T/wrk.sha256 && command -v wrk          # /usr/bin/wrk unchanged
```

Smoke test (V1), loopback only: a throwaway user-level Nginx on `127.0.0.1:18081` returning a fixed
body, plus its `stub_status` counter as the origin-side request count. Each tool sends 100
requests/s for 10 s, pinned to CPUs 4-7; the origin's count must be within 2 % of 1,000 and the
tool must report no errors.

```bash
S=$T/smoke; mkdir -p $S
cat > $S/nginx.conf <<EOF
worker_processes 1;
pid $S/nginx.pid;
error_log $S/error.log;
events { worker_connections 4096; }
http {
  access_log off;
  client_body_temp_path $S/t1; proxy_temp_path $S/t2; fastcgi_temp_path $S/t3;
  uwsgi_temp_path $S/t4; scgi_temp_path $S/t5;
  server {
    listen 127.0.0.1:18081;
    location = /status { stub_status; }
    location / { return 200 "ok\n"; }
  }
}
EOF
nginx -p $S -c $S/nginx.conf -e $S/error.log
n() { curl -s http://127.0.0.1:18081/status | awk 'NR==3{print $3}'; }   # requests seen by the origin

b=$(n); taskset -c 4-7 $L/wrk2-44a94c1/wrk2 -t2 -c10 -d10s -R100 --latency http://127.0.0.1:18081/; a=$(n); echo "origin saw $((a-b-1))"
b=$(n); echo 'GET http://127.0.0.1:18081/' | taskset -c 4-7 $L/vegeta-12.13.0/vegeta attack -rate=100 -duration=10s | $L/vegeta-12.13.0/vegeta report; a=$(n); echo "origin saw $((a-b-1))"
cat > $S/smoke.js <<'EOF'
import http from 'k6/http';
export const options = { scenarios: { s: { executor: 'constant-arrival-rate', rate: 100,
  timeUnit: '1s', duration: '10s', preAllocatedVUs: 10, maxVUs: 50 } } };
export default function () { http.get('http://127.0.0.1:18081/'); }
EOF
b=$(n); taskset -c 4-7 $L/k6-2.3.0/k6 run --quiet $S/smoke.js; a=$(n); echo "origin saw $((a-b-1))"
nginx -p $S -c $S/nginx.conf -e $S/error.log -s stop
```

**Side effects.** Root is used for the two `apt-get` commands only. They add 24 packages (the
`gcc-15` toolchain, `make`, `libssl-dev`, `zlib1g-dev` and their dependencies; the exact list is
`$T/pkgs.diff` and goes into the manifest); nothing is upgraded or removed. Outbound HTTPS goes to
`github.com`, `api.github.com`, the release-asset hosts and the Ubuntu mirrors.
`/home/artur/loadtools/` grew by 133 MB (estimate: 250 MB). Loopback traffic lasted about a minute
in total. Not touched: namespaces, the bridge, XDP, iptables, sysctl, the suite, any tracked file
of the repository; `/usr/bin/wrk` is checksummed before and after.

**To undo.** `rm -rf /home/artur/loadtools`; `sudo apt-get remove --purge` with the package names
in `$T/pkgs.diff` (not `autoremove`, which could take other packages with it). After Stage 1 the
same list is in `/home/artur/loadtools/stage1-record/pkgs.diff` and in apt's own log.

**Failure handling.** A failed download, checksum, signature or commit check stops the procedure and
is reported; nothing is retried silently. A wrk2 build failure keeps `build.log`, gets one retry
with documented `CFLAGS` additions (no source patches), and is otherwise recorded as "wrk2
unavailable on this OS"; vegeta and k6 are unaffected.

### E.2 Stage 2: the verification harness (HG1a, code)

Written (branch `feat/loadtools-harness`, three commits): `bench/loadtools.py` (wrapper, scope
lock, manifest `bench/loadtools.json`, readers), `bench/loadtool_validate.py` and `bench/loadgen.py`.
The harness starts S1 (a user-level Nginx on 127.0.0.1:18081, CPUs 0-1) and S2 (the scripted
origin on 127.0.0.1:18083, CPUs 2-3), runs V1-V7 of 8.4 for `vegeta`, `k6`, the engine and `wrk`
(the negative control of V4 only) on CPUs 4-7, parses each tool's own report, compares it with the
origin's ground truth, and writes a campaign-like directory (README, `results.json`, one directory
per job, `SHA256SUMS`). The matrix is 58 jobs and 18 minutes of load; `plan` prints every command
and starts nothing; `run` needs `--yes`. The readers for vegeta, k6 and wrk were written from the
tools' documented formats and are checked against real output by the first session. The first
session is proposed in two steps: V1 alone (3 jobs), then the full matrix.
(This paragraph is the text from before the first run; what happened and what was corrected
afterwards is in Appendix F.)

### E.3 Stage 1 outcome (run 2026-10-22, 07:46-07:50 on the VM clock, about 3 minutes of machine time)

Run with your approval, commands as in E.1 with these additions: logs redirected to files, an
`nginx -t` config test before the origin started, and a `trap` that stops the origin. The smoke
block did not abort when wrk2 failed, so the vegeta and k6 smoke runs also took place (both are in
the approved block). One slip: gpg had started a `gpg-agent` for the throwaway keyring, which I did
not notice until afterwards; I stopped it with `gpgconf --kill` and deleted that temporary keyring.
No agent or tool process is left running.

| Step | Result |
|---|---|
| Baseline | `/usr/bin/wrk` (Ubuntu 4.1.0) sha256 `f6536e3f9479584fa2b4a97d12c56671487be9f1011f309dc7a3b1bb0f6ea06c`; unchanged afterwards |
| apt | 24 packages added (57.4 MB download, 192 MB on disk), none upgraded or removed; `gcc` 15.2.0, `make` 4.4.1; list kept in `stage1-record/pkgs.diff` |
| vegeta v12.13.0 | sha256 `e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61` equals the checksum file and GitHub's digest; PGP signature of the checksum file good (signer "Vegeta CI", ed25519 key `9D94 22EC BBE6 237A 4EC6 D3BC D0B7 33D0 7608 C86C`, created 2023-07-11); binary reports v12.13.0, commit `507c4f02`, go1.22.12 |
| k6 v2.3.0 | sha256 `39c3117b6af817592dcd0ce4242105c0a7af10948c2a425306f0be8f7a8a8ab1` equals the checksum file and GitHub's digest; binary reports v2.3.0 (`e088784614`, go1.26.8) |
| wrk2 `44a94c1` | commit verified, tree clean, LuaJIT 2.0.3 sources present; `make` exit 0, 338 log lines, 49 lines mentioning warnings (largest groups: `_BSD_SOURCE` deprecation, format, misleading indentation), 0 errors; `-R` and `-L` present |
| Smoke, vegeta | origin counted 1,000 of 1,000; status 200 for all; latency p50 1.05 ms, p99 13.1 ms, max 28.7 ms |
| Smoke, k6 | origin counted 1,001; 0 failed; 100.08 requests/s; median 0.83 ms, p95 2.4 ms |
| Smoke, wrk2 | **failed**: exit 1, origin counted 0, output `PANIC: unprotected error in call to Lua API (attempt to index a nil value)` |

**Notes.**

1. The vegeta key expired on 2026-07-10; the signature is dated 2025-10-31, while the key was valid,
   so GnuPG reports a good signature by an expired key. As planned, the key ships in the same
   release, so this shows consistency, not independent authenticity.
2. wrk2 prints its usage and then dies when a run starts, before sending anything. Its source
   ignores the result of loading its own Lua module (`src/script.c`, line 51), so a failure there
   surfaces as this panic. The bundled LuaJIT (2.0.3, 2014) built with GCC 15 is the suspect; this
   was not tested. Decision (2026-10-22): record wrk2 as unavailable on this OS and do not retry.
   Its directory and build log stay as evidence; the manifest lists it as `unavailable`.
3. The evidence is kept in `/home/artur/loadtools/stage1-record/` (apt logs, package lists, the
   Nginx configuration and k6 script used, the three tools' smoke outputs). It is not yet in the
   manifest or in `results/`.
4. k6 sends an anonymous usage report each time it runs unless `--no-usage-report` (or
   `K6_NO_USAGE_REPORT`) is set. The Stage 1 smoke run did not set it, so one report was very likely
   sent (the VM has outbound HTTPS). According to k6's documentation it holds an installation ID,
   the k6 version, VU, duration and iteration settings, OS and architecture, the imported modules
   and outputs, and the build origin; no target address and no script content. This side effect was
   not in the approved list and I had not foreseen it. The wrapper of 8.4 always passes the flag.

## Appendix F: verification sessions of the load generators (HG1a)

Added 2026-10-22, after the first verification run. Tags as at the top.

### F.1 What was run

Both sessions were approved separately, on loopback, without root, with the commands that `plan`
prints (E.2).

* **Session A**: V1 alone, 3 jobs, 41 s. All three tools passed.
* **Session B**: the full matrix, 58 jobs, 18 min of load, 12:32:21-12:52:48 UTC, commit `210399c`
  (clean tree). It started after the gate (uptime 1808 s, 1-minute load 0.03) and ended with exit
  code 0, no infrastructure error and no process left over; `/usr/bin/wrk` is unchanged. The real
  output of vegeta, k6 and the engine parsed with the readers written from the documented formats.
* Output is in `/var/tmp/loadtool_validation/` (the approved `/var/tmp/ddos_campaigns` is owned by
  root). It is published as a *pilot* on `feat/loadtools-harness` (`455a6f0`):
  `results/2026-10-22_loadtool-validation-pilot/`, with a `NOTES.md` that says which of its
  verdicts not to use.

### F.2 What the first full run showed

Verdicts as computed by criteria version 1 (the table of 8.4):

| Tool | V1 | V2 | V3 | V4 | V5 | V6 | V7 |
|---|---|---|---|---|---|---|---|
| vegeta v12.13.0 | pass | pass (9/9) | fail (p99) | pass | fail | pass | held 2k, collapsed from 5k |
| k6 v2.3.0 | pass | fail (7/9) | pass | fail | pass | pass | held 2k, drops from 5k |
| in-repo engine | pass | pass (9/9) | fail (p50, p99) | pass | pass | pass | schedule held to 10k |
| wrk 4.1.0 (control) | - | - | - | control NOT as expected | - | - | - |

**These verdicts are not used.** The run exposed six faults in the harness and protocol, mixed into
them (details and numbers in the pilot's `NOTES.md`):

1. **Generic settings.** Every tool ran with 100 VUs or an idle pool of 100, whatever the test. k6
   under-delivered in 2 of 9 V2 runs (it reported `dropped_iterations` equal to the shortfall) and
   sent 621 of the 1,500 requests due during the stall [FACT]; a pre-allocated pool too small for a
   late wake-up is the likely cause [INFERENCE].
2. **V7 counted totals, not schedule adherence.** The engine delivered all 200,000 requests of the
   20,000/s step but only 16,000/s on schedule, finishing 2.3 s late, and the README called
   20,000 held [FACT]. Its schedule was exact to 10,000/s.
3. **No socket monitoring.** vegeta at 5,000/s sent bursts then nothing for 7 s with 1,780 timeouts
   and mostly system CPU time (13.8 s against 2.4 s of user time), and at 10,000 and 20,000/s only
   about 370 requests/s reached the origin [FACT]; connection churn and ephemeral-port exhaustion
   are suspected and not shown [INFERENCE].
4. **CPU per 1,000 requests included the steps after the load** (vegeta `report` and `encode`, the
   engine's summary), so it was an upper bound.
5. **The negative control was not one.** wrk 4.1.0 held its 50 connections and sent nothing during
   the stall (0 arrivals), yet reported p99 2.61 s against an analytic 2.6075 s [FACT]; its latency
   statistics appear to be corrected for coordinated omission after the run [INFERENCE].
6. **V3 did not tell apart latency from the intended time from latency from the actual send.** The
   engine's latency from the actual send agreed with the origin's own within 0.4 ms (p50) and 0.5 ms
   (p99); the 1.8 and 5.0 ms by which its reported figures exceed them are its schedule slip, which
   intended-time accounting includes on purpose [FACT].

Also [FACT]: k6 reports every request it fails to start; vegeta stops starting requests silently
once its `-max-workers` are busy (V5: 20,289 of 40,000 missing, nothing reported).

### F.3 What was corrected (offline; nothing run)

| Fault | Correction | Commit |
|---|---|---|
| 1 settings | `limits_for`: workers (vegeta workers, k6 pre-allocated VUs) = rate x 0.3 s between 100 and 2,000, for the stall test rate x (3 s + 0.2 s) = 1,600; 5,000 in flight at most for every tool; idle pool = workers; wrk keeps 50 connections; `plan` and `run` build the same spec and `job.json` records it. k6's kill timeout grows by 50 ms per VU (a margin, not a measurement) | `03186f4`, `58412df` |
| 2 V7 | the S1 origin reads its request counter once a second; `schedule_adherence` = share of rate x duration that arrived in its own part of the schedule (the schedule starts where the first stretch with arrivals puts it; per stretch at most rate x the part inside the schedule counts); a third V7 check, >= 0.99 | `8288401` |
| 3 sockets | a job starts only with fewer than 5,000 sockets in TIME_WAIT (a sixth of the 28,232 ephemeral ports; waits up to 90 s and says so); TIME_WAIT is recorded at start and end; "cannot assign requested address" is named in the notes | `03186f4` |
| 4 CPU | the wrapper records the CPU of every step; the cost is that of the load step (the engine: its own figure); cores used are reported | `03186f4` |
| 5 control | A1 | `cf4a1d3` |
| 6 V3 | A2 | `cf4a1d3` |
| (new) environment | `run` waits up to 30 min for the gate of 7.2 (up 30 min, 1-minute load below 0.3) or refuses; the timer probe also runs pinned to each CPU set in use, before and after (F.5) | `03186f4`, `59e873e` |

Tests: 648 pass, ruff is clean. Several unit tests that assumed this VM wakes a sleeping thread
within a second were rewritten to assert invariants or to skip when the machine stalled (F.5).

### F.4 Criteria version 2, and what it changes

* **A1 (post hoc, V4).** The closed-loop control is judged by the requests that reach the origin
  during the stall (at most 10 % of rate x stall = 150), not by its reported p99, which stays in
  the README marked "not counted". Reason: the pilot's wrk sent nothing during the stall and still
  reported 2.61 s.
* **A2 (post hoc, V3).** Latency is judged from the actual send for every tool. A tool that also
  reports it from the intended time (the engine) is judged on both: the figure from the actual send
  within the V3 tolerance of the origin's; the figure from the intended time at most the slip limit
  (50 ms, 8.3) above it, the difference being the schedule slip. vegeta and k6 report from the
  actual send and are judged as before.
* **C1 (not post hoc, V7).** Schedule adherence, the design's own criterion, which the first run did
  not apply. Jobs that recorded no readings are not judged on it.

Mechanics: `CRITERIA_VERSION` and `AMENDMENTS` are written to `results.json` and to a "Criteria"
section of the README; every check carries `counts` and `post_hoc`, and the README prints the
label next to each affected check. `reanalyse DIR` keeps the version DIR was judged by (1 when it
records none), so published verdicts cannot change under it; judging by another version needs
`--rejudge-into NEW`, which copies the job files, never overwrites, and records what changed.
**Effect on the pilot** [FACT; a scratch copy re-judged by version 2, the published directory
untouched]: exactly two verdicts change, the engine's V3 from fail to pass and the wrk V4 control
from "NOT as expected" to "ok". Every other verdict is unchanged; V7 cannot be re-judged because the
pilot recorded no readings. The first run keeps its original verdicts.

### F.5 The VM's timer noise, per vCPU (2026-10-22, about 13:30 UTC)

Passive probes (a process sleeping and timing its wake-ups, pinned with `taskset`, no traffic) [FACT]:

* 8 probes at once, 50 ms sleeps, 30 s: vCPUs 0-5 and 7 p50 25.5-30.7 ms, p99 102.8-113.6 ms, max
  112-305 ms; **vCPU 6: p50 1.4 ms, p99 6.1 ms, max 7.6 ms**.
* 2 probes (vCPU 5 and 6), 45 s: vCPU 5 p50 66.4 ms, p99 250.1 ms, max 395.8 ms, 87 sleeps over
  100 ms (57 of them in the last 18 s); vCPU 6 p50 1.9 ms, none over 100 ms.
* one probe at a time, 10 ms sleeps, 3 s: p50 0.5-3.7 ms, p99 6.9-39.4 ms, max up to 79.8 ms; the
  four CPU sets of the harness (0-1, 2-3, 4-7, 4) p99 14-38 ms.
* the harness's own unpinned probe (200 x 10 ms) at the same time: p50 4.2-5.1 ms, p99 9.7-12.5 ms.
* inside one unit-test run a `sleep(1.4)` returned after 2.95 s, and a step that begins with a
  `sleep(0.5)` took 2.4 s.
* steal time 0, 1-minute load 0.3-0.4, clocksource `tsc`.

Reading [INFERENCE]: the lateness belongs to the vCPU, grows with the time it sat idle and with how
many vCPUs idle together, and is not a VM-wide freeze; its cause (timer delivery to halted vCPUs) is
not diagnosed. Consequences: (a) V3's tolerance, the larger of 1 ms and 10 %, is below this noise
for any tool that sleeps between sends or between arrivals, so a V3 failure says as much about the
VM as about the tool (the pilot's vegeta p99 +7 ms may be this); (b) V7 at 1,000-2,000/s leaves
the tool idle between sends, so a late wake-up becomes a burst, which the one-second stretches
tolerate when it is short and charge when it is long; (c) time-to-mitigate figures taken on this VM
carry the same jitter. Since 59e873e the run records the probe for every CPU set it uses, before and
after, and its README is to be read with them. Mitigations **not taken**, because each changes what
is measured and is your call: a lowest-priority busy loop on every vCPU (keeps them out of halt,
raises the load average, shares SMT and caches with the tool), the engine's `--spin-ms`, or moving
the tool to vCPU 6.

### F.6 The corrected run, as proposed and approved (made 2026-10-22; outcome in F.7)

Two sessions, each on loopback, without root, from the worktree `audit-must-do-2-5`
(`feat/loadtools-harness` at `58412df`, clean):

```bash
# 0. offline, starts nothing: the 58 jobs with their commands and limits
./venv/bin/python bench/loadtool_validate.py plan

# C1: V1 alone (3 jobs, 30 s of load; about 2 min including the gate and the timer probes)
timeout -s INT 600 ./venv/bin/python bench/loadtool_validate.py run --yes --tests V1 \
    --gate-wait 30 --out /var/tmp/loadtool_validation/20261022_loadtool-validation-c1

# C2: the full matrix, only if C1 shows no infrastructure error and all three tools' results parse
timeout -s INT 3600 ./venv/bin/python bench/loadtool_validate.py run --yes \
    --gate-wait 30 --out /var/tmp/loadtool_validation/20261022_loadtool-validation-c2
```

* **Duration.** C2 is 58 jobs and 18.2 min of load. The first run took 20.5 min wall. Added: the
  timer probes (about 0.5 min), k6's start of up to 2,000 VUs (not measured), and waits for TIME_WAIT
  to fall below 5,000 after jobs with large pools (at most 90 s each). Expect about 25 min, at most
  about 45; plus up to 30 min of waiting for the gate if the VM is not idle at the start (the run
  refuses after that).
* **Side effects.** Processes on 127.0.0.1 only: a user-level Nginx (port 18081, CPUs 0-1), the
  scripted origin (port 18083, CPUs 2-3), vegeta, k6, the engine and wrk (CPUs 4-7, V7 on CPU 4),
  all stopped by the harness; up to about 5,000 sockets in TIME_WAIT and up to 5,000 connections
  and as many goroutines or VUs at a time (the first run reached 4,637 VUs without trouble); the
  1-minute load average rises well above the gate's 0.3 and takes minutes to fall; output of about
  7-10 MB under `/var/tmp/loadtool_validation/` (raw tool output is dropped). No root, no packages, no sysctl, XDP, iptables or namespaces, no
  external traffic (proxy variables are stripped; k6 runs with `--no-usage-report`). Afterwards I
  check for leftover processes and listening ports and that `/usr/bin/wrk` and the tool binaries
  are unchanged. Nothing else is run on the VM during C2, including my unit tests; please do the
  same.
* **Stop rules.** Stop and report on an infrastructure error or a leftover process; a tool that
  fails a job is a result, not a stop. If the timer probe after the run is far worse than before,
  the session is reported as suspect, not re-run silently.
* **What I expect (a guess, not a criterion).** V1 and V2 pass for all three; V4 passes for the three
  subjects and the control; V5 shows vegeta's silent cap again; V3 is the least predictable (F.5):
  vegeta fails again if the lateness is on the client, the others depend on the moment; V7 holds
  to 10,000/s for the engine (at about 90 % of a core, above the 70 % validity limit), and to
  2,000-5,000/s for vegeta and k6, with k6's cost including the start of its VUs. If V3 fails for
  every tool that does not spin, that is a finding about the VM, and whether to rebase V3's tolerance
  on the measured noise would be a third, separate, post hoc decision for you.
* **After the run.** Publish C2 as `results/2026-10-22_loadtool-validation-run2` with a `NOTES.md`
  (the pilot stays); then, and only then, edit the manifest statuses by hand.

### F.7 Outcome of the corrected run (2026-10-22)

Approved as written in F.6 ("C1, then C2 if C1 shows no infrastructure error and all three tools'
results parse"). **C1**: 13:55:33-13:56:40 UTC, 3 jobs, all pass, not published. **C2**: 13:57:12-14:24:11
UTC (27 min against the 25 expected), 58 jobs, exit code 0, after the gate (uptime 6900 s, load 0.24);
no infrastructure error, no process or listening port left over, `/usr/bin/wrk` and every tool binary
unchanged. Published on `feat/loadtools-harness` (`6d5ee97`) as `results/2026-10-22_loadtool-validation-run2/`
with a `NOTES.md`; the pilot is marked superseded in the index.

Verdicts by criteria version 2:

| Tool | V1 | V2 | V3 | V4 | V5 | V6 | V7: highest rate held on one core |
|---|---|---|---|---|---|---|---|
| vegeta v12.13.0 | pass | pass (9/9) | fail | pass | fail | pass | 2,000 |
| k6 v2.3.0 | pass | pass (9/9) | pass | pass | pass | pass | 2,000 |
| in-repo engine | pass | pass (9/9) | pass (A2) | pass | pass | pass | 10,000 |
| wrk 4.1.0 (control) | - | - | - | control ok (A1) | - | - | - |

What the run showed [FACT unless tagged]:

1. **The settings fix did what it was meant to.** k6's two pilot failures are gone (V2 9/9; V4 1,496 of
   1,500 arrivals in the stall, p99 2.625 s against 2.6075 s) with 300-1,600 pre-allocated VUs instead of
   100 [INFERENCE that this was the cause: the timer noise also differs between runs]. k6 starts 2,000 VUs
   in at most 1.6 s, so the 50 ms-per-VU timeout margin was far larger than needed.
2. **A1 and A2 behave as intended on corrected-harness data.** The engine's latency from the actual
   send is within 0.5 ms of the origin's own; from the intended time it is 3.0 / 18.7 ms (p50 / p99)
   above, which is its schedule slip (2.1 / 20.6 ms). wrk sent 0 requests into the stall and reported
   p99 3.0 s.
3. **vegeta is silent under overload (V5: 20,307 of 40,000 missing, nothing reported) and loses the
   schedule above 5,000/s on one core** (27 % of the 10,000/s step, 66 % of the 20,000/s step).
   TIME_WAIT grew by 9.8 k and 14.4 k during the 5,000 and 10,000/s jobs, so it opens thousands of
   connections a second despite an idle pool as large as its workers; no error was reported, so port
   exhaustion is still not shown.
4. **V3 is noise-dominated.** The origin's own p99 service time was 17.6, 25.4 and 152.6 ms in the three
   tools' jobs (maxima 241, 48 and 983 ms), so the tolerance (the larger of 1 ms and 10 %) was 1.8, 2.5 and
   15.3 ms, and vegeta's failure is in the job in which the origin itself stalled. With one repeat per tool
   V3 cannot tell a tool from this VM (F.5).
5. **The engine's slip gate (p99 above 50 ms) fired on this VM at rates from 100 to 10,000/s** (V1, two V2
   runs, V7 at 2,000, 5,000 and 10,000/s), 100/s included, where CPU is no limit; its `--spin-ms` was not
   used. At 10,000/s it also exceeds its CPU limit (0.95 of the core against 0.70).
6. **V7's adherence measure is strict at a start-up transient.** vegeta at 5,000/s delivered all 50,000
   requests (3,326, 4,435, 7,103, then about 5,000 a second); the registered measure gives 0.9538 and
   fails it. A view by lateness (within 1 s of the slot), computed offline and not part of any verdict,
   gives 100 % with a largest lag of 0.65 s and agrees with the registered verdict for every other V7 job.
7. **Timers.** Pinned 10 ms probes read p99 10-27 ms before and 13-15 ms after the run; the unpinned probe
   before the run caught a 0.86 s stall.
8. **Socket hygiene** worked as designed: seven jobs waited 34-62 s (366 s in total) for TIME_WAIT to fall
   below 5,000; none started above it.

**Decisions** (O1 was decided afterwards; nothing else below has been changed):

* **O1 (decided and applied 2026-10-22, `bdac0be` on `feat/loadtools-harness`)** The manifest statuses.
  k6 and the engine are `verified`, vegeta stays `smoke-tested` until V3 is repeated; the manifest has no
  "verified with restrictions" (statuses `unavailable`, `installed`, `smoke-tested`, `verified`, `unfit`;
  only `verified` is runnable), so restrictions go in `notes`. The notes of each tool cite the published
  run. A guard test requires a runnable tool to cite a published run in which V1 and V2 passed for exactly
  the sha256 pinned in the manifest, so editing `bench/loadgen.py` fails the suite until a new run is cited.
* **O2** V3. More repeats, or a tolerance that follows the noise measured in the same run: the second is
  a third post hoc change and yours to make.
* **O3** Whether the V7 adherence measure stays as registered (6.).
* **O4** Whether the engine runs with `--spin-ms` in the harm-gate benchmark, at the cost of a core per
  stream; and the V7 steps of 10 s, in which one stall of 70-90 ms flags p99.
* **O5** Merging `feat/loadtools-harness` (eleven commits since main) and `design/benchmark-harm`; EXP-C
  needs a per-bot rate and tool setting in `test_distributed_suite.py` and `eval/run_campaign.py`, not yet
  written.

### F.8 The V3 repeat session (2026-10-22)

Part of decision O2: V3 alone, three repeats per tool, all must pass, with an unscored warm-up job that I
added because both earlier vegeta V3 jobs were the first on the scripted origin's CPUs after ten idle
minutes (`--repeats 3 --warmup`, added in `d373c7d`). Run 15:11:51-15:17:35 UTC on loopback without root;
exit 0, nothing left over, binaries unchanged. Published as
`results/2026-10-22_loadtool-validation-v3-repeat/` (`8fcd0cf`) with a `NOTES.md`. The repetition and the
rule are post hoc and labelled so; the V3 checks are unchanged (criteria version 2).

| Tool | Scored jobs passing | p99 excess over the origin's own (ms) | V3 |
|---|---|---|---|
| vegeta | 0 of 3 (the warm-up fails too) | +16.3, +5.2, +8.7 (warm-up +12.7) | fail |
| k6 | 1 of 3 | +5.3, +5.9, +1.6 | fail |
| in-repo engine | 3 of 3 | +1.8, +0.9, +1.5 (from the actual send) | pass (A2) |

The tolerance was 1.7-2.8 ms (the larger of 1 ms and 10 % of the origin's p99); the p50 check passes in
every job (+0.5 to +0.7 ms). What it showed [FACT unless tagged]:

1. **The origin's own tail was calm**: p99 16.6-28.4 ms in all ten jobs, largest response 41-165 ms. The
   stalls of 578 and 983 ms in the two earlier vegeta jobs did not recur, so they cannot explain these
   failures.
2. **The warm-up did not differ from the scored vegeta jobs.** The first-job-after-idle explanation is
   neither shown nor ruled out: the CPUs were not idle for ten minutes before this session [INFERENCE].
3. **The Go tools' tails read 5-16 ms above the origin's on this VM**; the pinned timer probes on the tool
   CPUs read p99 12-16 ms, the same order, while the single-threaded engine is within 2 ms. The excess is
   probably on the tools' side [INFERENCE; the Go scheduler was not looked into].
4. k6's p99 excess over the five runs so far ranges from +0.5 to +5.9 ms against a tolerance of about 2 ms,
   so its two earlier passes were the lowest values.

By the rule of 8.4 (a generator that fails only V3-V6 is verified with restrictions), the engine is
unchanged, k6 would carry "no latency claims at millisecond precision", and vegeta "no latency or overload
claims". Nothing enforces notes, and an overload experiment driven by vegeta would silently lose offered
load (V5), so my recommendation is: k6 stays `verified` with the restriction in its notes; vegeta stays
`smoke-tested` with the repeat recorded in its notes, since k6 and the engine already drive open-loop load.

* **O1b** The statuses of k6 and vegeta after the repeat (above). Notes only, if you agree; no status changes.
* **O2b** V3's tolerance: leave it, so that only the engine can make millisecond-level latency claims on this
  VM, or let it follow the noise measured in the same session, which would be a third post hoc change.

# Design plan: a benchmark in which attacks cause measurable harm

**Status (2026-10-21): draft for your review. Design only: no production code, no VM workload.**
Nothing described here exists yet. The usual protocol applies: feature branch, static analysis
first, approval of the design before code, approval of every VM workload with its duration and side
effects, one concern per commit gated on `unittest` + ruff, you merge and push.

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
4. **Order.** The open-loop engine and EXP-C come first: EXP-C needs no new origin, answers G-13 on
   its own, and the engine is needed by everything else (section 12).
5. **Cost.** 12-17 working days of code (7-9 for the minimum version) and about 17 VM hours in
   sessions you approve one by one (6.5 h for the smallest useful cut).
6. **Limits, stated up front.** The cost model is a design choice, so conclusions are conditional
   on it and tested against it (x0.5 / x2); L3/L4 harm may be unproducible on veth;
   slow-connection harm needs a regime far above today's socket counts (6.4); nothing here is
   built to make a learned model win.
7. **What I need.** Decisions D1-D12 (section 15). The three that move cost most: D6 (first-wave
   scope), D4 (generator) and D11 (EXP-C first, on the legacy origin).

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
   lock of `ml/l7_gen.py` (it refuses a target outside the testbed subnet).

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
   0.3, governor and steal time recorded.
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

### 8.4 Implementation options

| Option | For | Against |
|---|---|---|
| **In-repo asyncio generator** (stdlib; **recommended**) | nothing to install; reviewable; scope lock and seeds built in; one engine for legit and attack load | must be validated; a Python event loop holds roughly a few thousand requests/s per core, enough for the ladders above |
| `wrk2` (constant throughput, built-in correction) | the reference implementation of the correction | not installed; the VM has no compiler; needs network access and approval |
| `vegeta` / `k6` | static binaries | not installed; download and trust |
| `aiohttp` / `httpx` | less client code | pip install (network, approval); extra dependency |

Validation without the VM: a fake server with known service times and a scripted stall, to show
that the reported latencies reproduce the known distribution and the stall (the correction), and
that validity flags fire when the schedule cannot be kept. The generator's own ceiling (requests/s
per core) is measured once on loopback (HG1a) and must exceed the highest planned rate with margin.
Optional cross-check, if you approve one installation (D4): the same schedule through `wrk2` or
`vegeta` on the VM, comparing the latency quantiles.

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

**What it needs.** The open-loop engine (HG1a) and a per-bot rate setting in the HTTP-flood
scenario (default unchanged). It does not need the calibrated origin, the populations or the gate:
the flood is the one EXP-A already showed to be harmful at this operating point, which is why it
can run first.

**Cost.** 120 runs (3 modes x 4 load models x 10 blocks) at EXP-A's 93 s per run is about 3.2 h,
plus the probe. The report's version, with no closed-loop arm in the same campaign, is 90 runs;
reusing EXP-A as the closed-loop reference would save 30 runs at the price of comparing across two
campaigns on different days (D11).

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
| **HG1a** open-loop engine | schedules, intended-time latency, validity flags, scope lock, per-request and 1-s records, fake-server validation; a per-bot rate setting for the HTTP flood (default unchanged) | `bench/loadgen.py`, a setting in `test_distributed_suite.py` and `eval/run_campaign.py`, tests | 4-6 days | loopback ceiling test, 15 min | tests and ruff green; ceiling above the highest planned rate |
| **EXP-C** | section 8.5 | a campaign | S | about 3.5 h | HYP-5 and HYP-6 reported |
| **HG1b** offline build | cost-calibrated origin; populations and seed namespaces; scenario specification and `--plan`; harm-gate analysis (time-resolved metrics, placebo, HRR); calibration runner and freeze file | `bench/origin.py`, `bench/population.py`, `bench/calibrate.py`, `eval/harm_gate.py`, tests | 8-11 days | none | tests and ruff green; golden `--plan` files |
| **HG2** calibration | steps 0-5 of 7.2: gates, origin check, capacity, transferability probe, ladders, freeze | `bench/calibration/*.json`, campaigns | - | about 3 h in 1-2 sessions | frozen file committed |
| **HG3** harm gate | confirmation of every candidate (7.2 step 6), sensitivity arm | campaigns, `harm_gate.md` | S | about 5-6.5 h in 2 sessions | verdicts published |
| **HG4** mitigation benchmark | admitted scenarios x (control + 4 modes) | campaigns | S-M | about 4 h | HRR, collateral, degraded seconds |
| **HG5** analysis and text | `docs/THESIS_CLAIMS.md`, errata, derived tables | docs, `results/..._derived` | S | none | numbers regenerate from `results/` |

Code effort is 12-17 working days in full (HG1a + HG1b) and 7-9 for the minimum viable version.
Mapping to the audit's phases (REPORT 11.7): G0 (seed namespaces, same netem, rate conformance)
is 9.1 and 8.3 here; G1 (backend and harm gate) is HG1b-HG3; G2 (entities, scenario language, open
loop) is HG1a, section 9 and Appendix B.

### 12.2 VM time, derived

A new-harness run is assumed to take 2.5 min (30 s baseline, 45 s attack, 30 s recovery, about 45 s
of set-up and tear-down); EXP-C uses the existing harness at EXP-A's measured 93 s per run (62 min
for 40 runs). Both are recomputed from the first real run.

| Step | Runs | Min/run | Hours |
|---|---|---|---|
| EXP-C: capacity probe + 3 modes x 4 load models x 10 blocks | 1 + 120 | 1.6 | 0.25 + 3.2 |
| Generator ceiling on loopback | - | - | 0.25 |
| HG2: environment gate, origin check, capacity probe, transferability probe | - | - | 0.7 |
| HG2: screening, 3 families x (7 levels x 2 repeats + 4 controls) | 54 | 2.5 | 2.25 |
| HG3: confirmation, 3 families x 10 blocks x (control, placebo, attack) | 90 | 2.5 | 3.75 |
| HG3: second-level confirmation for one family whose first level failed (contingency) | 30 | 2.5 | 1.25 |
| HG3: sensitivity arm, costly-route family at cost x0.5 (probe + 10 blocks x 3 runs) | 30 | 2.5 | 1.5 |
| HG4: 2 admitted L7 scenarios x (control + 4 modes) x 10 blocks | 100 | 2.5 | 4.2 |
| **Minimum viable version** | | | **about 17 h** (16 h without the contingency) |

Smaller cuts (D10): the two L7 families through HG2-HG4 plus EXP-C, with no L3/L4 family and no
sensitivity arm, is about 12.5 h; EXP-C plus one costly-route family through HG2-HG3 is about
6.5 h. Not included: the `bench-stock` and SYN-cookie arms (about 1.5 h each, D3), re-runs of
invalid blocks (at most 6 runs per gate), the optional `wrk2` / `vegeta` cross-check, and the
second-wave families.

### 12.3 Approvals and side effects

Each VM session is proposed separately with its exact command, duration and side effects, as for
EXP-A and EXP-B: root; namespaces, Nginx, the origin and generators started and stopped; XDP
programs attached and removed; traffic inside the testbed only; results written under
`/var/tmp/ddos_campaigns` and published afterwards (`docs/EVALUATION.md`, "Side effects of a
suite run"). HG1a and HG1b run nothing on the VM except offline unit tests; the loopback ceiling
test needs neither root nor namespaces.

## 13. Validity threats and risks

| Threat | Why it matters | Mitigation |
|---|---|---|
| The cost model *creates* the niche for low-rate harm [RISK] | a backend built so that cheap requests can hurt makes any rule-evading story easy | classes anchored to external grounding; ratios, not tuning; sensitivity at x0.5 / x2; controls where rules win and hard negatives that use expensive routes; conclusions stated as conditional (principle 4) |
| Goodhart: tuning the gate until a scenario passes | an admitted scenario would mean nothing | frozen floor and SLOs; stopping rules (7.5); all candidates and the placebo reported |
| Generator is the bottleneck | harm would be measured on the client, not the server | validity rules (8.3); CPU pinning; server-side count check |
| Host drift, cold start | the run of 2026-10-20 started 3 minutes after a restart; its HTTP-flood time to mitigate was 1.08 s against 0.55-0.69 s warm, and warm-up could not be separated from phase | environment gate and drift check (7.2); boot time in provenance |
| Veth charges the receive work to the sender | L3/L4 CPU harm and XDP-vs-iptables CPU may not transfer | transferability probe; the limit stated; second VM as future work |
| The unprotected stack is already hardened | slow-connection and SYN harm may be invisible | `bench-stock` and SYN sensitivity arms (D3); a FAIL is reported as such |
| Switching the legit measurement tool | latencies are not comparable with campaigns that used `curl` | new campaigns are labelled; old ones are not re-analysed with the new tool |
| Calibration overfits one host state | thresholds drift | calibration dated and hashed; drift check; recalibrate when the check fails |
| Time budget | the full plan is several weeks | MVP (D6); the thesis does not depend on it; the negative result of `docs/THESIS_CLAIMS.md` L2 stands without it |
| Safety | load generators can be pointed anywhere | scope lock in every generator; only namespace addresses; no external targets |

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
| D4 | Open-loop generator: in-repo asyncio, or install `wrk2` / `vegeta` / `k6` (needs network, a compiler for `wrk2`, and your approval); a one-off cross-check install? | In-repo. Cross-check optional, only with your explicit approval |
| D5 | Population size: 200+ benign, 8+ attacker instantiations per family; reduced to 120 / 40 if the VM cannot hold it | Accept, with the reduction rule |
| D6 | First wave: cheap-route L7 flood, costly-route family (C3/C4), L3/L4 transferability probe + one packet flood. Second wave: slow connections, credential stuffing, pulsing and low-rate variants | Accept |
| D7 | Where code lives: new modules in `bench/` (it holds two component micro-benchmarks today, run as scripts) and `eval/harm_gate.py`, or a new package `harm/` | `bench/` + `eval/`; `ml/` stays for the L7 model track |
| D8 | Second VM or physical NIC for L3/L4 | Out of scope; revisit only if the probe says CPU harm is not producible here |
| D9 | How a gate FAIL appears in the thesis: labelled "label-detection only", or dropped | Report it, labelled |
| D10 | VM budget ceiling: minimum viable version about 17 h; two L7 families + EXP-C about 12.5 h; EXP-C + one costly-route family about 6.5 h | Stage it: EXP-C first, then HG2 for the costly-route family, look at the result, then decide. Each session is approved separately anyway; the ceiling is for planning |
| D11 | EXP-C: first, on the legacy origin (comparable with EXP-A), with a closed-loop arm in the same campaign (120 runs, about 3.5 h); or reuse EXP-A as the closed-loop reference (90 runs, about 2.7 h, comparing across days); or wait for the calibrated origin | First option |
| D12 | Gate B (harm that remains under the deterministic daemon): reported here as the daemon's HRR in HG4, with the ML admissibility rule left to the ML track; or implemented now as a second gate with its own floor | Report HRR; decide the ML rule when the ML track resumes |

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
blocking and replication; Ranjan et al., DDoS-Shield (INFOCOM 2006).

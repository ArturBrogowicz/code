# HG1c: the executor, the gate campaign and the calibration runner (design note, written before the code)

**Status (2026-10-26): approved (D18 to D26 as recommended, including option (b) and A1) and built offline on `feat/hg1c`; the VM
has run S1 and S1b (no root, loopback), S2 (root, in namespaces) and S3 twice (root; the first stopped at the Nginx start, the second ran to the end and was found unsound) and nothing else.
Section 14 records what was built, what S1, S1b, S2 and S3 found and what came of it, and where it departs from this note, which is otherwise left as it was written (2026-10-23).** This note is on `design/hg1c`, off `feat/hg1b-minimal` (7528089); it changed no code. It is the follow-up that `docs/HG1B_MINIMAL_DESIGN.md`
promised in its section 7 (decision D16): the part that runs a scenario in the namespaces and writes the run contract that
`eval/harm_gate.py` reads; the loop that makes blocks of three runs under the re-run rule; and the runner that measures and freezes
the calibration. "design N" is a section of `docs/BENCHMARK_HARM_DESIGN.md` (branch `design/benchmark-harm`), "HG1b N" a section of
the note above. Tags: **[FACT]** read from a file or a command (`path:line` at 7528089); **[ARITHMETIC]**; **[ESTIMATE]**;
**[INFERENCE]**; **[PROPOSAL]** a value or rule fixed here and frozen before the data it will judge; **[RISK]**; **[UNVERIFIED]** not
checked yet, with the step that will check it.

## 1. What I ask you to decide, and what I found

**One finding blocks the gate as built, and it belongs to HG1b, not to HG1c** (section 4.1). The suite gives its clients tc-netem
links of 20 to 300 ms and up to 5 % loss; the gate judges every legit request against a latency SLO of 100 to 3,000 ms and requires the
control to reach 99 %. A first-order estimate puts the control at **88 to 90 %** (Appendix A). Every block would be INVALID whatever
the attack does, and the capacity probe (design 7.2 step 2), which defines `C_slo` as the largest load with `Q` at or above 99 %,
would have nothing to find. The HG1b tests could not show it: their synthetic requests had no link delay. No Gate A data exist, so
the rule can still be corrected before any is taken; D19 is that correction. A smaller flaw of the same kind came out while reading the
code again: the control rule's per-class clause cannot fail (F6, section 4.2).

| # | Decision | Recommendation | Why, and what the alternative costs |
|---|---|---|---|
| D18 | Where the executor lives: **(a)** inside `test_distributed_suite.py`, driven by `eval/run_campaign.py`; **(b)** a separate runner that imports the suite's testbed primitives, as four existing tools do; **(b')** a separate runner with its own copy of them | **(b)** | The suite is the instrument of three published campaigns and 2,163 lines; (a) adds a second path through its `build_topology`, `_start_web_stack` and `main` and a conditional re-run that `run_campaign` cannot express (sections 3 and 5). (b) has four precedents. (b') is the fallback if you do not want the suite's import side effects |
| D19 | How a latency SLO is judged on links that already exceed it: **A1** Q and p95 over the clean links only (`perfect`, `broadband`, 76 % of the legit requests at seed 1), the mobile profiles reported per profile and not judged; A2 an allowance for the link; A3 no netem on the legit streams in Gate A; A4 larger SLOs | **A1** | A1 keeps the SLO table, the 99 % control rule and the one link distribution for every identity; it costs the mobile clients their vote (section 4.1) |
| D20 | Scope: L7 families only. The L3/L4 transferability probe and any packet flood become HG1d | accept | They need a packet generator inside the namespaces with its own scope lock and verification (design 7.3, D6) |
| D21 | Rebuild the whole topology for every run | yes | About 10 s of 150 s per run buys three runs of a block that start from the same state |
| D22 | Server stack: gunicorn 2 workers x 8 threads on 127.0.0.1:8080 with the ambient limits, recorded; Nginx = `nginx_unprotected.conf` with only its two log paths changed; both on CPUs 0-1 | accept | Section 6.4 |
| D23 | Align the streams' clocks with an estimator (exit time minus the engine's `wall_s`), no change to the engine | accept; S1 measures its error | A start barrier in the engine changes its pinned hash and needs the 27-minute verification again |
| D24 | Add `judged_profiles` and `drift_reference` to the calibration record, and `netem` and an `executor` block to `run.json`, in place (schema stays 1; no frozen record exists) | accept | Section 4.2, Appendix B |
| D25 | One unscored warm-up run before block 1 of every campaign | yes | The precedent of HG1a (`--warmup`); cold caches and CPU state |
| D26 | The first contact with the VM is a ladder of four small steps (S1-S4, about 0.5 h in all), each approved on its own with its exact command | accept | Section 10 |

## 2. Scope

| In | Out (named, not forgotten) |
|---|---|
| `bench/executor.py`: one run of a plan in the namespaces, ending in the run contract (HG1b 5.5) | Mitigated runs `M_<mode>` (HG4): the daemon, XDP, iptables and Nginx limits under the new workload |
| `bench/gate_campaign.py`: blocks of C, Cp, U in shuffled order, the re-run rule, resume | L3/L4 floods, the transferability probe, slow connections (HG1d and later) |
| `bench/calibrate.py`: HG2 steps 0-5 and the drift check (design 7.2) | POST routes, TLS, HTTP/2, the SYN and cookie arms |
| The contract changes of section 4 and their tests | A publisher for these campaigns (`eval/publish_campaign.py` knows the suite's layout) |
| An offline `--plan` for the executor and the calibrator; fakes for every command | The sensitivity arm (design 11) and Gate B |
| The first-contact ladder S1-S4 on the VM | HG2 and HG3 themselves: each gets its own approval with exact commands |

## 3. What exists (facts)

| Fact | Where |
|---|---|
| The suite reads its configuration from the environment **when it is imported** (`OPERATING_POINT`, `SERVER_CPUS`, `FLOOD_TOOL`, ...) | `test_distributed_suite.py:61-138` |
| Importing it registers `cleanup_all` with `atexit` and SIGINT/SIGTERM handlers; `cleanup_all` kills gunicorn, nginx, `control_plane.py`, hping3 and `_dist_` processes **system-wide by pattern**, deletes namespaces matching `server_ns`, `legit_`, `bot_`, the bridge and the veths `vo_legit_`, `vo_bot_`, `veth_srv_br` | `:454-456`, `:396-451` |
| `build_topology()` makes 20 legit and N bot namespaces with one address each and applies netem to the legit ones only; `main()` always starts curl-based legit workers and walks a fixed scenario registry | `:808-864`, `:2125`, `:2132-2151` |
| `_start_web_stack()` starts gunicorn on `dummy_app:app` and nginx; the app is not a parameter; `start_server_services()` rewrites `dummy_app.py` in the repository | `:613-621`, `:669-680` |
| `run()` returns `None` on a timeout and never raises on a non-zero exit; it pins only `bot_*` namespaces | `:365-383` |
| `apply_tc` shapes the **client's egress only**: perfect none; broadband 20 +/- 2 ms; mobile_3g 150 +/- 40 ms and 2 % loss; mobile_bad 300 +/- 80 ms, 5 % loss and 1 % corruption. The server side has no qdisc | `:555-579` |
| `create_client_ns` names the host-side veth `vo_` plus the first 12 characters of the namespace and derives the MAC from the primary address | `:524-526` |
| `eval/run_campaign.py` plans every run up front, runs one suite process per run, resumes from `DONE` files, and checks leftovers against the namespaces `server_ns`, `legit_`, `bot_`, four process patterns and the names `wrk` and `k6` | `eval/run_campaign.py:142-158`, `:306-323`, `:296`, `:67-80` |
| **Four tools already import the suite as a library**: `capture_testbed_dataset.py:31`, `ml/capture_l7.py:384`, `ml/eval_l7.py:328`, `ml/smoke_l7.py:278`. `capture_l7` imports it after its root, venv and clean-tree checks, names its own namespaces `b_<ip>` and `a_<ip>`, writes its own cleanup ("`cleanup_all()` only knows `server_ns`/`legit_*`/`bot_*`, so without this every run leaked its clients"), renders its own Nginx configuration and starts its own gunicorn. A test pins the suite symbols a runner uses | `ml/capture_l7.py:143-164`, `:283-311`; `tests/test_suite_harness.py:32-38` |
| The engine's schedule starts 50 ms after its loop starts; neither its records nor its summary carry an absolute time, only `wall_s` | `bench/loadgen.py:322`, `:345`, `:370-412` |
| The wrapper builds the engine command; `run_plan` runs it synchronously; the suite launches the same argv with `Popen` and wraps it in `prlimit` | `bench/loadtools.py:460-489`, `:541-585`; `test_distributed_suite.py:1337-1360` |
| The HG1a harness has the environment gate (`wait_for_gate`), the timer probe pinned per CPU set (`timer_lateness_by_cpus`) and the TIME_WAIT settle, all injectable | `bench/loadtool_validate.py:837`, `:1187`, `:884` |
| `harm_gate.run_metrics` judges one fixed window (the attack's); the calibration holds no reference value for the drift check, and `drift_ok` takes them from its caller | `eval/harm_gate.py:163`, `bench/calibration.py:225` |
| The suite's runs of EXP-C took a median of 97 s and a mean of 115 s each (86 to 423 s), with a 30 s attack and 30 namespaces | `results/2026-10-23_expc-open-vs-closed-loop/**/DONE`, 120 files |
| Nginx: `worker_processes auto`, `worker_connections 16384`, `keepalive_timeout 15s`, `proxy_pass http://127.0.0.1:8080` (a new upstream connection per request), the access log at an absolute host path | `nginx_unprotected.conf:1,4,63,87,24` |
| Host: 8 vCPUs, 9,426 MiB, Linux 7.0.0-38-generic, nginx 1.28.3, gunicorn 26.2.0, Python 3.14.4; no cpufreq governor file | `uname`, `free`, `nginx -v`, `gunicorn --version` |

## 4. Findings that change the HG1b contracts

### 4.1 F1: the links already exceed the SLOs (blocks the gate)

**Facts.** The legit streams run in namespaces that carry the suite's netem profiles (HG1b 5.3; `test_distributed_suite.py:555-579`).
The engine times a request from the actual send to the end of the response (HG1b 5.6, delta 6), so the request-path delay is in the
latency; a new connection pays it twice (SYN, then the request). The SLOs are C0 100 ms, C1 and C2 300 ms, C3 1 s, C5 3 s
(`bench/calibration/placeholder.json`); the control is healthy only if `Q(C)` is at least 99 % and every class's p95 is within its SLO
(`eval/harm_gate.py:255`).

**Arithmetic** (Appendix A, seed 1, placeholder numbers; the model is first order and its assumptions are in the script):

| | perfect | broadband | mobile_3g | mobile_bad |
|---|---|---|---|---|
| Share of the legit requests | 39.3 % | 37.0 % | 17.2 % | 6.5 % |
| Q of the control (connection reuse 70-100 %) | 100 % | 100 % | 59-68 % | 27-33 % |

* `Q(C)` over all links is **88.2 to 90.1 %**, against the 99 % the control rule asks. Even without loss and reuse effects, **8.1 % of
  all requests are C0 requests on a mobile link whose own delay draw is above 100 ms, so `Q(C)` cannot exceed 91.9 %**.
* The pooled p95 of the control's successes is **245 ms on all links and 53 ms on the clean links**, so a uniform slowdown of 100 ms
  moves the pooled `dL` by 0.5 instead of 1.5: the latency criterion is dominated by the links.
* Consequences: every block is INVALID by the control rule; `C_slo` is undefined; HG2 cannot start.

**Options.**

| | What it does | Keeps | Costs |
|---|---|---|---|
| **A1** | `Q`, p95, the per-class figures and the 1-s bins are taken over the streams of `judged_profiles` (default `perfect`, `broadband`); the other profiles get their own `Q` and p95 per profile in the report, not judged | the SLO table, the 99 % rule, the floor, one link distribution for every identity, attackers on all four profiles | 76 % of the legit requests vote; a harm that reaches only the mobile clients is reported, not gated |
| A2 | Success means `service - E[link delay] <= SLO` (the allowance is the profile's mean delay, twice on a new connection) | all clients vote | in the same model (Appendix A, two lines changed) the control lands at **98.7 to 99.1 %**, on the edge of the 99 % rule, so a block would be valid or not by the luck of its loss draws; and the gate then depends on a model of the link |
| A3 | No netem on the legit streams of Gate A | simplicity | Gate A's population stops being HG4's; it contradicts the approved single distribution (HG1b 5.3) |
| A4 | Larger SLOs (C0 at 500 ms or more) | all clients vote | the SLO stops meaning anything for the clients that can meet it, and the table was fixed before data for a reason |

**Recommendation: A1.** It is a rule change made before any Gate A datum exists, and it is stated here and again in the commit that
makes it. [PROPOSAL] The mobile profiles stay in the population, as load and as victims reported per profile; a study that needs them
judged (HG4, ML) chooses its own SLOs.

### 4.2 F2 to F6: smaller contract gaps

| # | Gap | Fix [PROPOSAL] |
|---|---|---|
| F2 | The record has no reference for the drift check (design 7.2 step 7 needs a `Q` and a p95 to reproduce), and no required `host` content | `drift_reference {rho_rps, q_pct, p95_s, attack {family: {level, q_pct, p95_s}}}`, required in a frozen record; `host` must carry the uname, CPU count, memory, the pin plan, the gunicorn and Nginx versions and settings, and the sha256 of `bench/origin.py`, `bench/loadgen.py` and the Nginx configuration |
| F3 | The engine does not say when it started; 29 legit processes pinned to one vCPU cannot be released together | An estimator, section 6.6, and validity limits on its output |
| F4 | `run_metrics` has one fixed window; the capacity probe needs `Q` over each of ten steps | `run_metrics(..., window=(lo, hi))`; the gate's definition of `Q` is then the probe's |
| F5 | Nothing the executor knows (a stream that started late, an attack that began off its mark, a failed readiness check) reaches the gate | `run.json` gets `executor {ok, reasons, t0_spread_legit_s, attack_start_error_s}`; `validity` treats `ok: false` as invalid, under both profiles |
| F6 | `control_health` checks each class's p95 **over its successes**, and a success is by definition within the SLO, so the clause fails only when a class has no success (`eval/harm_gate.py:255-266`); the design's "p95 within its class SLO" over all the class's requests means a per-class success share of at least 95 % (my test of it used a state `run_metrics` cannot produce) | the clause becomes `by_class[k].Q >= 95`, tested on `run_metrics` output |

### 4.3 Hazards found in the stack (checked at first contact, not assumed)

| Hazard | Why it matters | Where it is checked |
|---|---|---|
| gunicorn inherits the shell's `nofile` limit; here it is 524,288 (soft and hard) in a normal shell and under `sudo` [FACT: `ulimit -n`] | a `gthread` worker accepts up to 1,000 connections, so a limit of 1,024 would make the "knee" a descriptor artefact; at 524,288 it is not expected | nothing is set (a lower limit than the earlier campaigns had would change the system under test); S3 reads `/proc/<pid>/limits` of the gunicorn and Nginx processes and the limit goes into `environment.json`; the executor refuses to start below 16,384 |
| `worker_processes auto` under `taskset -c 0-1` | Nginx counts online CPUs, not the affinity mask, so 8 workers may share 2 CPUs [UNVERIFIED] | S3 records the worker count; the probe measures the capacity of whatever stack results |
| `proxy_pass` opens a new upstream connection per request | extra CPU and loopback ports at about 1,000 requests/s; it is the stack of every earlier campaign | recorded; not changed (the stack is the system under test) |
| netem on the client's egress only | replies are not delayed, so the mobile numbers understate a real mobile link | stated in the report; F1's arithmetic uses the same model |

## 5. Options (a) and (b)

### 5.1 What each means

**(a)** A new scenario type in `test_distributed_suite.py`, selected by settings (`SCENARIO_SPEC`, `CALIBRATION`, `RUN_KIND`,
`BLOCK_SEED`) and driven by `eval/run_campaign.py` with modes `C`, `Cp`, `U`. In the suite: a topology of four namespaces with
aliases beside `build_topology`; no curl legit workers (the suite starts 20 of them for every scenario); an origin backend selected in
`_start_web_stack`; per-stream pinning; a scenario function and a branch in `main()` that skips the daemon; the run-contract writer. In
the runner: new modes and variables (`EVAL_VARS`, `SETTABLE`), a block record, and the re-run decision, which needs the result of the
gate's `assess_block` between runs. Today `build_plan` fixes every run in advance (`run_campaign.py:142-158`).

**(b)** A new runner, as `ml/capture_l7.py` is. It imports the suite lazily, after its own checks, and uses a fixed list of its
primitives: `run`, `create_host_bridge`, `create_server_ns`, `create_client_ns`, `apply_tc`, and the constants `SERVER_NS`, `SERVER_IP`,
`HTTP_URL`, `SUBNET_MASK`, `BRIDGE_NAME`, `PYTHON_VENV`. Everything the benchmark adds is its own: aliases, stack, streams, timeline,
telemetry, cleanup, leftovers, run contract. A contract test pins the symbols, as `test_suite_harness.py:32-38` does for the capture.

**(b')** The same runner with those six primitives copied into `bench/testbed_hg.py` (about 80 lines) and a test that reads the suite's
source and checks that the netem parameters and the MAC rule agree.

### 5.2 Comparison

| Criterion | (a) in the suite | (b) imports the suite | (b') own copy |
|---|---|---|---|
| Change to the instrument of EXP-A, EXP-B and EXP-C | yes: a 2,163-line file whose default behaviour is pinned by published results | none | none |
| Reuse of the testbed code | all of it | the six primitives | none; a copy that can drift |
| Reuse of campaign tooling (resume, `DONE`, leftovers, ownership) | all of it, with a conditional re-run added | the helpers are importable (`leftovers`, `chown_tree`, `git`, `write_json` are plain functions) | same as (b) |
| Fit with the re-run rule | poor: needs a new planning mode | natural: the runner decides after each block | natural |
| Import-time side effects | none new | `atexit` cleanup with system-wide `pkill`, signal handlers, environment parsing; the four existing runners live with them; the executor clears the evaluation variables before importing | none |
| Failure handling | `run()` swallows failures; the suite's `main()` is a long script | the executor checks every command it issues; `run()` is used for the six primitives only | same |
| Cleanup and leftovers | the suite's patterns would have to learn `hg_*` (and so would `run_campaign.leftovers`) | own, as `capture_l7` does; refuses to start on leftovers | same |
| Offline testability | the suite is imported with its handlers patched out (`tests/test_suite_harness.py:23`) | a `Host` object is injected; the suite is touched only through it | same, without any import |
| Path to HG4 (mitigation modes under the new workload) | the modes already exist | the executor adds daemon start and ban events (about 40 lines) or HG4 migrates to (a) once the machinery is proven | same as (b) |
| Code, [ESTIMATE] | 400-600 lines changed in two files that others depend on, plus tests | executor about 500, campaign about 250, calibrator about 450, in new files | plus about 80 |
| Precedent in this repository | EXP-C added `FLOOD_TOOL` and `FLOOD_RATE` this way, to one scenario | four tools | none |

### 5.3 Recommendation

**(b)**, with these conditions: the suite is imported only after the preflight; the evaluation variables are removed from the
environment first (the list in `run_campaign.EVAL_VARS`); the executor does not use the suite's private helpers; its namespaces are
named `hg_<index>_<profile>` (the host-side veth is then `vo_hg_<index>_<profile>` cut at 12 characters, and the index keeps
`mobile_3g` and `mobile_bad` apart); and it never kills by pattern (section 6.8). If you do not want the suite's import-time
`pkill -9 -f gunicorn` to be possible at the end of a benchmark session, (b') removes it at the price of a copy. (a) is the right choice
only if the aim is to retire the suite's `legit_*` curl workers and run every future campaign on the new workload; that is HG4's
question, and (b) leaves it open.

## 6. The executor (`bench/executor.py`)

### 6.1 Interface

* **In:** a plan (a scenario record and a block's seed from `bench/scenario.py`, a calibration, the run kind `C`, `Cp` or `U`, a
  results directory) and a `Host`.
* **Out:** `<run>/run.json` and `<run>/streams/<id>/...` as in HG1b 5.5 with the additions of Appendix B, plus `plan.json` (the
  streams, the alias plan, the exact commands), `environment.json`, `executor.log`, `server.csv`, `server_requests.csv`, the rendered
  `nginx.conf` and the Nginx logs.
* **`Host`:** `run(argv, ns=None)` returning the exit code and output, `popen(argv, ns=None)`, `sleep`, `clock`, `read(path)`,
  `write(path, text)`. The real one
  delegates to the suite's `run` for the six primitives and to `subprocess` for the rest; the fake records the commands and answers
  queries (`ip -j addr show`, `ip netns pids`). Every test of the executor runs on the fake. This is the shape of HG1a's `RealEnv`.
* `python3 bench/executor.py --plan SPEC ...` prints the commands without root and without the suite, as `ml/capture_l7.py --plan` does.

### 6.2 Lifecycle of a run [ESTIMATE of times; S4 measured them: see the note below the table]

| Step | What | Time |
|---|---|---|
| 1 | Preflight: root, venv, clean tree (`--allow-dirty` is recorded), no leftovers (it refuses and reports; `--clean` runs the cleanup), the manifest says the engine is `verified` with the pinned hash, the scope lock accepts `http://10.0.0.1/` | 1 s |
| 2 | Environment: uptime and load (`wait_for_gate`), timer lateness p99 on CPU 6 (200 samples, below the calibration's `validity.timer_p99_ms`, 10 ms, or a smoke test's `--timer-limit-ms`: departure 19; judged; the other CPU sets once per campaign, recorded), steal, TIME_WAIT settle, `git` state | 4 s plus waiting |
| 3 | Topology: bridge, `server_ns`, the namespaces `hg_<i>_<profile>` with their aliases and netem; verification | 6 s |
| 4 | Stack: render `nginx.conf`, start gunicorn then Nginx in `server_ns`, wait for HTTP 200 and check `X-Route-Class` of each sample route | 12 s |
| 5 | Warm-up: two requests per route from `server_ns`; telemetry starts | 3 s |
| 6 | Timeline (T = 0 at the launch of the legit streams): legit streams T = 0 to 105 s; attack streams at T = 30 s for 45 s (only in `U`) | 105 s |
| 7 | Drain: the engine waits up to its timeout plus 2 s for requests in flight (`loadgen.py:339`) | 2-12 s |
| 8 | Collection: summaries, records, `nstat`, Nginx logs, the run contract; `executor.ok` computed | 3 s |
| 9 | Teardown: `ip netns pids` of every namespace, TERM then KILL, delete namespaces, veths, bridge; leftover check | 5 s |
| | **A run** | **about 140-150 s** (design 12.2 assumed 150 s) |

[FACT] S4 (2026-10-28, four runs of 105 s on the real stack) measured a run at 120.3 to 127.2 s from the start of the command to the end of the teardown (mean 123.6 s): preflight and gate 2.5 s, topology 5.4 to 10.3 s (200 and 300 addresses), the stack ready 1.9 to 4.5 s after Nginx started, the timeline 108.6 to 111.5 s from the launch (the 2.5 s start-up, the 105 s and the drain), collection 0.5 s, teardown 0.4 s. The estimates above were high for the stack (15 s against 1.9 to 4.5 s), the collection (3 s against 0.5 s) and the teardown (5 s against 0.4 s).

### 6.3 Topology

* Four client namespaces, one per link profile (`per_profile` in the scenario multiplies them), as `population.namespaces()` defines;
  the population's `client_<profile>_<j>` are labels, the executor's names are `hg_<index>_<profile>`.
* `S.create_client_ns(name, first_address)` creates the namespace, the veth pair and a unique MAC; the other addresses of the
  namespace's alias plan (`Population.alias_plan()`: 106, 102, 68 and 24 addresses at seed 1) follow in one `ip -batch` call, all
  `/16` as the suite's. `S.apply_tc(name, profile)` applies the same netem.
* **Verified, not trusted:** `S.run` swallows failures, so after the build the executor reads `ip -j addr show dev veth_in` of each
  namespace and compares the addresses with the plan, checks that every MAC is unique (the suite's own invariant, `:851-859`), and that
  `server_ns` answers from one alias per namespace. Any difference fails the run at step 3.
* **Per run, not per block (D21):** three runs of a block start from identical state, and a block's aliases change with its seed.
* Mutual exclusion with the suite and the ML runners comes from the leftover check: all of them share `server_ns` and `ddos_br0`.

### 6.4 Server stack [PROPOSAL, D22]

| Part | Setting | Reason |
|---|---|---|
| Origin | `gunicorn --chdir bench --workers 2 --threads 8 --bind 127.0.0.1:8080 origin:app`, with `ORIGIN_CALIBRATION` and `ORIGIN_SEED=1` in the environment | HG1b 7: 2 x 8 slots; bound to loopback so that nothing reaches the origin except through Nginx; each worker builds its own SQLite and, with a frozen calibration, runs the 25 % self-check before serving |
| Nginx | `nginx_unprotected.conf` rendered into the run directory, **only** `access_log` and `error_log` changed, the log files created with mode 0666 (the workers run as `nobody`); a test compares the rendering with the original and fails on any other difference; its sha256 goes into the record; it is started like the origin, a process of its own with no pipe for its daemon to hold (departure 20) | the stack of every earlier campaign; the log of each run is then its own (precedent: `ml/capture_l7.py:285-295`) |
| Pins | `taskset -c 0-1` for gunicorn and Nginx; the executor and its sampler on CPU 2; legit streams on 6; attack streams on 3-5,7 (`population.PIN_PLAN`, HG1b 4) | D14 |
| Daemon, XDP, iptables | none (Gate A is the unprotected stack) | design 10 |

### 6.5 Streams

* One engine process per stream of `Population.streams`, command from `bench/loadtools.build_plan("loadgen", to_load_spec(...))`
  (`taskset` first), run as `ip netns exec <ns> prlimit --nofile=<n> -- <argv>`, with the wrapper's clean environment. `<n>` is the
  figure the plan prints (2,394 for the largest legit stream and 5,216 for the largest attack stream of the search scenario).
* `Popen`, not `run_plan`: the streams run concurrently. Each stream has its own directory `streams/<id>/` holding the engine's
  `loadgen.summary.json`, `loadgen.records.csv.gz` and `loadgen.stderr`, and a small `provenance.json` (argv, pid, launch and exit
  times, return code). `run.json` names these paths, which the gate already reads.
* The legit streams are launched first, in one loop; the attack streams are launched by the executor at the time that puts their
  start at T = 30 s (section 6.6). A stream that exits before its duration, or with a non-zero code, fails the run.
* Attack streams exist only in `U` (and later `M_<mode>`); `C` and `Cp` are the same legit streams, the same seeds, the same
  schedules: the pairing is by common random numbers, as the HG1b tests assume.

### 6.6 Clock alignment and executor validity (F3)

**Problem.** The gate puts a request at `t_intended + offset_s` on the run's axis and judges the window `[baseline, baseline + attack)`
(HG1b 5.5). The engine's zero is 50 ms after its loop starts; there is no absolute time in its output. Twenty-nine processes on one
vCPU spend about 29 x 60 ms of CPU importing before their loops start [ESTIMATE; S1 measures it]; under fair sharing they finish
together, about 1.7 s after the launch, but nothing guarantees how closely.

**Estimator [PROPOSAL, D23].** For each stream, `t0 = t_exit - wall_s + 0.05 - delta`, where `t_exit` is the wall-clock time at which
the process was seen to exit (one watcher thread per process, so that no stream waits for another) and `delta` is the time between the
end of the run loop and the exit (summary, records, interpreter shutdown: 20 to 100 ms, nearly the same for every stream).
`offset_s` is then `t0 - median(t0 of the legit streams)`; `delta` cancels. The run's axis zero is the median legit `t0`.

**Executor validity [PROPOSAL; limits frozen after S1 and S4, before HG2].** `executor.ok` is false when the legit `t0` spread exceeds
0.5 s, when the attack streams' median `t0` is more than 0.5 s away from `baseline_s` on that axis, when a process died or did not
finish, or when readiness or the topology check failed. All of these are independent of what the attack does to the server.

**If ignored.** A 2 s offset error moves 2 s of a 45 s window, a dilution of about 4 % of the harm [ARITHMETIC]; the first degraded
second would be off by the same.

**Check.** S1 launches the 29 legit processes against the scripted origin of HG1a on loopback and compares the estimator with the
origin's own arrival log. If its error exceeds 0.1 s, the fallback is the engine change of D23's alternative.

### 6.7 Telemetry (recorded, not judged)

At 1 Hz from the executor's sampler thread (no subprocess; `/proc` reads): per-CPU busy and steal from `/proc/stat`; CPU of the
gunicorn and Nginx processes found with `ip netns pids server_ns`; TCP counters from `/proc/<pid>/net/netstat` of a process in the
namespace (`ListenOverflows`, `ListenDrops`) and `net/sockstat`; the load average. After the run, `server_requests.csv` from the Nginx
log by arrival second and client class, as the suite's `aggregate_access_log` does (the class by address prefix, `:1433`). The
**delivered-rate check is not a validity rule**: an overloaded server logs fewer requests than it was sent (the R50 probe logged 20 to
97 % of the nominal rate), so a rule on it would select the runs in which the attack failed.

### 6.8 Failure handling and cleanup

* **No pattern kills.** The runner tracks the pids it starts and kills the namespaces' contents with `ip netns pids <ns>`; it never
  calls `pkill -f` or `pgrep -f` on a word that its own command line can contain (the self-kill of 2026-10-22, `8235d39`). Tests pin
  that no argv of the executor, the campaign runner or the calibrator matches the suite's kill patterns or the leftover patterns.
* Anything raised after step 3 runs the teardown of step 9 in a `finally`, writes `FAILED` with the reason and stops the campaign: the
  rule for a leftover or an error is to stop and report.
* A failure **before the first stream starts** (steps 1-5) is retried in place up to twice and logged (`setup_retries`); it consumes
  no block re-run, because it is independent of any outcome, and the final run directory is a complete one. The files of an attempt that
  is retried are removed; those of the last failed attempt stay, because they say why it failed (departure 20). A failure after the first
  stream started makes the block attempt invalid and counts toward the gate's two re-runs. [PROPOSAL]
* `KeyboardInterrupt` and SIGTERM tear down and mark the campaign interrupted; the same command resumes (section 7). The executor
  registers its teardown with `atexit` after it has imported the suite, so that it runs before the suite's own `cleanup_all` (LIFO), and
  installs its own signal handlers after the import.

### 6.9 Provenance

`environment.json` and `campaign.json` record the commit, branch and dirty files; the sha256 of the scenario, the calibration, the
rendered Nginx configuration, `bench/origin.py`, `bench/loadgen.py`, `bench/loadtools.json` and the population plan; the versions of
Nginx, gunicorn and Python; `uname`, uptime, load, steal and the timer probe by CPU set; the pins and limits actually applied.

## 7. The gate campaign (`bench/gate_campaign.py`)

```
for block b = 1 .. blocks:                       seed = first_seed + b - 1
    attempt = 1
    repeat:
        order = shuffle(C, Cp, U) with Random(order_seed, b, attempt)
        for run in order: executor.run(plan(scenario, seed, run))   # DONE written after each run
        write block.json (scenario sha, calibration sha, plan sha of the legit streams, timeline, seed, attempt, order)
        a = harm_gate.assess_block(block dir, calibration)
        stop if a.valid, or attempt == 2, or the gate already used its max_reruns
        attempt += 1                              # same seed; a new order
```

* The legit streams of the three runs of a block must be identical: the campaign compares their plan hashes and refuses otherwise.
* The decision to re-run uses the gate's own `assess_block`, so the rule cannot be applied differently here and in the analysis;
  `harm_gate.analyse` re-checks the whole directory (`protocol_problems`) and still has the last word.
* Resume: a run with `DONE` is skipped, a partial one is removed and redone, and the order is recomputed from the seeds. The
  campaign refuses to resume with other settings, as `run_campaign.py:275-281` does.
* One unscored **warm-up** run (a `C` run at the first block's seed) precedes block 1 and is kept apart from the blocks (D25).
* `--simulate` runs the whole campaign on the fake host with the synthetic server model of the HG1b tests, and `harm_gate` then
  returns a verdict: this is the offline integration test.

## 8. The calibration runner (`bench/calibrate.py`)

Each subcommand that touches the VM is a separate approval. Everything it records is a campaign directory in the run contract, so any
number can be recomputed offline; `freeze` reads those directories and never touches the VM.

| Design 7.2 step | Subcommand | Definition [PROPOSAL] | Output |
|---|---|---|---|
| 0 environment gate | in every other subcommand | as 6.2 step 2; refuses to start; asks to wait | `environment.json` |
| 1 origin check | `origin` | `measure_unloaded` in three separate sessions on CPU 0, 21 repeats each, median of medians; a session spread over 10 % repeats the session once, then stops. Also, as a diagnostic, the server CPU per request through the whole stack (sequential requests, 200 per route), so that the stack's overhead against the in-process cost is known | `route_costs_ms`, `host.origin` |
| 2 capacity | `capacity` | legit only, `population.draw(rho = level)`; levels `50 x 1.3^k`, k = 0..9 (50 to 530 req/s); 20 s per level, `Q` over the last 15 s of the judged streams; 3 repeats. **`C_slo`** = the last level before the first level at which any repeat is below 99 %; **`C_sat`** = the lowest level at which at least two repeats are below 50 %. If the first level is already below 99 %, or no level reaches 50 %, stop (design 7.5) | `capacity`, `rho = 0.5 C_slo` |
| 3 screening | `ladder --family F` | the unprotected stack at `rho`; levels `S x {1/8 .. 8}`; 2 repeats of a `U` run per level; a `C` run after every fourth run, in a random order from a seed. A repeat's harm is normalised, `h = max(dQ / floor_pp, dL / floor_log2_p95)` against the mean of the session's controls, so that `calibration.knee(ladder, floor=1.0)` applies the either-or rule of design 10. The session is valid only if its controls are healthy and within 2 pp of each other | `ladder_<F>.json` |
| 4 knee | `freeze` | `calibration.knee`; none passing means "cannot harm this server within the generator limit" and nothing is tuned | `knees` |
| 5 freeze | `freeze --out bench/calibration/<host>-<date>.json` | assemble the record with the measured costs, capacity, knees, `drift_reference` (three 120 s legit probes at `rho` plus one run at each family's knee, medians) and `host`; `calibration.freeze` and `dump`; you commit it before any confirmation data | the frozen file |
| 6 confirmation | `gate_campaign` | HG3 | verdicts |
| 7 drift | `drift` | a 120 s legit probe at `rho` and one attack run at a family's knee; `calibration.drift_ok` against `drift_reference`; a failure is rerun once after the environment gate, twice stops (design 7.5) | `drift.json` |

Sources of the attack in the ladders are the scenario's (`sub_threshold`: 100, `cheap_static`: 5); the number of sources is a recorded
factor, not a ladder axis.

**Steps of the capacity probe are staged inside one run per repeat.** The processes of step k+1 are launched early by the start-up delay
the executor measures (each process's actual `t0` comes from the estimator of 6.6), and `Q` is taken over the middle of each step, from
5 s to 17 s, so that a start-up skew of up to 3 s on either side stays outside it. If S4 shows a larger skew, each step becomes its own
run (about 0.4 h more for the probe). **Ladder levels that the scenario plan flags** (the in-flight cap of the engine, the generator's
CPU limit) are not run, because a run whose validity would depend on the attack's effect is not a valid run: the ladder ends below them,
and "cannot harm this server within the generator limit" is then literal. For the cheap flood that is level 8 (8,837 requests in flight
against a cap of 5,000).

## 9. Offline build

Modules: `bench/executor.py`, `bench/gate_campaign.py`, `bench/calibrate.py`, and a shared `tests/synth_runs.py` made from the
synthetic server of `tests/test_harm_gate.py`. Each commit is one concern, gated on the whole suite and ruff, offline.

| # | Commit | Tests |
|---|---|---|
| 1 | **Contracts (F1-F6):** `judged_profiles`, `drift_reference` and the `host` keys in `bench/calibration.py` and the placeholder (rehashed); the control's per-class clause as a success share; the article in the plan's in-flight warning ("a attack stream"); `netem` and `executor` in the stream and run records; `harm_gate` judges the profiles and adds the per-profile figures, takes a window, reads `executor.ok`; `--block DIR` prints one block's assessment; the scenario plan prints the share of the legit requests that is judged and warns below half (its golden files change); HG1b 5.3/5.6 amended | the schema; Q and p95 over the judged streams only; the per-profile report; a window equals the attack window by default; `executor.ok: false` invalidates under both profiles; a control with one starved class and 99 % overall is unhealthy; the synthetic blocks get link delays so that the control is healthy only on the judged profiles |
| 2 | **Executor, plan:** `Host`, the topology, stack and stream commands as data, `--plan`, the rendered Nginx configuration | golden command lists; the rendering differs from the original in two lines only; the alias plan equals `Population.alias_plan()`; `nofile` and pins as the scenario plan prints; the veth names are unique |
| 3 | **Executor, run:** lifecycle on the fake host, the estimator, `executor.ok`, telemetry, collection, teardown | a failure injected at each step still tears down and leaves `FAILED`; no argv matches a kill or leftover pattern; the estimator recovers known offsets; the run contract is read by `harm_gate` |
| 4 | **Gate campaign:** blocks, order, the re-run rule through `assess_block`, resume, plan hashes, `--simulate` | the rule on synthetic outcomes (a failed block re-run once, a third failure not, two re-runs in all); a resumed campaign equals an uninterrupted one; the simulated campaign passes |
| 5 | **Calibrator:** capacity, ladders, knee, freeze, drift as pure functions over run directories, and the subcommands over the executor; a third scenario spec for the export family (`costly_export_sub_threshold`), since the ladders need one spec per family and two ship | a synthetic server with a known `C_slo` and knee is found; the stop rules; the normalised harm; `freeze` writes a record that `calibration.load` accepts; the new spec passes `scenario.py --check` and has a golden plan |
| 6 | **Docs:** `docs/EVALUATION.md`, the status of this note | |

Not tested offline, and said so: that any command does on the VM what the fake says; that the estimator is accurate; the real
per-run overhead; that Nginx and gunicorn behave as section 4.3 lists. Those are S1-S4.

## 10. First contact with the VM (S1-S4)

Each step is approved separately, with its exact command, which I give when I ask. Shapes and side effects:

| Step | What | Root | Time | Side effects | It answers |
|---|---|---|---|---|---|
| **S1** | 29 legit-rate engine processes pinned to CPU 6, each against its own instance of HG1a's scripted origin on loopback (`--allow-loopback`, the verification flag), 30 s; the estimator against each origin's first arrival | no | 5 min | 29 processes and 29 listeners on loopback; a temporary directory; nothing left over | the start-up spread, the estimator's error, memory and CPU per process, the limits of 6.6 |
| **S2** | Topology only for seed 1: bridge, `server_ns`, four namespaces, 300 aliases, netem; verification; one ping to `server_ns` from each namespace and from one alias each; teardown | yes | 3 min | namespaces, veths and the bridge created and deleted; ARP and ICMP inside the testbed | that 300 aliases are accepted, the time to build them, ARP behaviour, the leftover check |
| **S3** | The stack and a short legit-only run: origin under gunicorn, Nginx, readiness, `X-Route-Class` of each route, 30 s of the control's legit streams at 20 req/s; `harm_gate --block`; teardown | yes | 8 min | as a suite run without the daemon: gunicorn and Nginx in `server_ns`, traffic inside the testbed, results under `/var/tmp/ddos_campaigns` | the worker counts and limits of 4.3, `Q` per profile (F1 in practice), the run contract on real records |
| **S4** | One block (C, Cp, U) of `costly_search_sub_threshold` on the placeholder calibration, `--dry-run`, default timeline, with the warm-up run | yes | 12 min [measured: 8 min 16 s] | as S3, with the scenario's attack of 37 req/s in `U` | the real per-run time, the offset spread with 33 processes, delivered rates, memory, `assess_block` on real data (no verdict: a block is not a gate) |

Stop and report on an error, a leftover, a non-zero exit or a stream that did not start. After S4 I would bring the numbers, the changes
they imply (the limits of 6.6, the per-run time) and the HG2 plan (section 8) for the next approval. S1-S4 produce no result about the
testbed's harm; the calibration stays a placeholder until HG2.

## 11. Budget

| | Runs | Min per run | Hours |
|---|---|---|---|
| S1-S4 (HG1c's own VM time): 5 + 3 + 8 + 12 min | 4 full runs in S4, three shorter steps | 2.5 | 0.5 |
| HG2: origin 0.1 h; capacity 3 repeats of 10 steps (about 4.5 min each, 0.22 h); screening 3 families x 18 runs (2.25 h); the freeze's reference probes, 3 legit and 3 attack runs (0.3 h) | 63 | 2.5 | about 2.9 |
| HG3: 3 families x 10 blocks x 3 runs | 90 (+ at most 6 re-runs per gate) | 2.5 | 3.75 (+ 0.25 per gate) |
| Drift check before each later campaign | 2 | 2.5 | 0.1 |

[ESTIMATE] These agree with design 12.2 (2.25 h of screening, 3.75 h of confirmation); S4 replaces the 2.5 min with a measurement.
[FACT] S4 measured 123.6 s a run (120.3 to 127.2 s, set-up and teardown included), 2.06 min against the 2.5. [ARITHMETIC] At S4's timeline HG3's 90 runs are 3.1 h, not 3.75; the screening's 54 runs 1.85 h, not 2.25; a re-run of a block (three runs) 6.2 min, not 7.5.
Offline build: five code commits and a docs commit; the executor (commits 2 and 3) is the largest part and the contract change
(commit 1) the smallest.

## 12. Risks and limits

| Risk | Mitigation |
|---|---|
| F1 is the first of its kind: a rule that cannot be met was only found by arithmetic. Others like it may remain | S3 reports `Q` per profile on real records before anything is calibrated; the offline tests gain link delays |
| 29 processes on one vCPU may start unevenly | S1 measures it; the limits of 6.6 are frozen only after S1 and S4 |
| The suite's import-time cleanup kills gunicorn and Nginx system-wide when a benchmark session ends | as it does for the four existing runners; (b') removes it; stated before each root step |
| A campaign that stops on an error leaves a half block | `DONE` per run, resume removes and redoes a partial run, `FAILED` is kept |
| Interaction with other work on the VM | the environment gate (load, uptime) and the leftover check; no concurrent suite runs |
| The cost model is first order and the in-process costs omit the stack's own overhead (gunicorn, Nginx, the upstream connection), which is not yet measured | the ladders find the knee empirically; the diagnostic of step 1 measures the overhead |
| The population is assumed, not sourced; Gate A says nothing about detection | HG1b 8 and 9 stand |
| The mobile profiles are not judged under A1 | reported per profile; HG4 and ML choose their own SLOs |

## 13. What I need from you

Decisions D18 to D26 of section 1; above all D19, without which no gate can pass or fail. If you approve, I would build commits 1 to 6
of section 9 offline on a new branch `feat/hg1c` off `design/hg1c` (so that it carries this note and everything of `feat/hg1b-minimal`),
merge nothing, push nothing, and bring S1 for approval when the executor's plan prints.

## 14. As built (2026-10-24)

Built offline on `feat/hg1c`, off this note, in the order of section 9; no merge, no push. One commit was added to section 9's six
(the capacity probe needed the executor to launch streams at their own start), and two small ones followed. The VM ran S1, S1b, S2, S3 (with its repeats, a timer survey and a 2x2 with a stall monitor), the 15-run dissection of that monitor
and S4; six commits came out of the first three (the last rows of the table), one followed your decision on the timer gate
(departure 19), one came out of the first S3 (departure 20), one out of the second (departure 21) and two out of the replay of the
eight S3 runs (departures 22 and 23). The dissection and S4 changed no code.

| Commit | What | New tests | Textual mutations killed |
|---|---|---|---|
| 7681825 | contracts F1 to F6 (`judged_profiles`, `drift_reference`, the `host` shape, the control's per-class clause, `executor` and `netem` in the records, the harm gate's judged links and window, `--block`) | | |
| dbc73c5 | the executor's plan: `Host`, topology, stack and streams as data, the rendered Nginx configuration, `--plan` | 41 | |
| 59a09a9 | the executor's run on a `Host`, and `bench/sim_host.py` to test it on | 157 | 70 |
| 46e7934 | `bench/gate_campaign.py`: blocks, orders, the re-run rule, resume, `--simulate` | 68 | 41 |
| 77462f5 | streams launched at their own start (`launch_due`), grouped alignment, `population.staged` and `plan_population` | 28 | 19 |
| e28de6a | `bench/calibrate.py` and the third scenario `costly_export_sub_threshold` (spec, golden plan), a server with a capacity in the simulated host | 117 | 66 |
| cf6f963, e0d4473 | the executor prints a run's figures by link; a failed drift check is made once more | 3 | 8 |
| the docs commit | `docs/EVALUATION.md`, this section | | |
| 681e013, 83ab963 | the clock probe: a tuple and a list were concatenated (found by S1's first attempt); its rows say when each stream was launched, began and exited | 16 | 20 |
| a6e6b95 | the wall time of an engine is held to its records; the simulated host follows the engine in two points (S1b) | 33 | 34 |
| 938a1df | a stream is dead on a non-zero exit or on missing output, not on an early exit; the simulated host's engines end with their last request | 12 | 27 |
| e80e6fc | the legit starts are judged by a pack, and up to 10 % of a group may be stragglers whose loops ended with their last request; the settings are what S1 and S1b measured; the simulated host starts its engines as measured | 33 | 40 (of 41; one is equivalent) |
| d2593d4 | the topology's ping check sends three packets per source and passes on any reply (S2) | 6 | 17 |
| abed669 | the environment gate's timer limit is the calibration's `validity.timer_p99_ms`; `--timer-limit-ms` sets another for a smoke test; the harm gate gives no verdict on runs that carry overrides | 45 | 56 (all) |
| 5730707 | Nginx is started like the origin: a process of its own with no pipe for its daemon to hold, its stderr in `nginx_start.log`, its launcher waited for; the files of the last failed attempt stay; the simulated host's Nginx daemon holds the pipes of a captured call (S3) | 12 | 36 (of 37; one is equivalent) |
| 10dd6c0 | the harm gate's CPU-share rule skips a stream whose schedule has no request; the teardown logs the time of each step (S3, second run) | 7 | 31 (all) |
| 2a6dea5 | the pack of a group must be a majority and stragglers may begin up to 2.5 s from the others: `straggler_share` 0.5 capped below half, `t0_range_limit_s` 2.5 (S3, replay of the eight runs) | 13 | 27 (all) |
| 4925912 | the relative profile judges the slip p99 pooled over the legit requests against 100 ms (`validity.slip_pooled_s`), not each stream's own against 250 ms; the placeholder is rehashed (S3, replay of the eight runs) | 8 | 17 (all) |
| 9680336, 2eb4d7d, c61cb1e and the docs commits after d2593d4, after abed669, after 5730707, after 10dd6c0, after 4925912 and after S4 | this section, `docs/EVALUATION.md`, `docs/HG1B_MINIMAL_DESIGN.md` 9.7 | | |

1,574 tests pass; ruff is clean. The mutations were made on private copies of the tree (a textual change to one line, the executor's or
campaign's or calibrator's tests run against it); each one that was not equivalent made a test fail, and the survivors of the first rounds
were closed with tests (an equivalent branch of `program_of` was removed instead).

**Where it departs from this note.** Each was a choice made while building and is open to your objection.

| # | Note | Built | Why |
|---|---|---|---|
| 1 | 6.8: the executor registers its teardown with `atexit` after the suite's, so that it runs first (LIFO) | the suite's `atexit` cleanup is unregistered after the import, and its signal handlers put back; the teardown is a `finally` and SIGTERM and SIGHUP raise `KeyboardInterrupt` | 5.3 said it never kills by pattern, and the suite's cleanup is a system-wide `pkill -9 -f gunicorn` and `-f "nginx: ..."`; letting it run after the executor's own teardown would have been the one place that does |
| 2 | 6.8: no `pgrep -f` on a word the command line can contain | no `pgrep` at all: the leftover check reads `ps -eo pid=,ppid=,args=` and decides by what each process runs (the first word, or the script or `-m` module of a Python), and leaves out the executor and its parents; a listing that cannot be read raises `TableUnreadable`, so that an unreadable machine is never "clean" | a pattern over whole command lines finds the executor's own (`--out /var/tmp/gunicorn/...`) |
| 3 | 6.2 step 2: uptime, load and a TIME_WAIT settle before every run | the full gate (waiting for uptime and load) for the first run of a process, the timer on CPU 6 for every run; no TIME_WAIT settle | a run's own load keeps the 1-minute average above 0.3 for minutes, so every next run would wait for it; the sockets of a run die with its namespaces (D21), and the host's count is not theirs |
| 4 | 6.8 | the teardown runs inside a shield that ignores SIGINT, SIGTERM and SIGHUP | a second Ctrl-C would leave the namespaces standing |
| 5 | 6.6: `t0 = t_exit - wall_s + 0.05`, `delta` the same for all | `exit_delay_per_request_s` in the settings, 0 until S1 says otherwise, subtracted per request | the engine writes its summary and records after the loop, so `delta` grows with the request count; the legit streams have at most 1,239 requests and the flood's attack streams up to 19,882 |
| 6 | 6.1 and 6.5: legit streams together, attack streams once | every stream is launched so that its loop starts at its `start_s` (`launch_due`), and `alignment` judges groups of one kind and start; for a plain run the schedule and the rule are the old ones | the staged capacity probe needs it; a test pins that plain runs are unchanged |
| 7 | 7: the re-run decision | a run that fails or is found unsound ends its attempt at once; a campaign that can no longer reach `min_blocks` stops (`--keep-going` goes on) | finishing an invalid block spends VM time on nothing; both are independent of any outcome |
| 8 | 8, step 1: "a session spread over 10 %" | read as: any route's three session medians differ by more than 10 % of their median, then the three sessions are made once more and only the second round counts; twice over stops | the sentence does not say which spread |
| 9 | 8: the stack's CPU per request, a diagnostic of step 1 | computed from the telemetry and the request counts of the capacity runs (`stack_cost`), per level, and written next to the capacity; no separate run | no extra VM time; it is not part of the record |
| 10 | 8 | calibration populations draw from calib seeds 11 (capacity), 21 (ladders, one seed per family), 31 (reference) and 41 (drift), outside the gate's 1 to 10 | the knee should not be tuned on the clients the gate judges |
| 11 | 8: "a failure is rerun once after the environment gate" | `calibrate.py drift` makes the second attempt itself, with a new runner that waits for the full gate again, in `<out>.second` | |
| 12 | 9: a shared `tests/synth_runs.py` made from the HG1b synthetic server; `--simulate` on a fake host | `bench/sim_host.py` in `bench/`, so that the command line can use it: commands answered from a model, a virtual clock, faults, and a synthetic server that makes a harm of a known size or has a capacity | one model for the tests of the executor, the campaign and the calibrator; the HG1b tests keep theirs |
| 13 | 10, S3: `harm_gate --block` on the run | `executor.py run` prints the figures (Q, p95, slip, Q per link profile) | a `block.json` exists only for a campaign |
| 14 | 6.6: `t0 = t_exit - wall_s + 0.05` | the wall time is first raised to the last request's `t_done` plus 0.05 s when it is shorter (`consistent_wall`, `last_done`); the estimator is named `exit-minus-consistent-wall` and `executor.wall_gap_s` lists the raise of each stream | S1b: the engine reads the schedule's zero and, one statement later, its wall clock, and a process descheduled in between (29 starting together on one CPU) reports too short a wall time, by 54 ms at the median, 258 ms at the 90th percentile and 2.03 s at most; the exit delay itself is 0.015 to 0.03 s |
| 15 | 6.6: executor validity is false "when a process died" | `run_timeline` calls a stream dead if it exits more than `EARLY_SLACK_S` (2 s) before its end with a non-zero code or without its summary and records (`left_output`, shared with `collect`); an early exit with its output is the end of its schedule | S1b: the engine exits when its last request is done, so 11 or 12 of the 29 legit streams exited more than 2 s early; the first version called each of them dead and would have ended the first real run (see below) |
| 16 | 6.6: the legit `t0` spread exceeds 0.5 s | `alignment` takes the pack of each group of legit streams, the most that began within 0.5 s of one another, and the rest are stragglers; a group is sound when at most `straggler_share` (0.1: 2 of 29; since departure 22 a pack that is a majority, 0.5 and a range limit) of it are stragglers and each has a tail (how long its loop outlived its last request) of at most `straggler_tail_s` (0.1 s); the zero, the spread and the error of a later group are the pack's; `executor.stragglers`, `t0_range_legit_s` (all) and `t0_spread_legit_s` (the pack) in `run.json` | S1b: in 2 of 3 runs one or two streams began 0.6 to 2.3 s before the others, and their offsets are right to 0.06 s once the wall time is held to the records; the harm gate places a stream's records at `t_intended + offset_s`; you approved 10 % |
| 17 | 6.6 and 10: the start-up delays and the exit delay per request are proposals | `startup_delay_legit_s` 2.5 (was 1.8), `startup_delay_attack_s` 0.15 (0.3), `exit_delay_per_request_s` 8e-6 (0); the simulated host starts its engines as measured (2.4 s, 0.14 s, 8e-6) | S1 and S1b: legit loops begin 2.0 to 2.55 s after the launch (median 2.04 to 2.40), attack loops 0.13 to 0.15 s, and an attack stream exits 8.0 us later for each request; with 1.8 s every U run would have put the attack 0.8 s early; S4 measures them again with the real launch chain and they are frozen after it |
| 18 | 6.3 and 10, S2: "one ping to `server_ns` from each namespace and from one alias each" | each of those pings sends three packets 0.2 s apart (`ping -c 3 -i 0.2 -W 3`) and the namespace answers if any one is answered | the client links drop packets on their way out (netem: 2 % on `mobile_3g`, 5 % and 1 % corrupted on `mobile_bad`): with one packet the eight pings failed in one build of seven (15 % [ARITHMETIC]), and `smoke_topology` does not retry; with three, about one in a thousand |
| 19 | 6.2 step 2 and 10: the timer on CPU 6 must have p99 below 10 ms (a constant of the load-tool harness, `TIMER_WARN_MS`) | the limit is `plan.timer_limit_ms`, the calibration's `validity.timer_p99_ms` (a required key that nothing read; 10 ms in the placeholder); `--timer-limit-ms MS` on `executor.py plan|run` and `gate_campaign.py` sets another for a smoke test, recorded as an override in `plan.json`, `run.json` and `block.json` and, with the limit used, in `environment.json`; the probe is the same and recorded as it was; a campaign needs `--dry-run` with it. The harm gate gives no verdict on a campaign whose runs or blocks carry any override (`rho_rps`, `timeline_s` or `timer_limit_ms`): INVALID, with the reason, whatever the figures, and the report has a SMOKE TEST banner; the blocks are assessed all the same, so the reason starts no re-run. `--allow-overrides` lifts it, and `gate_campaign.py` passes it itself only for a host that says it is simulated | [FACT] the timer on CPU 6 had p99 of 11.7 to 40.8 ms in all ten probes of S1 and S1b, so the gate as it was would refuse S3 [INFERENCE: ten readings]; you approved a smoke-test override (the option of a higher limit for S3 only), so that a run on a noisy VM is a recorded smoke test and neither refused nor loosened without a trace. [FACT] `rho_rps` and `timeline_s` overrides were written to every record and read by nothing, so a smoke test's campaign was given a verdict like any other; the same refusal now covers them |
| 20 | 6.2 step 4: "start gunicorn then Nginx in `server_ns`" (as built, Nginx was run to completion like any other command, with its output captured) | Nginx is started like the origin (`Cmd.detach`): a `Popen` in `server_ns` whose stdout goes nowhere and whose stderr goes to `nginx_start.log`; the executor waits up to 10 s (`DAEMON_FORK_WAIT_S`) for the launcher to return, which it does once the daemon has forked, and fails with the launcher's last lines if it exits non-zero or with "did not return" if it does not; the daemon is found again by namespace (the sampler, the teardown). The files of the last failed attempt stay in the run directory (`_reset` also ran after the final failure); those of an attempt that is retried are removed | [FACT] S3: the Nginx command, run to completion with its output captured, came back only at the 120 s command timeout, on all three attempts (6.5 min), and `_reset` had erased the files that would say why. The suite starts the same command with `Popen` and its output sent to `/dev/null`. [INFERENCE] a daemon that keeps the pipes of such a call keeps it from returning; not observed, and the fix is untested on the real Nginx. The simulated host now models it (a captured call returns at its timeout with the daemon up): with the executor as it was, 139 of the 508 tests of the five modules that run a stack failed or errored, and with the change none; the one deviation from "as the suite does" is that stderr goes to a file, as gunicorn's does, so that a start that fails keeps its message |
| 21 | HG1b 4: "a stream is invalid when its CPU share exceeds 0.70" | a stream whose schedule has no request is not judged for its CPU share (`validity`: `intended > 0`); every other rule still applies to it | S3, second run: the engine's summary of a stream with no request had `cpu.share` 2.82 (2.4e-5 s of CPU over a wall time of 8.4e-6 s) and the harm gate called it too busy, which made the control invalid; at 20 req/s over 30 s one stream of 29 has no request [FACT: the engine's own schedule], and the real engine's empty run in the test gave 2.99. The engine's own `flags.cpu` and `valid` still say so: it is pinned by its hash and is not changed |
| 22 | 6.6 and departure 16: a group is sound when at most `straggler_share` (0.1: 2 of 29) of it are stragglers whose tails are at most `straggler_tail_s` | the pack of a group must be a majority of it, and `straggler_share` is 0.5 (`stragglers_allowed`: the whole number in the share and fewer than half of the group whatever the share, so 14 of 29 and 1 of 4); no two legit streams of a group may begin further apart than `t0_range_limit_s` (2.5 s; a reason of its own per group); the tail of each straggler is asked about as before | [FACT] the eight S3 runs (s3_stack_2 to 5, s3_ab_1 to 4) had 4, 4, 7, 5, 2, 4, 2 and 2 streams outside the pack, 30 in all, every one early (0.37 to 1.81 s before the pack's median) with a tail of at most 0.0004 s, and the count alone voided five of the eight. Against the Nginx access log (each stream's server-side start, compared within a link profile; the log is in whole seconds, so the check resolves about 0.1 s) the executor's offset of those 30 differs by 0.07 s at the median and 0.21 s at most (the 194 in the pack: 0.07 and 0.97 s), and S1b's are within 0.06 s of the true start. They follow the launch order (Spearman +0.36 to +0.87 between a stream's place in the plan and its offset, in 8 of 8 runs): the first streams launched, the high-rate ones, begin first. [INFERENCE] a start-up skew of engines that start when they are ready, not a fault. [ARITHMETIC] the price of placing such a stream by its offset: one that began x s early has x/10 of its attack-window requests from another part of its schedule than one that began with the pack; between two of the eight runs that is 2.7 % of the legit requests at the median and 4.2 % at most. Replayed with `alignment()` on S1b (3 runs) and the eight: all 11 are sound, where the 10 % rule kept 6. [UNVERIFIED] under attack load, where the exit times may behave differently; S4 is the first datum |
| 23 | HG1b 4 and 9.3: no stream's slip p99 above 250 ms (`validity.slip_gross_s`), and the pooled p99 within 50 ms of the control's | the p99 pooled over the legit requests of a run may not exceed 100 ms (`validity.slip_pooled_s`), the control's included; the difference to the control (50 ms) and the strict profile (each stream's p99 under 50 ms, judging nothing unless chosen) are as before. The key set of a calibration is exact, so one with the old key is refused; the placeholder is rehashed (67c0b2ad to ac4e3156) and the six golden plans that quote its hash change by that prefix | [FACT] the legit streams of the eight S3 runs have a median of 11 requests (at most 72, none with 100 or more), so a stream's p99 is its largest slip or next to it and the clause read "no request of any stream more than about 250 ms late"; the pooled p99 over a run's 535 requests is the 6th to 7th largest. Pooled p99 was 16, 24 and 16 ms in the three runs with the stall monitor beside them (largest slip 33, 49 and 197 ms) and 221, 275, 278, 428 and 542 ms in the five without (largest 433 to 1,081 ms); nothing between 24 and 221 ms was seen. The old clause gave the same verdicts as a pooled 100 ms on all eight, by the luck of where a late request fell (ab_4, pooled 221 ms, failed on 2 streams; ab_3, 16 ms, had streams at 190 and 162 ms); a pooled 250 ms would have cut through the stalled regime. 100 ms is 4x above the largest healthy run and 2.2x below the smallest stalled one, and anything from 50 to 200 ms gives the same verdicts on these eight. The stalls are not free: the controls' p95 in the attack window was 97 to 105 ms in the three and 106 to 151 ms in the five. [PROPOSAL] the threshold, anchored on eight runs on one VM on one day, controls only |

**Not built.** The calibration of the legit mix, the SLOs and the gate's constants: they stay the template's (the placeholder's) and are
frozen with the record; changing them is a decision, not a measurement. The mitigated runs `M_<mode>` (HG4). Anything on the L3 and L4 paths (D20).

**What S1 and S1b found (2026-10-26; no root, loopback; commits 681e013 and 83ab963).** S1 ran the 29 legit streams of
`costly_search_sub_threshold` (cold, the first run after a reboot) and the 29 legit and 3 attack streams of `cheap_static_flood` (warm), 30 s
each, each against its own scripted origin; S1b ran the first again three times in a row, with all 29 streams launched within 0.07 s, as a
run's plan has them. Every stream reported and nothing was left over. [FACT] The timer on CPU 6 was above the 10 ms gate in all ten probes
taken around them (p99 11.7 to 40.8 ms), so the executor's environment gate would have refused to start a run in that state.

| | S1 cold | S1 warm | S1b run 1 | S1b run 2 | S1b run 3 |
|---|---|---|---|---|---|
| a legit loop begins after its own launch, median (range) | 4.53 s (3.41 to 4.66) | 2.95 s (2.57 to 3.06) | 2.40 s (0.18 to 2.55) | 2.04 s (1.86 to 2.17) | 2.15 s (0.19 to 2.21) |
| an attack loop begins after its own launch | | 0.13 to 0.15 s | | | |
| the engine's wall time was too short by, median (max) | 0.06 s (1.17) | 0.00 s (0.06) | 0.09 s (2.03) | 0.11 s (0.29) | 0.03 s (1.81) |
| exit less the end of the last request, legit streams | -0.02 to 0.16 s | 0.02 to 0.06 s | -0.03 to 0.04 s | 0.01 to 0.05 s | 0.01 to 0.06 s |
| the estimator's error as it was | 0.01 to 1.19 s | 0.02 to 0.08 s (attack 0.05 to 0.13) | 0.01 to 2.05 s | 0.01 to 0.32 s | 0.01 to 1.83 s |
| estimated legit starts apart as it was (limit 0.5 s) | | | 0.622 s | 0.141 s | 0.295 s |
| the same with the wall time held to the records | | | 2.381 s | 0.313 s | 2.088 s |
| the largest pack within 0.5 s, and how wide it is | | | 27 of 29, 0.35 s | 29 of 29, 0.31 s | 28 of 29, 0.36 s |
| the streams outside it (before the pack's median) | | | 2 (2.26 s, 0.64 s) | none | 1 (1.99 s) |

[FACT] One legit stream in S1 command 1 and in S1b runs 1 and 3 began about 2 s before the others (0.2 s after its launch). In S1b its
`wall_s` was 2.03 s shorter than its own records allow (the last request finished 29.28 s after its schedule's zero, `wall_s` was 27.29 s),
and its first four requests, due between 0.3 and 1.9 s, were all sent 1.98 s after its zero. [INFERENCE] bench/loadgen.py `run()` reads the
schedule's zero, `loop.time() + 0.05`, and one statement later the clock its wall time counts from; the process was descheduled between the
two, while the others were starting on the same CPU. The same happens at a smaller size in most streams: over S1b's 87 streams `wall_s` was
shorter than `last t_done + 0.05` by 54 ms at the median and 258 ms at the 90th percentile. [FACT] That gap, not the exit delay, was the
estimator's error; the first reading of S1 (an exit delay that queues on the legit CPU) was wrong. The exit delay proper, exit less the end
of the last request, is -0.03 to 0.16 s for legit streams (median 0.015 to 0.03 s); for attack streams it grows with the request count, 8.0 us
per request from three points (4.3k, 4.4k and 13.3k requests).

**What the correction does to the rule.** [FACT] a6e6b95 raises a wall time that is shorter than `last t_done + 0.05` to that. Replayed
through `alignment()` on S1b's files, the offsets are within 0.05 s of the true ones for all 87 streams (the error is -0.03 to 0.06 s). As it
was, the three runs came out 0.622 s (unsound), 0.141 s and 0.295 s apart, and the stream that began at 0.21 s was put at 2.26 s, inside the
pack; corrected, they come out 2.38 s (unsound), 0.31 s and 2.09 s (unsound), because streams really began before the rest: in run 1 one 2.26 s
and another 0.64 s before the median of the others, in run 3 one 1.99 s. (An earlier version of this paragraph said that the rest lay within
0.18 to 0.31 s; that was true of the streams whose wall time needed no correction, not of all the others.) The harm gate places a stream's
records at `t_intended + offset_s`, so a right offset repairs its placement, and e80e6fc lets up to `straggler_share` of a group (10 %:
2 of 29) begin outside the 0.5 s of the others when their loops ended with their last request (departure 22 replaced the 10 % by a pack that must be
a majority and a range limit). Replayed on S1b's files that makes all three
runs sound, with 2, 0 and 1 stragglers: run 1 uses both places, so a run with a third would be unsound. The settings that go with it, from
the same data, are applied in e80e6fc: `startup_delay_legit_s` 2.5 s (S1's 3.0 s was for a cold start), `startup_delay_attack_s` 0.15 s and
`exit_delay_per_request_s` 8e-6 s (S1, three points). They are S1's and S1b's, on loopback without namespaces: S4 measures them again with
the real launch chain and they are frozen after it.

**What S2 found (2026-10-26 11:06 UTC; root, in namespaces; commit d2593d4).** `sudo ./venv/bin/python -B bench/executor.py smoke-topology
bench/scenarios/costly_search_sub_threshold.json --kind U --seed 1 --out /var/tmp/ddos_campaigns/s2_topology/U`, once. [FACT] Exit 0. The log
says: 4 namespaces, 300 addresses, built and verified in 13.1 s (the suite's primitives, `ip -batch -` with 105, 101, 67 and 23 lines, netem on
three links, the read-back of addresses, MACs and qdiscs, and eight pings of three packets); teardown complete after 17.8 s, so 4.6 s for the
teardown; the whole command took 17.9 s. Checked from outside afterwards: no namespace, the links are `lo`, `enp0s3` and `enp0s8` as before, no
process of the testbed, the git index still owned by the user, and nothing in the checkout touched (`-B`: no bytecode written as root). The
modules `sch_netem`, `veth` and `bridge` (with `stp` and `llc`) were not loaded before and are now; they stay until a reboot. The only file it
left is `executor.log` (150 bytes, root) in the output directory. Section 6.2 estimated 6 s for the topology (step 3) and 5 s for the teardown
(step 9): the topology took 13.1 s, twice that, and the teardown 4.6 s. [INFERENCE] A run is then about 7 s longer than the 140 to 150 s of 6.2,
other steps as estimated; the log does not split the 13.1 s between the build, the read-back and the pings, and one run says nothing of its
variation. The command in the S2 row of section 14 had no `--kind`, which would have built the control's 200 addresses; U has the
300 that the design means to test. The ping check was changed before this run (departure 18).

**What S3 found (2026-10-26 13:44:43 to 13:51:16 UTC; root; HEAD 4853ea4; the change is 5730707).** `sudo -n env PYTHONDONTWRITEBYTECODE=1 ./venv/bin/python -B bench/executor.py run bench/scenarios/benign_control.json --kind C --seed 1 --rho 20 --timeline 10,10,10 --timer-limit-ms 50 --wait-gate 5 --out /var/tmp/ddos_campaigns/s3_stack/C`, once. [FACT] Exit 2, `SetupFailed: taskset -c 0-1 nginx -c …/nginx.conf exited -1: timeout`, after 392.8 s. The gate passed without waiting (uptime 20,530 s, load 0.18). The timer on CPU 6 had p50 0.66 ms, p99 14.50 ms and max 19.39 ms: above the calibration's 10 ms and below the override's 50 ms, so without `--timer-limit-ms` the run would have been refused. The topology (4 namespaces, 200 addresses) was verified in 8.7, 6.6 and 7.8 s on the three attempts (section 6.2 estimated 6 s; S2 took 13.1 s for U's 300 addresses). gunicorn was started each time; the Nginx command ran to the executor's 120 s command timeout each time; the executor took the testbed down after each attempt ("no namespace, link or process of the testbed is left", after 1.4, 2.3 and 0.8 s) and retried twice as designed. Nothing reached readiness, so there is no stack record, no stream and no figure: S3 has not been done. Checked from outside afterwards, against a snapshot taken just before: no namespace, links `lo`, `enp0s3` and `enp0s8` as before, no process of the testbed, no `/run/nginx.pid`, listeners and loaded modules identical, `/var/log/nginx` unchanged, the git index and every file of `bench/__pycache__` still yours. The run directory (root) holds `FAILED`, `environment.json`, `executor.log` and `plan.json` only, because `_reset` ran after the final attempt too and removed `nginx.conf`, `nginx_error.log` and `gunicorn.log`: what Nginx did is not known. [INFERENCE] The suite starts this command with `Popen` and its output sent to `/dev/null`; the executor ran it to completion with the output captured, and a daemon that keeps those pipes keeps the call from returning until its timeout. The rendered configuration is the template's but for its two log paths and has no `daemon off`. The change (departure 20) starts Nginx like the origin and keeps the last attempt's files, so that a second failure explains itself.

**What the second S3 run found (2026-10-27 08:58:08 to 08:59:17 UTC; root; HEAD 2284dcb).** The VM had been rebooted (uptime 101 s) between the proposal and the approval, so the run was held for 29 min until the machine met the gate's uptime of 1,800 s (the gate itself then waited 0 s); it was the first stack run after a boot, and it loaded the kernel modules `bridge`, `llc`, `sch_netem`, `stp` and `veth` again. `sudo -n env PYTHONDONTWRITEBYTECODE=1 ./venv/bin/python -B bench/executor.py run bench/scenarios/benign_control.json --kind C --seed 1 --rho 20 --timeline 10,10,10 --timer-limit-ms 50 --wait-gate 5 --out /var/tmp/ddos_campaigns/s3_stack_2/C`, once. [FACT] Exit 3, UNSOUND, 47 s to `run.json` and 59.5 s to the end of the teardown (69 s on the wall clock). The gate: uptime 1,824 s, load 0.08, and the timer on CPU 6 with p50 3.33 ms, p99 17.99 ms, max 68.5 ms, so that the calibration's 10 ms would have refused the run again (all 12 readings of S1, S1b and S3 are at least 11.7 ms). Topology 5.6 s, Nginx's launcher back after 0.36 s, the stack ready at 12.1 s. The stack record: Nginx has 9 processes, a master and 8 workers, on CPUs 0 and 1 (`worker_processes auto` counts the 8 online CPUs, not the affinity: the hazard of 4.3 is real), with 65,535 open files for the workers and 524,288 for the master; the origin has 3 processes (a master and 2 workers) with 524,288. Requests: 535 intended, sent and completed, none dropped, no error (the offline schedule has 535); Nginx logged 552 lines, 17 of them the readiness and warm-up requests. The server used 0.8 % of the CPUs on average (at most 2.9 %), Nginx 0.7 %, the origin 9.6 % (at most 28.5 %), with no steal; CPU 6 was at 100 % for the first four seconds of the engines' start-up and at about 1 % after. Figures over 10 to 20 s: on the judged links Q 100.00 % of 146 requests (perfect 77, broadband 69), p95 151 ms; on the links not judged `mobile_3g` 36.4 % of 33 requests and `mobile_bad` 25.0 % of 16 (about 83 % over all links [ARITHMETIC]: F1 on real records, with the placeholder's SLOs and few requests); `control_health` finds the control healthy. Unsound: the legit streams began 1.08 s apart; 4 of 29 began 0.50, 0.70, 1.04 and 1.05 s before the others, where 2 are allowed, each with a tail of 0 s, so that their offsets are trustworthy; the pack alone spread 0.484 s against the limit of 0.5 s; the wall time of 11 streams was raised, by up to 0.36 s (S1b: 47 of 87, by up to 2.03 s). The harm gate's validity (profile `relative`, placeholder) finds the run not valid for three reasons: these stragglers; four streams whose slip p99 is over the gross ceiling of 250 ms (475, 369, 286 and 280 ms, one of them a straggler); and the stream with no request, whose CPU share was 2.82 (departure 21). The slip is not the start-up's: of 22 requests sent more than 100 ms late, 8 requests of 7 streams were 160 to 499 ms late within 12.00 to 12.33 s on the pack's time axis, which is one stall of about 0.5 s, and there are smaller clusters near 22 s and 28 s; the first 3 s of a stream have a slip p99 of 99 ms; the sampler on CPU 2 saw no gap (its largest interval was 1.054 s). [INFERENCE] CPU 6 stalls; it was the healthy vCPU of the survey of 2026-10-22. Leftovers: none, against a snapshot taken just before (no namespace, links `lo`, `enp0s3` and `enp0s8`, no testbed process, no `/run/nginx.pid`, listeners and `/var/log/nginx` unchanged, the git index and `bench/__pycache__` still yours). Side effects not listed beforehand: gunicorn 26.2.0 opened a control socket at `/root/.gunicorn/gunicorn.ctl`; it is gone and the empty root-only directory stays. The teardown took 12.6 s, of which gunicorn's stop was 1 s, and the log said no more; the change of this commit logs each step. Open: the straggler share (4 of 29 here, 2, 0 and 1 in S1b) and the limit on the pack; the slip clause, whose per-stream p99 is a one-request statistic for a stream of 10 requests; the survey of the vCPUs; and whether two more runs, warm, would separate the cold first run after a boot from what is structural.

**What the replay of the eight S3 runs found (offline, 2026-10-27 and 28; no VM run).** The eight are the four stack runs made one after another (s3_stack_2 to 5; the fourth ran with the stall monitor beside it) and the 2x2 s3_ab_1 to 4 (drawn order: monitor, none, monitor, none); the monitor is a scratch script that times every vCPU's wake-ups and samples the guest's accounting, and is not part of the executor. [FACT] The three runs with it (s3_stack_5, ab_1, ab_3) had no cluster of late requests (pooled slip p99 16, 24 and 16 ms), the five without had 2 to 7 (221 to 542 ms). Which part of the monitor keeps the stalls away is not known: its sparse probes were themselves 150 to 257 ms late outside the engines' windows and never while the engines ran [ARITHMETIC] (about 3 such moments were expected in those windows, none was seen; Poisson p about 0.04). The executor's own `alignment()` and the harm gate's own `validity()` were replayed on the stored runs (with the old rules the replay reproduces the stored stragglers, spreads, ranges and per-stream and pooled p99 of all eight): the old rules kept 2 of the 8 (ab_1 and ab_3), the new ones keep 3 (s3_stack_5 as well), and the five stalled runs stay invalid under every variant tried (a straggler share of 10, 15 or 25 %, or any; a pack of 2 s; a slip ceiling per stream, or pooled 100 or 250 ms), but for ab_4 under a pooled 250 ms. [INFERENCE] The rules cannot make a stalled run valid and should not; what is left is the stalls. A companion that keeps them away from the executor's runs is not built and which of the monitor's parts it needs is open; a 15-run dissection of the monitor on the VM is proposed [PROPOSAL]. The replay scripts and their outputs are scratch (`/var/tmp/hg1c_scratch/options_*.py`) and are not in the repository.

**What the dissection of the stall monitor found (2026-10-28, 11:48 to 12:12 UTC; the monitor's parts taken apart in 15 S3 runs; HEAD 034a8f7; no code changed).** The VM had been rebooted at about 08:55 UTC and the venv rebuilt by hand that morning (`code/venv` is a link to `/home/artur/DDoS-mitigation/.venv`, with gunicorn 26.2.0 copied in). Five conditions, three runs each, in three blocks of five, each block a permutation drawn once (seed `dissection-2026-10-28`): no companion (N); the monitor's timer probes alone (S: 10 ms on CPU 2, 100 ms on the seven others); its sampler alone (P: 10 ms wake-ups on CPU 4 and what it reads from `/proc`); the whole monitor (F, the replication); a minimal ticker (T: eight processes, one pinned to each vCPU, sleeping 10 ms). The S3 command was the 2x2's but for `--out`, started 15 s after the companion's START file (17 s after the snapshot for N). [FACT] All 15 runs exited 0, were sound and left nothing, and **none stalled, the three with no companion included**: the pooled slip p99 was 15, 13 and 16 ms for N, 16, 14 and 12 for S, 15, 12 and 12 for P, 15, 16 and 14 for F, 13, 16 and 13 for T (the largest slip 17 to 51 ms; no request more than 100 ms late; no cluster; p95 95 to 111 ms), and the gate probe's p99 was 2.8 to 4.1 ms in all 15 (14.6 to 18.1 ms in the five stalled runs of 10-27). The reading fixed beforehand says F **does not replicate** (N was free of stalls in 3 of 3) and S, P and T **do not protect**; what that means is that **the stall regime of 10-27 was absent today, not that the monitor does nothing**. The question is unanswered, and the effect of 10-27 (3 runs with the monitor clean, 5 without stalled; one-sided Fisher p = 0.018, 4 of the 8 randomised) is neither confirmed nor refuted. The host is not the one of 10-27 either: the vCPU that wakes on time is CPU 7 now (p50 lateness 0.26 to 0.30 ms against 1.1 to 1.4 ms elsewhere), it was CPU 2. Two by-products. (1) [FACT] The cost of the companions, from the telemetry (the sum over the CPUs of the busy share, against the runs with none): +2.3 points of one CPU for the probes, +1.9 for the sampler, +2.7 for the whole monitor and +5.2 for the ticker (spread of the sum 0.1 to 0.9). The +12.5 that the options write-up of 10-27 gave (0.12 to 0.16 vCPU) was confounded by the stall regime: the runs without the monitor had a sum of 19.8 then, 32.6 today and 32.2 for the monitored runs of 10-27. (2) [post hoc, exploratory, two days] **The executor's own timer gate at the calibration's 10 ms is a detector of the stall regime.** Of the 23 runs of the two days, the 17 with a gate probe p99 under 10 ms (15 of today, 2 of 10-27) had a pooled slip p99 of at most 24 ms; of the 6 at 10 ms or more, 5 had stalled (the five runs without the monitor of 10-27, 14.6 to 18.1 ms) and one had not (14.4 ms). Every smoke test so far ran with `--timer-limit-ms 50` (departure 19), which switched this detector off. [PROPOSAL] Run campaigns under the calibration's limit and let the gate refuse on a noisy day; a keep-awake companion in the executor is shelved, as a fallback if the gate refuses too often. [UNVERIFIED] The relation rests on two days and was found after the data were seen. The scripts and their outputs are scratch (`/var/tmp/hg1c_scratch/dissect_*.py`, `ticker.py`, `dissect_*_out.txt`) and are not in the repository.

**What S4 found (2026-10-28, 12:31:01 to 12:39:17 UTC; root; HEAD 034a8f7, a clean tree).** `bash /var/tmp/hg1c_scratch/s4_run.sh` ran `gate_campaign.py run bench/scenarios/costly_search_sub_threshold.json --blocks 1 --dry-run --wait-gate 5` with a snapshot of the host before and after, `vmstat` every 5 s and `free`: the warm-up C and the block's runs U, C and Cp (the order drawn for seed 1), under the placeholder calibration and **the calibration's own timer limit, with no override**. A VS Code server of your session was connected and used a few per cent of a CPU. [FACT] Exit 0; all four runs sound, the block valid, no re-run, the gate 'INVALID (dry run), 1 valid blocks of 1' as it must be; afterwards no namespace, `executor.leftovers()` `[]`, and the links, modules and listeners as before. The first run's full gate waited 0 s (uptime 12,960 s, load 0.29 against 0.3, after a wait of mine for the VS Code server's start-up to settle) and the timer probe on CPU 6 gave p99 2.95, 3.07, 3.46 and 3.25 ms against 10 ms. A run took 120.3 to 127.2 s (mean 123.6) against the 140 to 150 s of 6.2, the campaign 8 min 16 s. **Clocks with 33 processes.** The legit streams began outside the pack 6 times in the warm-up (up to 1.83 s early; the rule of 10 % would have called it unsound) and twice in each of U, C and Cp (up to 1.27, 1.79 and 0.53 s), every one early, with a tail of at most 0.0006 s; the range of the starts was 1.92, 1.38, 1.84 and 0.60 s (limit 2.5 s). Against the Nginx access log (90 req/s, so 20 to 400 requests a stream) the offsets of the 12 stragglers differ by 0.017 s at the median and 0.149 s at most, those of the 104 streams in the packs by 0.024 and 0.464 s, and the 2 stragglers of U by 0.04 s: **the estimator holds under attack load** (one U run). The four attack streams began within 0.03 s of one another and 0.32 s before the end of the baseline (`attack_start_error_s` -0.32 s, limit 0.5 s): [INFERENCE, one sample] the legit loops begin about 2.8 s after their launch with the real launch chain, not the 2.5 s of `startup_delay_legit_s`; the setting waits for the U runs of HG2. **Delivered and loaded.** The legit streams sent 9,479 requests in each run (90.3 req/s), all completed in C and Cp, none dropped; the attack 1,655 (36.8 req/s; four streams of 10.2, 14.4, 9.8 and 2.4), 22 of which timed out; the generators' slip p99 was 5 to 6 ms (the largest 42 to 50 ms), their CPU share at most 0.01. The server's CPUs 0 and 1 were 36 to 40 % busy in the baseline, 98 and 96 % under the attack (the origin at 188 % of a CPU) and 57 % in the recovery, with no listen overflow or drop. Free memory was at least 2,074 MiB of 9,426, with no swap. **The harm, on a placeholder (a result about the protocol and none about a server).** Q was 99.1 % (C), 99.5 % (Cp) and 11.1 % (U) over the judged links, so dQ 88.0 pp and dL 2.63 (p95 135 to 832 ms), the placebo dQ' -0.4 pp; 61 of the 105 seconds were degraded and the recovery came 15 s after the attack ended. The attack of level 2.0 overwhelms the two server CPUs: the placeholder's capacity is not the stack's, which is what HG2 measures. The outputs are scratch (`/var/tmp/hg1c_scratch/s4_*`) and the campaign is `/var/tmp/ddos_campaigns/s4_1`.

**Found by S1b, fixed in 938a1df.** `run_timeline` treated a stream that exits more than `EARLY_SLACK_S` (2 s) before its nominal end as dead,
whatever its exit code. [FACT] The engine exits when its last request is done, not at the end of its duration: in S1b's 30 s probes 12, 11 and
11 of the 29 legit streams exited more than 2 s early (pulse streams of 0.07 to 0.4 req/s with 2 to 12 requests, a Poisson stream of 0.11 req/s
with two; the earliest at 13.5 s of 31.8). [INFERENCE] A real run would have been ended at the first of them and called unsound; with a longer timeline
fewer streams end early, but every stream of a few tenths of a request per second may. The simulated host ran every stream to its nominal end
and could not show it. Now a stream is dead if it exits early with a non-zero code or without its summary and records, and the simulated host's
engines end with their last request (the records are made when it is due, the wall time is until it is answered, a timeout included, and the process
exits `exit_delay_s` later). One consequence: a single dead engine no longer always ends a run in `RunFailed`. Other streams have left output by
the time it is seen (a stream with no request in its window exits at once), so the run is carried out and found unsound, and the attempt ends as
before; a run in which every engine dies (`engines_die`) is still `RunFailed`.

**What the tests cannot show, and which step does.** That the real commands do what the model says: `ip -batch -` with 100 addresses,
`prlimit` and `taskset` inside `ip netns exec`, `/proc/<pid>/net/netstat` of a process in another namespace, `curl` in `server_ns` (S3).
(S2 showed that `ip -batch -` takes 105 lines, that `ping -I` from an alias, `ip -j addr` and `ip -j link`, `tc qdisc show`, `ip netns list`,
`ip -br link show` and `ps` are parsed as the model has them, and that the teardown leaves nothing.) That Nginx and gunicorn behave as 4.3 lists, and the worker counts and limits under
`taskset` (S3, from `environment.json`'s `stack` record). That the estimator of the streams' clocks is accurate and the start-up spread of
29 processes on one vCPU (S1 and S1b measured them on loopback, without namespaces; S4 measures them with the real launch chain), and the
real per-run time (S4). That the control reaches 99 % on the judged links (S3, S4). The limits of 6.6 stay [PROPOSAL] until S4.

**The first contact (section 10), with the commands as built.** Each is approved on its own, with its command, before it runs.

| Step | Command | Root | Time | Side effects |
|---|---|---|---|---|
| S1 | `./venv/bin/python bench/executor.py clock-probe bench/scenarios/costly_search_sub_threshold.json --duration 30 --out /var/tmp/hg1c_s1/s1_clock_probe`, and the same with `bench/scenarios/cheap_static_flood.json --attack` (the attack streams with the most requests, to fit the exit delay's dependence on them) | no | about 1 min each | 29 (and with `--attack` 32) engine processes on CPU 6 (the attack's on 3-5 and 7) and as many listeners on loopback, one process pinned to CPU 2, files under the output directory; nothing left over |
| S2 | `sudo ./venv/bin/python -B bench/executor.py smoke-topology bench/scenarios/costly_search_sub_threshold.json --kind U --seed 1 --out /var/tmp/ddos_campaigns/s2_topology/U` (done; 18 s) | yes | 3 min [ESTIMATE; it took 18 s] | namespaces, veths and the bridge created and deleted; ARP and ICMP inside the testbed |
| S3 | `sudo ./venv/bin/python bench/executor.py run bench/scenarios/benign_control.json --kind C --seed 1 --rho 20 --timeline 10,10,10 --out /var/tmp/ddos_campaigns/s3_stack/C` (run twice with `--timer-limit-ms 50`, see section 14: the first stopped at the Nginx start after 6.5 min, the second ran to the end in 47 s and was found unsound) | yes | 3 min [ESTIMATE; about 70 s if nothing fails] | as a suite run without the daemon: gunicorn and Nginx in `server_ns`, traffic inside the testbed, the run's directory |
| S4 | `sudo ./venv/bin/python bench/gate_campaign.py run bench/scenarios/costly_search_sub_threshold.json --blocks 1 --dry-run --out /var/tmp/ddos_campaigns/s4_block`, then `./venv/bin/python eval/harm_gate.py --block /var/tmp/ddos_campaigns/s4_block/b01_a1 --calibration bench/calibration/placeholder.json` | yes | 12 min | as S3, with the scenario's attack of 37 req/s in `U`; four runs (the warm-up and the block's three) |

S1 and S1b wrote under `/var/tmp/hg1c_s1/` because `/var/tmp/ddos_campaigns` is owned by root and a step without root cannot create a directory
there; S1b is the first command three times in a row (`s1b_1` to `s1b_3`).

A run from a worktree needs a temporary `ln -s /home/artur/DDoS-mitigation/code/venv ./venv` there (the executor looks for `<checkout>/venv/bin/python`).

## Appendix A: the control against the links (offline, from the repository root)

Save the script below as `appendix_a.py` and run `./venv/bin/python appendix_a.py` from the repository root. Its assumptions: the suite's profiles on the request path only; the
request is delayed by one draw of the normal delay on a reused connection and by two on a new one; a lost SYN costs 1 s and a lost
request segment 0.3 s, with the loss rate of the profile; the server adds the route's unloaded cost and 1 ms; the stream weights are
the population's rates at seed 1.

```python
import math, random, sys
import numpy as np
sys.path.insert(0, "bench")
import calibration as C, population as P

cal = C.load(C.PLACEHOLDER)
slo = {k: v / 1000 for k, v in cal["slo_ms"].items()}
cost = {k: v / 1000 for k, v in cal["route_costs_ms"].items()}
# the suite's apply_tc shapes the client's egress only: (mean delay, normal jitter, loss on the request path), seconds
NETEM = {"perfect": (0, 0, 0), "broadband": (.020, .002, 0), "mobile_3g": (.150, .040, .02), "mobile_bad": (.300, .080, .06)}
OVERHEAD = 0.001                  # nginx and gunicorn per request, unloaded (assumed)
pop = P.draw("calib", 1, C.rho_rps(cal), 200)
streams = pop.of_kind("legit")

def latency(profile, route, reuse, rng):
    mean, jitter, loss = NETEM[profile]
    t = max(0.0, rng.gauss(mean, jitter))
    new = rng.random() >= reuse
    t = t * (2 if new else 1) + cost[route] + OVERHEAD
    if new and rng.random() < loss:
        t += 1.0                  # SYN lost: initial RTO 1 s
    if rng.random() < loss:
        t += 0.3                  # request segment lost: RTO about 0.3 s
    return t

for reuse in (1.0, 0.9, 0.7):     # share of requests that reuse an idle connection
    rng, tot, ok = random.Random(1), {}, {}
    for s in streams:
        good = sum(latency(s.netem, s.route_class, reuse, rng) <= slo[s.route_class] for _ in range(4000)) / 4000
        tot[s.netem] = tot.get(s.netem, 0) + s.rate
        ok[s.netem] = ok.get(s.netem, 0) + s.rate * good
    clean = ("perfect", "broadband")
    print(f"reuse {reuse:.0%}: Q(control) {100 * sum(ok.values()) / sum(tot.values()):.1f} %, clean links "
          f"{100 * sum(ok[p] for p in clean) / sum(tot[p] for p in clean):.1f} %, "
          + ", ".join(f"{p} {100 * ok[p] / tot[p]:.1f} %" for p in sorted(tot)))
total = sum(s.rate for s in streams)
print("request share:", {p: round(100 * sum(s.rate for s in streams if s.netem == p) / total, 1) for p in NETEM})
phi = lambda x: 0.5 * (1 + math.erf(x / math.sqrt(2)))
c0 = sum(s.rate * (1 - phi((slo["C0"] - NETEM[s.netem][0]) / NETEM[s.netem][1]))
         for s in streams if s.route_class == "C0" and NETEM[s.netem][1] > 0)
print(f"C0 requests whose link delay alone exceeds {1000 * slo['C0']:.0f} ms: {100 * c0 / total:.1f} % of all requests, "
      f"so Q(control) <= {100 - 100 * c0 / total:.1f} %")
rng, all_lat, clean_lat = random.Random(2), [], []
for s in streams:
    for _ in range(max(50, round(s.rate * 40))):
        t = latency(s.netem, s.route_class, 0.9, rng)
        if t <= slo[s.route_class]:
            all_lat.append(t)
            if s.netem in ("perfect", "broadband"):
                clean_lat.append(t)
print(f"pooled p95 of the control's successes: {1000 * np.quantile(all_lat, .95):.0f} ms on all links, "
      f"{1000 * np.quantile(clean_lat, .95):.0f} ms on the clean links")
```

Output at 7528089:

```
reuse 100%: Q(control) 90.1 %, clean links 100.0 %, broadband 100.0 %, mobile_3g 67.5 %, mobile_bad 33.3 %, perfect 100.0 %
reuse 90%: Q(control) 89.4 %, clean links 100.0 %, broadband 100.0 %, mobile_3g 64.5 %, mobile_bad 30.8 %, perfect 100.0 %
reuse 70%: Q(control) 88.2 %, clean links 100.0 %, broadband 100.0 %, mobile_3g 59.1 %, mobile_bad 27.0 %, perfect 100.0 %
request share: {'perfect': 39.3, 'broadband': 37.0, 'mobile_3g': 17.2, 'mobile_bad': 6.5}
C0 requests whose link delay alone exceeds 100 ms: 8.1 % of all requests, so Q(control) <= 91.9 %
pooled p95 of the control's successes: 245 ms on all links, 53 ms on the clean links
```

Option A2 (section 4.1) is the same model with two lines changed: `latency` also returns `allowance = mean * (2 if new else 1)`, and the
success test is `t - allowance <= slo[route]`. Output: Q(control) **99.1 %, 99.0 % and 98.7 %** at connection reuse 100, 90 and 70 %.

## Appendix B: the contract changes

`run.json` (HG1b 5.5), additions marked:

```json
{
  "role": "attack", "mode": null, "started_utc": "2026-10-24T08:00:00Z",
  "executor": {"ok": true, "reasons": [], "t0_spread_legit_s": 0.12, "attack_start_error_s": 0.05,
               "estimator": "exit-minus-consistent-wall", "setup_retries": 0,
               "wall_gap_s": {"L-poisson-C0-broadband-1": 0.0, "L-poisson-C1-perfect-0": 0.07}},
  "streams": [{"id": "L-poisson-C0-broadband-1", "kind": "legit", "route_class": "C0", "netem": "broadband",
               "summary": "streams/L-poisson-C0-broadband-1/loadgen.summary.json",
               "records": "streams/L-poisson-C0-broadband-1/loadgen.records.csv.gz", "offset_s": 0.03}]
}
```

`block.json` gains `scenario_sha256` and `plan_sha256` (the hash of the legit streams, equal in the three runs). The calibration gains:

```json
"judged_profiles": ["perfect", "broadband"],
"drift_reference": {"rho_rps": 90.0, "q_pct": 100.0, "p95_s": 0.053,
                    "attack": {"costly_search_flood": {"level": 2.0, "q_pct": 71.0, "p95_s": 0.060}}},
"host": {"uname": "...", "cpus": 8, "mem_mib": 9426, "pins": {"server": "0-1", "daemon": "2", "legit": "6", "attack": "3-5,7"},
         "gunicorn": {"version": "26.2.0", "workers": 2, "threads": 8, "nofile": 524288},
         "nginx": {"version": "1.28.3", "conf_sha256": "..."}, "origin_sha256": "...", "loadgen_sha256": "...", "origin_seed": 1}
```

(The values above are shapes, not results.) A placeholder may leave `drift_reference` null; a frozen record may not.

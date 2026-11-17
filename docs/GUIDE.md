# Running and interacting with the system

This guide is for a reader who has this repository and a fresh Ubuntu virtual machine and wants to run every kind of
simulation the project ran, and to look at the system while it runs. It is task-oriented: to do X, run Y, expect Z,
check W. The reference manual is [`EVALUATION.md`](EVALUATION.md) (modes, settings, outputs, metrics, statistics); this
guide links to its sections instead of repeating them. What was done, when, and with what outcome is in
[`PROJECT_HISTORY.md`](PROJECT_HISTORY.md); what each result may be cited for is in
[`THESIS_CLAIMS.md`](THESIS_CLAIMS.md).

Conventions:

* Every command runs from the repository root. `venv/bin/python` is the virtual environment of [section 3](#3-setup).
* **(root, VM)** marks a command that changes the machine (namespaces, Nginx, XDP, iptables, processes, logs). Run it
  only on a disposable VM, never on a workstation ([section 2](#2-safety-first)).
* **(offline)** marks a command that needs no root and sends no traffic. Every offline command shown with its output was
  run for this guide on 2026-11-17, at commit `4f31066`, in a sandbox without network; the output is shortened (`...`)
  and its scratch paths are written as `/tmp/...`.
* "the record" is a frozen calibration record of the harm benchmark under [`bench/calibration/`](../bench/calibration/).

Contents: [1 Mental model](#1-mental-model) · [2 Safety first](#2-safety-first) · [3 Setup](#3-setup) · [4 Offline
work](#4-offline-work-no-root) · [5 The running system](#5-interacting-with-the-running-system-root-vm) · [6 The testbed
suite and campaigns](#6-the-testbed-suite-and-campaigns) · [7 The harm benchmark](#7-the-harm-benchmark) · [8 The L7 and
GRU pipelines](#8-the-l7-and-gru-pipelines) · [9 Reproducing published results](#9-reproducing-published-results) · [10
Building the thesis](#10-building-the-thesis) · [11 Troubleshooting](#11-troubleshooting)

## 1. Mental model

**The protected host** runs three things:

* **The mitigation daemon**, [`control_plane.py`](../control_plane.py). Through BCC it compiles and attaches the XDP
  program [`xdp_ddos_filter.c`](../xdp_ddos_filter.c) to the interface `veth_server`. The program counts per-source
  telemetry (`telemetry_map`, `flow_map`) and drops packets from sources in `blacklist_map` before the kernel's network
  stack sees them. Deterministic rule engines in the daemon read that telemetry, the socket table (`ss`) and Nginx's
  access and error logs, and ban a source for 300 s (`BAN_TTL_SECONDS`), into the XDP blacklist or, with
  `MITIGATION_BACKEND=iptables`, as an iptables DROP rule. The engines that can ban are `l4_syn`, `l4_volumetric`,
  `l4_slowconn`, `l4_lowsyn`, `l7_rate`, `l7_rudy`, and three that are off by default: `gru`, `l4_slowconn_pc` and
  `l7v2` ([`EVALUATION.md`, "Ban events"](EVALUATION.md#ban-events-ban_eventsjsonl)).
* **The service**: Nginx in front of Gunicorn. The suite serves [`dummy_app.py`](../dummy_app.py) behind
  [`nginx.conf`](../nginx.conf) (with `limit_req` and `limit_conn`) or
  [`nginx_unprotected.conf`](../nginx_unprotected.conf); the harm benchmark serves the cost-calibrated origin
  [`bench/origin.py`](../bench/origin.py).
* **The event log**: every start, ban, unban and error of the daemon is one JSON line
  ([`ban_events.py`](../ban_events.py)), `ban_events.jsonl` in the run's directory.

**Optional modules, all off by default**: the XDP-fed GRU (`XDP_GRU=1`), the L7 shadow engine on Nginx's request log
(`L7_SHADOW=1`, observe-only), the L7 v2 enforcing arm (`L7_ENFORCE=1`), the per-connection slow rule (`SLOW_PC=1`,
shadow; `SLOW_PC_ENFORCE=1` to act) and the tolerant threshold profile (`HEURISTIC_PROFILE=tolerant`). [Section
5](#5-interacting-with-the-running-system-root-vm) lists every switch.

**The testbed** is one Linux VM with network namespaces on a bridge. The suite's layout
([`test_distributed_suite.py`](../test_distributed_suite.py), lines 40-58):

```
                         host (default) namespace: bridge ddos_br0
        +-----------------------------+------------------------------+
        |                             |                              |
  legit_* x 20                     bot_* x 5 (10 at the knee)     server_ns  10.0.0.1
  10.0.1.x, curl clients           10.0.2.x, wrk / hping3 /       veth_server  <-- XDP program here
  each with a netem profile        slow-attack scripts            Nginx :80/:443 -> Gunicorn 127.0.0.1:8080
  (perfect, broadband,                                            control_plane.py (the daemon)
   mobile_3g, mobile_bad)
```

The harm benchmark's executor builds its own layout with the suite's primitives: `server_ns` and four client namespaces
(`hg_0_perfect`, `hg_1_broadband`, `hg_2_mobile_3g`, `hg_3_mobile_bad`) that carry about 200 legit and attack addresses
between them ([7.2](#72-one-run-and-one-gate-campaign)).

**Two benchmarks.**

1. **The suite and its campaigns** (`test_distributed_suite.py`, `eval/`). Ten attack scenarios against 20 legit
   clients, one run in one of four modes (`xdp`, `iptables`, `nginxlimits`, `unprotected`); it measures the share of
   legit requests answered within 10 s before, during and after each attack, the bans and the time to mitigate.
   `eval/run_campaign.py` interleaves runs into paired blocks, `eval/analyze_campaign.py` and `eval/run_level_stats.py`
   judge them.
2. **The harm benchmark** (`bench/`, `eval/harm_gate.py`). Built so that an attack is shown to harm the unprotected
   server before a defence is judged: a calibration record of the host (route costs, capacity, each attack family's
   knee, a reference), open-loop load from [`bench/loadgen.py`](../bench/loadgen.py), blocks of a control `C`, a placebo
   `Cp`, the unprotected attack `U` and a protected arm `M_<mode>`, a gate and a pre-registered outcome.

**The simulated host**, [`bench/sim_host.py`](../bench/sim_host.py), answers the harm benchmark's commands from a model
of the testbed on a virtual clock. The unit tests and every `--simulate` option run on it. It shows the protocol working
and says nothing about any server.

## 2. Safety first

### 2.1 What root changes

The suite, the campaign runner, the harm benchmark's runners, the L7 runners, `capture_testbed_dataset.py`, `setup.sh`
and the daemon itself, between them, kill processes (the suite and `setup.sh` by name), delete and re-create network
namespaces and a bridge, attach and detach XDP, flush iptables in `server_ns` and truncate or move Nginx's logs under
`/var/log/nginx/`. The full list for a suite run is [`EVALUATION.md`, "Side effects of a suite run
(root)"](EVALUATION.md#side-effects-of-a-suite-run-root); the harm benchmark's runners are described in ["The harm
benchmark's runners (HG1c)"](EVALUATION.md#the-harm-benchmarks-runners-hg1c) (they never kill by pattern and refuse a
machine with leftovers). The legacy [`setup.sh`](../setup.sh) also installs Nginx with apt when it is missing and stops
and disables the distribution's Nginx service. **Use a disposable VM**, take a snapshot before the first root command,
and keep nothing else on it.

### 2.2 Validity checklist for a measurement

Three precautions decide whether a measurement counts at all: **the VM's host must not sleep**, **the VM must be idle
apart from the step**, and **automatic package updates must be suspended** for the whole window (and restored
afterwards). Items 1, 5 and 3 below say how; the rest are the checks the tools add.

A run on a disturbed host can look like harm or like mitigation. The 2026-11 campaigns enforced the points below by tool
(the packet pre-checks of [`bench/packets/prechecks.py`](../bench/packets/prechecks.py), the per-run host check of
[`bench/hostcheck.py`](../bench/hostcheck.py)) or by an operator's rule written into the pre-registrations
([`HS1_PREREG.md`](HS1_PREREG.md) section 2, [`RECALIBRATION_2026-11_DESIGN.md`](RECALIBRATION_2026-11_DESIGN.md) D2 and
5, [`RECALIBRATION_2026-11_PREREG.md`](RECALIBRATION_2026-11_PREREG.md)). Items marked *operator's observation* come
from the project's operation notes, not from a published file.

1. **The VM's host must not sleep.** HS1 required the PC plugged in, sleep and hibernation off on AC power and the lid
   set to do nothing ([`HS1_PREREG.md`](HS1_PREREG.md) 2.6); the re-calibration held "on the PC sleep and hibernation
   off" (D2); HS1 notes that "a full suspension (host sleep) moves the clock" ([`HS1_PREREG.md`](HS1_PREREG.md) 8.3).
   *Operator's observation, in no published file*: on 2026-11-11 the host PC slept while nobody was at it; the guest
   froze with no trace in its own logs, and afterwards its clock was hours behind true time while chrony slewed it back.
   The laptop can also sleep through Windows Modern Standby, so its sleep settings on AC power must be off for the whole
   window.
2. **Check the guest clock against an outside source before a step** (HS1 2.3: within 1 s of an outside HTTPS `Date`
   header). For example `date -u` beside `curl -sI https://www.kernel.org | grep -i '^date:'`, and `chronyc tracking`.
   The packet pre-check and H4 require chrony synchronised: leap status normal, |System time| under 0.1 s, a selected
   source within 1 s.
3. **Suspend automatic package updates and system timers: no package job and no timer inside a step.** For the 2026-11
   programme five timers were masked (`apt-daily`, `apt-daily-upgrade`, `fwupd-refresh`, `logrotate`, `man-db`) and the
   kernel packages held (`linux-generic`, `linux-headers-generic`, `linux-image-generic`)
   ([`HS1_PREREG.md`](HS1_PREREG.md) 2.2); `unattended-upgrades.service` was disabled on 2026-11-15 after the pre-check
   refused R1 on a running package job
   ([`results/2026-11-15_harm-recalibration/README.md`](../results/2026-11-15_harm-recalibration/README.md), D-107). HS1
   also recommends masking `motd-news`, `update-notifier-*`, `dpkg-db-backup`, `fstrim`, `e2scrub_all`, `xfs_scrub_all`
   and holding snap refreshes. With systemd's and apt's own commands that is, for example (root, VM; not run for this
   guide, and the repository does not record the exact commands the operator typed):

       sudo systemctl mask --now apt-daily.timer apt-daily-upgrade.timer fwupd-refresh.timer logrotate.timer man-db.timer
       sudo apt-mark hold linux-generic linux-headers-generic linux-image-generic
       sudo systemctl disable --now unattended-upgrades.service
       systemctl list-timers --all                     # the five timers must not show a next run

   `mask` alone only stops the timers from being started again; `--now` also stops those already active (systemctl(1)).
   **Undo all of it when the measurements are over**: `sudo systemctl unmask ...` and then `sudo systemctl start ...`
   for the same timers (or a reboot; unmasking does not start them), `sudo apt-mark unhold ...` and
   `sudo systemctl enable --now unattended-upgrades.service`. A VM left without updates and log rotation is not a VM to
   keep. A rotated Nginx log in the middle of a campaign was seen once before the timers were masked: the first review
   found the access log of the 2026-10-11 campaign "rotated by logrotate at 12:34:25 mid-campaign"
   ([`REPORT.md`](REPORT.md), section 7).
4. **Mind the daily window.** The pre-check refuses a packet when an apt, dpkg or daily timer is due within the packet's
   worst-case length (180 min) plus 10 min (`DUE_MARGIN_S`, `PACKET_MIN`). With `dpkg-db-backup.timer` due at 00:00 UTC
   every day, no packet can start from about 20:50 UTC to midnight: AP-13's first launch was refused at 21:37:08Z for
   that reason and started at 00:40Z, after the timer and the weekly `fstrim`
   ([`packets/r_launch_20261115T213308Z.log`](../results/2026-11-15_harm-recalibration/packets/r_launch_20261115T213308Z.log),
   [`after_timers_launch_20261115T213900Z.log`](../results/2026-11-15_harm-recalibration/packets/after_timers_launch_20261115T213900Z.log)).
5. **Keep the VM idle apart from the step.** No unit tests, no other workload, nothing typed into an agent session on
   the VM (HS1 2.4 and 2.5). The pre-check refuses when any process that is not the testbed's uses more than 5 % of a
   CPU over 60 s (`QUIET_PCT`), and H6 judges the same during every run. One drift attempt of 2026-11-11 was disturbed
   by the session's own activity and is kept as recorded ([`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), HB1).
6. **Wait 30 minutes after a boot** (`UPTIME_MIN_S` 1800, the environment gate's uptime) and start a step only with the
   load low: the executor's environment gate waits for uptime 30 min and load below 0.3, the timer gate for a timer
   probe with p99 under the record's `validity.timer_p99_ms` (10 ms).
7. **The host's speed must be the record's.** The VM's speed can change from the host side with an idle guest: on
   2026-11-11 the origin refused its own start because the routes cost 26-68 % more than the frozen record
   ([`results/2026-11-11_harm-drift-check/README.md`](../results/2026-11-11_harm-drift-check/README.md)). A packet
   starts with a speed hold (two probe pairs in a row within 10 %), and every run is bracketed by speed probes (H1).
8. **One host per record.** A frozen record names its host (kernel, MemTotal, CPU model, VirtualBox version), and every
   step refuses another host (`calibration.host_problems`). After a change of PC, VirtualBox, guest memory or kernel the
   benchmark must be calibrated again; the 2026-11-04 record (the desktop) cannot be used on the laptop
   ([`RECALIBRATION_2026-11_DESIGN.md`](RECALIBRATION_2026-11_DESIGN.md)).
9. **Raw data under `/var/tmp` is deleted after 30 days** by systemd-tmpfiles
   ([`bench/vm/README.md`](../bench/vm/README.md), "Read before running"). Publish what a result needs
   ([6.4](#64-publish-a-campaign)).

The host checks that enforce these on the VM: [`bench/hostcheck.py`](../bench/hostcheck.py) (H1 speed bracket, H3-H7
from `mpstat`, `pidstat`, chrony and the journal, a host-invalid run kept as `<run>.hostinvalid<k>`), the HS1 series
[`bench/vm/hs1_series.sh`](../bench/vm/hs1_series.sh), [`hs1_probe.py`](../bench/vm/hs1_probe.py) and
[`hs1_eval.py`](../bench/vm/hs1_eval.py) (a 3-h stability check of an idle host, [`HS1_PREREG.md`](HS1_PREREG.md)), and
the paired check [`bench/vm/paired_check.py`](../bench/vm/paired_check.py) (P-1: the speed probe as the user and as root
agree within 5 %). HS1's script writes only under a directory of the orchestrator's workspace, hard-coded as the
constant `HOST_BASE` (`hs1_series.sh` line 23), and runs its probes through that workspace's sandbox runner (the
environment variable `HS1_SBX`, empty to run without it): on another machine the constant must be edited, which is a
change of the pre-registered script.

## 3. Setup

### 3.1 Packages

The testbed VM ran Ubuntu 26.04 LTS with kernel 7.0.0-42 and Python 3.14.4 ([`README.md`](../README.md), "Environment").
BCC comes from apt, so the virtual environment must see the system packages. The packages the code calls, as installed
on the testbed VM (`dpkg-query`, 2026-11-17):

    sudo apt install python3-venv python3-bpfcc bpfcc-tools python3-psutil nginx hping3 wrk iproute2 ethtool \
        curl iputils-ping openssl sysstat chrony bpftool git

* `python3-psutil`: the suite and the campaign runner run under the system `python3` as root
  (`sudo python3 eval/run_campaign.py` starts the suite with `sys.executable`), and the suite imports `psutil`.
* `hping3`, `wrk`, `curl`, `ping`, `tc`, `ip`, `ethtool`: the suite's dependency check (`test_distributed_suite.py`,
  `main`).
* `sysstat` (`mpstat`, `pidstat`) and `chrony` (`chronyc`): the harm benchmark's host check, H3-H7.
* `bpftool`: the executor's teardown looks for XDP programs and maps left loaded.
* k6 and vegeta are external load tools pinned by sha256 in [`bench/loadtools.json`](../bench/loadtools.json) under
  `~/loadtools`; only the load-tool validation ran them (the suite also accepts `FLOOD_TOOL=k6`). The in-repo engine
  `bench/loadgen.py`, which EXP-C and the harm benchmark use, needs nothing.

### 3.2 The virtual environment

    python3 -m venv --system-site-packages venv
    venv/bin/pip install -r requirements.txt
    venv/bin/pip install -r requirements-plot.txt    # optional: matplotlib, for the figures only

[`requirements.txt`](../requirements.txt) pins gunicorn, joblib, numpy, pandas, psutil, requests, scikit-learn, scipy,
torch and urllib3 at the testbed's versions. The suite and the runners look for `venv/bin/python` in the checkout they
run from: the suite stops at once without it.

### 3.3 Which Python runs what

| Runs under | What | Evidence |
|---|---|---|
| the system `python3`, as root (`sudo python3 ...`) | `test_distributed_suite.py` and `eval/run_campaign.py` (standard library and `psutil`, from `python3-psutil`); the suite starts Gunicorn and the daemon with the checkout's `venv/bin/python` | `"python": "/usr/bin/python3"` in the `campaign.json` of EXP-A, EXP-C and the 2026-10-20 regression run; `PYTHON_VENV` in the suite |
| `./venv/bin/python -B`, as root | every step of the harm benchmark on the VM: `bench/hostcheck.py speed-hold`, `bench/calibrate.py`, `bench/executor.py run`, `bench/gate_campaign.py run` (through `bench/packets/packet.sh`) | the packet logs, e.g. `R1_20261115T180935Z.log` lines 11 and 16, `R4_20261116T115437Z.log` line 8, `P2-2_20261116T173249Z.log` line 8 |
| `venv/bin/python`, as the user | every offline tool: analysis, publication, the harm gate, the plans, the simulated host, the calibrator's `plan` and `freeze`, `bench/hg4_spec.py`, the unit tests | this guide's offline runs |

The system `python3` has no numpy (Ubuntu's `python3-numpy` is not installed). In the offline sandbox at `4f31066`,
`python3 bench/gate_campaign.py plan`, `python3 bench/calibrate.py plan`, `python3 bench/hg4_spec.py`, and
`eval/harm_gate.py`, `eval/publish_campaign.py`, `eval/analyze_campaign.py` and `eval/run_level_stats.py` under
`python3` all stop with `ModuleNotFoundError: No module named 'numpy'`; `bench/scenario.py`, `bench/calibration.py`,
`bench/origin.py`, `bench/executor.py plan`, `bench/loadgen.py`, `bench/packets/prechecks.py`, `bench/hostcheck.py`,
`eval/expc_probe.py` and the pure-Python P2 recomputation run under it. On the testbed VM a numpy in the user's own site
directory hid this, so some usage lines in the code were written with `python3`; where a tool needs numpy, use
`venv/bin/python` whatever its usage line says. Use `venv/bin/python` for everything but the suite and the campaign
runner.

### 3.4 Confirm it works

    venv/bin/python -m unittest discover -s tests                     # (offline) the whole suite
    venv/bin/python -m unittest tests.test_harm_gate -v               # (offline) one module

The whole suite is about 3,600 tests and took about 39 minutes on the laptop VM; the commit message of `18386ed` records
"Ran 3579 tests in 2317.345s, FAILED (failures=1, skipped=21)". The one failure is known and environmental
([11.5](#115-the-known-unit-test-failure)). On a quieter or faster machine the suite is shorter; no test needs root or
network, and the suite's import guard keeps the testbed's cleanup from running.

## 4. Offline work (no root)

### 4.1 Unit tests

[3.4](#34-confirm-it-works). What they cover: [`EVALUATION.md`, "Tests"](EVALUATION.md#tests). A module that reads the
documents (for example `tests.test_p4_outcome`, `tests.test_slow_pc_rule`, `tests.test_daemon_robustness`) fails when a
pinned sentence of [`EVALUATION.md`](EVALUATION.md) changes.

### 4.2 Plan a harm-benchmark run without running it

Check every scenario and print one plan against the laptop's record (offline):

    $ venv/bin/python bench/scenario.py --check bench/scenarios/*.json
    bench/scenarios/benign_control.json: valid
    bench/scenarios/cheap_static_flood.json: valid, paired with benign_control
    ...
    $ venv/bin/python bench/scenario.py --plan bench/scenarios/cheap_static_flood_hg4.json \
          --calibration bench/calibration/ddos-mitigation-2026-11-16.json
    == cheap_static_flood_hg4: attack, cheap_static_flood, class F ==
    calibration   frozen sha256:7005a2ed (2026-11-16T10:05:07+00:00)
    timeline      30 s baseline + 45 s attack + 30 s recovery = 105 s a run
    legit load    rho 42.25 req/s = 0.5 x c_slo 84.5; mean cost 9.02 ms; ...
    attack        cheap_static_flood on C1 (5.11281 ms unloaded) from 5 sources
      total 596.26 req/s = 119.251 req/s a source; cost 3.0485 CPU-s/s = 8.000 S
      ...
        limit_req  30 req/s  119.251  3.975  ABOVE; below it from 20 sources
        l7_rule    50 req/s  119.251  2.385  ABOVE; below it from 12 sources

Inspect the record, the origin's routes and the generator's schedule (offline):

    $ venv/bin/python bench/calibration.py show bench/calibration/ddos-mitigation-2026-11-16.json
    {
     "c_slo_rps": 84.5,
     ...
     "knees": {
      "cheap_static_flood": 4.0,
      "costly_export_flood": 4.0,
      "costly_search_flood": 2.0
     },
     ...
     "sha256": "7005a2edfcbf0acae1737b0a384f52aaa28169f6193fdd56e53eb48d4f2fb01c",
     "status": "frozen"
    }
    $ venv/bin/python bench/origin.py --routes
    C0  /static/(\d{1,6})
    C1  /page/(\d{1,9})
    ...
    $ venv/bin/python bench/loadgen.py --url http://10.0.0.1/ --rate 100 --duration 10 --plan
    constant: 1000 requests over 10 s (first 0.0000 s, last 9.9900 s)

What one run and one campaign would do, command by command (offline; `executor.py plan` prints the topology, the stack,
the daemon's exact environment and every stream):

    $ venv/bin/python bench/executor.py plan bench/scenarios/cheap_static_flood_hg4.json \
          --calibration bench/calibration/ddos-mitigation-2026-11-16.json --kind M_xdp --seed 1
    == run M_xdp (mitigated) of cheap_static_flood_hg4, seed 1 ==
    ...
    mode          xdp: nginx.conf's limits, and control_plane.py banning into XDP (MITIGATION_BACKEND=xdp, XDP_GRU=0)
    pins          server 0-1, daemon 2, executor 6, legit 7, attack 3-5: ...
    $ venv/bin/python bench/gate_campaign.py plan bench/scenarios/cheap_static_flood_hg4.json \
          --calibration bench/calibration/ddos-mitigation-2026-11-16.json --modes xdp
    == gate campaign: cheap_static_flood_hg4 (calib), 10 blocks ==
    ...
    VM time      41 runs at about 150 s = 1.7 h; each re-run adds 10.0 min (4 runs); at most 2 re-runs, 20.0 min
    $ venv/bin/python bench/calibrate.py plan
    ...
    runs    3 capacity + 54 screening + 20 reference = 77; ... 2.9 h (the origin step is 0.1 h more)

### 4.3 Run the harm benchmark on the simulated host

The whole protocol runs offline on [`bench/sim_host.py`](../bench/sim_host.py): directories marked `SIMULATED`, nothing
measured. A calibration session, its freeze and its drift check (each step takes seconds):

    $ S=/tmp/sim_session
    $ venv/bin/python bench/calibrate.py origin   --simulate --out $S
    $ venv/bin/python bench/calibrate.py capacity --simulate --out $S
    capacity: C_slo 142.8 req/s, C_sat 407.9 req/s
    $ venv/bin/python bench/calibrate.py ladder --simulate --family cheap_static_flood --out $S     # and the other two families
    ladder cheap_static_flood: session valid; knee 2.0
    $ venv/bin/python bench/calibrate.py reference --simulate --out $S
    $ venv/bin/python bench/calibrate.py freeze --dir $S --out /tmp/sim_record.json
    {
     "c_slo_rps": 142.8,
     ...
     "status": "frozen"
    }
    $ venv/bin/python bench/calibrate.py drift --simulate --sim-capacity-cpu 1.10457 \
          --calibration /tmp/sim_record.json --out /tmp/sim_drift
    ...
    drift: within the frozen reference

`--sim-capacity-cpu 1.10457` gives the drift check's simulated server the capacity the session's had (the placeholder's
C_slo 180 req/s times its mean cost 6.1365 ms). Without it the drift check builds its server from the frozen record's
own C_slo and ends "drift: OUT of it" (exit 3): the check catching a host whose capacity changed. A record frozen on the
real VM is refused on the simulated host, which reports the desktop's kernel and CPU ("this host is not the one the
record was measured on"): use a record frozen on the simulated host, as here.

A gate campaign of ten blocks, its status and the judge (seconds):

    $ venv/bin/python bench/gate_campaign.py run bench/scenarios/cheap_static_flood.json \
          --calibration /tmp/sim_record.json --out /tmp/sim_gate --simulate pass
    warm-up run C at seed 1
    ...
    gate: PASS (simulated), 10 valid blocks of 10, 0 re-run(s)
    $ venv/bin/python bench/gate_campaign.py status /tmp/sim_gate
    campaign cheap_static_flood (calib), 10 blocks, calibration 0cbe3898 frozen, SIMULATED   # the hash differs per freeze
    ...
    gate PASS: 10 valid blocks of 10
    $ venv/bin/python eval/harm_gate.py /tmp/sim_gate --calibration /tmp/sim_record.json --md gate.md --json gate.json
    PASS: 10 valid blocks of 10

`--simulate fail` makes a harm too small to pass ("gate: FAIL (simulated)"); `small` and `latency` are the other
presets, and `--simulate-fault NAME[:N]` injects a fault. Running the same `run` command again resumes: every block says
"made already". HG4's spec `cheap_static_flood_hg4.json` runs only with `--modes` and at twice the record's knee, so it
is refused on a simulated record whose knee is 2.

### 4.4 Analysis and publication on a published entry

These rewrite files: point `--out` elsewhere, or work on a copy, when you only want to look.

    $ venv/bin/python eval/analyze_campaign.py results/2026-10-12_exp2a-knee_prototype --out /tmp/exp2a_analysis
    [+] analysis written to /tmp/exp2a_analysis/ (summary.md + tables)
    $ diff -r --exclude=figures results/2026-10-12_exp2a-knee_prototype/analysis /tmp/exp2a_analysis    # prints nothing
    $ venv/bin/python eval/run_level_stats.py results/2026-10-20_expa-knee-10-blocks
    | Scenario | Mode vs reference | Design | Mean diff (pp) | 95 % t-interval | ... | Decision | ... |
    | Distributed HTTP Flood | xdp vs unprotected (during) | paired by PROFILE_SEED (10 blocks) | +33.2 | [+26.1, +40.2] | ... | supported (+) | 3 |
    | Distributed HTTP Flood | iptables vs unprotected (during) | ... | +33.2 | [+26.1, +40.2] | ... | supported (+) | 3 |
    | Distributed HTTP Flood | nginxlimits vs unprotected (during) | ... | -22.5 | [-32.0, -13.1] | ... | supported (-) | 5 |

`eval/plot_campaign.py` needs matplotlib and stops with `ModuleNotFoundError` without it. `eval/publish_campaign.py`
([6.4](#64-publish-a-campaign)) writes `results/<name>/` of the checkout it lies in; on a copy of the repository,
publishing `results/2026-10-13_exp2a-knee_reproduction` again as a new name gave a directory equal to the original apart
from the figures, which it leaves out without matplotlib and says so:

    [!] no figures (No module named 'matplotlib'): analysis/figures/ is missing from this copy; ...
    [+] published 105 files (0.33 MB) to results/<name>/

## 5. Interacting with the running system (root, VM)

### 5.1 Start and stop the daemon by hand

The daemon attaches to `veth_server` in its own network namespace and opens `xdp_ddos_filter.c` and
`training_results/feature_config_testbed.json` by relative path, so it runs **inside `server_ns`, from the repository
root**, with Nginx writing `/var/log/nginx/ddos_ml_access.log` and `/var/log/nginx/error.log` beside it. The suite
starts it as (`test_distributed_suite.py`, `_daemon_cmd`):

    ip netns exec server_ns env MITIGATION_BACKEND=xdp BAN_EVENTS=<run dir>/ban_events.jsonl venv/bin/python -u control_plane.py

The simplest way to have a namespace, a service and the daemon by hand is the legacy two-namespace lab
[`setup.sh`](../setup.sh) **(root, VM)**: it builds `server_ns` (10.0.0.1) and `attacker_ns` (10.0.0.2) joined by one
veth pair, starts Gunicorn and Nginx (`nginx.conf`) in `server_ns`, and runs the daemon in the foreground:

    sudo bash setup.sh

The measurements never used it (its Gunicorn listens on `0.0.0.0:8080`, the bind the suite closed on 2026-10-30). It
also kills any Nginx master, Gunicorn and `control_plane.py` on the machine, deletes any `server_ns` and `attacker_ns`
first, rewrites `dummy_app.py` (with the same bytes) and runs `venv/bin/python -m pip install gunicorn`, which needs the
network when Gunicorn is missing. The daemon is ready when it prints the line that starts with
`[*] Listening for Nginx logs (heuristic engine)`. Traffic from the other side, for example a request and a short
open-loop load above the L7 rate rule's 50 requests/s:

    sudo ip netns exec attacker_ns curl -s http://10.0.0.1/
    sudo ip netns exec attacker_ns venv/bin/python bench/loadgen.py --url http://10.0.0.1/ --rate 100 --duration 5

**Stop** with Ctrl-C or SIGTERM (`sudo pkill -TERM -f control_plane.py`): both reach the daemon's `finally`, which
detaches XDP, and with it every XDP ban ([`EVALUATION.md`, "Daemon
robustness"](EVALUATION.md#daemon-robustness-2026-10-30)). SIGKILL, which the suite uses, leaves the program attached:
detach it with `sudo ip netns exec server_ns ip link set dev veth_server xdp off`. The executor stops a protected run's
daemon with SIGINT, then KILL after 10 s, then that same `xdp off`. Stopping the daemon leaves the rest of `setup.sh`'s
lab running; take it down with (root, VM; not run for this guide; the suite's `cleanup_all` does not know
`attacker_ns`):

    sudo ip netns pids server_ns | xargs -r sudo kill     # the lab's Nginx and Gunicorn
    sudo ip netns del server_ns && sudo ip netns del attacker_ns

### 5.2 The daemon's switches

Read by [`control_plane.py`](../control_plane.py) (line numbers at `4f31066`); the suite passes only
`MITIGATION_BACKEND` and `BAN_EVENTS` explicitly, the rest through the environment it inherits.

| Variable | Default | Effect | Line |
|---|---|---|---|
| `MITIGATION_BACKEND` | `xdp` | `iptables`: bans as `iptables -A INPUT -s IP -j DROP` in `server_ns` (XDP still collects telemetry) | 376 |
| `BAN_EVENTS` | `/var/log/ddos/ban_events.jsonl` | the event log's path; `""` disables it | 216, `ban_events.py` 38 |
| `XDP_GRU` | `0` (`1` when `GRU_ONLY=1`) | 1: the XDP-fed GRU's feed and drain (off since 2026-10-19) | 122 |
| `GRU_ONLY` | `0` | 1: only the GRU may ban (isolation tests) | 116 |
| `HEURISTIC_PROFILE` | `default` | `tolerant`: `l7_rate` at 108 r/s and SlowConn at 180 connections; anything else stops the daemon | 180 |
| `L7_SHADOW` | `0` | 1: the L7 engine reads Nginx's log over a datagram socket and logs `l7_would_ban`, never bans | 36 |
| `L7_SOCKET_PATH` | `/run/ddos_l7.sock` | that socket (`l7_ingest.DEFAULT_SOCKET_PATH`) | 37 |
| `L7_MODEL`, `L7_RECORD` | (none) | the shadow engine's model package; a file that records its exact input for replay | 44, 45 |
| `L7_ENFORCE` | `0` | 1: the L7 v2 enforcing arm; needs `L7_SHADOW=1`, `L7_NGINX_CONF`, `L7_SELECTION`, `L7_SELECTION_SHA256`, `L7_ARM`, and `L7_MODEL` unset | 52 |
| `L7_ENFORCE_DIR`, `L7_NGINX_CONF`, `L7_ALLOWLIST`, `L7_KILL_FILE`, `L7_SOCKET_GROUP`, `L7_SELECTION`, `L7_SELECTION_SHA256`, `L7_ARM` | `/run/l7v2`, none, none, `/run/l7v2/kill`, `nogroup`, none, none, none | the arm's settings ([`EVALUATION.md`, "L7 v2"](EVALUATION.md#l7-v2-the-enforcing-arm-2026-10-31)) | 53-68 |
| `SLOW_PC`, `SLOW_PC_ENFORCE` | `0`, `0` | the per-connection slow rule in shadow; 1 also closes and bans | 198, 199 |
| `SLOW_PC_KILL_FILE`, `SLOW_PC_RECORD` | `/run/l7v2/kill`, none | its kill switch; a gzip file of every poll's input | 200, 201 |
| `SLOW_PC_T`, `SLOW_PC_F`, `SLOW_PC_K` | 20, 16, 6 | a point of the frozen grid, else the daemon stops | 202-204 |

The suite's own settings (operating point, attack duration, seeds, flood tool, CPUs) are in [`EVALUATION.md`,
"Settings"](EVALUATION.md#settings); the modes are `MITIGATION_MODE=none`, `NGINX_PROTECTED=1` and `MITIGATION_BACKEND`
([`EVALUATION.md`, "Modes"](EVALUATION.md#modes)).

### 5.3 Watch it

* **Events**: `tail -f <run dir>/ban_events.jsonl` (or the `BAN_EVENTS` path). Every line has `t_wall`, `t_mono_ns` and
  `kind`; a ban names its `engine`, `reason`, `value` and `threshold`. Schema: [`EVALUATION.md`, "Ban
  events"](EVALUATION.md#ban-events-ban_eventsjsonl).
* **Console**: the daemon prints `[BAN] <ip> banned for 300s. Reason: ...` and `[TTL] Unblocked IP: ...`. In a suite run
  it goes to `/tmp/mitigation_distributed_test.log` and is appended to the run's `daemon.log`; in a harm-benchmark run
  to the run's `daemon.log`.
* **XDP**: `sudo ip netns exec server_ns ip -j link show veth_server` (the attached program's id under `xdp.prog.id`, as
  the executor reads it), `sudo bpftool prog show`, `sudo bpftool map show`, and the bans themselves with
  `sudo bpftool map dump name blacklist_map` (keys are IPv4 addresses in network byte order).
* **iptables** (with `MITIGATION_BACKEND=iptables`): `sudo ip netns exec server_ns iptables -L INPUT -n -v`.
* **Nginx**: `/var/log/nginx/ddos_ml_access.log` and `error.log`, which the daemon reads. The suite truncates them
  whenever it starts the services; the harm benchmark's executor gives every run its own `nginx_access.log` and
  `nginx_error.log`, and a protected run first moves the host's logs into its `feed_before/`.

### 5.4 Unban and clear state

There is no unban command. A ban ends after its TTL of 300 s (an `unban` event). To clear every ban, stop the daemon:
XDP is detached with its blacklist. With the iptables backend a stopped daemon leaves its DROP rules: flush them with
`sudo ip netns exec server_ns iptables -F` (the suite does the same at every reset). A whole testbed is cleared by the
next suite run (`build_topology` calls `cleanup_all` first), by `--clean` of the harm benchmark's runners, or by a
reboot ([11.4](#114-stale-namespaces-or-processes-after-a-crash)).

### 5.5 Which Nginx configuration each mode serves

| File | Served by |
|---|---|
| [`nginx.conf`](../nginx.conf) | suite modes `xdp`, `iptables`, `nginxlimits` (`limit_req` 30 r/s, `limit_conn` 50); harm benchmark `M_xdp` and `M_limits` (a run's copy with its log paths changed); `setup.sh`; `capture_testbed_dataset.py`; P1's M arms (`l7_conf.protected`) |
| [`nginx_unprotected.conf`](../nginx_unprotected.conf) | suite mode `unprotected`; harm benchmark `C`, `Cp`, `U` (pinned by its sha256); P1's C, C', U (`l7_conf.unprotected`) |
| [`nginx_l7capture.conf`](../nginx_l7capture.conf) | `ml/capture_l7.py` (the l7json log to a lossless file) |
| [`nginx_profile_r.conf`](../nginx_profile_r.conf), [`nginx_profile_r_limits.conf`](../nginx_profile_r_limits.conf) | P4's profile R (`eval/p4_runner.py`; [`EVALUATION.md`, "P4"](EVALUATION.md#p4-the-per-connection-slow-rule-and-profile-r-2026-10-30)) |

`ml/eval_l7.py` and `ml/smoke_l7.py` render their own copies of `nginx.conf` with the L7 socket sink.

## 6. The testbed suite and campaigns

### 6.1 One suite run (root, VM)

    sudo python3 test_distributed_suite.py                                  # all ten scenarios, mode xdp, default point
    sudo env MITIGATION_MODE=none python3 test_distributed_suite.py         # the unprotected mode
    sudo env OPERATING_POINT=knee ONLY_SCENARIOS=4 ATTACK_DURATION=30 python3 test_distributed_suite.py

The scenarios, in order (`ONLY_SCENARIOS` picks a subset): 1 SYN flood, 2 slow SYN, 3 UDP flood, 4 HTTP flood, 5 ACK
flood, 6 fragmentation, 7 Slowloris, 8 R.U.D.Y., 9 Yo-Yo (a pulsing flood), 10 multi-vector. Each run writes a new
directory `/var/tmp/ddos_campaigns/<UTC>_<mode>/` (or `RESULTS_DIR`) with `provenance.json`, `scenario_results.csv`,
`availability.csv`, `availability_raw.csv`, `metrics.csv`, `server_requests.csv`, `ban_events.jsonl` and `daemon.log`
([`EVALUATION.md`, "Outputs of a run"](EVALUATION.md#outputs-of-a-run-results_dir)). One full run of the ten scenarios
took 11 minutes on 2026-10-20 ([`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), "What was run on 2026-10-20"). The settings and
their defaults: [`EVALUATION.md`, "Settings"](EVALUATION.md#settings) (note `ATTACK_DURATION` of at least 40 s for equal
exposure in all ten scenarios).

### 6.2 A campaign (root, VM), and what it took

`eval/run_campaign.py` runs every mode once per block, in a seeded order, with `PROFILE_SEED = --seed-base + block`,
each run in `<campaign>/<mode>/run<k>/`, and resumes when started again. It refuses a dirty tree (unless
`--allow-dirty`) and leftovers; `--dry-run` prints the plan and runs nothing. Options: `--modes`, `--runs`,
`--scenarios`, `--operating-point`, `--attack-duration`, `--seed-base`, `--order-seed`, `--set NAME=VALUE`, `--loads`,
`--out`.

| Campaign | Command | Time |
|---|---|---|
| full suite, new defaults (2026-10-20) | `sudo python3 eval/run_campaign.py --modes xdp --runs 1 --seed-base=-1` | 11 min |
| EXP-B, tolerant profile | `sudo env HEURISTIC_PROFILE=tolerant python3 eval/run_campaign.py --modes xdp --runs 3 --seed-base 200 --out /var/tmp/ddos_campaigns/20261020_tolerant-suite` | 33 min |
| EXP-A, knee, 10 paired blocks | `sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 10 --attack-duration 30 --seed-base 100` | 62 min |
| EXP-C, open-loop cells | `sudo timeout -s INT 28800 python3 eval/run_campaign.py --operating-point knee --scenarios 4 --attack-duration 30 --modes unprotected,nginxlimits,xdp --runs 10 --seed-base 100 --loads wrk,loadgen:125,loadgen:250,loadgen:500` | 3.85 h |

The commands and times are those of [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), "What was run on 2026-10-20 and what
remains". The EXP-C protocol is [`EXPC_PROTOCOL.md`](EXPC_PROTOCOL.md); the load model as a setting, [`EVALUATION.md`,
"Quick start"](EVALUATION.md#quick-start).

### 6.3 Worked example: EXP-A end to end

1. **Record** (root, VM, about an hour): from a clean tree at the commit you want to cite,

       sudo python3 eval/run_campaign.py --operating-point knee --scenarios 4 --runs 10 --attack-duration 30 --seed-base 100

   It prints each run as `[*] i/40 <mode>/run<k> (block b, PROFILE_SEED=s)` and writes `campaign.json` and a `DONE` per
   run into `/var/tmp/ddos_campaigns/<UTC>_knee_s4/`, handed to the user who ran `sudo`.
2. **Analyse** (offline): `venv/bin/python eval/analyze_campaign.py /var/tmp/ddos_campaigns/<campaign>` writes
   `analysis/summary.md` and the tables (`--window` sets the equal-exposure window, `--reference` the reference mode).
3. **Plot** (offline, needs matplotlib): `venv/bin/python eval/plot_campaign.py /var/tmp/ddos_campaigns/<campaign>`.
4. **Decide** (offline): `venv/bin/python eval/run_level_stats.py /var/tmp/ddos_campaigns/<campaign>`; a contrast is
   *supported* with at least 10 paired blocks, a 95 % t-interval excluding 0 and at least 80 % of the blocks with the
   mean's sign ([`EVALUATION.md`, "Statistics"](EVALUATION.md#statistics)). On the published EXP-A it prints the table
   of [4.4](#44-analysis-and-publication-on-a-published-entry).
5. **Publish** ([6.4](#64-publish-a-campaign)), then cite `results/<name>/`.

### 6.4 Publish a campaign

    venv/bin/python eval/publish_campaign.py /var/tmp/ddos_campaigns/<campaign> --name <yyyy-mm-dd_what>
    git add results/<yyyy-mm-dd_what> && git commit

It copies the run files, regenerates `analysis/` in the copy (and names every file that differs from an analysis the
source already had), writes `SHA256SUMS`, warns above 20 MiB and refuses over 100 MiB. The same tool publishes
harm-benchmark directories (one or more, `--with PATH` for READMEs and logs, `--calibration` for a drift check's
record): [`EVALUATION.md`, "The harm benchmark's runners (HG1c)"](EVALUATION.md#the-harm-benchmarks-runners-hg1c),
"Publishing". Write the entry's `README.md` and add a row to [`results/README.md`](../results/README.md); a published
entry is never edited afterwards.

## 7. The harm benchmark

The design is [`BENCHMARK_HARM_DESIGN.md`](BENCHMARK_HARM_DESIGN.md), the offline tools
[`HG1B_MINIMAL_DESIGN.md`](HG1B_MINIMAL_DESIGN.md), the runners [`HG1C_DESIGN.md`](HG1C_DESIGN.md) (section 14 lists
every departure), the 2026-11 re-calibration [`RECALIBRATION_2026-11_DESIGN.md`](RECALIBRATION_2026-11_DESIGN.md) and
its pre-registration [`RECALIBRATION_2026-11_PREREG.md`](RECALIBRATION_2026-11_PREREG.md). The tools in brief:
[`EVALUATION.md`, HG1b](EVALUATION.md#the-harm-benchmarks-offline-tools-hg1b) and
[HG1c](EVALUATION.md#the-harm-benchmarks-runners-hg1c).

### 7.1 The pieces

| Piece | File | Use |
|---|---|---|
| origin | [`bench/origin.py`](../bench/origin.py) | WSGI app with five route classes of known CPU cost: C0 `/static/<n>`, C1 `/page/<id>`, C2 `/api/item/<id>`, C3 `/search?q=`, C5 `/export`; served as `gunicorn --chdir bench origin:app` with `ORIGIN_CALIBRATION` set, refuses to start when a route is more than 25 % off the record |
| load generator | [`bench/loadgen.py`](../bench/loadgen.py) | open-loop engine; latency from the intended send time; validity flags; `--plan` sends nothing |
| population | [`bench/population.py`](../bench/population.py) | seeds, benign classes, attack families, link profiles, CPU pins |
| scenarios | [`bench/scenarios/*.json`](../bench/scenarios/) | `benign_control`, `cheap_static_flood` (HG3), `cheap_static_flood_hg4` (P2, level 8), `costly_export_sub_threshold`, `costly_search_sub_threshold` |
| record | [`bench/calibration/`](../bench/calibration/) | `placeholder.json` (template, no verdict), `ddos-mitigation-2026-11-04.json` (the desktop, never confirmed), `ddos-mitigation-2026-11-16.json` (the laptop, frozen and confirmed) |
| executor | [`bench/executor.py`](../bench/executor.py) | `plan` (offline), `run`, `smoke-topology`, `clock-probe` |
| gate campaign | [`bench/gate_campaign.py`](../bench/gate_campaign.py) | `plan`, `run` (root, or `--simulate`), `status` |
| judge | [`eval/harm_gate.py`](../eval/harm_gate.py) | PASS / FAIL / INVALID of a campaign, `--block` for one block, the P2 outcome (`P2_OUTCOME`) |
| calibrator | [`bench/calibrate.py`](../bench/calibrate.py) | `plan`, `origin`, `capacity`, `ladder --family F`, `reference`, `freeze`, `drift` |
| HG4 spec | [`bench/hg4_spec.py`](../bench/hg4_spec.py) | sets the tracked `cheap_static_flood_hg4.json` to twice a new record's cheap knee (`--write`; commit it before any run) |
| host check | [`bench/hostcheck.py`](../bench/hostcheck.py) | `speed-hold`, `judge`, `chrony-sampler` |
| packet | [`bench/packets/packet.sh`](../bench/packets/packet.sh), [`prechecks.py`](../bench/packets/prechecks.py) | one approved step: pre-checks, speed hold, the step detached with a time budget, tar, sha256, one-line summary |
| VM helpers | [`bench/vm/`](../bench/vm/README.md) | `vm_step.sh` (snapshots around a step; the steps of the first calibration and its drift checks ran through copies of it), HS1, P-1 |

### 7.2 One run and one gate campaign

    sudo ./venv/bin/python bench/executor.py run SPEC --calibration FILE --kind C --seed 1 --out DIR/C      # (root, VM)
    sudo ./venv/bin/python bench/gate_campaign.py run SPEC --calibration FILE --out DIR [--modes xdp]       # (root, VM)
    venv/bin/python bench/gate_campaign.py status DIR                                                     # (offline)
    venv/bin/python eval/harm_gate.py DIR --calibration FILE --md gate.md --json gate.json               # (offline)

`--kind` is `C`, `Cp`, `U`, `M_xdp` or `M_limits`. A run is 30 s baseline, 45 s attack and 30 s recovery; a campaign is
an unscored warm-up control and 10 blocks of `C`, `Cp`, `U` (and `M_<mode>` per `--modes`) in a drawn order, with at
most two block re-runs, and resumes when started again (`--stop-after MIN` pauses it, exit 4). `--rho`, `--timeline` and
`--timer-limit-ms` are smoke-test overrides, and a campaign that carries one gets no verdict. Every run is host-checked
(H1, H3-H7) unless `--no-host-check`. The run directory's files: [`EVALUATION.md`, HG1c, "A run
directory"](EVALUATION.md#the-harm-benchmarks-runners-hg1c). The gate and the P2 outcome:
[`results/2026-11-16_harm-p2-hg4/README.md`](../results/2026-11-16_harm-p2-hg4/README.md), "The pre-registered rule".

### 7.3 Calibrate a host

    sudo ./venv/bin/python bench/calibrate.py origin    --out SESSION        # route costs
    sudo ./venv/bin/python bench/calibrate.py capacity  --out SESSION        # C_slo, C_sat (3 staged runs)
    sudo ./venv/bin/python bench/calibrate.py ladder    --out SESSION --family cheap_static_flood   # and the other two
    sudo ./venv/bin/python bench/calibrate.py reference --out SESSION        # 5 rounds at the knees
    venv/bin/python bench/calibrate.py freeze --dir SESSION --out bench/calibration/<host>-<date>.json   # offline
    venv/bin/python bench/hg4_spec.py --calibration bench/calibration/<host>-<date>.json --write         # offline, HG4
    git add bench/calibration/<host>-<date>.json bench/scenarios/cheap_static_flood_hg4.json && git commit
    sudo ./venv/bin/python bench/calibrate.py drift --calibration bench/calibration/<host>-<date>.json --out DIR

All but `freeze`, `hg4_spec.py` and the commit are (root, VM). A step stops rather than tunes (exit 7, "not frozen", for
a step's own rule; exit 5, host unfit; exit 4, paused by `--stop-after`), and the same command resumes. `hg4_spec.py
--write` rewrites the tracked `bench/scenarios/cheap_static_flood_hg4.json` (the protected arms' spec, HG4) whenever the
new cheap knee is not 4, and leaves it unchanged otherwise. Commit the frozen record and that spec before the drift check
and before any campaign: the executor's preflight refuses uncommitted changes to tracked files (`bench/executor.py`,
`preflight`; `--allow-dirty` would record them, and a packet's tree check refuses them outright), and the drift run then
names a commit that contains its record. The programme committed the 2026-11-16 record at `ec819fb` before `drift`
confirmed it after a reboot (R4), and the HG4 spec after that, at `688594a`; the drift check does not read the spec.

A campaign that does not start in the confirmation's window needs a drift check of its own first (the pre-registration).

### 7.4 The packet wrapper

[`bench/packets/packet.sh`](../bench/packets/packet.sh) is the **2026-11 programme's wrapper for its own host**, not a
general tool. It wraps one approved step of that programme: `R1`, `R2a`, `R2b`, `R2c`, `R3`, `R4`, `P2-1` or `P2-2`. Its
pre-check holds R1 to the programme's laptop (`PROGRAMME_HOST` in `bench/packets/prechecks.py`: kernel 7.0.0-42-generic,
7,422 MiB, AMD Ryzen 7 7730U, VirtualBox 7.2.10r174163) and every later packet to the session's first step, so on any
other host R1 prints `NO host` and nothing starts. Its default session and campaign directories are the programme's
(`recal_2026-11`, `hg4_mvp_xdp_recal`), and R1 needs HS1's medians, which only `hs1_series.sh` makes, under its
hard-coded workspace directory. **On another host, run the steps of [7.3](#73-calibrate-a-host) and
[7.2](#72-one-run-and-one-gate-campaign) directly** (the pre-check's other rules, item by item, are in
[2.2](#22-validity-checklist-for-a-measurement)); adapting the wrapper means changing `PROGRAMME_HOST`, the defaults and
HS1's directory in a commit of its own, which starts a new programme. `--print` shows what it would do (offline):

    $ bash bench/packets/packet.sh R1 --print
    == packet R1: speed hold against HS1's medians on this PC (K11); origin step; capacity (3 staged runs) ==
    session     /var/tmp/ddos_campaigns/recal_2026-11
    budget      85 min: no run starts after it (--stop-after the minutes left). ...
    pre-checks  ./venv/bin/python -B bench/packets/prechecks.py --packet R1 --session /var/tmp/ddos_campaigns/recal_2026-11 --minutes 180 --commit COMMIT
    ...
    step 1      ./venv/bin/python -B bench/hostcheck.py speed-hold --calibration bench/calibration/placeholder.json --medians HS1_MEDIANS ...
    step 2      ./venv/bin/python -B bench/calibrate.py origin --out /var/tmp/ddos_campaigns/recal_2026-11
    step 3      ./venv/bin/python -B bench/calibrate.py capacity --out /var/tmp/ddos_campaigns/recal_2026-11 --stop-after REMAINING

As the programme ran it (root, VM, on the laptop only), each from a clean checkout at the pinned commit:

    sudo bench/packets/packet.sh R1 --commit SHA --medians HS1_MEDIANS.json --paired PAIRED_DIR
    sudo bench/packets/packet.sh R2a --commit SHA                       # likewise R2b, R2c, R3
    sudo bench/packets/packet.sh R4 --commit SHA --record bench/calibration/<record>.json
    sudo bench/packets/packet.sh P2-2 --commit SHA --record bench/calibration/<record>.json --campaign /var/tmp/ddos_campaigns/<dir>

The foreground runs the checks, prints one `OK` or `NO` line per pre-check (tree, frozen hashes, host, uptime, chrony,
timers, jobs, testbed, quiet, record) and starts the stage detached (`setsid nohup`), printing its pid and its log. Stop
it with `sudo kill -TERM <stage pid>`; the tar, its sha256 and the summary are still written, and the same command
resumes. The log ends with one summary line, `PACKET <name> <state> (exit N): runs made ..., host-invalid ...`, the
state being done, paused, host unfit, not frozen or stopped.

### 7.5 How the 2026-11 campaigns were actually run

Reconstructed from the published launcher and packet logs
([`results/2026-11-15_harm-recalibration/packets/`](../results/2026-11-15_harm-recalibration/packets/),
[`results/2026-11-16_harm-p2-hg4/packets/`](../results/2026-11-16_harm-p2-hg4/packets/)) and the two READMEs. Every step
had its own approval packet (AP-11 to AP-18, published in each entry's `preregistration/`). The orchestrator started
each step with a small launcher script that is **not published**. What each launcher did; *[logs]* marks what the
published launcher logs show, *[script only]* what only the unpublished scripts show (read for this guide, not
published, so not checkable here):

1. *[logs]* waited 180 s "for the orchestrator's turn to end", so that the agent session on the VM was idle when
   anything was measured; R4's launcher, started 91 s after a reboot, first waited for the uptime (its log: 90.92 s at
   the start, 1,861.47 s when it went on); *[script only]* the threshold, 1,860 s, in the R4 and P2 launchers;
2. *[script only]* changed into a dedicated clean checkout at the pinned commit and refused to go on unless `HEAD` was
   the pin (and, after the freeze, the record existed); *[logs]* the packet's own pre-checks `OK tree` and
   `OK frozen hashes` check the same;
3. *[logs]* for R1 only, ran P-1, `bench/vm/paired_check.py run DIR --medians <HS1's medians.json>` (two probe contexts
   within 5 %), and went on only on "GO ON";
4. *[logs]* ran `bench/packets/packet.sh <packet> --commit <pin> ...` as root and logged its pre-check lines and the
   stage's pid;
5. *[script only]* watched the stage's `/proc` entry once a minute; *[logs]* when the stage ended, printed the time and
   the packet log's last lines;
6. *[logs]* for `P2-2`, started the same command again 120 s after a packet ended "paused (exit 4)" (its 85-min budget),
   up to three packets ("max packets 3"), and stopped on any other ending.

| When (UTC) | What happened | Log |
|---|---|---|
| 2026-11-14 | HS1, the 3-h host check of the laptop: passed (its medians are R1's speed reference; the run itself is not published) | `recal_2026-11/speed_reference.json` in the re-calibration entry |
| 2026-11-15 15:57 | the pre-registration approved | entry README |
| 11-15 17:21-17:27 | R1, first launch: P-1 D +0.14 %, GO ON; pre-check `NO jobs: a package job runs`, the job being the service's idle helper `unattended-upgrade-shutdown --wait-for-signal`; exit 3, nothing started; `unattended-upgrades.service` was therefore disabled | `r1_launch_20261115T172154Z.log` |
| 11-15 18:04-18:33 | R1: P-1 D +0.03 %; all pre-checks OK; speed hold, origin, capacity: C_slo 84.5, C_sat 241.3 req/s; done (exit 0) | `r1_launch_20261115T180427Z.log`, `R1_*.log` |
| 11-15 18:43-19:49 | R2a, packet 1: 11 runs, 4 set aside by H7 (a race in reading the monitors); "host unfit (exit 5)"; R2b not started | `r2_launch_*.log`, `R2a_20261115T184751Z.log` |
| 11-15 | departure 1 (K22, post hoc): the judge reads the monitors 2 s after a run's window; new pin `9c0c25a` | [`RECALIBRATION_2026-11_DEPARTURE_1.md`](RECALIBRATION_2026-11_DEPARTURE_1.md) |
| 11-15 21:33-21:37 | R2a resume: pre-check `NO timers: dpkg-db-backup.timer is due at 00:00`; nothing started | `r_launch_20261115T213308Z.log` |
| 11-15 21:39 to 11-16 02:04 | a waiter let `dpkg-db-backup` (00:00) and the weekly `fstrim` pass, then R2a resumed (knee 4.0) and R2b ran (knee 4.0) | `after_timers_launch_*.log` |
| 11-16 08:02-10:02 | R2c (knee 2.0) and R3, the reference (5 rounds) | `r_launch_20261116T080211Z.log` |
| 11-16 10:05 | freeze, offline: `bench/calibrate.py freeze --dir <session> --out bench/calibration/ddos-mitigation-2026-11-16.json`; record `7005a2ed`, committed at `ec819fb` | entry README, "F, the freeze" |
| 11-16 11:19-12:33 | reboot by the user; R4 waited for 30 min of uptime, then confirmed the record for legit and all three families | `r4_launch_20261116T112106Z.log`, `R4_*.log` |
| 11-16 | HG4's spec set to level 8, twice the new cheap knee (K8, commit `688594a`; the tool is `venv/bin/python bench/hg4_spec.py --calibration <record> --write`) | P2 README, `git show 688594a` |
| 11-16 14:13-14:29 | P2-1: two smoke runs, `bench/executor.py run cheap_static_flood_hg4.json --kind M_xdp` and `--kind M_limits`, seed 1 | `p21_launch_*.log` |
| 11-16 14:34-15:47 | P2-2: 23 runs, 4 valid blocks; INVALID (exit 2): the attack began more than 0.5 s early in 3 runs | `p22_launch_*.log` |
| 11-16 | K23 (post hoc): the attack is launched from the legit engines' observed start; pin `18386ed` | [`HG1C_DESIGN.md`](HG1C_DESIGN.md) departure 42 |
| 11-16 17:28-19:40 | P2-2b in a new directory: packet 1 paused by its budget after 29 runs, packet 2 finished: gate PASS, P2 outcome NOT MET | `p22b_launch_20261116T172849Z.log` |

Both entries were published with `eval/publish_campaign.py` and recomputed offline
([9](#9-reproducing-published-results)).

### 7.6 The steps before 2026-11-14

The first calibration (2026-11-04, the desktop) and its drift checks (2026-11-08 to 11-11) were run with
[`bench/vm/vm_step.sh`](../bench/vm/vm_step.sh) around each `bench/calibrate.py` command, as the copies
[`bench/vm/README.md`](../bench/vm/README.md) describes:
`S=<records dir> bash bench/vm/vm_step.sh NAME -- sudo -n env PYTHONDONTWRITEBYTECODE=1 ./venv/bin/python -B bench/calibrate.py ...`.
`vm_step.sh --print NAME -- COMMAND` shows the plan (offline). Those steps and what they found:
[`results/2026-11-11_harm-drift-check/README.md`](../results/2026-11-11_harm-drift-check/README.md).

## 8. The L7 and GRU pipelines

All of this is off by default and none of it is part of a current claim of benefit
([`THESIS_CLAIMS.md`](THESIS_CLAIMS.md), L1-L3).

* **The XDP-fed GRU** (off by default since 2026-10-19, `XDP_GRU=0`): `capture_testbed_dataset.py` (root, VM) captures a
  labelled flow dataset against the real stack into `training_data/testbed_flows.csv`; `train_testbed_gru.py` (offline)
  trains on it and writes `training_results/gru_testbed_model.pth`, `scaler_testbed.save` and
  `feature_config_testbed.json`, which the daemon loads at start whatever `XDP_GRU` says. `ml/diagnose_gru.py` (offline)
  is the diagnosis of [`ML_INVESTIGATION.md`](ML_INVESTIGATION.md). Across the published ban logs it made one ban, a
  false one.
* **The L7 track, P1-P5c** ([`L7_GRU_DESIGN.md`](L7_GRU_DESIGN.md)): `ml/smoke_l7.py` (root, VM; the P1 and P2 gates),
  `ml/capture_l7.py --pipeline legacy ...` (root, VM; `--plan` offline), `ml/train_l7.py DATASET --out PKG` (offline,
  CPU), `ml/eval_l7.py --model PKG ...` (root, VM, shadow mode; `--plan` offline), `ml/replay_l7.py RECORDING`
  (offline). The published commands are in each `results/2026-10-1*_l7-*` README. Verdict: no advantage (P5c.4).
* **L7 v2, P1, P3, P4** ([`L7V2_DESIGN.md`](L7V2_DESIGN.md), [`P3_DATASET_DESIGN.md`](P3_DATASET_DESIGN.md),
  [`P4_SLOW_DESIGN.md`](P4_SLOW_DESIGN.md)): built and tested offline, pre-registered (`ml/*prereg*.json`), never run on
  the VM. `eval/p1_runner.py` and `eval/p4_runner.py` are VM workloads with an offline `--plan`, which also needs
  `--phase` and `--seed` (`eval/p1_runner.py` lines 1158-1159; `eval/p4_runner.py` stops with "--phase and --seed are
  required").

## 9. Reproducing published results

| Check | Command (offline) | What it reproduces |
|---|---|---|
| integrity of an entry | `cd results/<entry> && sha256sum --quiet -c SHA256SUMS` | every file as published; all 35 entries with a `SHA256SUMS` pass (the superseded `2026-10-11_superseded-dup-mac` has none) |
| a suite analysis | `venv/bin/python eval/analyze_campaign.py results/<entry>` then `git status` | `analysis/` byte for byte ([`EVALUATION.md`, "Quick start"](EVALUATION.md#quick-start)); the figures need matplotlib |
| run-level decisions | `venv/bin/python eval/run_level_stats.py results/<entry>` | the contrasts of [`EVALUATION.md`, "Statistics"](EVALUATION.md#statistics) |
| derived audit analyses | `sh results/2026-10-20_audit-derived/regenerate.sh`, then its `sha256sum -c` | order ablation, L7 harm and roles, run-level tables, suite comparison, ban-event census (about a minute) |
| the addendum's numbers | `sh results/2026-10-21_prototype-claims-check/regenerate.sh`, then its `sha256sum -c` | the 139 comparisons with the prototype campaigns |
| the re-calibration | `results/2026-11-15_harm-recalibration/README.md`, "How to re-check": `recompute_from_runs.py` piped into `diff`, and `cmp` of the freeze | capacity, knees, reference, the frozen record byte for byte, R4's verdict |
| P2 | `results/2026-11-16_harm-p2-hg4/README.md`, "How to re-check": `python3 -I recomputation/recompute_p22b.py ...`, and `eval/harm_gate.py` with `cmp` | P2-2b's blocks and outcome (pure Python), and the project's own judge byte for byte |

All of these were run for this guide on a copy of the repository at `4f31066` and reproduced: the two `regenerate.sh`
with their `SHA256SUMS`, both recomputations (`diff` and `cmp` print nothing), the judge on P2-2b ("PASS: 10 valid
blocks of 10", `gate.md` and `gate.json` identical to `recomputation/rejudge_harm_gate/`), and EXP-2a's analysis. The
two `regenerate.sh` and `publish_campaign.py` rewrite files inside `results/`: run them on a clean tree and check
`git status`. The scripts use `./venv/bin/python` unless `PYTHON=...` is set.

## 10. Building the thesis

[`thesis/main.tex`](../thesis/main.tex) is a single file (article class, Polish) with its images in `thesis/images/`;
the bibliography is written in the file. Build it with pdfLaTeX, three runs for the table of contents and the
references:

    cd thesis && pdflatex main.tex && pdflatex main.tex && pdflatex main.tex

It needs a TeX distribution with the packages named in its preamble (at `4f31066`: `inputenc`, `fontenc`, `babel` with
Polish, `graphicx`, `float`, `geometry`, `parskip`, `tabularx`, `longtable`, `booktabs`, `hyperref`, `pdfpages`,
`amsmath`, `xcolor`, `listings`, `tikz`). The testbed VM has no TeX installation; build elsewhere (for example Overleaf
with pdfLaTeX). Each claim of the thesis is traced to its evidence in [`THESIS_CLAIMS.md`](THESIS_CLAIMS.md).

## 11. Troubleshooting

### 11.1 A run marked host-invalid

The host check set the run aside as `<run>.hostinvalid<k>` with its reasons in `HOSTINVALID`, and the runner made it
again with the same seed after a speed hold. Three in a row, or four in a packet, pause the packet: "host unfit (exit
5)". Read the reasons (H1 speed, H3 slip, H4 clock, H5 mpstat gaps, H6 other processes' CPU, H7 monitors' coverage)
before resuming; R2a's four set-aside runs and their reasons are in
[`results/2026-11-15_harm-recalibration/README.md`](../results/2026-11-15_harm-recalibration/README.md), "Departure 1".
`venv/bin/python bench/hostcheck.py judge RUN_DIR --monitors DIR --start ISO --end ISO` judges a finished run again
offline.

### 11.2 The origin refuses to start

`bench/origin.py` times its routes at start and refuses when one is more than 25 % off the record's cost: the host is
slower (or faster) than when the record was made, or it is another host. Wait and try a speed hold
(`sudo ./venv/bin/python bench/hostcheck.py speed-hold --calibration FILE --reference FILE --lo -0.10 --hi 0.10 --max-min 30`),
check the guest is idle ([2.2](#22-validity-checklist-for-a-measurement)), and calibrate again if the host changed. This
stopped AP-7 on 2026-11-11
([`results/2026-11-11_harm-drift-check/README.md`](../results/2026-11-11_harm-drift-check/README.md)).

### 11.3 A packet paused or refused

* `paused (exit 4)`: the 85-min budget is used (no run starts after it); the same command resumes. P2-2b took two
  packets.
* `NO <check>` and `nothing was started` (foreground exit 3): read the line. `timers` names the timer that is due (see
  the daily window, [2.2](#22-validity-checklist-for-a-measurement) item 4); `jobs` a running package job; `quiet` a
  busy process; `uptime` waits for 1,800 s; `tree` or `frozen hashes` a checkout that is not the pin.
* exit 2 for R1: the P-1 paired check did not let it start (`prechecks.py paired`).
* `stopped (exit 2)` after runs: a refusal or a defect; the log's last error line says which (P2-2 stopped this way when
  10 valid blocks could no longer be reached).

### 11.4 Stale namespaces or processes after a crash

A suite run cleans up at exit (`cleanup_all`, registered with `atexit`), and the next run's `build_topology` calls it
first: it kills `control_plane.py`, Gunicorn, Nginx, hping3, the attack scripts and `wrk`, and deletes `server_ns`,
`legit_*`, `bot_*`, `ddos_br0` and the left `vo_legit_*`, `vo_bot_*`, `veth_srv_br` links. `eval/run_campaign.py`
refuses to start while any of those namespaces or processes remain, and says so. The harm benchmark's runners refuse
leftovers too, and `--clean` (`executor.py run`, `gate_campaign.py run`, the calibrator's steps) takes down the
namespaces and links of an earlier testbed and nothing else. After a SIGKILLed daemon, detach XDP by hand
([5.1](#51-start-and-stop-the-daemon-by-hand)). When in doubt, reboot the VM (and wait 30 minutes before measuring).

### 11.5 The known unit-test failure

`tests.test_l7_train_default.DocumentedP5cCommandTest.test_reproduces_the_published_gru_report` retrains the published
L7 GRU and requires the report to equal `results/2026-10-16_l7-p5c3-train/l7_metrics.json` exactly. On the laptop it
differs in the fifth significant digit: in this guide's runs the key `probes` holds 0.07812660769559443 against the
published 0.07812802796252072. The commit messages since 2026-11-14 (for example `ab49d04`, `18386ed`) record it as the
one failure of every full run on the laptop, identical on `main` at `efa8f54`, and attribute it to "floating point of
another CPU"; they treat it as environmental. On the desktop host the full runs passed it: for example the commit
messages of `6fc8ec5` and `73e960a` (2026-11-10) record "Gate: 3271 tests OK". Every other test passes.

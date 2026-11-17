# Host-level DDoS mitigation: XDP enforcement, rule engines and GRU experiments

This repository holds the code, the evaluation testbed, the published measurements and the LaTeX
sources of an engineering thesis (in Polish): *Badanie skuteczności i implementacja rozwiązań w
obronie przed różnymi technikami ataków DDoS*. This page is for an examiner: what the system is,
where everything is, what can be checked without root, and what has not been run.

- [`docs/GUIDE.md`](docs/GUIDE.md): how to set up a VM, run every kind of simulation the project ran,
  watch the running system and reproduce the published results.
- [`docs/PROJECT_HISTORY.md`](docs/PROJECT_HISTORY.md): what was done, phase by phase, from the first
  prototype to the latest measurements, with each outcome and where its evidence is.

## What the system is

- **A mitigation daemon on the protected host** (`control_plane.py`). Through BCC it loads an XDP
  program (`xdp_ddos_filter.c`) on the server's interface. The program collects per-source
  telemetry and drops packets from banned sources before the kernel's network stack handles them.
  Deterministic rule engines in the daemon read that telemetry, the connection table and Nginx's
  logs, and decide the bans. Every ban, unban and start is written as a JSON event
  (`ban_events.py`). Bans can be enforced as iptables rules instead (`MITIGATION_BACKEND=iptables`).
- **Experimental learned detectors.** A GRU on XDP flow features (`GRU_ML_model.py`,
  `train_testbed_gru.py`, the model in `training_results/`), off by default (`XDP_GRU=0`). An L7
  module on Nginx request logs (`l7_*.py`, trainers in `ml/`) with a GRU, a gradient-boosting
  model and rules: off by default (`L7_SHADOW=0`), observe-only when on, enforcing only with
  `L7_ENFORCE=1`. A per-connection slow-connection rule (`slow_pc.py`), off by default.
- **The evaluation testbed.** One Linux VM with network namespaces: a server namespace (Nginx,
  Gunicorn, the daemon) and legitimate-client and bot namespaces on a bridge
  (`test_distributed_suite.py`). `eval/` records and analyses campaigns of the suite. `bench/` is a
  second benchmark, built so that attacks cause measurable harm (the "harm benchmark"):
  calibration, scenario executor and harm gate.

## Repository layout

| Path | Content |
|---|---|
| `control_plane.py`, `xdp_ddos_filter.c` | the daemon and its XDP program |
| `ban_events.py`, `slow_pc.py`, `l7_*.py` | the event log, the per-connection slow rule, the L7 engine, scorer, rules and enforcing arm |
| `GRU_ML_model.py`, `capture_testbed_dataset.py`, `train_testbed_gru.py`, `training_results/` | the XDP-fed GRU: model, testbed dataset capture (root), training, the model and scaler the daemon loads |
| `nginx*.conf`, `dummy_app.py`, `l7_webapp.py`, `gunicorn_profile_r.py` | the protected service and its configurations |
| `test_distributed_suite.py` | the testbed suite (root): topology, attacks, legitimate clients, availability metrics |
| `eval/` | campaign runner, analysis, plots, statistics, publisher; the P1 and P4 runners and verdicts |
| `bench/` | the harm benchmark: origin, load generator, population, scenarios, executor, gate campaign, calibration (`bench/calibration/` holds the frozen records), the per-run host check, the packet wrapper (`bench/packets/`) and the VM helpers (`bench/vm/`) |
| `ml/` | the L7 datasets, traffic generators, trainers and pre-registration records (`*prereg*.json`) |
| `tests/` | the unit tests (no root) |
| `results/` | the published campaigns, one directory each (`results/README.md` is the index) |
| `docs/` | the run guide (`GUIDE.md`), the project's history (`PROJECT_HISTORY.md`), the evaluation manual, claims, design notes and pre-registrations, the two reviews (`REPORT.md`, `project_analysis_v2/REPORT.md`) |
| `thesis/`, `presentation/` | the thesis sources (`main.tex`, `images/`) and a slide deck (Polish) |
| `server/`, `attacker/` | an early two-VM layout (last changed 2026-10-03), not used by the measurements |
| `test_mitigation_suite.py`, `setup.sh`, `GRU_ML_init.py`, `build_cicids2017_dataset.py`, `merge_datasets.py`, `slowloris.py`, `rudy_script.py`, `todo.txt` | legacy files the measurements do not use (the CIC-IDS2017 line, the first single-attacker suite); `docs/project_analysis_v2/REPORT.md` lists them |

## Environment

The testbed is one VirtualBox guest, today Ubuntu 26.04 LTS, kernel 7.0.0-42, 8 vCPUs and Python
3.14.4; every run records its own kernel and Python. The guest has run on two host PCs. The
measurements up to 2026-11-11 ran on a desktop (Intel Core i7-10700F, VirtualBox 7.2.4: the reviews'
environment snapshots and `docs/HS1_PREREG.md`). The measurements since 2026-11-14 ran on a laptop
(AMD Ryzen 7 7730U, VirtualBox 7.2.10r174163), with 7,422 MiB of guest memory, kernel
7.0.0-42-generic, Nginx 1.28.3 and gunicorn 26.2.0 (the host block of
`bench/calibration/ddos-mitigation-2026-11-16.json`;
`results/2026-11-15_harm-recalibration/README.md`). A calibration record of the harm benchmark is
valid only on the host it names. BCC comes from the distribution, not from pip, so the virtual
environment sees the system packages:

    sudo apt install python3-venv python3-bpfcc bpfcc-tools python3-psutil nginx hping3 wrk iproute2 ethtool \
        curl iputils-ping openssl sysstat chrony bpftool git
    python3 -m venv --system-site-packages venv
    venv/bin/pip install -r requirements.txt
    venv/bin/pip install -r requirements-plot.txt    # optional: the figures only

`requirements.txt` pins what the code imports at the versions of the VM's environment, and its
header names the packages that came from apt there; BCC (python3-bpfcc 0.35.0) comes only from
apt and is not in the file. The VM has no matplotlib: the figures are the only step that needs it
(`requirements-plot.txt`), and `eval/publish_campaign.py` publishes a campaign without them when
it is missing.

The commands in `docs/EVALUATION.md` call `venv/bin/python` from the repository root, so create
`venv` there. The unit tests need only the Python packages. The rest is for the testbed: the suite
and the campaign runner run as root under the system `python3`, which needs `python3-psutil`;
everything else, the harm benchmark's tools and the analysis included, runs under `venv/bin/python`
(the system `python3` has no numpy); the harm benchmark's host check reads `mpstat`, `pidstat`
(sysstat) and `chronyc`. Before a measurement, read the validity checklist of `docs/GUIDE.md`
(section 2): the host must not sleep, the VM must be idle apart from the step, and automatic package
updates must be suspended (and restored afterwards).

## Checks without root

1. **The unit tests.** No root, no network, no VM: the daemon's rules run against fakes and the
   harm benchmark's runners against a simulated host (`docs/EVALUATION.md`, "Tests").

       venv/bin/python -m unittest discover -s tests

2. **A published entry is intact.** Inside a `results/<entry>/` directory:

       sha256sum --quiet -c SHA256SUMS

3. **A published analysis regenerates.** The quick start of `docs/EVALUATION.md` re-runs the
   analysis of `results/2026-10-12_exp2a-knee_prototype`; `git status` stays clean. The harm
   benchmark's two latest entries recompute from their own runs ("How to re-check" in each README);
   `docs/GUIDE.md`, section 9, lists every such check.

## What needs root and a VM

The suite, the campaign runner (`eval/run_campaign.py`), the L7 runners (`ml/capture_l7.py`,
`ml/eval_l7.py`, `ml/smoke_l7.py`), the harm benchmark's runners (`bench/executor.py run`,
`bench/gate_campaign.py run`, `bench/calibrate.py` except `freeze` and `plan`, and the packet wrapper
`bench/packets/packet.sh`), `capture_testbed_dataset.py`, the legacy `setup.sh` and the daemon
itself. Between them they kill processes (the suite and `setup.sh` by name, the harm benchmark's
runners only those of their own namespaces), delete and re-create network namespaces and a
bridge, attach XDP programs, flush iptables in the server namespace and truncate or move Nginx's
logs.
Run them only on a disposable VM. The full list of side effects is in `docs/EVALUATION.md`,
"Side effects of a suite run (root)"; the harm benchmark's runners are described there in "The
harm benchmark's runners (HG1c)".

## Results and claims

- `results/README.md` lists every published campaign with its status. A published entry is not
  edited afterwards. Each has a `README.md`, and each but the superseded
  `2026-10-11_superseded-dup-mac` has a `SHA256SUMS`.
- `docs/THESIS_CLAIMS.md` gives, for each claim of the thesis, the strongest sentence the evidence
  supports, the evidence and what it does not show.
- `docs/EVALUATION.md` is the manual: modes, settings, outputs, metrics, statistics.

## The thesis

`thesis/main.tex` (article class, Polish) and `thesis/images/`. There is no bibliography database
(the bibliography is written in the file), no class file and no build script. Build with pdfLaTeX:

    cd thesis
    pdflatex main.tex && pdflatex main.tex && pdflatex main.tex

It needs a TeX distribution with `babel` (Polish), `tikz`, `listings`, `tabularx`, `longtable`,
`booktabs`, `hyperref`, `pdfpages` and the other standard packages its preamble loads; the three
runs settle the table of contents and the cross-references.
The testbed VM has no TeX installation, so the build is done elsewhere (for example Overleaf with
the pdfLaTeX compiler). `presentation/Prezentacja_WEiTI_PL.pptx` is a slide deck in Polish.

## What has run, and what has not

- **The harm benchmark** gave its first result in 2026-11. Its calibration of 2026-11-04 (the
  desktop) was never confirmed: the drift check of 2026-11-08 failed twice and its three repeats
  (2026-11-10 and 11) gave no reading (`results/2026-11-11_harm-drift-check/`), and no claim rests
  on that record. On the laptop the benchmark was calibrated again under a pre-registration approved
  before its data (2026-11-15/16): the record `bench/calibration/ddos-mitigation-2026-11-16.json`
  was frozen and then confirmed after a reboot, for the legit probe and all three attack families,
  one with a wide-spread label (`results/2026-11-15_harm-recalibration/`; departure 1 of the
  pre-registration is post hoc). P2 then ran on that record (`results/2026-11-16_harm-p2-hg4/`): the
  cheap static flood at twice its knee harmed the unprotected server in 10 of 10 blocks (gate PASS),
  and the protected arm (Nginx's limits plus the daemon banning into XDP) banned all 50 attack
  identities and no legit one, but kept at least 0.99 of the control's quality in 0 of 10 blocks:
  the pre-registered P2 outcome is **NOT MET**. That result follows a post hoc fix of the attack's
  launch (the first campaign, P2-2, was INVALID) and covers one family, one level, one host and that
  one protected arm. Claims HB1-HB3 of `docs/THESIS_CLAIMS.md` give the wording.
- **The registered experiments P1, P3 and P4** have not run: P1, the arms of the L7 v2 module
  (`docs/L7V2_DESIGN.md`); P3, learning curves on entity-disjoint L7 datasets
  (`docs/P3_DATASET_DESIGN.md`); P4, the per-connection slow rule (`docs/P4_SLOW_DESIGN.md`). Their
  code, pre-registrations and verdict rules are in the repository and tested offline; the thesis
  lists them with empty result slots (table `tab:zarejestrowane`).
- **Not run either:** any harm-benchmark campaign beyond P2 (other families and levels, the
  limits-only and GRU arms), and any suite campaign since 2026-10-23. `docs/PROJECT_HISTORY.md` ends
  with the full list and the reasons.

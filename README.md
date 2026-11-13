# Host-level DDoS mitigation: XDP enforcement, rule engines and GRU experiments

This repository holds the code, the evaluation testbed, the published measurements and the LaTeX
sources of an engineering thesis (in Polish): *Badanie skuteczności i implementacja rozwiązań w
obronie przed różnymi technikami ataków DDoS*. This page is for an examiner: what the system is,
where everything is, what can be checked without root, and what has not been run.

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
| `bench/` | the harm benchmark: origin, load generator, population, scenarios, executor, gate campaign, calibration (`bench/calibration/` holds the frozen record) |
| `ml/` | the L7 datasets, traffic generators, trainers and pre-registration records (`*prereg*.json`) |
| `tests/` | the unit tests (no root) |
| `results/` | the published campaigns, one directory each (`results/README.md` is the index) |
| `docs/` | evaluation manual, claims, design notes, the two reviews (`REPORT.md`, `project_analysis_v2/REPORT.md`) |
| `thesis/`, `presentation/` | the thesis sources (`main.tex`, `images/`) and a slide deck (Polish) |
| `server/`, `attacker/` | an early two-VM layout (last changed 2026-10-03), not used by the measurements |
| `test_mitigation_suite.py`, `setup.sh`, `GRU_ML_init.py`, `build_cicids2017_dataset.py`, `merge_datasets.py`, `slowloris.py`, `rudy_script.py`, `todo.txt` | legacy files the measurements do not use (the CIC-IDS2017 line, the first single-attacker suite); `docs/project_analysis_v2/REPORT.md` lists them |

## Environment

The measurements were made on one VirtualBox guest: Ubuntu 26.04 LTS, kernel 7.0.0-42, 8 vCPUs,
Python 3.14.4. BCC comes from the distribution, not from pip, so the virtual environment sees the
system packages:

    sudo apt install python3-venv python3-bpfcc bpfcc-tools nginx hping3 wrk iproute2 ethtool
    python3 -m venv --system-site-packages venv
    venv/bin/pip install -r requirements.txt

The commands in `docs/EVALUATION.md` call `venv/bin/python` from the repository root, so create
`venv` there. The unit tests need only the Python packages; Nginx, hping3 and wrk are for the
testbed.

## Checks without root

1. **The unit tests.** No root, no network, no VM: the daemon's rules run against fakes and the
   harm benchmark's runners against a simulated host (`docs/EVALUATION.md`, "Tests").

       venv/bin/python -m unittest discover -s tests

2. **A published entry is intact.** Inside a `results/<entry>/` directory:

       sha256sum --quiet -c SHA256SUMS

3. **A published analysis regenerates.** The quick start of `docs/EVALUATION.md` re-runs the
   analysis of `results/2026-10-12_exp2a-knee_prototype`; `git status` stays clean.

## What needs root and a VM

The suite, the campaign runner (`eval/run_campaign.py`), the L7 runners (`ml/capture_l7.py`,
`ml/eval_l7.py`, `ml/smoke_l7.py`), the harm benchmark's runners (`bench/executor.py run`,
`bench/gate_campaign.py run`, `bench/calibrate.py`), `capture_testbed_dataset.py` and the daemon
itself. They kill processes by name, delete and re-create network namespaces and a
bridge, attach XDP programs, flush iptables in the server namespace and truncate Nginx's logs.
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

It needs a TeX distribution with `babel` (Polish), `tikz`, `listings`, `tabularx`, `booktabs`,
`hyperref` and `pdfpages`; the three runs settle the table of contents and the cross-references.
The testbed VM has no TeX installation, so the build is done elsewhere (for example Overleaf with
the pdfLaTeX compiler). `presentation/Prezentacja_WEiTI_PL.pptx` is a slide deck in Polish.

## What has not run

- **The harm benchmark's campaign (P2)** has not run. Its calibration was frozen on 2026-11-04.
  The first drift check of that record (2026-11-08) did not uphold it and the three repeats
  (2026-11-10 and 11) gave no reading (`results/2026-11-11_harm-drift-check/`), so no
  harm-benchmark claim exists.
- **The registered experiments P1, P3 and P4** have not run: P1, the arms of the L7 v2 module
  (`docs/L7V2_DESIGN.md`); P3, learning curves on entity-disjoint L7 datasets
  (`docs/P3_DATASET_DESIGN.md`); P4, the per-connection slow rule (`docs/P4_SLOW_DESIGN.md`). Their
  code, pre-registrations and verdict rules are in the repository and tested offline; the thesis
  lists them with empty result slots (table `tab:zarejestrowane`).

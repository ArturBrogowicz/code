# EXP-1d: calibration sweep for the knee operating point, five single runs (2026-10-12), raw files

Five single runs of the HTTP flood (`ONLY_SCENARIOS=4`) in **unprotected** mode (no daemon, no rate
limits), each with a different server capacity or attack intensity, to find a configuration at
which the unprotected server drops below 100 % legit availability. Recorded on 2026-10-12,
11:24–11:30 UTC (`sweep.log`: start 11:24:16, end 11:30:35, 0 Nginx processes and 0 namespaces
left). Reported in `docs/REPORT_ADDENDUM_EXP0_EXP1.md` §J ("Why") and §M. The sweep led to the
knee used in `../2026-10-12_exp2a-knee_prototype/` and `../2026-10-12_exp2b-knee-nginxtuned_prototype/`.

These are the files as recorded, **not converted** into the campaign layout (reasons below). They
have no `analysis/`, and `eval/analyze_campaign.py` does not read them. The `console.log` files are
verbatim, with their ANSI colour codes; every file has the SHA-256 of its original (`SHA256SUMS`).

Tags: **[FACT]** read from the files of this directory; **[INFERENCE]** reasoned; **[CLAIMED]**
stated in the addendum, no data here.

## Result

**[FACT]** (`sweep.log`; the percentages and request counts agree with a recomputation from
`availability_raw_unprotected.csv`, see "Checking")

| Configuration (directory) | Workers × threads, server CPUs | `wrk` connections per bot × bots | Legit success before / during / after |
|---|---|---|---|
| `w1t1_cpu0_c50_b5` | 1 × 1, cpu0 | 50 × 5 | 100 % (n = 40) / 100 % (n = 124) / 100 % (n = 74) |
| `w1t1_cpu0_c200_b5` | 1 × 1, cpu0 | 200 × 5 | 100 % (29) / 100 % (110) / 100 % (70) |
| `w1t1_cpu0_c200_b10` | 1 × 1, cpu0 | 200 × 10 | 100 % (34) / 100 % (103) / 100 % (74) |
| `w1t1_cpu0_c400_b10` | 1 × 1, cpu0 | 400 × 10 | 100 % (32) / **77 %** (60) / **84 %** (38) |
| `w2t2_cpu01_c200_b10` | 2 × 2, cpu0–1 | 200 × 10 | 100 % (33) / 100 % (112) / 100 % (71) |

* Only the heaviest configuration on the single-core server degraded: 14 of its 60 requests during
  the flood failed (76.7 %), and 6 of 38 afterwards (84.2 %). The established TCP connections in
  its metrics rows are 8,105–9,053, against about 6,000 at `c200_b10`.
* The harness reports FAIL for every run (no daemon, so 0 bots banned, by the suite's own criterion).

**[INFERENCE]** The knee used later (one worker and one thread on cpu0, `wrk -c400`, 10 bots) is the
only configuration here at which the unprotected server lost legit requests. It is a single run
(n = 60 during the flood), not a rate.

## Why it is raw

* **Five operating points, one run each.** The campaign layout is `<mode>/<run>` and the analysis
  pools the runs of a mode; five configurations imported as five runs would be averaged over
  different operating points.
* **The suite copy is not recorded.** `sweep.log` has the commit (`6fc27fa`) but no hash of the
  patched suite copy `d/`, and that copy was edited after the sweep (the version of 13:20 has
  SHA-256 `f11ff9fc…` and is reproduced in `../2026-10-12_exp2b-knee-nginxtuned_prototype/source/`;
  EXP-2a ran a different one, `6e57743a…`). The sweep's own version is therefore unknown, and so
  is whether the `ATTACK_CPUS` and `NGINX_CONF_OVERRIDE` hooks existed.
* There is no `provenance.txt`, no input hashes and no kernel or journal state. The configuration of a
  run is only in the first line of its `console.log` and in `run_calib_sweep.sh`.

## What is in the sweep, what is missing

* The run script sets `GUNICORN_WORKERS`, `GUNICORN_THREADS`, `SERVER_CPUS`, `WRK_CONNS` and
  `BOTNET_COUNT` (**[FACT]**: `run_calib_sweep.sh`). It does not set `ATTACK_CPUS`, so the attack
  generators were not pinned away from the server's core. **[INFERENCE]** Part of the degradation at
  `c400_b10` may therefore be CPU contention between the generators and the server on cpu0; EXP-2a
  pinned the generators to cpus 1–7 for that reason (addendum §J, **[CLAIMED]**).
* One run per configuration, unseeded client profiles (the mix differs per run, see each console),
  no repetition, no other scenario. No ban events (no daemon).

## Checking

```bash
cd results/2026-10-12_exp1d-calibration-sweep_raw && sha256sum -c SHA256SUMS && cd ../..
venv/bin/python - <<'EOF'
import glob
import pandas as pd
for f in sorted(glob.glob("results/2026-10-12_exp1d-calibration-sweep_raw/*/availability_raw_unprotected.csv")):
    r = pd.read_csv(f)
    print(f.split("/")[-2], {p: (round(float(100 * g.OK.mean()), 1), len(g)) for p, g in r.groupby("Period")})
EOF
```

prints the percentages and request counts of the table. The original directory is
`/root/project_analysis/campaigns/2026-10-12_calib/` on the testbed VM (root-owned, outside the
repository).

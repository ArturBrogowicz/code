# HS1: the standalone host stability check before the re-calibration (pre-registration v1)

Status: **draft v1, 2026-11-14** (W-HOST, task T-110). It binds once the user approves it and the orchestrator records the
sha256 of this file and of `bench/vm/hs1_series.sh`, `bench/vm/hs1_probe.py` and `bench/vm/hs1_eval.py` in the ledger before
the series starts. A change after that is a new, dated version. Tags: [FACT] (with its source), [INFERENCE], [CLAIMED] (ledger
or the user's word, not re-checked here), [ESTIMATE], [PROPOSAL]. The name is HS1 because the re-calibration design
(`docs/RECALIBRATION_2026-11_DESIGN.md`) already uses H1-H7 for its per-run rules.

## 1. Purpose and place
* HS1 asks one question: **does the PC the user chose hold the VM up, unpaused and at one speed, for one measurement
  window (3 h)?** It runs once, attended, **inside a window, before R1's packet**. It is a go/no-go. It does not replace H1-H7,
  the packet pre-checks or R1's speed hold. A PASS is necessary; it is not sufficient.
* It reads only the host's records and the origin's own cost estimate. It reads no Q, p95 or harm. Nothing of the testbed
  starts (tier T1: offline, no network, no root state change; the probes run in the offline sandbox).
* User decisions it implements (ledger D-096, 2026-11-14) [CLAIMED]:
  * the laptop runs every measurement until 2026-12-03;
  * HS1 is 3 h inside an attended window, with a pause-rate rule;
  * cut-off 2026-11-21.

## 2. Conditions: all must hold to start
`hs1_series.sh` records them in `identity_start.txt`. `hs1_eval.py --precheck` refuses the start if a guest-checkable one fails.
1. **The laptop's identity** [FACT for the current boot: kernel log, /proc]. These four values are checked at the start and again
   at the end (P7):
   * CPU model "AMD Ryzen 7 7730U with Radeon Graphics" (/proc/cpuinfo);
   * VirtualBox host version "7.2.10r174163" (the kernel line "vboxguest: host-version");
   * kernel "7.0.0-42-generic";
   * MemTotal within 1 % of 7,600,852 kB (amended 2026-11-14, D-102, section 12b; at the start and the end of the series the
     value must still be equal, since it cannot change within one boot).
   The VM has also run on a desktop (i7-10700F, VirtualBox 7.2.4). That desktop is not the programme's host.
2. **Software** (D-086) [CLAIMED].
   * Five timers are masked: apt-daily, apt-daily-upgrade, fwupd-refresh, logrotate, man-db.
   * linux-generic, linux-headers-generic and linux-image-generic are held.
   * HAR-1 H10's extra quieting is recommended (masks for motd-news, update-notifier-*, dpkg-db-backup, fstrim, e2scrub_all,
     xfs_scrub_all; `snap refresh --hold`). Without it, a snap refresh inside the 3 h fails P6. snapd refreshes 4 times a day
     [FACT, `snap refresh --time` on 2026-11-14].
3. **Uptime and clock.**
   * Uptime at least 1,800 s.
   * chrony: leap status Normal, |System time| < 0.1 s, a selected source within 1 s.
   * The guest's time zone is UTC (`date +%z` = +0000), so that dpkg.log's local times read as UTC; the monitors run with
     TZ=UTC. (Added after review T-105, F11; the guest is Etc/UTC [FACT, `timedatectl`, 2026-11-14].)
   * The orchestrator also checks, by hand just before the launch, that the guest clock agrees with an outside HTTPS Date header
     within 1 s. The script has no network.
4. **Quiet guest.**
   * Agents idle: no worker, no unit suite (the pre-check refuses if `-m unittest`, `bench/executor.py`, `bench/calibrate.py` or
     `eval/run_campaign.py` runs), no offline job.
   * The orchestrator launches HS1 as the last action of its turn.
5. **The Claude app open but idle** (D3), under the session-quiet protocol of the design's section 5.3: nobody types into any
   session, no /compact, no session opened. The app's own load is measured, not excluded (section 6).
6. **The PC side** [CLAIMED, the user's report of 2026-11-14]: plugged in; power mode Best performance; lid "Do nothing" on AC;
   sleep and hibernation off on AC; VirtualBox's engine VT-x/AMD-V, no turtle. Add the laptop addendum to HAR-1
   (tasks/T-110/artifacts/HAR1_laptop_addendum.md): power throttling off for the VirtualBox processes, and the VM window not
   minimised. Nothing heavy runs on the PC.
7. **Storage** (user-reported; the guest sees only "VBOX HARDDISK" either way).
   * v1 expects the VM's disk on **the laptop's internal SSD**. The launch passes `HS1_STORAGE="internal SSD"`. The value is
     recorded, and P7 requires it to equal the expected one.
   * Today the disk is on an external spinning USB hard disk [CLAIMED, the user, 2026-11-14]. Evidence of its cost [CLAIMED,
     orchestrator, this boot]: `sar -d` showed sda await about 27 ms and the LVM volume (dm-0) about 93 ms while the unit suite
     ran; iowait 53 % at 12:40Z [FACT, sar]; main's full suite took 2,311 s here against about 1,390 s on the desktop.
   * **If the user keeps the USB HDD**, a dated amendment before the start must change four things:
     * the expected storage becomes "USB HDD" (in `EXPECTED` of `hs1_eval.py`, so its sha256 changes);
     * the three USB items of the laptop addendum become conditions: USB selective suspend Disabled on AC, "Turn off hard disk
       after: Never" on AC, the USB hubs' "allow the computer to turn off this device" unticked;
     * HS1's PASS then speaks for that storage only;
     * the reported disk latency (4.9) becomes the evidence to watch. A drive that spins down, or a USB link that sleeps, stalls
       guest I/O for seconds [INFERENCE]. Such a stall shows up as hung-task lines (pause events, P4), not in P2: the probe is
       CPU-only.
   * Moving the disk later (USB to SSD, or back) changes the host, so HS1 must be repeated.

## 3. What is measured: the origin's own cost estimate
`bench/vm/hs1_probe.py`, one call per probe:
* It imports `bench/origin.py` from the same tree.
* It builds `Origin` with the knobs of the frozen record `bench/calibration/ddos-mitigation-2026-11-04.json`.
* It times the routes with `time_routes(origin, repeats=21, clock=time.thread_time)` (origin.py:298-327), the estimator of the
  origin's start-up check and of the calibrator [FACT, read]:
  * for each route C0, C1, C2, C3 and C5, a batch size is found by doubling until a batch lasts at least 1 ms of thread CPU time
    (the lesser of two timings per try);
  * then 21 round-robin rounds time one batch per route each;
  * a route's cost is the median of its 21 per-call times.
* It prints one JSON line: `utc`, `utc_end`, `sample`, `cpus` (from the affinity set by `taskset`), `repeats`, `clock`,
  `estimator_version`, `costs_ms`, `batch`, `offset_pct` (against the record's costs) and `refused` (the routes the origin's
  25 % rule, `self_check`, would refuse). It writes nothing.
* **Why 21 repeats:** 21 is the design's H1 estimator. It makes HS1's medians a reference R1's speed hold can use with the same
  estimator (section 7). The published 2026-11-11 series used 5.
* [INFERENCE] Thread CPU time carries no steal correction under VirtualBox ([FACT] /proc/stat steal 0, no kvm-stealtime line).
  So a probe also counts time the host took the vCPU away, plus host frequency and SMT or cache contention. It is the host's
  speed as the guest feels it.

## 4. The series
* **N = 36 sample times, 300 s apart (3 h).**
* At each sample time, one probe on CPU 0, then on CPU 1, then on CPU 7, each in the sandbox (`sbx.sh`, as the published series).
* Beside the probes:
  * `mpstat -P ALL 5`;
  * `pidstat -u -l -h -H 10`;
  * `chronyc -c tracking` and `chronyc -c sources` every 30 s;
  * `iostat -dxy -t 30 sda dm-0` (disk latency, **reported only**: there is no baseline for this storage, so no rule).
* Start and end: the identity snapshot. At the stop, `--collect` writes the series boot's kernel and chronyd journal lines, the
  boot's last 80 lines, the dpkg.log lines from the start, and `snap changes --abs-time`.
* Each of those five extracts starts with the collector's header (its file name, the series' boot id and its command's exit
  status) and ends with the collector's end marker. An extract counts as a record only with both, the series' boot id and
  exit status 0 (for `snap changes`, also its own "no changes found"); the kernel extract must also hold a time-stamped line.
  Otherwise it is a missing record (section 5's NO READING, with the extract named). (Added after review T-105, F4.)
* Every file lands in RUN_DIR, which must be new and under `/home/artur/agent_workspace/host/`.

## 5. Rules and verdict (final numbers; `hs1_eval.py` holds the same constants)
**P1, reported only.** The origin's 25 % check against the 2026-11-04 costs, per CPU: probes accepted, the refusing routes, the
median offsets. Those costs are the desktop's, so on the laptop P1 compares two different CPUs and decides nothing.

**P2, speed steadiness.**
* Values: C3 and C5. Each value is taken against the median of the same route on the same CPU over the series:
  dev = cost / median - 1.
* A CPU enters P2 with at least 12 probes. The values are pooled over CPUs 0, 1 and 7 (108 per route in a full series).
* Per route, pass when **at least 95 % of |dev| <= 10 %** (inclusive; at most 5 of 108 outside) **and no |dev| > 20 %**
  (exactly 20 % passes).
* P2 passes when both routes pass.

**P3, no unclean end.**
* Pass: the series wrote its END file in its own boot.
* FAIL: its boot ended without a systemd-shutdown sequence before END was written.
* No verdict from P3 alone: a clean shutdown, or a series still running or dead without END.

**P4, pause rate.**
* A **pause line** is any of:
  * a gap above 6 s between consecutive mpstat samples (time: the later sample; measured length: gap - 5 s);
  * a kernel "Long readout interval" (measured: cs_nsec);
  * a kernel "rcu: INFO: ... detected stalls";
  * a kernel "blocked for more than N seconds" (hung task);
  * a chronyd "Forward time jump detected", "System clock was stepped by X" or "System clock wrong by X" (measured: |X|).
* Lines within 60 s of an event's first line (inclusive) are **one pause event**. "Can't synchronise" and "hogged CPU" lines are
  counted and reported, not judged.
* **Allowed events = ceil(0.5 per h x 3 h) = ceil(1.5) = 2. Pass when events <= 2** (inclusive).
* **A single long pause does not fail by itself.** Its measured length is reported (evidence in 8.3).

**P5, clock.** In every 30-s chrony sample of the window, |System time| < 0.1 s. The selected source's offset stays at most 1 s.

**P6, no software change.**
* Equal at the start and the end: kernel release, /proc/cmdline, the hash of the dpkg package list, the hash of `snap list`,
  `apt-mark showhold`.
* No dpkg.log line and no snap change spawned inside the window.

**P7, same host.**
* At the start, the identity equals section 2.1 plus the storage of 2.7.
* At the start and the end: the same boot_id, CPU model, VirtualBox host version, TSC MHz and MemTotal.

**Guest quiet (section 6) and evidence.**
* Every monitor's records (mpstat, pidstat, chrony) must reach within 60 s of the window's start and end.
* At most 5 % of the sample times may be guest-busy.

**Verdict, in this order:**
1. **NO READING**, not started: no start identity, a refused pre-check, or no probe.
2. **FAIL** if any of P3, P4, P5, P6 or P7 fails. This includes a series that stopped early.
3. **NO READING** if a monitor's records are missing or more than 5 % of the sample times are guest-busy. A slowdown is then not
   attributable to the host.
4. **FAIL** if P2 fails on the probes present. This includes a short series: a slowdown already seen is not undone by the
   samples that are missing.
5. **NO READING** if the series is early, or if P2, P3, P5, P6 or P7 could not be judged. Early means fewer than 36 complete
   sample times (all three CPUs). Causes: stopped by a person, a clean shutdown, the script or a monitor dying, or
   `boot_end.txt` missing.
6. **PASS** otherwise.

`hs1_eval.py` prints every rule's numbers. It writes `verdict.json` (schema `hs1-verdict/1`: verdict, reasons, each rule's
figures, the constants, both identities) and `medians.json` (section 7). Exit codes: 0 PASS, 1 FAIL, 3 NO READING.

## 6. The app's own load (D3)
* pidstat names every process. HS1's own processes and the kernel's threads (UID 0, a bare name) are left out. HS1's own are:
  the script, the sandbox, sudo, unshare, taskset, the probe, mpstat, pidstat, iostat, chronyc, sleep and the snapshot tools.
* A sample time is **guest-busy** if, within 30 s of it, the other processes (the app's server
  `~/.claude/remote/srv/.../server`, its bridge, sshd and anything else) use more than 5 % of one CPU on average, or more than 50 %
  in a single 10-s sample. These are H6's two lines.
* A sample time with no pidstat record nearby counts as busy (fail closed).
* Busy probes are kept and judged. More than 5 % busy sample times (2 or more of 36) makes the series NO READING.
* [INFERENCE] Thread CPU time hardly sees another guest process on the same vCPU. The app's bursts on all eight vCPUs (ledger
  C-129) load the host's cores, though, and can slow a probe through the host.

## 7. What HS1 writes for the re-calibration: `medians.json`
* **Schema `hs1-medians/1`.** Fields:
  * `verdict`;
  * `usable_as_reference`: true only for PASS;
  * `host`: cpu_model, vbox_host_version, kernel, memtotal_kb, tsc_mhz, boot_id;
  * `estimator`: function, repeats (21), origin_sha256, probe_sha256, knobs_from, record_sha256;
  * `window`: start_utc, end_utc, complete_sample_times, interval_s;
  * `medians_ms`: for CPU "0" and CPU "1", for each route C0, C1, C2, C3, C5: `median_ms`, `n`, `min_ms`, `max_ms`;
  * `reported_only`: the same for CPU "7".
* **Use in R1** (K11, as the user approved it, D-098). On the laptop, R1's speed hold (design 5.2) cannot use the 2026-11-04
  costs: they are another CPU's. It uses `medians_ms` of a PASS run instead.
  * Each hold probe is HS1's probe (same estimator and repeats). Run it on CPU 0 and on CPU 1.
  * Per CPU c and route r in {C3, C5}: dev = cost / medians_ms[c][r].median_ms - 1.
  * d = the mean over the two CPUs of the mean of the two routes' dev (H1's d).
  * The hold passes on two consecutive pairs that both lie within **-10 % to +10 %** (H1's band) and agree within **5 %**, at
    most **45 min** (K11's `R1_HOLD`, bench/hostcheck.py).
  * R1's hold refuses a medians.json whose `usable_as_reference` is false, or whose `host` or `estimator.origin_sha256` differs
    from the session's.
  * [INFERENCE] HS1's probe (hs1_probe.py, in the sandbox as uid 1000) and R1's hold (calibrate.py, as root outside the
    sandbox) use the same estimator and knobs but not the same process context; a systematic offset of a few % between them is
    possible, and it is checked before R1.
  * *Note 2026-11-14, consistency with the approved K11 (D-098); no HS1 rule changed.* The draft proposed |d| <= 7 %.

## 8. Evidence and false-fail risk
**8.1 P2** [FACT, published 2026-11-11 series and 2026-11-12 probes, 5 repeats, desktop].
* At normal speed (24 probes with C3 and C5 within -5..+12 % of the record) the values against their median had an SD of
  4.2 pp, a largest |dev| of 7.2 % (C3) and 7.7 % (C5), and 0 of 24 outside 10 %.
* [ESTIMATE] Under a normal model with SD 4.2 pp, about 1.7 % of values fall outside 10 %. Pooled over 108 values with 5 allowed,
  a route then fails about 1.1 % of the time, about 2 % for both routes. 21 repeats lower the spread further.
* What it catches: a slow stretch of 2 or more sample times (10 min or more) on all three CPUs puts 6 or more values out, and
  any single value more than 20 % off.
* The tail of the "none beyond 20 %" rule is unknown. A disturbance that moves one value in 1,000 fails P2 in about 19 % of
  series (216 values).

**8.2 P1** [FACT]. At normal speed on the desktop, C0, C1 and C2 reached +18..+25 % (C0 +25 % was refused at 20:18:37Z, CPU 1).
That is why P1 was not a rule in the draft. On the laptop it is moot.

**8.3 P4.** From the journal of the record's era: the desktop boots of 2026-10-29..11-06, 9 boots, 72.6 h counted from 30 min
of uptime, pause events as defined in 5.
* [FACT] (tasks/T-110/work/p4_empirics.py):
  * 55 events, **0.76 per hour pooled**, a median of 0.88/h per boot;
  * the boots split into quiet days (0, 0.12, 0.30, 0.30/h) and busy ones (0.88-2.31/h).
  * In the 555 three-hour windows (one starting every 5 min), the share with more than k events:

    | k | 0 | 1 | 2 | 3 | 4 | 5 |
    |---|---|---|---|---|---|---|
    | share of windows | 45.6 % | 35.9 % | 31.4 % | 25.6 % | 20.7 % | 15.7 % |

  * So **with 2 allowed, an October-like host fails P4 in about 31 % of 3-h windows.** The early-November calibration (11-04: 2
    events in 6.7 h) would have passed.
  * These counts are lower bounds: there was no mpstat sampler then, and a Long readout line is printed only above twice the
    boot's largest so far (ledger C-114).
* [ARITHMETIC] For a host at exactly 0.5/h (Poisson, lambda = 1.5 in 3 h): P(<= 1) = 0.558, P(<= 2) = 0.809, P(<= 3) = 0.934.
  * Allowing 2 (the rounded-up 1.5) fails such a host 19 % of the time; allowing 1 would fail it 44 %.
  * The laptop's boot of 2026-11-13 16:48Z (1 event in its 0.6 h after 30 min, 1.63/h, a thin estimate; lambda = 4.9) fails
    with probability 0.87.
  * The current boot (6 events in 0.4 h, 14.8/h) fails with certainty.
  * Allowing 3 would lower the October false-fail only to 26 %, because the October events come in bursts.
* **Single long pause** [FACT, same data]. 17.5 % of the October 3-h windows held a measured pause above 30 s; 9.9 % above 60 s;
  9.2 % above 120 s; none above 300 s. The calibration day 11-04 had a 173 s pause (12:38Z), and 11-02 had 285 s. A rule
  "fail on one pause > 30 s" would therefore fail the record's own era about one window in six, and add to P4's 31 %.
  Per run, H4/H5 already void any run a pause falls in. So HS1 reports the longest pause and does not fail on it. A full
  suspension (host sleep) moves the clock and fails P5.
* [FACT] The AP-7 mpstat (desktop, 2026-11-11 18:39-19:17Z, testbed under load) had 21 gaps of 7-9 s. Under load, the 6-s
  gap line fires without a host pause. HS1's guest is quiet, so this does not apply to HS1. It matters for H5 (W-HARM).

**8.4 Disk latency** is reported, not judged: there is no baseline on either storage, and the probe is CPU-only. The figures in
2.7 are the reason to record it.

## 9. Past data under these rules [FACT, tests/test_hs1_eval.py]
* **2026-11-11 19:27-21:23Z** (the published series, desktop, CPUs 0 and 1, 23 sample times, 5 repeats; judged against the
  desktop's identity): **FAIL by P2**.
  * C3 and C5 each have fewer than 95 % of 46 values within 10 % of their CPU's median, and values beyond 20 %.
  * P4: 1 event (chronyd forward jump 19:32:23Z) of 2 allowed. P1: 11 of 23 accepted on each CPU.
  * Against the laptop's identity it also fails P7.
* The current laptop boot (from 11:41Z, 17 chronyd forward jumps, a 28 s Long readout and a 60 s RCU stall in 55 min) would fail
  P4 within the first hour [FACT, journal].

## 10. How it runs
```
HS1_STORAGE="internal SSD" bench/vm/hs1_series.sh /home/artur/agent_workspace/host/hs1_<UTC date>   # pre-check, then detached
kill -TERM "$(cat /home/artur/agent_workspace/host/hs1_<...>/run.pid)"                                 # stop (clean)
bench/vm/hs1_series.sh --collect /home/artur/agent_workspace/host/hs1_<...>    # after a host reset, once, in the next boot
/home/artur/DDoS-mitigation/.venv/bin/python -I -B bench/vm/hs1_eval.py /home/artur/agent_workspace/host/hs1_<...>
```
* The tree to run from: a clean checkout holding these files at the recorded hashes. `identity_start.txt` records git HEAD, the
  dirty-file count and every hash.
* Stop with SIGTERM only. The series runs detached from a non-interactive shell, which starts it with SIGINT ignored; an
  ignored signal cannot be trapped, so `kill -INT` does nothing (review T-105, F3).
* Evaluate after the series process has exited: END is written before the extracts.
* Environment overrides exist for development only: HS1_SAMPLES, HS1_INTERVAL, HS1_REPEATS, HS1_PY, HS1_EVAL_PY, HS1_SBX. A run
  with any of them changed is not HS1 v1.
* Dry run: `HS1_DRYRUN=1`, honoured only with HS1_SAMPLES < 36. The pre-check's refusals are recorded in precheck.txt and
  ignored; the run is marked `dry_run=1`; `hs1_eval.py` judges it on its own length, names it in its reasons, and its medians are
  never usable as a reference. It exercises the mechanics only; it is never an HS1 reading.

## 11. Compatibility with the re-calibration design, section 5
* Shared with H1-H7: H1's estimator (`time_routes`, 21 repeats); H4's clock bounds; H5's 6-s mpstat gap (as a pause line);
  H6's two CPU lines for the quiet test; H7's fail-closed evidence rule (here: NO READING).
* HS1 adds no per-run rule and changes no threshold of H1-H7.
* Items for W-HARM:
  * host identity (2.1 and 2.7) belongs in K5's comparison and in every packet's pre-check;
  * R1's speed hold needs this host's reference (section 7, K11);
  * H5 vs AP-7's loaded mpstat gaps (8.3).

## 12. Changes from the T-108 draft (each with its reason)
* 8 h became 3 h attended, and "no pause" became a pause rate: the user's decision D-096.
* P1 is reported only: the laptop is not the record's CPU.
* Probe repeats went from 5 to 21, to serve R1's hold (section 7).
* In the verdict order, a P2 FAIL now comes before the early-stop NO READING. Under the draft's order the published 2026-11-11
  series (stopped after 23 sample times, no CPU 7) would be NO READING, although its unsteadiness is plain.
* Added: storage (P7, 2.7), disk latency (reported), hung tasks and RCU stalls as pause lines, and the dpkg/snap window check.

## 12a. Changes after review T-105 (2026-11-14, before any HS1 data)
No rule, constant or step of the verdict order changed. The code now does what section 5 already said.
* **F3** Stop instructions say `kill -TERM` (header, the launcher's message, section 10). A test sends SIGINT to a detached
  series (ignored) and then SIGTERM, and finds END, identity_end.txt and the five extracts.
* **F4** A missing or failed extract no longer reads as "no pause" or "no change". The journal extracts count as records under
  step 3 (NO READING); a missing dpkg, snap or boot_end extract leaves P6 or P3 unjudged (step 5). Pause lines that are present
  (mpstat gaps) still fail P4.
* **F8** Section 7 carries K11's approved hold (-10 % to +10 %, 5 %, 45 min) and the note on process context.
* **F11** The monitors run with TZ=UTC. The pre-check refuses a guest not in UTC, and the evaluator gives NO READING for a
  record of one.
* **F12** An END whose time stamp cannot be read no longer passes P3: it is NO READING. Chrony samples without a selected
  source, or with a leap status other than Normal, are counted and reported. They are not failed, because P5 as written bounds
  the selected source's offset only while there is one, and P4 already reports "Can't synchronise" without judging it.
* Added for the dry run: `HS1_DRYRUN` (section 10), which cannot produce a reading.
* Found by the dry run (2026-11-14 15:06Z): this sysstat (12.7.7) prints HH:MM:SS under `pidstat -h`, which the evaluator
  skipped, so pidstat read as missing and every sample time as busy (a NO READING for every run). The series now runs
  `pidstat -u -l -h -H 10` (epoch times), and the evaluator also reads HH:MM:SS against the header's date.

## 13. Open points for the user
1. The internal SSD (recommended), or keep the USB HDD with the amendment of 2.7.
2. Accept that an October-like host fails P4 about one window in three (allowed = 2). Raising the allowance does little (8.3).
3. If HS1 gives FAIL or NO READING: repeat it once in another window before 2026-11-21, or decide on the host otherwise.

## 12b. Amendment approved by the user (2026-11-14, D-102, before any HS1 data)
* **MemTotal within 1 % of 7,600,852 kB** in the start conditions (2.1) and P7's comparison with the expected host, instead of exact
  equality. Reason [FACT]: MemTotal moves by a few kB between boots of the same VM (7,600,844 kB on 2026-11-12, 7,600,852 on
  2026-11-14 morning, 7,600,856 since 14:37:42Z), so the exact value failed both dry runs on P7 alone (T-112). The tolerance is K5's
  (bench/calibration.py); a change of the VM's memory setting (8 to 10 GiB: +25 %) is still refused. The start-to-end comparison of
  P7 within one boot stays exact. Constant `MEMTOTAL_TOL = 0.01` in hs1_eval.py, pinned in tests (MemTotalAmendmentD102).
* Not changed: F12b (chrony's unsynchronised state) stays reported only, as in 12a; that is the orchestrator's recommendation, and the
  user may still make it a rule before any HS1 data.

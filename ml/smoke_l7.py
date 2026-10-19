#!/usr/bin/env python3
"""L7 smoke capture: the P1 and P2 verification gates (docs/L7_GRU_DESIGN.md §8).

Default — the P1 gate (transport health). Brings up the testbed with the daemon in
L7 shadow mode (L7_SHADOW=1), drives a short mix of legit traffic, an attack burst
and a long-User-Agent probe, and measures what only a live run can show:

  * drop rate  — nginx writes every request to BOTH the durable file access_log
                 and the Unix-datagram socket; SOCK_DGRAM gives the receiver no
                 drop counter, so drops = (file lines) - (socket received) over
                 the measurement window (§4.3);
  * truncation — datagrams that arrived cut short (counted in the daemon);
  * ingest CPU — the control_plane python process's CPU while ingesting.

The XDP-fed GRU is off here as well: XDP_GRU defaults to 0 since 2026-10-19 (it had
false-banned a legit client in the first P1 smoke), and this gate does not set it.

--p2 — the P2 gate (the shadow scoring engine end to end), additionally:

  * records the engine's exact input stream (L7_RECORD) and replays it offline
    through a fresh engine: the live would-ban decisions and counters must be
    reproduced exactly (determinism);
  * a SYN flood from bots that are NOT already banned arms the L3/L4 flood
    suppression (banned IPs are dropped in XDP before telemetry counts them), so
    the engine must report suppressed polls and then age-gate windows;
  * scores with an UNTRAINED, seeded GRU package of production size (threshold
    0.5) unless --model is given. This exercises scoring, the decision policy and
    the probes; its scores say nothing about detection (no L7 model is trained
    before P4);
  * pins XDP_GRU=0 explicitly (the daemon's default as well, see above), so the
    XDP-fed GRU's known false positive cannot confound the run;
  * writes windows.csv (one feature summary per scored window) for the feature
    review, and the invariance-probe report.

This IS a VM workload. It builds namespaces/veths/bridge, attaches XDP, starts
nginx + gunicorn + the daemon in server_ns, binds /run/ddos_l7.sock and sends
traffic. Run with sudo. It reuses test_distributed_suite for every state change,
so the capture runs in the suite's own environment. The shadow path never bans.
The deterministic rules still run and ban the attack bots (expected).

    sudo ./venv/bin/python ml/smoke_l7.py [--duration 180] [--legit 6] [--bots 4]
    sudo ./venv/bin/python ml/smoke_l7.py --p2 [--model PKG]
"""
import argparse
import itertools
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = "/var/tmp/ddos_l7_smoke"
# The durable file access_log, written by both nginx confs (the socket's ground truth).
ACCESS_LOG = "/var/log/nginx/ddos_ml_access.log"
DETERMINISTIC_ENGINES = {"l4_syn", "l4_volumetric", "l4_slowconn", "l4_lowsyn",
                         "l7_rate", "l7_rudy"}


def wc_lines(path):
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def read_events(events_path):
    try:
        with open(events_path, encoding="utf-8") as fh:
            out = []
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
            return out
    except OSError:
        return []


def last_shadow_event(events_path):
    """Return the most recent l7_shadow event dict, or None."""
    last = None
    for rec in read_events(events_path):
        if rec.get("kind") == "l7_shadow":
            last = rec
    return last


def daemon_cpu_sampler(find_pid):
    """Return a callable that samples the daemon process CPU% since the last call."""
    import psutil
    proc = {"p": None}

    def sample():
        if proc["p"] is None or not proc["p"].is_running():
            pid = find_pid()
            proc["p"] = psutil.Process(pid) if pid else None
            if proc["p"]:
                proc["p"].cpu_percent(None)   # prime
            return None
        try:
            return proc["p"].cpu_percent(None)
        except psutil.Error:
            proc["p"] = None
            return None

    return sample


def control_plane_pid():
    """PID of the control_plane.py python process (not the `ip netns exec` wrapper)."""
    res = subprocess.run(["pgrep", "-f", "control_plane.py"], check=False,
                         capture_output=True, text=True)
    for pid in res.stdout.split():
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                if "python" in fh.read():
                    return int(pid)
        except OSError:
            continue
    return None


def make_untrained_package(path):
    """A seeded, UNTRAINED GRU package of production size (hidden 64, 2 layers,
    20-step windows), threshold 0.5: for pipeline mechanics only."""
    sys.path.insert(0, REPO)
    import torch

    import l7_scorer
    from GRU_ML_model import GRUDDoSClassifier
    from l7_features import columns
    torch.manual_seed(0)
    cols = columns()
    model = GRUDDoSClassifier(len(cols), 64, 2)
    l7_scorer.save_package(path, model, cols, 20, [0.0] * len(cols), [1.0] * len(cols),
                           threshold=0.5, consecutive=2, hidden_size=64, num_layers=2,
                           meta={"note": "UNTRAINED, seed 0 — P2 mechanics only, "
                                         "scores carry no detection meaning"})
    return path


def analyse_p2(out_dir, events_path, record_path, model_path):
    """Replay determinism, feature summaries and probes from a --p2 run."""
    import csv

    import torch
    torch.set_num_threads(1)                      # as the daemon: bit-identical scores
    sys.path.insert(0, REPO)
    sys.path.insert(0, os.path.join(REPO, "ml"))
    import l7_probes as P
    import replay_l7 as R

    import l7_engine as E
    import l7_features as F

    events = read_events(events_path)
    summaries = [e for e in events if e.get("kind") == "l7_gru_poll"]
    covered = [s["t_last_poll"] for s in summaries if s.get("t_last_poll") is not None]
    if not covered:
        return {"error": "no l7_gru_poll summary covering a poll in the run"}
    # The daemon is stopped with SIGKILL, so its exit-time summary is never written:
    # compare up to the last poll that a written summary covers. (The recorder rounds
    # its timestamps to 1 µs, hence the tolerance.)
    cutoff = max(covered)
    with open(record_path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    last = -1
    for i, line in enumerate(lines):
        if '"poll":true' in line:
            try:
                if json.loads(line)["rx"] <= cutoff + 1e-6:
                    last = i
            except (ValueError, KeyError):
                continue
    kept = lines[:last + 1]

    csv_path = os.path.join(out_dir, "windows.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh_csv:
        writer = csv.writer(fh_csv)
        state = {"header": False}

        def hook(now, key, recs, p):
            vec, names = F.window_summary(recs, engine.cols)
            if not state["header"]:
                writer.writerow(["t_poll", "ip", "ua_h", "class", "p", *names])
                state["header"] = True
            writer.writerow([f"{now:.3f}", key[0], key[1], R.ip_class(key[0]),
                             "" if p is None else f"{p:.6f}", *(f"{v:.6g}" for v in vec)])

        engine = E.build_engine(model_path, window_hook=hook)
        replayed = R.replay(E.read_stream(kept), engine)

    live = [e for e in events if e.get("kind") == "l7_gru_poll"
            or (e.get("kind") == "l7_would_ban" and e.get("t_poll", 0) <= cutoff + 1e-6)]
    determinism = R.compare_live(live, replayed)

    probes = None
    if model_path:
        windows = P.windows_from_items(list(E.read_stream(kept)), engine.scorer.seq_len)
        probes = P.run_probes(engine.scorer, windows[:2000])
        with open(os.path.join(out_dir, "probes.json"), "w", encoding="utf-8") as fh:
            json.dump(probes, fh, indent=1)
            fh.write("\n")

    bans = [e for e in events if e.get("kind") == "ban"]
    would = [e for e in events if e.get("kind") == "l7_would_ban"]
    by_class = {}
    for e in would:
        by_class.setdefault(R.ip_class(e["ip"]), set()).add(e["ip"])
    return {
        "recorded_lines": len(lines), "replayed_lines": len(kept),
        "determinism": determinism,
        "live_totals": R._sums(summaries),
        "would_ban_ips_by_class": {k: sorted(v) for k, v in by_class.items()},
        "suppress_on_events": sum(1 for e in events if e.get("kind") == "suppress_on"),
        "bans_by_engine": {k: sum(1 for b in bans if b.get("engine") == k)
                           for k in sorted({b.get("engine") for b in bans})},
        "non_deterministic_bans": [b for b in bans
                                   if b.get("engine") not in DETERMINISTIC_ENGINES],
        "probes": probes, "windows_csv": csv_path,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--duration", type=float, default=180.0, help="total seconds")
    ap.add_argument("--legit", type=int, default=6, help="legit client namespaces")
    ap.add_argument("--bots", type=int, default=4, help="attacker namespaces")
    ap.add_argument("--out", default=DEFAULT_OUT, help="results directory root")
    ap.add_argument("--p2", action="store_true", help="run the P2 gate (see module doc)")
    ap.add_argument("--model", help="with --p2: a model package instead of the untrained one")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (namespaces + XDP). Use sudo.")
    if args.p2 and args.bots < 2:
        sys.exit("[-] --p2 needs >= 2 bots (one half bursts, the other floods).")

    out_dir = os.path.join(args.out, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(out_dir, exist_ok=True)
    events_path = os.path.join(out_dir, "ban_events.jsonl")
    record_path = model_path = None

    # Must be set before the daemon is launched: the daemon subprocess inherits the
    # environment (_daemon_cmd uses `env`), so these reach it.
    os.environ["L7_SHADOW"] = "1"
    os.environ["BAN_EVENTS"] = events_path
    os.environ.setdefault("L7_SOCKET_PATH", "/run/ddos_l7.sock")
    if args.p2:
        record_path = os.path.join(out_dir, "l7_record.jsonl")
        model_path = args.model or make_untrained_package(os.path.join(out_dir, "untrained_pkg"))
        os.environ["L7_RECORD"] = record_path
        os.environ["L7_MODEL"] = model_path
        os.environ["XDP_GRU"] = "0"

    sys.path.insert(0, REPO)
    import test_distributed_suite as S

    S.LEGIT_COUNT = args.legit
    S.BOTNET_COUNT = args.bots
    access_log = ACCESS_LOG

    report = {"out_dir": out_dir, "mode": "p2" if args.p2 else "p1",
              "duration_s": args.duration, "legit": args.legit, "bots": args.bots,
              "socket": os.environ["L7_SOCKET_PATH"], "model": model_path,
              "model_untrained": bool(args.p2 and not args.model)}
    try:
        print(f"[*] Building topology (L7_SHADOW=1, {args.legit} legit, {args.bots} bots"
              f"{', P2: record + model + XDP_GRU=0' if args.p2 else ''})...")
        legit_nodes, botnet_nodes = S.build_topology()
        half = len(botnet_nodes) // 2 if args.p2 else len(botnet_nodes)
        burst_bots, flood_bots = botnet_nodes[:half], botnet_nodes[half:]

        # Wait for the shadow thread to bind the socket.
        ready = False
        for _ in range(60):
            try:
                with open(S.LOG_FILE, encoding="utf-8", errors="replace") as fh:
                    if "L7 shadow ingestion on" in fh.read():
                        ready = True
                        break
            except OSError:
                pass
            time.sleep(0.5)
        report["shadow_ready"] = ready
        print(f"[{'+' if ready else '-'}] L7 shadow thread "
              f"{'ready' if ready else 'NOT ready (continuing)'}.")

        sample_cpu = daemon_cpu_sampler(control_plane_pid)
        sample_cpu()                      # prime
        S.start_legit_traffic(legit_nodes)
        time.sleep(8)                     # warm up, let startup transient pass

        base_file = wc_lines(access_log)
        base_ev = last_shadow_event(events_path) or {}
        base_recv = base_ev.get("received", 0)
        print(f"[*] Baseline: file={base_file} lines, socket received={base_recv}.")

        cpu_samples = []
        series = []                       # (elapsed_s, file_lines, socket_received)
        burst_at = args.duration / 3.0     # attack burst fired here
        probe_at = (0.42 if args.p2 else 0.5) * args.duration
        flood_at = 0.5 * args.duration     # --p2 only
        settle_after = 2.0 * args.duration / 3.0   # steady window = after burst + bans settle
        t_end = time.time() + args.duration
        burst_done = probe_done = flood_done = False
        flood_procs, flood_stop = [], None
        while time.time() < t_end:
            elapsed = args.duration - (t_end - time.time())
            # Attack burst (the socket stress; the rate rule will ban these bots,
            # which is expected — we measure the burst that flows).
            if not burst_done and elapsed >= burst_at:
                print(f"[*] Attack burst (wrk from {len(burst_bots)} bots)...")
                for ns, _ in burst_bots:
                    S.run(f"wrk -t2 -c30 -d10s {S.HTTP_URL}", ns=ns, bg=True)
                burst_done = True
            # A legit client sends a ~900 B User-Agent, to probe truncation.
            if not probe_done and elapsed >= probe_at:
                ns = legit_nodes[0][0]
                big_ua = "UA-" + "x" * 900
                for _ in range(5):
                    S.run(["curl", "-s", "-o", "/dev/null", "-A", big_ua,
                           "--max-time", "5", S.HTTP_URL], ns=ns, timeout=8)
                probe_done = True
                print("[*] Truncation probe sent (long User-Agent).")
            # --p2: a short SYN flood from not-yet-banned bots arms flood suppression.
            if args.p2 and not flood_done and elapsed >= flood_at:
                print(f"[*] SYN flood ({len(flood_bots)} bots, ~6 s) to arm flood suppression...")
                flood_procs = [S.run(f"hping3 -S -p 80 -i u1000 {S.SERVER_IP}", ns=ns, bg=True)
                               for ns, _ in flood_bots]
                flood_stop = time.time() + 6.0
                flood_done = True
            if flood_stop and time.time() >= flood_stop:
                for p in flood_procs:
                    if p is not None and p.poll() is None:
                        p.terminate()
                flood_stop = None
            c = sample_cpu()
            if c is not None:
                cpu_samples.append(c)
            series.append((round(elapsed, 1), wc_lines(access_log),
                           (last_shadow_event(events_path) or {}).get("received", 0)))
            time.sleep(2)

        S.stop_legit_traffic()
        # Let the socket fully drain and at least one more l7_shadow event fire (every
        # 5 s), so `received` catches up to the instantaneous file count — otherwise the
        # final counts differ by the handful of lines that arrived in the last <5 s
        # (sampling lag, not loss).
        time.sleep(7)
        final_file = wc_lines(access_log)
        final_ev = last_shadow_event(events_path) or {}

        def drop_pct(file_d, recv_d):
            d = max(file_d - recv_d, 0)
            return (d, round(100 * d / file_d, 3) if file_d else None)

        # Overall (includes the flood burst, so dominated by it).
        file_delta = final_file - base_file
        recv_delta = final_ev.get("received", 0) - base_recv
        drops, overall_pct = drop_pct(file_delta, recv_delta)
        # Steady window = the sub-threshold regime the GRU targets: after the burst and
        # its bans settle, pure legit traffic.
        steady = [s for s in series if s[0] >= settle_after]
        s_file = s_recv = s_pct = s_drops = None
        if len(steady) >= 2:
            s_file = steady[-1][1] - steady[0][1]
            s_recv = steady[-1][2] - steady[0][2]
            s_drops, s_pct = drop_pct(s_file, s_recv)
        # Worst single ~2 s interval (the burst peak).
        peak = 0
        for a, b in itertools.pairwise(series):
            peak = max(peak, (b[1] - a[1]) - (b[2] - a[2]))
        report.update({
            "file_lines_delta": file_delta, "socket_received_delta": recv_delta,
            "estimated_drops": drops, "overall_drop_pct": overall_pct,
            "steady_file_delta": s_file, "steady_received_delta": s_recv,
            "steady_drops": s_drops, "steady_drop_pct": s_pct,
            "peak_interval_drops": peak,
            "truncated_total": final_ev.get("truncated", 0),
            "parse_errors_total": final_ev.get("parse_errors", 0),
            "parsed_total": final_ev.get("parsed", 0),
            "received_total": final_ev.get("received", 0),
            "active_keys": final_ev.get("active_keys", 0),
            "distinct_ips": final_ev.get("distinct_ips", 0),
            "full_windows": final_ev.get("full_windows", 0),
            "daemon_cpu_pct_mean": round(sum(cpu_samples) / len(cpu_samples), 1) if cpu_samples else None,
            "daemon_cpu_pct_max": round(max(cpu_samples), 1) if cpu_samples else None,
            "cpu_n_samples": len(cpu_samples),
            "series": series,
        })
    finally:
        try:
            S.stop_legit_traffic()
        except Exception as e:            # noqa: BLE001 — cleanup must not mask the result
            print(f"[-] stop_legit_traffic during cleanup: {e}")
        S.cleanup_all()
        print("[+] Topology cleaned up.")

    if args.p2:
        print("[*] P2 analysis: replay determinism, feature summaries, probes...")
        report["p2"] = analyse_p2(out_dir, events_path, record_path, model_path)

    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
        fh.write("\n")

    print("\n=== L7 smoke summary ===")
    for k, v in report.items():
        if k == "series":
            print(f"  {k:24s} {len(v)} samples (in summary.json)")
        elif k == "p2":
            print(f"  {k:24s} (see below)")
        else:
            print(f"  {k:24s} {v}")
    print(f"\n[+] Wrote {os.path.join(out_dir, 'summary.json')}")
    # The gate judges the sub-threshold regime the GRU targets (steady window), not
    # the flood burst (which the deterministic rate rule owns and the file sink keeps).
    # A few residual steady "drops" are 5 s counter-vs-file sampling lag, not loss, so
    # the tolerance is absolute (a handful of lines) as well as relative.
    s_drops = report.get("steady_drops")
    s_file = report.get("steady_file_delta") or 0
    tol = max(5, int(0.01 * s_file))
    ok = (report.get("parsed_total", 0) > 0 and report.get("full_windows", 0) > 0
          and report.get("truncated_total", 0) == 0 and report.get("parse_errors_total", 0) == 0
          and s_drops is not None and s_drops <= tol)
    print(f"[{'+' if ok else '!'}] P1 transport health: {'PASS' if ok else 'REVIEW'} "
          f"— steady-regime drops {s_drops}/{s_file} (tol {tol}, lag not loss), "
          f"truncation {report.get('truncated_total')}, windows filled {report.get('full_windows')}. "
          f"Flood-burst drop (rate rule's regime; file sink retains all): "
          f"overall {report.get('overall_drop_pct')}%, peak 2 s interval {report.get('peak_interval_drops')}.")

    if args.p2:
        p2 = report["p2"]
        print(json.dumps({k: v for k, v in p2.items() if k != "probes"}, indent=1, default=str))
        probes = p2.get("probes")
        if probes:
            print("probes:", json.dumps({k: (v["pass"] if isinstance(v, dict) else v)
                                         for k, v in probes.items()}))
        exact_ok = (not probes) or all(
            isinstance(probes.get(n), dict) and probes[n]["pass"]
            for n in ("ua_swap", "uri_bijection", "time_offset"))
        totals = p2.get("live_totals", {})
        ok2 = (ok and p2.get("determinism", {}).get("match", False)
               and totals.get("windows", 0) > 0 and totals.get("suppressed_polls", 0) > 0
               and exact_ok and not p2.get("non_deterministic_bans"))
        print(f"[{'+' if ok2 else '!'}] P2 shadow engine: {'PASS' if ok2 else 'REVIEW'} — "
              f"replay determinism {p2.get('determinism', {}).get('match')}, "
              f"windows scored {totals.get('windows')}, suppressed polls "
              f"{totals.get('suppressed_polls')}, gated (age) {totals.get('gated_age')}, "
              f"exact probes {'pass' if exact_ok else 'FAIL'}, "
              f"non-deterministic bans {len(p2.get('non_deterministic_bans', []))}.")


if __name__ == "__main__":
    main()

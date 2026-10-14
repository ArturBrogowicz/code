#!/usr/bin/env python3
"""P1 smoke capture for the L7 ingestion path (docs/L7_GRU_DESIGN.md §8, P1 gate).

Brings up the testbed with the daemon in L7 shadow mode (L7_SHADOW=1), drives a
short mix of legit traffic, an attack burst and a long-User-Agent probe, and
measures the three things only a live run can show:

  * drop rate  — nginx writes every request to BOTH the durable file access_log
                 and the Unix-datagram socket; SOCK_DGRAM gives the receiver no
                 drop counter, so drops = (file lines) - (socket received) over
                 the measurement window (§4.3);
  * truncation — datagrams that arrived cut short (counted in the daemon);
  * ingest CPU — the control_plane python process's CPU while ingesting.

This IS a VM workload: it builds namespaces/veths/bridge, attaches XDP, starts
nginx + gunicorn + the daemon in server_ns, binds /run/ddos_l7.sock and sends
traffic. Run with sudo. It reuses test_distributed_suite for every state change,
so capture == the suite's environment. Nothing is banned by the shadow path; the
existing deterministic rules still run and may ban the attack burst (expected).

    sudo ./venv/bin/python ml/smoke_l7.py [--duration 180] [--legit 6] [--bots 4]
"""
import argparse
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_OUT = "/var/tmp/ddos_l7_smoke"


def wc_lines(path):
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def last_shadow_event(events_path):
    """Return the most recent l7_shadow event dict, or None."""
    last = None
    try:
        with open(events_path, encoding="utf-8") as fh:
            for line in fh:
                if '"l7_shadow"' in line:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("kind") == "l7_shadow":
                        last = rec
    except OSError:
        return None
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--duration", type=float, default=180.0, help="total seconds")
    ap.add_argument("--legit", type=int, default=6, help="legit client namespaces")
    ap.add_argument("--bots", type=int, default=4, help="attacker namespaces for the burst")
    ap.add_argument("--out", default=DEFAULT_OUT, help="results directory root")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("[-] Must run as root (namespaces + XDP). Use sudo.")

    out_dir = os.path.join(args.out, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(out_dir, exist_ok=True)
    events_path = os.path.join(out_dir, "ban_events.jsonl")

    # Must be set before the daemon is launched: the daemon subprocess inherits the
    # environment (_daemon_cmd uses `env`), so L7_SHADOW/BAN_EVENTS reach it.
    os.environ["L7_SHADOW"] = "1"
    os.environ["BAN_EVENTS"] = events_path
    os.environ.setdefault("L7_SOCKET_PATH", "/run/ddos_l7.sock")

    sys.path.insert(0, REPO)
    import test_distributed_suite as S

    S.LEGIT_COUNT = args.legit
    S.BOTNET_COUNT = args.bots
    access_log = S.NGINX_LOG_FILE

    report = {"out_dir": out_dir, "duration_s": args.duration, "legit": args.legit,
              "bots": args.bots, "socket": os.environ["L7_SOCKET_PATH"]}
    try:
        print(f"[*] Building topology (L7_SHADOW=1, {args.legit} legit, {args.bots} bots)...")
        legit_nodes, botnet_nodes = S.build_topology()

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
        t_end = time.time() + args.duration
        burst_done = truncation_probe_done = False
        while time.time() < t_end:
            elapsed = args.duration - (t_end - time.time())
            # ~1/3 in: attack burst from all bots (the socket stress; the rate rule
            # will ban them, which is expected — we measure the burst that flows).
            if not burst_done and elapsed >= args.duration / 3:
                print("[*] Attack burst (wrk from all bots)...")
                for ns, _ in botnet_nodes:
                    S.run(f"wrk -t2 -c30 -d10s {S.HTTP_URL}", ns=ns, bg=True)
                burst_done = True
            # ~1/2 in: a legit client sends a ~900 B User-Agent, to probe truncation.
            if not truncation_probe_done and elapsed >= args.duration / 2:
                ns = legit_nodes[0][0]
                big_ua = "UA-" + "x" * 900
                for _ in range(5):
                    S.run(["curl", "-s", "-o", "/dev/null", "-A", big_ua,
                           "--max-time", "5", S.HTTP_URL], ns=ns, timeout=8)
                truncation_probe_done = True
                print("[*] Truncation probe sent (long User-Agent).")
            c = sample_cpu()
            if c is not None:
                cpu_samples.append(c)
            time.sleep(2)

        S.stop_legit_traffic()
        time.sleep(2)
        final_file = wc_lines(access_log)
        final_ev = last_shadow_event(events_path) or {}

        file_delta = final_file - base_file
        recv_delta = final_ev.get("received", 0) - base_recv
        drops = max(file_delta - recv_delta, 0)
        report.update({
            "file_lines_delta": file_delta, "socket_received_delta": recv_delta,
            "estimated_drops": drops,
            "drop_pct": round(100 * drops / file_delta, 3) if file_delta else None,
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
        })
    finally:
        try:
            S.stop_legit_traffic()
        except Exception as e:            # noqa: BLE001 — cleanup must not mask the result
            print(f"[-] stop_legit_traffic during cleanup: {e}")
        S.cleanup_all()
        print("[+] Topology cleaned up.")

    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")

    print("\n=== L7 P1 smoke summary ===")
    for k, v in report.items():
        print(f"  {k:24s} {v}")
    print(f"\n[+] Wrote {os.path.join(out_dir, 'summary.json')}")
    # A quick health verdict for the P1 gate.
    ok = (report.get("parsed_total", 0) > 0 and report.get("full_windows", 0) > 0
          and (report.get("drop_pct") or 0) < 1.0 and report.get("truncated_total", 0) == 0)
    print(f"[{'+' if ok else '!'}] P1 transport health: {'PASS' if ok else 'REVIEW'} "
          f"(parsed>0, windows filled, drops<1%, no truncation).")


if __name__ == "__main__":
    main()

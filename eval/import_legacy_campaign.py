#!/usr/bin/env python3
"""Convert a campaign recorded before the reproducible harness existed into the layout
that eval/analyze_campaign.py reads.

    venv/bin/python eval/import_legacy_campaign.py SRC DST --operating-point knee

SRC is a prototype campaign directory (the 2026-10-12 experiments of
docs/REPORT_ADDENDUM_EXP0_EXP1.md): one sub-directory per mode with the suite's
CSVs, where several runs were APPENDED into one file, plus
    console.log                  console of all runs ("===== ... run i/N =====" markers)
    daemon_log_timestamped.txt   daemon log lines prefixed with an epoch timestamp taken
                                 by a tail -F observer (the suite deleted the log itself)
and a campaign-level provenance.txt ("HEAD <sha> ... COMMON: K=V ..." + sha256 lines).

DST receives <mode>/run<k>/ with per-run CSVs (rows copied verbatim), ban_events.jsonl
derived from the [BAN] lines, scenario_results.csv and provenance.json (marked
"imported"). Approximations, recorded in provenance.json:
  * the attack start is the Phase-1 (baseline) metrics timestamp, written just before
    the launch; the attack end is the Phase-3 timestamp, written just before the kill;
  * event times are the observer's read times; request start = completion - latency;
  * CSV timestamps are naive local time, which was UTC on the testbed VM.
"""
import argparse
import csv
import datetime
import json
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ban_events

TAG = {"xdp": "performance", "iptables": "iptables", "nginxlimits": "nginxlimits",
       "unprotected": "unprotected"}
MODE_ENV = {"xdp": ("active", "xdp", False), "iptables": ("active", "iptables", False),
            "nginxlimits": ("none", "xdp", True), "unprotected": ("none", "xdp", False)}
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SCENARIO_RESULT_FIELDS = [
    "Scenario", "Data_Scenario", "Mode", "Operating_Point", "Profile_Seed", "Attack_Duration_s",
    "Scenario_T0", "Attack_Start", "Attack_End", "Exposure_s", "Bots",
    "Banned_Harness", "Banned_Events", "TTM_Harness_Mean_s", "TTM_Exact_Median_s",
    "TTM_Exact_Max_s", "TTM_Exact_By_Bot", "Engine_By_Bot", "FP_Source", "FP_IPs",
    "FP_Ping_IPs", "Legit_HTTP_OK", "Legit_HTTP_Total", "Result"]


def _fmt(x):
    return "" if x is None else f"{x:.3f}"


def epoch_utc(iso):
    return datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.UTC).timestamp()


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    return rows[0], rows[1:]


def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def split_runs(metrics_rows):
    """Runs from the appended metrics rows: a run restarts when a scenario's Phase 1
    reappears. Returns [{"start": epoch, "scenarios": [{"name", "p1", "p3"}]}]."""
    runs = []
    for ts, scen, phase, *_ in metrics_rows:
        t = epoch_utc(ts)
        if phase.startswith("Phase 1"):
            if not runs or any(s["name"] == scen for s in runs[-1]["scenarios"]):
                runs.append({"start": t, "scenarios": []})
            runs[-1]["scenarios"].append({"name": scen, "p1": t, "p3": None})
        elif phase.startswith("Phase 3") and runs:
            runs[-1]["scenarios"][-1]["p3"] = t
    return runs


def run_index(runs, t, margin=10.0):
    """Index of the run a timestamp belongs to (the last run starting before it)."""
    idx = None
    for i, r in enumerate(runs):
        if t >= r["start"] - margin:
            idx = i
    return idx


def daemon_line_runs(runs, dlog):
    """Run index of every daemon-log line. A daemon instance starts up to ~60 s before
    the scenario it serves (topology build / reset), so its "start" line belongs to the
    NEXT scenario's run, and every later line to the same instance."""
    p1s = sorted((s["p1"], i) for i, r in enumerate(runs) for s in r["scenarios"])
    out, current = [], None
    for t, _, ev in dlog:
        if ev is not None and ev["kind"] == "start":
            nxt = [i for p1, i in p1s if p1 >= t]
            current = nxt[0] if nxt else run_index(runs, t)
        out.append(current if current is not None else run_index(runs, t))
    return out


def console_sections(path):
    """Console text per run, split at the "===== ... run i/N =====" markers."""
    sections, cur = [], None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if re.match(r"^===== .* run \d+/\d+ =====", ANSI.sub("", line)):
                cur = []
                sections.append(cur)
            if cur is not None:
                cur.append(line)
    return ["".join(s) for s in sections]


def report_blocks(console_text):
    """[{name, result, banned, avg_ttm, http_ok, http_total, bots}] from report blocks."""
    text = ANSI.sub("", console_text)
    bots = re.search(r"Botnet ready: (\d+) nodes", text)
    blocks = []
    for line in text.splitlines():
        m = re.match(r"^\s+\[(PASS|FAIL)\] (.+?)\s*$", line)
        if m:
            blocks.append({"result": m.group(1), "name": m.group(2),
                           "bots": int(bots.group(1)) if bots else None})
            continue
        if not blocks:
            continue
        if m := re.search(r"Botnet banned:\s+(\d+)/(\d+)", line):
            blocks[-1]["banned"], blocks[-1]["bots"] = int(m.group(1)), int(m.group(2))
        elif m := re.search(r"Avg TTM:\s+([\d.]+)s", line):
            blocks[-1]["avg_ttm"] = float(m.group(1))
        elif m := re.search(r"Legit HTTP:\s+(\d+)/(\d+)", line):
            blocks[-1]["http_ok"], blocks[-1]["http_total"] = int(m.group(1)), int(m.group(2))
    return blocks


def daemon_events(path):
    """(epoch, line, event-or-None) for every daemon line of an observer log; [BAN] and
    start lines become ban-event records.

    The observer (`tail -n +1 -F`) first dumped whatever log file already existed, i.e.
    the PREVIOUS mode's last run, all stamped with the observer's start time. That replay
    ends at tail's "has become inaccessible" notice (the suite deleting the file) and is
    dropped, as are tail's own notices."""
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    if lines and " tail: " not in lines[0][:40]:          # started on a pre-existing file
        stale_end = next((i for i, ln in enumerate(lines) if "has become inaccessible" in ln), -1)
        lines = lines[stale_end + 1:]
    for line in lines:
        m = re.match(r"^(\d+\.\d+) (.*)$", line)
        if not m or m.group(2).startswith("tail: "):
            continue
        t, text = float(m.group(1)), m.group(2)
        ev = None
        if b := re.match(r"\[BAN\] (\S+) banned for (\d+)s\. Reason: (.*)$", text):
            ev = {"t_wall": t, "t_mono_ns": None, "kind": "ban", "ip": b.group(1),
                  "engine": ban_events.engine_from_reason(b.group(3)), "reason": b.group(3),
                  "ttl_s": int(b.group(2)), "source": "observer"}
        elif text.startswith("[*] Starting tri-engine"):
            ev = {"t_wall": t, "t_mono_ns": None, "kind": "start", "source": "observer"}
        out.append((t, line + "\n", ev))
    return out


def parse_provenance(path):
    info = {"head": None, "common": {}, "sha256": {}, "started": None}
    if not os.path.isfile(path):
        return info
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if m := re.search(r"HEAD (\w+)", line):
                info["head"] = m.group(1)
            if m := re.search(r"COMMON: (.*)$", line.strip()):
                info["common"] = dict(kv.split("=", 1) for kv in m.group(1).split() if "=" in kv)
            if m := re.match(r"^([0-9a-f]{64})\s+(\S+)$", line.strip()):
                info["sha256"][m.group(2)] = m.group(1)
    return info


def convert_mode(src_mode, dst_mode, mode, op_name, prov):
    tag = TAG[mode]
    metrics_name = "mitigation_performance.csv" if tag == "performance" else f"metrics_{tag}.csv"
    m_hdr, m_rows = read_csv(os.path.join(src_mode, metrics_name))
    a_hdr, a_rows = read_csv(os.path.join(src_mode, f"availability_{tag}.csv"))
    r_hdr, r_rows = read_csv(os.path.join(src_mode, f"availability_raw_{tag}.csv"))
    runs = split_runs(m_rows)
    consoles = console_sections(os.path.join(src_mode, "console.log"))
    dlog = daemon_events(os.path.join(src_mode, "daemon_log_timestamped.txt"))
    mm, backend, protected = MODE_ENV[mode]
    lat_i, ts_i = r_hdr.index("Latency_ms"), r_hdr.index("Timestamp")
    dlog_run = daemon_line_runs(runs, dlog)
    for k, run in enumerate(runs, 1):
        rdir = os.path.join(dst_mode, f"run{k}")
        os.makedirs(rdir, exist_ok=True)

        def mine(rows, col=0, k=k):
            return [r for r in rows if run_index(runs, epoch_utc(r[col])) == k - 1]

        write_csv(os.path.join(rdir, "metrics.csv"), m_hdr, mine(m_rows))
        write_csv(os.path.join(rdir, "availability.csv"), a_hdr, mine(a_rows))
        raw = mine(r_rows, ts_i)
        write_csv(os.path.join(rdir, "availability_raw.csv"), r_hdr + ["Client_IP", "T_Start"],
                  [r + ["", f"{epoch_utc(r[ts_i]) - float(r[lat_i]) / 1000.0:.3f}"] for r in raw])
        lines = [entry for entry, idx in zip(dlog, dlog_run) if idx == k - 1]
        events = [ev for _, _, ev in lines if ev]
        with open(os.path.join(rdir, "ban_events.jsonl"), "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(ev, separators=(",", ":")) + "\n" for ev in events)
        with open(os.path.join(rdir, "daemon.log"), "w", encoding="utf-8") as fh:
            fh.writelines(line + ("" if line.endswith("\n") else "\n") for _, line, _ in lines)
        if k - 1 < len(consoles):
            with open(os.path.join(rdir, "console.log"), "w", encoding="utf-8") as fh:
                fh.write(consoles[k - 1])
        blocks = report_blocks(consoles[k - 1]) if k - 1 < len(consoles) else []
        has_daemon = any(ev["kind"] == "start" for ev in events)
        results = []
        for j, sc in enumerate(run["scenarios"]):
            blk = blocks[j] if j < len(blocks) else {}
            start, end = sc["p1"], sc["p3"]
            n_bots = blk.get("bots") or int(prov["common"].get("BOTNET_COUNT", 5))
            bot_ips = [f"10.0.2.{i}" for i in range(1, n_bots + 1)]
            first = ban_events.first_bans(events, ips=bot_ips, since=start, until=(end or start) + 15)
            ttm = {ip: e["t_wall"] - start for ip, e in sorted(first.items())}
            fps = sorted(ip for ip in ban_events.first_bans(events, since=start - 4.0)
                         if ip.startswith("10.0.1."))
            vals = sorted(ttm.values())
            med = statistics.median(vals) if vals else None
            fmt = _fmt
            results.append([
                blk.get("name", sc["name"]), sc["name"], mode, op_name, "", 0.0,
                fmt(start - 4.0), fmt(start), fmt(end), fmt(end - start if end else None), n_bots,
                blk.get("banned", ""), len(ttm) if has_daemon else "", fmt(blk.get("avg_ttm")),
                fmt(med), fmt(vals[-1] if vals else None),
                json.dumps({ip: round(t, 3) for ip, t in ttm.items()}),
                json.dumps({ip: first[ip].get("engine", "unknown") for ip in sorted(first)}),
                "ban events" if has_daemon else "no daemon", json.dumps(fps), "",
                blk.get("http_ok", ""), blk.get("http_total", ""), blk.get("result", "")])
        write_csv(os.path.join(rdir, "scenario_results.csv"), SCENARIO_RESULT_FIELDS, results)
        provenance = {
            "schema": 1, "run_id": f"run{k}", "status": "completed",
            "imported": {
                "tool": "eval/import_legacy_campaign.py", "from": os.path.abspath(src_mode),
                "note": ("Recorded with a prototype copy of test_distributed_suite.py before the "
                         "reproducible harness existed; attack start/end approximated by the "
                         "Phase-1/Phase-3 metrics timestamps, event times by a tail -F observer "
                         "(its replay of the previous mode's log and its own notices removed), "
                         "client profiles unseeded (plan not recorded).")},
            "started_utc": datetime.datetime.fromtimestamp(run["start"] - 4.0, datetime.UTC)
                                              .isoformat(timespec="seconds"),
            "git": {"commit": prov["head"], "branch": None, "dirty": None, "dirty_files": []},
            "mode": {"label": mode, "MITIGATION_MODE": mm, "MITIGATION_BACKEND": backend,
                     "NGINX_PROTECTED": protected, "GRU_ONLY": False},
            "operating_point": {"name": op_name, **{k2: v for k2, v in prov["common"].items()
                                                    if k2 != "ONLY_SCENARIOS"}},
            "settings": {"ATTACK_DURATION": 0.0, "PROFILE_SEED": None,
                         "ONLY_SCENARIOS": prov["common"].get("ONLY_SCENARIOS", "")},
            "profile_plan": [],
            "inputs_sha256": prov["sha256"],
        }
        with open(os.path.join(rdir, "provenance.json"), "w", encoding="utf-8") as fh:
            json.dump(provenance, fh, indent=1)
            fh.write("\n")
    return len(runs)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", help="prototype campaign directory (one sub-directory per mode)")
    ap.add_argument("dst", help="output directory (must not exist)")
    ap.add_argument("--operating-point", required=True, help="name recorded in provenance")
    ap.add_argument("--modes", default="xdp,iptables,nginxlimits,unprotected")
    args = ap.parse_args()
    if os.path.exists(args.dst):
        sys.exit(f"{args.dst} exists; refusing to overwrite")
    prov = parse_provenance(os.path.join(args.src, "provenance.txt"))
    for mode in args.modes.split(","):
        n = convert_mode(os.path.join(args.src, mode), os.path.join(args.dst, mode), mode,
                         args.operating_point, prov)
        print(f"[+] {mode}: {n} runs")


if __name__ == "__main__":
    main()

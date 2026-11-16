"""Independent recomputation of P2-2b's gate figures and P2 outcome from the run files (pure Python, no project import).

Definitions written from the pre-registered rule (harm_gate.P2_OUTCOME, run_metrics as read): per run, over the legit streams of
the judged link profiles, the requests whose intended time on the run's axis (t_intended + offset_s) lies in the attack window
[baseline, baseline + attack); a request is ok if answered (err empty, t_sent and t_done present), 2xx and its service time
(t_done - t_sent) is within its route class's SLO. Q = 100 ok / n; p95 = linear-interpolated 95th percentile of the ok service
times. Unprotected harmed: dQ = Q(C) - Q(U) >= 10 pp or p95(U) >= 2 x p95(C). Protected works: Q(M) >= 0.99 x Q(C) in 9 of 10
blocks and no benign address (10.0.1.0/24, 10.0.3.0/24) banned in any M_xdp attempt. TTM: an attack address's first ban less
(zero_epoch_s + median of the attack streams' offsets)."""
import csv, glob, gzip, ipaddress, json, math, os, statistics, sys

ROOT = sys.argv[1]
CAL = json.load(open(sys.argv[2]))
SLO = {k: v / 1000.0 for k, v in CAL["slo_ms"].items()}
JUDGED = set(CAL["judged_profiles"])
BENIGN = [ipaddress.ip_network("10.0.1.0/24"), ipaddress.ip_network("10.0.3.0/24")]
ATTACK = [ipaddress.ip_network("10.0.2.0/24")]


def quantile(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    pos = q * (len(xs) - 1)
    lo = math.floor(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def fnum(s):
    try:
        return float(s)
    except ValueError:
        return float("nan")


def run_q(run_dir):
    meta = json.load(open(os.path.join(run_dir, "run.json")))
    plan = json.load(open(os.path.join(run_dir, "plan.json")))
    tl = plan["timeline"]
    lo, hi = tl["baseline_s"], tl["baseline_s"] + tl["attack_s"]
    n = ok = 0
    good = []
    for s in meta["streams"]:
        if s["kind"] != "legit" or s["netem"] not in JUDGED:
            continue
        limit = SLO[s["route_class"]]
        with gzip.open(os.path.join(run_dir, s["records"]), "rt", newline="") as fh:
            rd = csv.DictReader(fh)
            for r in rd:
                t_run = fnum(r["t_intended"]) + float(s["offset_s"])
                if not (lo <= t_run < hi):
                    continue
                n += 1
                ts, td, st = fnum(r["t_sent"]), fnum(r["t_done"]), fnum(r["status"])
                answered = r["err"] == "" and not math.isnan(ts) and not math.isnan(td)
                if answered and 200 <= st < 300 and (td - ts) <= limit:
                    ok += 1
                    good.append(td - ts)
    return meta, 100.0 * ok / n, quantile(good, 0.95), n, ok


def bans(run_dir, meta):
    path = os.path.join(run_dir, "ban_events.jsonl")
    first = {}
    for line in open(path):
        e = json.loads(line)
        if e["kind"] == "ban" and e["ip"] not in first:
            first[e["ip"]] = e["t_wall"]
    benign = sorted(ip for ip in first if any(ipaddress.ip_address(ip) in net for net in BENIGN))
    attack = sorted(ip for ip in first if any(ipaddress.ip_address(ip) in net for net in ATTACK))
    idents = {a for s in meta["streams"] if s["kind"] == "attack" for a in s.get("addresses", [])}
    offs = [s["offset_s"] for s in meta["streams"] if s["kind"] == "attack"]
    start = meta["executor"]["zero_epoch_s"] + statistics.median(offs)
    ttm = [first[ip] - start for ip in attack]
    return benign, attack, idents, ttm


gate = json.load(open(os.path.join(ROOT, "gate.json")))
gblocks = {b["block"]: b for b in gate["blocks"]}
rows = []
all_benign = set()
all_ttm = []
attack_ids = attack_banned = 0
mism = 0
print("block dir    QC      QCp     QU     QM      dQ     dL    harmed  works  benign  sound(all 4)  start_err(U,M)  launch(U,M)")
for d in sorted(glob.glob(os.path.join(ROOT, "b*_a*"))):
    blk = json.load(open(os.path.join(d, "block.json")))
    res = {}
    snd = []
    for arm in ("C", "Cp", "U", "M_xdp"):
        meta, q, p95, n, ok = run_q(os.path.join(d, arm))
        res[arm] = (q, p95, meta)
        ex = meta["executor"]
        snd.append(ex["ok"] and not ex["reasons"] and meta["speed"]["ok"] and blk["runs"][arm]["host"]["ok"])
    qc, pc = res["C"][0], res["C"][1]
    qu, pu = res["U"][0], res["U"][1]
    qm = res["M_xdp"][0]
    dQ = qc - qu
    dL = math.log2(pu / pc)
    harmed = dQ >= 10.0 or pu >= 2.0 * pc
    benign, attack, idents, ttm = bans(os.path.join(d, "M_xdp"), res["M_xdp"][2])
    all_benign |= set(benign)
    all_ttm += ttm
    attack_ids += len(idents)
    attack_banned += len(attack)
    works = qm >= 0.99 * qc
    b = blk["block"]
    g = gblocks.get(b)
    gp = next(r for r in gate["protected"][0]["blocks"] if r["block"] == b)
    diffs = [abs(g["dQ"] - dQ) > 1e-9, abs(g["dL"] - dL) > 1e-9, abs(gp["q_control"] - qc) > 1e-9,
             abs(gp["q_mitigated"] - qm) > 1e-9]
    mism += sum(diffs)
    se = [res[a][2]["executor"].get("attack_start_error_s") for a in ("U", "M_xdp")]
    la = [res[a][2]["executor"].get("attack_launch", {}).get("rule") for a in ("U", "M_xdp")]
    rows.append((b, qc, qm, works))
    print(f"{b:>3} {os.path.basename(d)} {qc:7.2f} {res['Cp'][0]:7.2f} {qu:6.2f} {qm:7.2f} {dQ:6.2f} {dL:5.2f}  {harmed!s:6} {works!s:6} "
          f"{len(benign):>3}     {all(snd)!s:6}   {se[0]:+.3f},{se[1]:+.3f}   {la[0]},{la[1]}   mismatches vs gate: {sum(diffs)}")
need = math.ceil(0.9 * len(rows) - 1e-9)
held = sum(1 for r in rows if r[3])
print(f"\nblocks {len(rows)}; protected held {held} of {len(rows)} (needs {need}); benign banned {sorted(all_benign)}; "
      f"attack banned {attack_banned} of {attack_ids}; TTM median {statistics.median(all_ttm):.3f} max {max(all_ttm):.3f} n {len(all_ttm)}")
print("Q(M)/Q(C) per block:", [round(r[2] / r[1], 4) for r in rows])
print("total mismatches vs gate.json:", mism)

#!/usr/bin/env python3
"""Offline diagnosis of the GRU detection engine (see docs/ML_INVESTIGATION.md).

Read-only: no traffic, no XDP, no training. The deployed model is loaded with
torch.load(weights_only=True) and only scored. Writes only to --out.

  1. Ban-event census of every published run (results/): GRU bans and suppressed
     GRU detections since the MAC fix.
  2. Race per scenario in the full-suite regression run: first-ban engine, time to
     mitigate, and when flood suppression paused the GRU.
  3. Replay of the daemon's GRU decision rule on the Tier-1 capture: the earliest
     moment the GRU could ban each attacker (and whether it would ban a benign client).
  4. Out-of-distribution probes: what the model makes of the flows the suite's floods
     produce.
  5. Why leave-one-family-out R.U.D.Y. fails: feature profile of each attack family.
  6. Why transfer to CIC-IDS2017 fails: direction of every feature in both domains, and
     the deployed model's AUC with and without the out-of-range TCP window.

    venv/bin/python ml/diagnose_gru.py [--out ml/diagnosis]
"""
import argparse
import ast
import collections
import glob
import hashlib
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events
from GRU_ML_model import GRUDDoSClassifier

CFG_PATH = os.path.join(REPO, "training_results", "feature_config_testbed.json")
TIER1 = os.path.join(REPO, "training_data", "testbed_flows.csv")
CIC = os.path.join(REPO, "training_data", "cicids2017_dosddos.csv")
REGRESSION_RUN = os.path.join(REPO, "results", "2026-10-13_regression-default-full-suite")
# Capture schedule (capture_testbed_dataset.py SCHED): attacker IP -> (family, setting).
CAPTURE_BOTS = {"10.0.2.1": ("http-flood", "wrk -c50"), "10.0.2.2": ("http-flood", "wrk -c30"),
                "10.0.2.3": ("slowloris", "N=8"), "10.0.2.4": ("slowloris", "N=30"),
                "10.0.2.5": ("rudy", "N=10"), "10.0.2.6": ("rudy", "N=20")}
# Suite scenarios whose bots run the same tool and setting as a capture bot.
SUITE_MATCH = {"10.0.2.1": "Distributed HTTP Flood", "10.0.2.3": "Distributed Slowloris",
               "10.0.2.5": "Distributed R.U.D.Y."}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def daemon_constants():
    """Decision constants from control_plane.py, parsed (importing it attaches XDP)."""
    with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    want = {"PREDICTION_THRESHOLD", "GRU_CONSECUTIVE_THRESH", "L4_POLL_INTERVAL",
            "MAX_GRU_FLOWS_PER_POLL", "VOLUMETRIC_COOLDOWN", "HEURISTIC_MAX_RPS",
            "SLOWCONN_CONN_THRESHOLD", "SLOWCONN_CONSECUTIVE"}
    out = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in want):
            out[node.targets[0].id] = ast.literal_eval(node.value)
    return out


class Model:
    def __init__(self):
        with open(CFG_PATH) as fh:
            self.cfg = json.load(fh)
        self.features, self.seq = self.cfg["features"], self.cfg["seq_length"]
        self.net = GRUDDoSClassifier(self.cfg["input_size"], self.cfg["hidden_size"],
                                     self.cfg["num_layers"])
        self.net.load_state_dict(torch.load(os.path.join(REPO, self.cfg["model"]),
                                            map_location="cpu", weights_only=True))
        self.net.eval()
        self.scaler = joblib.load(os.path.join(REPO, self.cfg["scaler"]))

    def score(self, windows):
        w = np.asarray(windows, dtype=np.float64)
        x = self.scaler.transform(w.reshape(-1, w.shape[-1])).reshape(w.shape).astype(np.float32)
        with torch.no_grad():
            return torch.sigmoid(self.net(torch.from_numpy(x))).numpy().ravel()


def md_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def f(x, fmt="{:.2f}"):
    return "—" if x is None or (isinstance(x, float) and np.isnan(x)) else fmt.format(x)


# ─────────────────────────────── 1. census ───────────────────────────────

def census():
    rows = []
    for path in sorted(glob.glob(os.path.join(REPO, "results", "**", "ban_events.jsonl"),
                                 recursive=True)):
        ev = ban_events.read_events(path)
        if not any(e["kind"] == "start" for e in ev):
            continue
        kinds = collections.Counter(e["kind"] for e in ev)
        engines = collections.Counter(e.get("engine") for e in ev if e["kind"] == "ban")
        imported = all(e.get("source") == "observer" for e in ev)
        rows.append({"run": os.path.relpath(os.path.dirname(path), os.path.join(REPO, "results")),
                     "events": "imported (bans only)" if imported else "daemon",
                     "bans": kinds["ban"], "gru_bans": engines.get("gru", 0),
                     "gru_suppressed": kinds["gru_suppressed"], "suppress_on": kinds["suppress_on"]})
    return rows


# ─────────────────────────────── 2. race ───────────────────────────────

def race():
    if not os.path.isdir(REGRESSION_RUN):
        return []
    ev = ban_events.read_events(os.path.join(REGRESSION_RUN, "ban_events.jsonl"))
    out = []
    for r in pd.read_csv(os.path.join(REGRESSION_RUN, "scenario_results.csv")).itertuples():
        t0, start, end = r.Scenario_T0, r.Attack_Start, r.Attack_End
        window = [e for e in ev if t0 - 30 <= e["t_wall"] <= end + 12]
        sup = [e["t_wall"] - start for e in window if e["kind"] == "suppress_on"]
        gru = [e for e in window if e["kind"] == "gru_suppressed"
               or (e["kind"] == "ban" and e.get("engine") == "gru")]
        engines = collections.Counter(json.loads(r.Engine_By_Bot).values())
        out.append({"scenario": r.Data_Scenario, "ttm": r.TTM_Exact_Median_s,
                    "engines": ", ".join(f"{k} {v}" for k, v in sorted(engines.items())),
                    "suppress_from": sup[0] if sup else None, "gru_events": len(gru)})
    return out


# ─────────────────────────────── 3. replay ───────────────────────────────

def replay(df, model, thr, hits):
    """The daemon's rule, per source IP and in poll order: a window of the last SEQ
    snapshots is scored for every new snapshot once SEQ exist; the IP is banned after
    `hits` consecutive windows with p > thr, effective when the results are drained at
    the NEXT poll. Times are seconds since the IP's attack was launched (its first
    snapshot is taken one poll after launch)."""
    rows = []
    for ip, g in df.groupby("src_ip", sort=True):
        g = g.sort_values("poll", kind="stable")
        polls, X = g.poll.to_numpy(), g[model.features].to_numpy(np.float64)
        first = polls[0]
        rec = {"ip": ip, "label": int(g.y.iloc[0]), "rows": len(g), "windows": 0,
               "first_window_s": None, "decision_s": None, "frac_over": None, "p_median": None}
        ends = list(range(model.seq - 1, len(X)))
        if ends:
            p = model.score(np.stack([X[i - model.seq + 1:i + 1] for i in ends]))
            run = 0
            for j, pj in enumerate(p):
                run = run + 1 if pj > thr else 0
                if run >= hits:
                    rec["decision_s"] = float(polls[ends[j]] - first + 1) + 1.0
                    break
            rec.update(windows=len(p), first_window_s=float(polls[ends[0]] - first + 1),
                       frac_over=float((p > thr).mean()), p_median=float(np.median(p)))
        rows.append(rec)
    return rows


# ─────────────────────────────── 4. probes ───────────────────────────────

def probes(model):
    """Windows of SEQ identical one-packet flows, encoded as xdp_ddos_filter.c records
    them: [init_win, IAT total, header bytes, IAT max, max payload, IAT mean, pkts/s,
    payload bytes]. hping3's default TCP window is 64 and it sends no TCP options."""
    cases = [
        ("hping3 SYN (S1, S2 Low & Slow, S10) or ACK (S5) flow: 1 pkt, win 64, 20-B header",
         [64, 0, 20, 0, 0, 0, 0, 0]),
        ("same with window 512", [512, 0, 20, 0, 0, 0, 0, 0]),
        ("same with window 29200 (common Linux)", [29200, 0, 20, 0, 0, 0, 0, 0]),
        ("same with window 65535", [65535, 0, 20, 0, 0, 0, 0, 0]),
        ("Linux client SYN (curl's first snapshot): win 64240, 40-B header",
         [64240, 0, 40, 0, 0, 0, 0, 0]),
        ("legit handshake stalled by a flood: 2 SYNs 1 s apart, no payload",
         [64240, 1e6, 80, 1e6, 0, 1e6, 2, 0]),
    ]
    return [(name, float(model.score(np.array([[v] * model.seq]))[0])) for name, v in cases]


# ─────────────────────────────── 5. families ───────────────────────────────

def families(df, model):
    fam = df.src_ip.map(lambda ip: CAPTURE_BOTS.get(ip, ("benign",))[0])
    prof = df.assign(family=fam).groupby("family")[model.features].median()
    prof["rows"] = fam.value_counts()
    prof["ips"] = df.assign(family=fam).groupby("family").src_ip.nunique()
    z = pd.DataFrame(model.scaler.transform(df[model.features].to_numpy(np.float64)),
                     columns=model.features).assign(family=fam.to_numpy())
    cent = z.groupby("family")[model.features].median()
    dist = pd.DataFrame({a: {b: float(np.linalg.norm(cent.loc[a] - cent.loc[b])) for b in cent.index}
                         for a in cent.index})
    composition = {
        "init_win_by_label": df.groupby(["y", "Init_Win_bytes_forward"]).size().to_dict(),
        "syn_only_like_rows_by_label": df[(df["Fwd Packet Length Max"] == 0)
                                          & (df["Fwd IAT Total"] == 0)].groupby("y").size().to_dict(),
    }
    return prof, dist, composition


# ─────────────────────────────── 6. CIC-IDS2017 ───────────────────────────────

def cross_domain(df, model, max_per_class=200_000):
    if not os.path.isfile(CIC):
        return None
    cic = pd.read_csv(CIC, usecols=model.features + ["Label", "y"])
    cic = cic.replace([np.inf, -np.inf], np.nan).dropna()
    rng = np.random.default_rng(20261013)
    parts = []
    for _, g in cic.groupby("y"):
        parts.append(g.iloc[rng.choice(len(g), size=min(len(g), max_per_class), replace=False)])
    sample = pd.concat(parts)
    rows = []
    for feat in model.features:
        a_tb = roc_auc_score(df.y, df[feat]) if df[feat].nunique() > 1 else 0.5
        a_cic = roc_auc_score(sample.y, sample[feat]) if sample[feat].nunique() > 1 else 0.5
        rows.append({"feature": feat,
                     "tb_benign": df[df.y == 0][feat].median(), "tb_attack": df[df.y == 1][feat].median(),
                     "cic_benign": cic[cic.y == 0][feat].median(), "cic_attack": cic[cic.y == 1][feat].median(),
                     "auc_tb": a_tb, "auc_cic": a_cic, "flips": (a_tb - 0.5) * (a_cic - 0.5) < 0})
    per_type = cic.groupby("Label")[["Fwd Packet Length Max", "Init_Win_bytes_forward"]].median()
    return {"rows": rows, "per_type": per_type, "n_cic": len(cic), "n_sample": len(sample),
            "windows": cic_windows(model, max_per_type=3000)}


def cic_windows(model, max_per_type, hosts=400, per_host=60):
    """Deployed model on CIC-IDS2017 windows (15 consecutive flows of one source IP, file
    order), as recorded and with Init_Win_bytes_forward set to the testbed's 64240: how
    much of the transfer failure is the out-of-range TCP window alone? AUC ranks attack
    windows against benign windows (0.5 = chance, < 0.5 = inverted). Benign windows are
    sampled two ways, because the AUC depends on it: per host (`hosts` random benign
    hosts, at most `per_host` evenly spaced windows each, as in the audit behind REPORT.md
    §4.4; a ban acts on a host) and per flow (uniform over all benign windows, where a few
    internal servers carry most of the flows)."""
    cic = pd.read_csv(CIC, usecols=["Source IP", "Label"] + model.features)
    cic = cic.replace([np.inf, -np.inf], np.nan).dropna().reset_index(drop=True)
    rng = np.random.default_rng(20261013)
    X = cic[model.features].to_numpy(np.float64)

    def score(W):
        W_neutral = W.copy()
        W_neutral[:, :, model.features.index("Init_Win_bytes_forward")] = 64240
        return model.score(W), model.score(W_neutral)

    scored = {}
    for label, g in cic.groupby("Label", sort=True):
        starts = []
        for idx in g.groupby("Source IP").groups.values():
            idx = np.asarray(idx)
            if len(idx) >= model.seq:
                starts += [idx[i:i + model.seq] for i in range(len(idx) - model.seq + 1)]
        if not starts:
            continue
        pick = rng.choice(len(starts), size=min(len(starts), max_per_type), replace=False)
        scored[label] = score(np.stack([X[starts[i]] for i in pick]))
    flow_p = scored.pop("BENIGN", None)

    attackers = set(cic[cic.Label != "BENIGN"]["Source IP"])
    counts = cic[cic.Label == "BENIGN"]["Source IP"].value_counts()
    counts = counts[counts >= model.seq].index.tolist()
    chosen = set(np.random.default_rng(1).choice(counts, size=min(hosts, len(counts)), replace=False))
    starts, used = [], 0
    for ip, idx in cic[cic.Label == "BENIGN"].groupby("Source IP").groups.items():
        if ip not in chosen or ip in attackers:
            continue
        used += 1
        idx, n = np.asarray(idx), len(idx) - model.seq + 1
        at = range(n) if n <= per_host else np.linspace(0, n - 1, per_host).astype(int)
        starts += [idx[i:i + model.seq] for i in at]
    host_p = score(np.stack([X[s] for s in starts])) if starts else None

    def auc(pos, neg):
        if neg is None:
            return None
        return float(roc_auc_score(np.r_[np.ones(len(pos)), np.zeros(len(neg))], np.r_[pos, neg]))

    def row(name, p, attack=True):
        r = {"type": name, "windows": len(p[0]), "share_over_thr": float((p[0] > 0.95).mean()),
             "share_over_thr_win_64240": float((p[1] > 0.95).mean())}
        for key, ben in (("host", host_p), ("flow", flow_p)):
            for i, suffix in ((0, ""), (1, "_64240")):
                r[f"auc_{key}{suffix}"] = auc(p[i], None if ben is None else ben[i]) if attack else None
        return r

    out = []
    if host_p is not None:
        out.append(row(f"BENIGN, per host ({used} hosts, ≤ {per_host} windows each)",
                       host_p, attack=False))
    if flow_p is not None:
        out.append(row("BENIGN, per flow (uniform over all windows)", flow_p, attack=False))
    out += [row(label, p) for label, p in scored.items()]
    if scored:
        pooled = tuple(np.concatenate([p[i] for p in scored.values()]) for i in (0, 1))
        out.append(row("all attack types, pooled", pooled))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(REPO, "ml", "diagnosis"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    k = daemon_constants()
    thr, hits = k["PREDICTION_THRESHOLD"], k["GRU_CONSECUTIVE_THRESH"]
    model = Model()
    df = pd.read_csv(TIER1)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=model.features)

    L = ["# GRU diagnosis: tables", "",
         ("Generated by `ml/diagnose_gru.py` (read-only, deterministic). Narrative and "
          "conclusions: `docs/ML_INVESTIGATION.md`."), "",
         md_table(["Input", "Value"], [
             ["deployed model", f"`{model.cfg['model']}` sha256 `{sha256(os.path.join(REPO, model.cfg['model']))[:12]}`"],
             ["Tier-1 capture", f"`training_data/testbed_flows.csv` sha256 `{sha256(TIER1)[:12]}`, {len(df)} rows"],
             ["decision rule (control_plane.py)", (f"p > {thr} in {hits} consecutive windows of "
                                                   f"{model.seq} snapshots; poll {k['L4_POLL_INTERVAL']} s")],
             ["heuristic thresholds", (f"L7 > {k['HEURISTIC_MAX_RPS']} rps; SlowConn ≥ "
                                       f"{k['SLOWCONN_CONN_THRESHOLD']} idle conns × "
                                       f"{k['SLOWCONN_CONSECUTIVE']} polls")],
         ])]

    c = census()
    tot = collections.Counter()
    for r in c:
        tot.update({key: r[key] for key in ("bans", "gru_bans", "gru_suppressed", "suppress_on")})
    L += ["", "## 1. Ban-event census of the published runs", "",
          md_table(["Run", "Events", "Bans", "GRU bans", "GRU detections suppressed", "Suppression on"],
                   [[r["run"], r["events"], r["bans"], r["gru_bans"], r["gru_suppressed"], r["suppress_on"]]
                    for r in c] + [["**total**", f"{len(c)} runs", f"**{tot['bans']}**",
                                    f"**{tot['gru_bans']}**", f"**{tot['gru_suppressed']}**",
                                    tot["suppress_on"]]])]

    rc = race()
    L += ["", "## 2. Race per scenario (full-suite regression run, default settings)", "",
          md_table(["Scenario", "First-ban engines", "Time to mitigate (median)",
                    "GRU paused by flood suppression from", "GRU events"],
                   [[r["scenario"], r["engines"], f"{r['ttm']:.2f} s",
                     f"+{r['suppress_from']:.2f} s" if r["suppress_from"] is not None else "never",
                     r["gru_events"]] for r in rc])]

    rp = replay(df, model, thr, hits)
    heur = {r["scenario"]: r["ttm"] for r in rc}
    att = [r for r in rp if r["label"] == 1]
    ben = [r for r in rp if r["label"] == 0]
    L += ["", "## 3. Earliest possible GRU ban (replay of the decision rule on the Tier-1 capture)", "",
          md_table(["Attacker", "Family, setting", "First full window", "GRU ban (incl. drain at next poll)",
                    "Windows p > thr", "Matching suite scenario: heuristic ban"],
                   [[r["ip"], ", ".join(CAPTURE_BOTS.get(r["ip"], ("?", "?"))),
                     f(r["first_window_s"], "{:.0f} s"), f(r["decision_s"], "{:.0f} s"),
                     f(r["frac_over"], "{:.0%}"),
                     (f"{SUITE_MATCH[r['ip']]}: {heur[SUITE_MATCH[r['ip']]]:.2f} s"
                      if r["ip"] in SUITE_MATCH and SUITE_MATCH[r["ip"]] in heur else "—")]
                    for r in att]),
          "", (f"Benign clients: {len(ben)} IPs, {sum(r['windows'] for r in ben)} windows; would be "
               f"banned: {sum(r['decision_s'] is not None for r in ben)}; windows with p > {thr}: "
               f"{sum((r['frac_over'] or 0) * r['windows'] for r in ben):.0f}.")]

    pr = probes(model)
    L += ["", "## 4. Out-of-distribution probes (15 identical snapshots)", "",
          md_table(["Flow", "p (deployed model)"], [[n, f"{p:.4f}"] for n, p in pr])]

    prof, dist, comp = families(df, model)
    cols = ["Fwd Packet Length Max", "Total Length of Fwd Packets", "Fwd Header Length",
            "Fwd IAT Total", "Fwd IAT Max", "Fwd Packets/s", "Init_Win_bytes_forward"]
    L += ["", "## 5. Feature profile per family (median per snapshot; Tier-1 capture)", "",
          md_table(["Family", "IPs", "Snapshots"] + [c_.replace("Fwd ", "") for c_ in cols],
                   [[fam, int(prof.loc[fam, "ips"]), int(prof.loc[fam, "rows"])]
                    + [f(prof.loc[fam, c_], "{:.0f}") for c_ in cols] for fam in prof.index]),
          "", "Distance between family medians in the model's standardised feature space:", "",
          md_table(["from \\ to"] + list(dist.columns),
                   [[a] + [f(dist.loc[a, b], "{:.1f}") for b in dist.columns] for a in dist.index]),
          "", (f"Training composition: Init_Win by label {comp['init_win_by_label']}; "
               f"SYN-only-like snapshots (no payload, zero lifetime) by label "
               f"{comp['syn_only_like_rows_by_label']}.")]

    cd = cross_domain(df, model)
    if cd:
        L += ["", ("## 6. Testbed vs CIC-IDS2017: per-feature medians and direction (univariate AUC, "
                   "attack vs benign)"), "",
              (f"CIC-IDS2017 DoS/DDoS + benign: {cd['n_cic']} flows (AUC on a stratified sample of "
               f"{cd['n_sample']})."), "",
              md_table(["Feature", "testbed benign", "testbed attack", "CIC benign", "CIC attack",
                        "AUC testbed", "AUC CIC", "direction flips"],
                       [[r["feature"], f(r["tb_benign"], "{:.0f}"), f(r["tb_attack"], "{:.0f}"),
                         f(r["cic_benign"], "{:.0f}"), f(r["cic_attack"], "{:.0f}"),
                         f(r["auc_tb"], "{:.3f}"), f(r["auc_cic"], "{:.3f}"),
                         "**yes**" if r["flips"] else "no"] for r in cd["rows"]]),
              "", "CIC-IDS2017 medians per traffic type:", "",
              md_table(["Type", "Fwd Packet Length Max", "Init_Win_bytes_forward"],
                       [[t, f(v["Fwd Packet Length Max"], "{:.0f}"), f(v["Init_Win_bytes_forward"], "{:.0f}")]
                        for t, v in cd["per_type"].iterrows()]),
              "", ("Deployed model on CIC-IDS2017 windows, as recorded and with the TCP window set "
                   "to 64240: share with p > 0.95 (for BENIGN, the false-positive share) and AUC "
                   "against each benign sample (0.5 = chance, < 0.5 = inverted):"), "",
              md_table(["Type", "Windows", "p > 0.95, as recorded", "p > 0.95, Init_Win := 64240",
                        "AUC vs benign per host, as recorded", "same, Init_Win := 64240",
                        "AUC vs benign per flow, as recorded", "same, Init_Win := 64240"],
                       [[w["type"], w["windows"], f(w["share_over_thr"], "{:.1%}"),
                         f(w["share_over_thr_win_64240"], "{:.1%}"),
                         f(w["auc_host"], "{:.3f}"), f(w["auc_host_64240"], "{:.3f}"),
                         f(w["auc_flow"], "{:.3f}"), f(w["auc_flow_64240"], "{:.3f}")]
                        for w in cd["windows"]])]

    with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    with open(os.path.join(args.out, "replay.json"), "w", encoding="utf-8") as fh:
        json.dump({"replay": rp, "probes": pr, "race": rc, "census": c}, fh, indent=1, default=str)
        fh.write("\n")
    print(f"[+] wrote {os.path.relpath(args.out, REPO)}/report.md and replay.json")


if __name__ == "__main__":
    main()

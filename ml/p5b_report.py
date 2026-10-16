#!/usr/bin/env python3
"""The pre-registered P5b verdict (docs/L7_GRU_DESIGN.md §7.2), written and tested before
any P5b evaluation run exists.

Reads evaluation run directories (ml/eval_l7.py --mix overlap: summary.json, manifest.json,
baselines.json) and the benign soak, and applies §7.2 exactly:

  comparison set  fast sub-threshold attacker IPs (subthreshold_flood, scraper, padded_flood)
                  not banned by a deterministic engine, pooled over runs
  benign set      benign IPs not banned by a deterministic engine and not shaped by nginx
                  (V1 exclusions are listed, never silently dropped)
  V0 informative  in every run, B0 at 0 benign flagged catches fewer than the whole set
  V1 admissible   reported: deterministic bans of benign / comparison IPs, nginx shaping
  V2 usable       GRU catches > half (pooled); flags <= 5 % of benign IPs (pooled); soak
                  <= 1.0 benign would-bans per benign client-hour
  V3 beats all    each family B0-B4, tuned on these runs (oracle) at benign IPs flagged <=
                  the GRU's, catches strictly fewer pooled, and no more in any run
  significance    exact one-sided McNemar per family on per-attacker outcomes, alpha 0.05
                  (all must pass: an intersection-union test, no multiplicity correction)

    ./venv/bin/python ml/p5b_report.py --run A1=DIR ... --run A5=DIR --soak C=DIR \\
        --out p5b_report.json --md p5b_report.md
"""
import argparse
import json
import math
import os
import sys

FAST_FAMILIES = ("subthreshold_flood", "scraper", "padded_flood")
FAMILIES = ("B0", "B1", "B2", "B3", "B4")
KEYING_OR_BURST = ("B1", "B2", "B3")
FP_BUDGET_SHARE = 0.05           # decision 3
SOAK_FP_PER_CLIENT_HOUR = 1.0
ALPHA = 0.05


def _load(path, name):
    with open(os.path.join(path, name), encoding="utf-8") as fh:
        return json.load(fh)


def load_run(path):
    return {"dir": path, "summary": _load(path, "summary.json"),
            "manifest": _load(path, "manifest.json"),
            "baselines": _load(path, "baselines.json")}


def sets_for(run):
    """(comparison set, benign set, exclusions, gru flagged) for one run."""
    ip_map = run["manifest"]["ip_map"]
    an = run["summary"]["analysis"]
    det = an.get("det_banned_ips", {})
    shaped = set(run["baselines"].get("shaped_ips", []))
    comp, benign, excl = set(), set(), []
    for ip, e in ip_map.items():
        if e.get("class") == "attack" and e.get("family") in FAST_FAMILIES:
            if ip in det:
                excl.append({"ip": ip, "family": e["family"], "why": f"det-banned ({det[ip]})"})
            else:
                comp.add(ip)
        elif e.get("class") == "benign":
            if ip in det:
                excl.append({"ip": ip, "kind": e.get("kind"), "why": f"det-banned ({det[ip]})"})
            elif ip in shaped:
                excl.append({"ip": ip, "kind": e.get("kind"), "why": "shaped by nginx"})
            else:
                benign.add(ip)
    return comp, benign, excl, set(an.get("would_ban_ips", []))


def mcnemar_one_sided(b, c):
    """P(X >= b) for X ~ Binomial(b + c, 1/2): the exact one-sided McNemar p-value for
    'the GRU catches more' (b = GRU-only catches, c = baseline-only catches)."""
    n = b + c
    if n == 0:
        return 1.0
    return sum(math.comb(n, k) for k in range(b, n + 1)) / 2 ** n


def tune_family(runs, fam, gru_fp):
    """The oracle: the family's grid point with the most pooled comparison-set catches
    at pooled benign IPs flagged <= gru_fp (ties: fewer benign, then grid order)."""
    grid = None
    for r in runs:
        params = r["baselines"]["families"].get(fam)
        if params is None:
            return None
        grid = list(params) if grid is None else grid
    best = None
    for p in grid:
        caught = fp = 0
        for r in runs:
            flagged = set(r["baselines"]["families"][fam].get(p, []))
            caught += len(flagged & r["comp"])
            fp += len(flagged & r["benign"])
        if fp <= gru_fp and (best is None or (caught, -fp) > (best["caught"], -best["fp"])):
            best = {"param": p, "caught": caught, "fp": fp}
    return best or {"param": None, "caught": 0, "fp": 0}


def b0_best_at_zero(run):
    best = 0
    for flagged in run["baselines"]["families"]["B0"].values():
        f = set(flagged)
        if not f & run["benign"]:
            best = max(best, len(f & run["comp"]))
    return best


def evaluate(runs, soak=None):
    """Apply §7.2 to loaded runs (+ the soak). Returns the full report dict."""
    for r in runs:
        r["comp"], r["benign"], r["excl"], r["gru"] = sets_for(r)
    n_comp = sum(len(r["comp"]) for r in runs)
    n_benign = sum(len(r["benign"]) for r in runs)
    gru_caught = sum(len(r["gru"] & r["comp"]) for r in runs)
    gru_fp = sum(len(r["gru"] & r["benign"]) for r in runs)
    rep = {"runs": [os.path.basename(r["dir"].rstrip("/")) for r in runs],
           "comparison_set": n_comp, "benign_ips": n_benign,
           "gru": {"caught": gru_caught, "benign_flagged": gru_fp},
           "v1_exclusions": {os.path.basename(r["dir"].rstrip("/")): r["excl"] for r in runs}}

    v0 = [b0_best_at_zero(r) < len(r["comp"]) for r in runs]
    rep["V0_informative"] = {"per_run_b0_best_at_0_benign": [b0_best_at_zero(r) for r in runs],
                             "per_run_comparison_set": [len(r["comp"]) for r in runs],
                             "pass": bool(runs) and all(v0)}

    soak_rate = None
    if soak is not None:
        an = soak["summary"]["analysis"]
        hours = an["benign_ips_total"] * soak["summary"]["duration_s"] / 3600.0
        soak_rate = round(an["benign_would_ban_count"] / hours, 3) if hours else None
    rep["V2_usable"] = {
        "gru_catches_over_half": n_comp > 0 and gru_caught > n_comp / 2,
        "benign_flagged_share": round(gru_fp / n_benign, 4) if n_benign else None,
        "benign_within_budget": n_benign > 0 and gru_fp <= FP_BUDGET_SHARE * n_benign,
        "soak_fp_per_client_hour": soak_rate,
        "soak_within_budget": soak_rate is not None and soak_rate <= SOAK_FP_PER_CLIENT_HOUR}
    v2 = rep["V2_usable"]
    v2["pass"] = (v2["gru_catches_over_half"] and v2["benign_within_budget"]
                  and v2["soak_within_budget"])

    fams, missing = {}, []
    for fam in FAMILIES:
        best = tune_family(runs, fam, gru_fp)
        if best is None:
            missing.append(fam)
            continue
        per_run, b, c = [], 0, 0
        for r in runs:
            flagged = set(r["baselines"]["families"][fam].get(best["param"], [])) \
                if best["param"] else set()
            g, k = r["gru"] & r["comp"], flagged & r["comp"]
            per_run.append({"gru": len(g), "baseline": len(k)})
            b += len(g - k)
            c += len(k - g)
        p = mcnemar_one_sided(b, c)
        fams[fam] = {**best, "per_run": per_run, "gru_only": b, "baseline_only": c,
                     "mcnemar_p": round(p, 5),
                     "gru_beats": (gru_caught > best["caught"]
                                   and all(x["gru"] >= x["baseline"] for x in per_run)),
                     "significant": p < ALPHA}
    rep["V3_baselines"] = fams
    rep["missing_baselines"] = missing
    rep["outcome"] = outcome(rep)
    return rep


def outcome(rep):
    if not rep["V0_informative"]["pass"]:
        return "uninformative"
    if rep["missing_baselines"]:
        return f"incomplete (missing {', '.join(rep['missing_baselines'])})"
    if rep["V2_usable"]["soak_fp_per_client_hour"] is None:
        return "incomplete (no soak run)"
    fams = rep["V3_baselines"]
    if not rep["V2_usable"]["pass"]:
        return "no advantage"
    if all(f["gru_beats"] for f in fams.values()):
        return ("advantage shown - decisive" if all(f["significant"] for f in fams.values())
                else "advantage shown - indicative")
    if fams["B0"]["gru_beats"] and any(not fams[f]["gru_beats"] for f in KEYING_OR_BURST):
        return "advantage from keying or burst handling, not learning"
    return "no advantage"


def to_markdown(rep):
    v0, v2 = rep["V0_informative"], rep["V2_usable"]
    runs = (f"Runs: {', '.join(rep['runs'])}. Comparison set {rep['comparison_set']} attacker "
            f"IPs; {rep['benign_ips']} benign IPs (pooled).")
    gru = (f"- GRU: {rep['gru']['caught']}/{rep['comparison_set']} caught, "
           f"{rep['gru']['benign_flagged']} benign IPs flagged")
    v0_line = (f"- V0 informative: {v0['pass']} (B0 at 0 benign per run: "
               f"{v0['per_run_b0_best_at_0_benign']} of {v0['per_run_comparison_set']})")
    v2_line = (f"- V2 usable: {v2['pass']} (benign share {v2['benign_flagged_share']}, soak "
               f"{v2['soak_fp_per_client_hour']} FP/client-hour)")
    header = ("| Baseline | Oracle setting | Caught | Benign flagged | GRU-only / baseline-only "
              "| McNemar p | GRU beats |")
    lines = [f"**Outcome: {rep['outcome']}** (pre-registered rule, docs/L7_GRU_DESIGN.md §7.2)",
             "", runs, "", gru, v0_line, v2_line, "", header, "|---|---|---|---|---|---|---|"]
    for fam, f in rep["V3_baselines"].items():
        lines.append(f"| {fam} | `{f['param']}` | {f['caught']} | {f['fp']} | "
                     f"{f['gru_only']} / {f['baseline_only']} | {f['mcnemar_p']} | {f['gru_beats']} |")
    excl = {k: v for k, v in rep["v1_exclusions"].items() if v}
    lines += ["", f"V1 exclusions: {json.dumps(excl) if excl else 'none'}"]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", action="append", required=True, help="NAME=dir (eval run)")
    ap.add_argument("--soak", help="NAME=dir (benign soak run)")
    ap.add_argument("--out")
    ap.add_argument("--md")
    args = ap.parse_args()
    runs = [load_run(x.split("=", 1)[1]) for x in args.run]
    soak = None
    if args.soak:
        d = args.soak.split("=", 1)[1]
        soak = {"summary": _load(d, "summary.json")}
    rep = evaluate(runs, soak)
    md = to_markdown(rep)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, indent=1)
            fh.write("\n")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())

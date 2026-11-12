"""T-088: compare my recomputed numbers (artifacts/drift_recomputed.json, route 1) with the tool's drift.json files in the raw
directories and with the producer's copies. Reads only; prints every difference at full precision."""
import hashlib, json, os, sys
mine = json.load(open(sys.argv[1]))
RAW = "/var/tmp/ddos_campaigns"
WS = "/home/artur/agent_workspace"
pairs = [("AP-4 attempt 1", f"{RAW}/drift_20261108/drift/drift.json", f"{WS}/tasks/T-077/artifacts/drift_attempt1.json"),
         ("AP-4 attempt 2", f"{RAW}/drift_20261108.second/drift/drift.json", f"{WS}/tasks/T-077/artifacts/drift_attempt2.json"),
         ("AP-5 q1 attempt 1", f"{RAW}/drift_20261108_q1/drift/drift.json", f"{WS}/tasks/T-081/artifacts/ap5_q1_attempt1_drift.json")]
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
ndiff = 0
for label, raw, copy in pairs:
    d = json.load(open(raw))
    print(f"== {label}: raw drift.json sha {sha(raw)[:16]} copy sha {sha(copy)[:16]} identical={sha(raw) == sha(copy)}")
    print("   tool: ok =", d["ok"], "| reasons =", d["reasons"], "| created_utc =", d["created_utc"], "| smoke =", d["smoke"],
          "| calibration_sha256 =", d["calibration_sha256"][:8], "| waits =", json.dumps(d.get("waits"))[:400])
    att = mine["attempts"][label]
    rows = [("legit", d["legit"], att["runs"]["legit"]["route1_committed"])]
    rows += [(f, d["attacks"][f], att["runs"][f]["route1_committed"]) for f in sorted(d["attacks"])]
    for name, tool, me in rows:
        for k in ("Q", "p95_s", "requests"):
            same = tool[k] == me[k]
            ndiff += not same
            print(f"   {name:22s} {k:8s} tool={tool[k]!r:22} mine={me[k]!r:22} {'SAME' if same else 'DIFFERENT by ' + repr(tool[k] - me[k])}")
        if "level" in tool:
            print(f"   {name:22s} level    tool={tool['level']} record={mine['record']['drift_reference']['attack'][name]['level']}")
    sc = att["single_check_D062"]
    print("   single check: tool ok", d["ok"], "mine", sc["tool_ok"], "| reasons equal:", d["reasons"] == sc["tool_reasons"])
    ndiff += d["ok"] != sc["tool_ok"] or d["reasons"] != sc["tool_reasons"]
print("differences between the tool's drift.json and my recomputation:", ndiff)

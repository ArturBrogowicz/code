"""HG4's spec at twice the new knee (docs/RECALIBRATION_2026-11_DESIGN.md K8; docs/HG1C_DESIGN.md departures 39 and 40): after the
freeze (F) and before P2-1, `cheap_static_flood_hg4.json` takes level 2 x the new record's knee of the cheap flood (departure 39's rule,
gate_campaign.HG4_KNEE_MULTIPLE) and a description whose numbers are the scenario plan's on that record (departure 40's test). If the
knee is the spec's half already, nothing changes, byte for byte. Offline: it reads the record and the spec and writes the spec only
with --write.

    ./venv/bin/python bench/hg4_spec.py --calibration bench/calibration/<host>-<date>.json            # what the spec would be
    ./venv/bin/python bench/hg4_spec.py --calibration bench/calibration/<host>-<date>.json --write    # by hand, after F, before P2-1

When the plan's rate a source at that level is not above the L7 rule's 50 r/s, the protected arm would ban nothing: --write refuses,
and the user decides before P2-1 with no outcome seen (design 9).
"""
import argparse
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import calibration as C
import gate_campaign as GC
import scenario as SC

SPEC = os.path.join(HERE, "scenarios", "cheap_static_flood_hg4.json")
FAMILY = "cheap_static_flood"
GOLDENS = ()        # no golden plan prints this spec (tests/golden): none to make again when it changes
EXIT_OK, EXIT_USAGE, EXIT_REFUSED = 0, 1, 3


def _number(x):
    return int(x) if float(x).is_integer() else float(x)


def description(cal, level, plan):
    """What the spec says of itself at `level` on `cal`: the plan's rate a source and what the rules do at it (departure 40)."""
    a = plan["attack"]
    r = a["rules"]
    knee = cal["knees"][FAMILY]
    limit_req = next(t for t in a["thresholds"] if t["name"] == "limit_req")
    when = cal["created_utc"][:10]
    rules = (f"about {a['per_source_rate']:.1f} req/s a source, about {limit_req['ratio']:.2f} x limit_req's 30 r/s, so it sheds about "
             f"{round(100 * r['reject_share'])} %, and " + ("above the L7 rule's 50 r/s, so the rule bans" if r["l7_rule_bans"] else
                                                             "under the L7 rule's 50 r/s, so no ban: the rules may barely win"))
    return (f"HG4's control where the rules win (D-071, departure 39): the plain flood of the cheap dynamic route from {a['sources']} "
            f"sources at level {level:g}, twice the frozen knee of {knee:g} on the record of {when} ({cal['sha256'][:8]}): {rules}. "
            "HG3 confirms the family at its knee with cheap_static_flood.")


def spec_for(cal, current):
    """The spec for record `cal`: `current` itself when its level is already twice the knee, else a copy at that level with the
    description of description(). Returns (spec, changed, the plan's attack block at the level)."""
    knee = cal["knees"].get(FAMILY)
    if cal.get("status") != "frozen" or not isinstance(knee, (int, float)):
        raise ValueError(f"a frozen record with a knee for {FAMILY} is needed, got status {cal.get('status')!r}, knee {knee!r}")
    level = _number(GC.HG4_KNEE_MULTIPLE[FAMILY] * knee)
    if current["intensity"]["level"] == level:
        return current, False, SC.plan(SC.from_record(current), cal)["attack"]
    spec = copy.deepcopy(current)
    spec["intensity"]["level"] = level
    plan = SC.plan(SC.from_record(spec), cal)
    spec["description"] = description(cal, level, plan)
    return spec, True, plan["attack"]


def text_of(spec):
    """The spec as the repository keeps it: one key a line at the top level, as cheap_static_flood_hg4.json is written."""
    lines = [f" {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}" for k, v in spec.items()]
    return "{\n" + ",\n".join(lines) + "\n}\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--calibration", required=True, help="the new frozen record")
    ap.add_argument("--spec", default=SPEC)
    ap.add_argument("--write", action="store_true", help="write the spec (after F, before P2-1)")
    args = ap.parse_args(argv)
    try:
        cal = C.load(args.calibration)
        with open(args.spec, encoding="utf-8") as fh:
            current = json.load(fh)
        spec, changed, a = spec_for(cal, current)
    except (OSError, ValueError, C.RecordError, SC.ScenarioError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_USAGE
    print(f"knee {cal['knees'][FAMILY]:g} -> level {spec['intensity']['level']:g}: {a['per_source_rate']:.1f} req/s a source; "
          f"limit_req {'sheds' if a['rules']['limit_req_sheds'] else 'does not shed'}, the L7 rule "
          f"{'bans' if a['rules']['l7_rule_bans'] else 'does NOT ban'}")
    if not changed:
        print(f"{args.spec}: unchanged (level {spec['intensity']['level']:g} is already twice the knee)")
        return EXIT_OK
    if not a["rules"]["l7_rule_bans"]:
        print("REFUSED: at twice the knee a source stays under the L7 rule's 50 r/s, so the protected arm would ban nothing; the user "
              "decides before P2-1, with no outcome seen (docs/RECALIBRATION_2026-11_DESIGN.md 9)", file=sys.stderr)
        return EXIT_REFUSED
    if not args.write:
        print(text_of(spec), end="")
        print(f"(not written: --write writes it to {args.spec}; no golden plan prints it)")
        return EXIT_OK
    with open(args.spec, "w", encoding="utf-8") as fh:
        fh.write(text_of(spec))
    print(f"{args.spec}: level {spec['intensity']['level']:g}, description from the plan; its sha256 changes")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

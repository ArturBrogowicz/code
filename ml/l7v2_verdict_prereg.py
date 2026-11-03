"""The L7 v2 verdict pre-registration (docs/L7V2_DESIGN.md section 11 and section 13 item 4): the verdict ladder, the
effect sizes, the fixed testing order, the live set per block, R*'s definition, the statistics, the judging choices the
user settled (D-044) and each class's detection entities (D-043), read from the committed l7v2_verdict_prereg_v3.json.

Pure and standard library only. load() checks the file's format and its internal consistency; tests pin every value,
and the verdict code (ml/l7v2_verdict.py) reads its constants from here, so code and pre-registration cannot drift.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PREREG_PATH = os.path.join(HERE, "l7v2_verdict_prereg_v3.json")
FORMAT = "l7v2-verdict-prereg/3"
VERDICTS = ("V-D", "V-A", "V-B", "V-C", "inconclusive")
STEPS = ("harm_admission", "budget", "mitigation", "v_a", "best_learned_vs_rstar", "gru_vs_hgb", "gru_vs_shuffled")


class PreregError(ValueError):
    """The verdict pre-registration file is malformed or inconsistent."""


_cache = {}


def load(path=PREREG_PATH):
    """The pre-registration as a dict, after the format and consistency checks (cached per path)."""
    if path in _cache:
        return _cache[path]
    with open(path, encoding="utf-8") as fh:
        pre = json.load(fh)
    if pre.get("format") != FORMAT:
        raise PreregError(f"{path}: format {pre.get('format')!r}, expected {FORMAT!r}")
    if tuple(r["verdict"] for r in pre["ladder"]) != VERDICTS:
        raise PreregError(f"the ladder's rungs must be {VERDICTS}, in that order")
    if tuple(pre["testing_order"]) != STEPS:
        raise PreregError(f"the testing order must be {STEPS}")
    live, arms = pre["live_set"], pre["arms"]
    if not set(arms["contenders"]) <= set(arms["enforcing"]) or arms["default_rules"] in arms["contenders"]:
        raise PreregError("the contenders are enforcing arms, and the default rules are not one")
    if not pre["latency_alone"]["min_mean_gain_pp"] > 0:
        raise PreregError("the latency-alone gain is positive pp")
    if set(live["per_class"]) != set(pre["classes"]):
        raise PreregError("every class needs a live set, and only the classes have one")
    for cls, members in live["per_class"].items():
        if not {"U", "R*", arms["gru"]} <= set(members):
            raise PreregError(f"{cls}: the live set must hold U, R* and the GRU")
    if len(live["shared"]) + sum(len(m) for m in live["per_class"].values()) != live["runs_per_block"]:
        raise PreregError("runs_per_block must count the shared runs and every class's live arms")
    eff = pre["effect_sizes"]
    if not all(eff[k] > 0 for k in ("harm_beats_pp", "harm_equivalence_pp", "detection_beats_pp",
                                    "detection_equivalence_pp")):
        raise PreregError("the effect sizes are positive pp")
    if pre["units"]["min_blocks"] != pre["statistics"]["harm"]["min_blocks"]:
        raise PreregError("one minimum number of blocks")
    if len(pre["units"]["eval_seeds"]) < pre["units"]["min_blocks"]:
        raise PreregError("fewer evaluation seeds than the minimum number of blocks")
    ids = [c["id"] for c in pre["choices"]]
    if len(set(ids)) != len(ids):
        raise PreregError("duplicate choice ids")
    for c in pre["choices"]:
        if c["resolution"] not in c["options"]:
            raise PreregError(f"{c['id']}: the resolution must be one of its options")
    per_class = pre["detection_entities"]["per_class"]
    if set(per_class) != set(pre["classes"]) or not all(v["primary"] for v in per_class.values()):
        raise PreregError("every class needs its primary detection families, and only the classes have them")
    _cache[path] = pre
    return pre


def resolutions(pre=None):
    """{choice id: its resolution} (D-044): the verdict code judges under exactly these."""
    return {c["id"]: c["resolution"] for c in (pre or load())["choices"]}

"""The L7 v2 model-side pre-registration (docs/L7V2_DESIGN.md sections 8, 10, 11 and 13): keying, ingest hashing, the
site map, the request-level navigation features, the view tokens and their summaries, the model hyperparameters, the
probe gates, the benign budget and its tie rules, and the observe-only engine's constants, read from the committed
l7v2_model_prereg.json.

Pure and standard library only. load() checks the file's format and its internal consistency; tests pin every value,
and the modules that use a value (l7_ingest, l7_features, l7_probes, l7_engine, ml/train_l7v2.py) are tested against
this file, so code and pre-registration cannot drift apart.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PREREG_PATH = os.path.join(HERE, "l7v2_model_prereg.json")
FORMAT = "l7v2-model-prereg/1"
ARMS = ("view_gru", "hgb", "lr", "request_gru", "gru_shuffled")


class PreregError(ValueError):
    """The L7 v2 model pre-registration file is malformed or inconsistent."""


_cache = {}


def load(path=PREREG_PATH):
    """The pre-registration as a dict, after the format and consistency checks (cached per path)."""
    if path in _cache:
        return _cache[path]
    with open(path, encoding="utf-8") as fh:
        pre = json.load(fh)
    if pre.get("format") != FORMAT:
        raise PreregError(f"{path}: format {pre.get('format')!r}, expected {FORMAT!r}")
    views, sel, probes = pre["views"], pre["selection"], pre["probes"]
    if len(set(views["token_features"])) != len(views["token_features"]):
        raise PreregError("duplicate token features")
    nav = pre["request_level"]["nav_features"]
    if len(set(nav)) != len(nav) or "nav" not in pre["request_level"]["groups"]:
        raise PreregError("the request level must list each navigation feature once and use the nav group")
    if "server_timing" in pre["request_level"]["groups"] or "protocol" in pre["request_level"]["groups"]:
        raise PreregError("server_timing and protocol stay off (design 8.2)")
    if not 1 <= views["min_views"] <= views["max_views"]:
        raise PreregError("min_views must be in [1, max_views]")
    if pre["engine"]["min_views"] != views["min_views"]:
        raise PreregError("the engine scores at the views' min_views")
    if not 0.0 < sel["budget"] < 1.0:
        raise PreregError("the benign budget is a share in (0, 1)")
    if sel["theta_grid"] != sorted(sel["theta_grid"]) or sel["k_grid"] != sorted(sel["k_grid"]):
        raise PreregError("the grids are listed in ascending order (the tie rule's grid order)")
    if tuple(sel["arms"]) != ARMS:
        raise PreregError(f"the arms are {ARMS}")
    gate = probes["gate_v2"]
    if "uri_bijection" in gate or "uri_bijection_class" not in gate or "server_load" not in gate:
        raise PreregError("the v2 gate uses the class-preserving bijection and keeps server_load")
    if pre["keying"]["sid_is_a_feature"]:
        raise PreregError("the sid is a key component only")
    _cache[path] = pre
    return pre


def token_columns(pre=None):
    """The view-token matrix columns: ['valid', *token_features]."""
    return ["valid", *(pre or load())["views"]["token_features"]]


def selection(pre=None):
    """The selection block: budget, grids, ties."""
    return (pre or load())["selection"]

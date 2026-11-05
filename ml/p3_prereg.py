"""The P3 pre-registration (docs/P3_DATASET_DESIGN.md §5, §6, §8): seed lists, volume targets,
server configurations and the learning-curve constants, read from the committed p3_prereg.json.

Pure and standard library only. load() refuses a file whose seed lists overlap, so a seed can never
serve two roles; seed_role() and check_seed() are what the capture plan and the disjointness checker
use to tie a capture to its pre-registered role.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PREREG_PATH = os.path.join(HERE, "p3_prereg.json")
FORMAT = "p3-prereg/2"
ROLES = ("train", "val", "eval", "pilot")


class PreregError(ValueError):
    """The pre-registration file is malformed, or a seed does not fit its role."""


def load(path=PREREG_PATH):
    """The pre-registration as a dict, after checking its format, that every seed is an int and that
    no seed occurs in two lists (of any of the three notes)."""
    with open(path, encoding="utf-8") as fh:
        pre = json.load(fh)
    if pre.get("format") != FORMAT:
        raise PreregError(f"{path}: format {pre.get('format')!r}, expected {FORMAT!r}")
    seen = {}
    for name, seeds in pre["seeds"].items():
        for s in seeds:
            if not isinstance(s, int) or isinstance(s, bool):
                raise PreregError(f"{name}: seed {s!r} is not an int")
            if s in seen:
                raise PreregError(f"seed {s} is in both {seen[s]} and {name}")
            seen[s] = name
    if set(pre["p3_roles"]) != set(ROLES):
        raise PreregError(f"p3_roles must name {ROLES}")
    return pre


def seeds_for(role, pre=None):
    """The pre-registered P3 seeds of a role (train, val, eval or pilot)."""
    pre = pre or load()
    if role not in ROLES:
        raise PreregError(f"unknown P3 role {role!r}")
    return list(pre["seeds"][pre["p3_roles"][role]])


def seed_role(seed, pre=None):
    """The P3 role whose list holds `seed`, or None."""
    pre = pre or load()
    for role in ROLES:
        if seed in pre["seeds"][pre["p3_roles"][role]]:
            return role
    return None


def check_seed(seed, role, pre=None):
    """Raise PreregError unless `seed` is in the pre-registered list of `role`."""
    found = seed_role(seed, pre)
    if found != role:
        raise PreregError(f"seed {seed} is pre-registered as {found or 'nothing'}, not {role}")
    return role


def server_config(seed, pre=None):
    """(config id, its settings): A on odd seeds, B on even ones (D-D4)."""
    pre = pre or load()
    for cid, cfg in sorted(pre["server_configs"].items()):
        if (seed % 2 == 1) == (cfg["seeds"] == "odd"):
            return cid, dict(cfg)
    raise PreregError(f"no server configuration for seed {seed}")

"""The L7 v2 enforcing arm's contract with the evaluation tooling and the documentation (static; nothing runs):
every event kind the arm writes and every variable the daemon reads for it are documented, and every attribute
control_plane.py takes from the arm's modules exists (tests/test_control_plane_contract.py parses control_plane.py
only, and the arm writes its events from l7_enforce.py)."""
import ast
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events
import l7_enforce


def source(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fh:
        return fh.read()


def arm_event_kinds():
    kinds = set()
    for node in ast.walk(ast.parse(source("l7_enforce.py"))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "emit" \
                and node.args and isinstance(node.args[0], ast.Constant):
            kinds.add(node.args[0].value)
    return kinds


class ContractTest(unittest.TestCase):
    def test_the_arms_event_kinds(self):
        self.assertEqual(arm_event_kinds(), {"l7_enforce_arm", "l7_deny", "l7_deny_end", "l7_enforce_skip",
                                             "l7_enforce_miss", "l7_enforce_capped", "l7_reload", "l7_kill",
                                             "l7_enforce_poll"})

    def test_they_and_the_engine_are_documented(self):
        doc = source(os.path.join("docs", "EVALUATION.md"))
        events = doc[doc.index("## Ban events"):doc.index("## Metrics")]
        for kind in sorted(arm_event_kinds()) + [ban_events.L7V2_ENGINE, "lifted_by"]:
            self.assertIn(f"`{kind}`", events, kind)
        for reason in l7_enforce.SKIP_REASONS:
            self.assertIn(f"`{reason}`", events, reason)
        for kind in arm_event_kinds():
            self.assertIn(f'"{kind}"', ban_events.__doc__, kind)

    def test_the_section_names_every_variable_and_test(self):
        doc = source(os.path.join("docs", "EVALUATION.md"))
        start = doc.index("## L7 v2: the enforcing arm")
        section = doc[start:doc.index("\n## ", start + 1)]
        daemon = source("control_plane.py")
        for var in ("L7_ENFORCE", "L7_ENFORCE_DIR", "L7_NGINX_CONF", "L7_ALLOWLIST", "L7_KILL_FILE", "L7_SELECTION",
                    "L7_SELECTION_SHA256", "L7_ARM", "L7_SOCKET_GROUP"):
            self.assertIn(f'os.environ.get("{var}"', daemon, var)
            self.assertIn(f"`{var}`", section, var)
        for name in sorted(os.listdir(os.path.join(REPO, "tests"))):
            if name.startswith(("test_l7_denymap", "test_l7_rawkeys", "test_l7_enforce.py", "test_l7_safeguards",
                                "test_l7_arms", "test_l7_conf", "test_daemon_l7_", "test_l7_rstar")):
                self.assertIn(f"`tests/{name}`", section, name)
        self.assertIn("[NOT RUN]", section)

    def test_r_stars_path_is_documented_and_labelled(self):
        doc = source(os.path.join("docs", "EVALUATION.md"))
        start = doc.index("## L7 v2: the enforcing arm")
        section = doc[start:doc.index("\n## ", start + 1)]
        for name in ("deny_key.map", "key_map=True", "key_level=True", "L7_ARM=R*", "l7_rule_engine.py",
                     "ml/l7v2_replay.RulePath", "D-043"):
            self.assertIn(name, section, name)
        events = doc[doc.index("## Ban events"):doc.index("## Metrics")]
        for name in ("rule_arm", "statistic", "stat_threshold", "users_seen", "calibration_sha256"):
            self.assertIn(f"`{name}`", events, name)
        design = source(os.path.join("docs", "L7V2_DESIGN.md"))
        built = design[design.index("## As built: R*'s live path"):design.index("## References (T-012 ids")]
        for name in ("D-040", "D-043", "D-044", "RulePath", "post hoc", "`users_seen`", "NOT RUN"):
            self.assertIn(name, built, name)

    def test_every_attribute_the_daemon_takes_from_the_arms_modules_exists(self):
        import importlib
        tree = ast.parse(source("control_plane.py"))
        for mod_name in ("l7_enforce", "l7_denymap", "l7_arms"):
            mod = importlib.import_module(mod_name)
            refs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                    and isinstance(n.value, ast.Name) and n.value.id == mod_name}
            self.assertTrue(refs, mod_name)
            self.assertEqual(sorted(r for r in refs if not hasattr(mod, r)), [], mod_name)


if __name__ == "__main__":
    unittest.main()

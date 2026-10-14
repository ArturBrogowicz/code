"""Static contract tests for control_plane.py's ban events (no root, no import).

control_plane.py attaches XDP when imported, so it is parsed with `ast` instead.
These tests pin the contract between the daemon and the evaluation tooling:
every ban names its engine, event kinds are the documented ones, and the [BAN]
console line that test_distributed_suite.py parses keeps its format.
"""
import ast
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events

EVENT_KINDS = {"start", "ban", "unban", "suppress_on", "suppress_off", "gru_suppressed",
               "l7_shadow"}


def _calls(tree, predicate):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and predicate(n.func)]


class ControlPlaneContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(REPO, "control_plane.py"), encoding="utf-8") as fh:
            cls.source = fh.read()
        cls.tree = ast.parse(cls.source)
        cls.ban_calls = _calls(cls.tree, lambda f: isinstance(f, ast.Name) and f.id == "ban_ip")
        cls.emit_calls = _calls(cls.tree, lambda f: isinstance(f, ast.Attribute)
                                and f.attr == "emit" and isinstance(f.value, ast.Name)
                                and f.value.id == "EVENTS")

    def test_every_ban_names_a_known_engine(self):
        self.assertEqual(len(self.ban_calls), 7)       # one per detection path
        engines = []
        for call in self.ban_calls:
            kw = {k.arg: k.value for k in call.keywords}
            self.assertIn("reason", kw, ast.unparse(call))
            self.assertIn("engine", kw, ast.unparse(call))
            self.assertIsInstance(kw["engine"], ast.Constant)
            self.assertIn(kw["engine"].value, ban_events.ENGINES)
            engines.append(kw["engine"].value)
        self.assertEqual(sorted(engines), sorted(ban_events.ENGINES))   # each engine bans once

    def test_engine_matches_legacy_reason_mapping(self):
        # Old daemon logs are attributed from the reason text; it must agree with engine=.
        for call in self.ban_calls:
            kw = {k.arg: k.value for k in call.keywords}
            reason = kw["reason"]
            prefix = (reason.values[0].value if isinstance(reason, ast.JoinedStr)
                      else reason.value)
            self.assertEqual(ban_events.engine_from_reason(prefix), kw["engine"].value, prefix)

    def test_event_kinds_are_documented(self):
        kinds = set()
        for call in self.emit_calls:
            first = call.args[0]
            if isinstance(first, ast.IfExp):            # "suppress_on" if ... else "suppress_off"
                kinds |= {first.body.value, first.orelse.value}
            else:
                kinds.add(first.value)
        self.assertEqual(kinds, EVENT_KINDS)

    def test_ban_console_line_unchanged(self):
        # test_distributed_suite.tail_logs_for_bans() matches "[BAN]" + IP; _classify_engine()
        # reads the reason text after "Reason:".
        self.assertIn('print(f"[BAN] {ip_str} banned for {BAN_TTL_SECONDS}s. Reason: {reason}")',
                      self.source)

    def _func(self, name):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return node
        self.fail(f"function {name} not found")

    def test_l7_shadow_never_bans(self):
        # Phase P1 shadow mode must only observe: no ban/enforce call may be
        # reachable from the shadow monitor (docs/L7_GRU_DESIGN.md §8).
        forbidden = {"ban_ip", "block_ip_in_xdp", "kill_zombie_connections"}
        called = {n.func.id for n in ast.walk(self._func("l7_shadow_monitor"))
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertEqual(called & forbidden, set())

    def test_l7_shadow_thread_is_guarded(self):
        # The shadow thread must start only under `if L7_SHADOW:`, so the default
        # daemon behaviour is unchanged.
        guarded = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) \
                    and node.test.id == "L7_SHADOW":
                guarded.append("l7_shadow_monitor" in ast.unparse(node))
        self.assertTrue(guarded and all(guarded),
                        "l7_shadow_monitor thread must start inside `if L7_SHADOW:`")


if __name__ == "__main__":
    unittest.main()

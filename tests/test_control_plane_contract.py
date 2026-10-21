"""Static contract tests for control_plane.py's ban events (no root, no import).

control_plane.py attaches XDP when imported, so it is parsed with `ast` instead.
These tests pin the contract between the daemon and the evaluation tooling:
every ban names its engine, event kinds are the documented ones, and the [BAN]
console line that test_distributed_suite.py parses keeps its format.
"""
import ast
import os
import sys
import types
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import ban_events

EVENT_KINDS = {"start", "ban", "unban", "suppress_on", "suppress_off", "gru_suppressed",
               "l7_shadow", "l7_gru_poll", "l7_would_ban"}
# The L7 shadow modules must not be able to enforce anything (docs/L7_GRU_DESIGN.md §8).
L7_MODULES = ("l7_ingest.py", "l7_features.py", "l7_scorer.py", "l7_engine.py")
BAN_PATH_NAMES = ("ban_ip", "block_ip_in_xdp", "blacklist_map", "kill_zombie_connections",
                  "iptables")


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

    def test_l7_module_attributes_exist(self):
        # control_plane.py cannot be imported offline (it attaches XDP at import), so
        # check that every l7_* module attribute it references actually exists.
        import importlib
        for mod_name in ("l7_engine", "l7_ingest"):
            mod = importlib.import_module(mod_name)
            refs = {n.attr for n in ast.walk(self.tree) if isinstance(n, ast.Attribute)
                    and isinstance(n.value, ast.Name) and n.value.id == mod_name}
            self.assertTrue(refs, mod_name)
            self.assertEqual(sorted(r for r in refs if not hasattr(mod, r)), [], mod_name)

    def test_l7_modules_cannot_reach_the_ban_path(self):
        for name in L7_MODULES:
            with open(os.path.join(REPO, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            used |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            self.assertEqual(used & set(BAN_PATH_NAMES), set(), name)

    def _guarded_by(self, flag, needle):
        """Unparsed bodies of the `if <flag>:` blocks, checked for `needle`."""
        found = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If) and isinstance(node.test, ast.Name) \
                    and node.test.id == flag:
                found.append(needle in "\n".join(ast.unparse(s) for s in node.body))
        return any(found)

    def test_xdp_gru_feed_and_drain_are_guarded(self):
        # XDP_GRU=0 must skip both the flow_map feed and the result drain.
        self.assertTrue(self._guarded_by("XDP_GRU", "flow_map.items()"))
        self.assertTrue(self._guarded_by("XDP_GRU", "drain_inference_results()"))
        calls = [n for n in ast.walk(self._func("l3_l4_telemetry_monitor"))
                 if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                 and isinstance(n.value.func, ast.Name)
                 and n.value.func.id == "drain_inference_results"]
        self.assertEqual(len(calls), 1)         # exactly one call: the guarded one above

    def _switches(self, **env):
        """(GRU_ONLY, XDP_GRU) as control_plane.py's own two assignments evaluate under `env`.
        The module cannot be imported offline, so the statements run against a stub `os`."""
        names = ("GRU_ONLY", "XDP_GRU")
        stmts = [n for n in self.tree.body if isinstance(n, ast.Assign)
                 and getattr(n.targets[0], "id", None) in names]
        self.assertEqual([s.targets[0].id for s in stmts], list(names))     # source order
        scope = {"os": types.SimpleNamespace(environ=env)}
        exec(compile(ast.Module(stmts, []), "control_plane.py", "exec"), scope)  # noqa: S102
        return scope["GRU_ONLY"], scope["XDP_GRU"]

    def test_xdp_gru_is_off_by_default(self):
        # Audit G-16 (2026-10-19): 0 true bans and 1 false ban in the published ban-event logs
        # (results/2026-10-20_audit-derived/events_census.md).
        self.assertEqual(self._switches(), (False, False))
        self.assertEqual(self._switches(XDP_GRU="1"), (False, True))       # opt-in still works
        self.assertEqual(self._switches(XDP_GRU="0"), (False, False))

    def test_gru_only_still_runs_the_xdp_gru(self):
        # GRU_ONLY=1 disables every other engine. With the XDP-fed GRU off as well, nothing
        # could ban, so the isolation mode implies it unless XDP_GRU says otherwise.
        self.assertEqual(self._switches(GRU_ONLY="1"), (True, True))
        self.assertEqual(self._switches(GRU_ONLY="1", XDP_GRU="0"), (True, False))

    def test_start_event_records_the_xdp_gru_setting(self):
        # No campaign file records XDP_GRU, so the daemon's start event is the provenance.
        starts = [c for c in self.emit_calls if c.args and getattr(c.args[0], "value", None)
                  == "start"]
        self.assertEqual(len(starts), 1)
        self.assertIn("xdp_gru", {k.arg for k in starts[0].keywords})

    def test_tolerant_profile_matches_the_frozen_derivation(self):
        # P5c.2 (§7.3.3): HEURISTIC_PROFILE=tolerant overrides exactly the two daemon
        # thresholds the derivation relaxed, to the frozen values; defaults are unchanged.
        sys.path.insert(0, os.path.join(REPO, "ml"))
        import l7_traffic
        t = l7_traffic.THRESHOLDS_TOLERANT
        node = next(n for n in self.tree.body if isinstance(n, ast.Assign)
                    and any(getattr(x, "id", None) == "TOLERANT_OVERRIDES" for x in n.targets))
        self.assertEqual(ast.literal_eval(node.value),
                         {"HEURISTIC_MAX_RPS": t["l7_rate_ban_rps"],
                          "SLOWCONN_CONN_THRESHOLD": t["slowconn_ban_conns"]})
        self.assertIn("HEURISTIC_MAX_RPS = 50 ", self.source)
        self.assertIn("SLOWCONN_CONN_THRESHOLD = 8 ", self.source)
        switch = next(n for n in self.tree.body if isinstance(n, ast.If)
                      and "HEURISTIC_PROFILE" in ast.unparse(n.test))
        assigned = {t.id for st in switch.body for t in st.targets}
        self.assertEqual(assigned, {"HEURISTIC_MAX_RPS", "SLOWCONN_CONN_THRESHOLD"})
        # it runs at import, before XDP is attached, so a bad profile fails fast
        self.assertLess(self.source.index("HEURISTIC_PROFILE = os.environ"),
                        self.source.index("bpf.attach_xdp("))

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

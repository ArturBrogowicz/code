"""Offline tests for bench/population.py: seed namespaces, identities, link profiles, addresses, the benign
classes and attack families, and the streams that become engine commands (docs/HG1B_MINIMAL_DESIGN.md 5.3).

Nothing here opens a socket or starts a process. The engine is asked, in process and with --plan, whether it
accepts the command a stream produces.
"""
import contextlib
import inspect
import io
import itertools
import os
import re
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "bench"))
import calibration as C
import loadgen as LG
import loadtools as LT
import population as P
from test_loadtools import fake_root

CAL = C.load(C.PLACEHOLDER)
RHO, SPARE = C.rho_rps(CAL), C.spare_capacity(CAL)
COST_C3 = CAL["route_costs_ms"]["C3"]


def attack(sources=100, level=1.0, family="costly_search_flood"):
    cost = CAL["route_costs_ms"][P.ATTACK_FAMILIES[family].route_class]
    return family, sources, P.attack_rate(level, SPARE, cost)


POP = P.draw("calib", 1, RHO, 200, attack())


class SeedTest(unittest.TestCase):
    def test_the_namespaces_are_disjoint_ranges(self):
        seen = set()
        for namespace, rng in P.SEED_RANGES.items():
            self.assertFalse(seen & set(rng), namespace)
            seen |= set(rng)
        self.assertEqual(set(P.SEED_RANGES), {"calib", "train", "val", "test"})

    def test_a_seed_outside_its_namespace_is_refused(self):
        P.check_seed("calib", 99)
        P.check_seed("test", 300)
        for namespace, seed in (("calib", 100), ("calib", 0), ("test", 299), ("test", 400), ("val", 1)):
            with self.subTest(namespace=namespace, seed=seed), self.assertRaises(ValueError):
                P.check_seed(namespace, seed)
        with self.assertRaises(ValueError):
            P.check_seed("production", 1)
        with self.assertRaises(ValueError):
            P.draw("test", 1, RHO)

    def test_the_entity_seed_depends_on_every_part_of_its_key(self):
        base = P.entity_seed("calib", 1, "benign:page_browser", 0)
        self.assertEqual(base, P.entity_seed("calib", 1, "benign:page_browser", 0))
        for args in (("train", 1, "benign:page_browser", 0), ("calib", 2, "benign:page_browser", 0),
                     ("calib", 1, "benign:nat_pool", 0), ("calib", 1, "benign:page_browser", 1)):
            self.assertNotEqual(base, P.entity_seed(*args))
        self.assertLess(base, 2**64)

    def test_no_namespace_shares_an_entity_seed_with_another(self):
        owner = {}
        for namespace, rng in P.SEED_RANGES.items():
            for seed in rng:
                for index in range(3):
                    key = P.entity_seed(namespace, seed, "benign:page_browser", index)
                    self.assertNotIn(key, owner)
                    owner[key] = namespace


class DrawTest(unittest.TestCase):
    def test_a_draw_is_reproducible_and_every_seed_differs(self):
        again = P.draw("calib", 1, RHO, 200, attack())
        self.assertEqual(POP, again)
        other = P.draw("calib", 2, RHO, 200, attack())
        self.assertNotEqual({i.address for i in POP.identities}, {i.address for i in other.identities})
        self.assertNotEqual([s.rate for s in POP.streams], [s.rate for s in other.streams])
        train = P.draw("train", 100, RHO, 200, attack())
        self.assertNotEqual({i.address for i in POP.identities}, {i.address for i in train.identities})

    def test_the_counts_follow_the_class_shares(self):
        benign = [i for i in POP.identities if i.role.startswith("benign:")]
        attackers = [i for i in POP.identities if i.role.startswith("attack:")]
        self.assertEqual((len(benign), len(attackers)), (200, 100))
        counts = {c.name: sum(1 for i in benign if i.cls == c.name) for c in P.BENIGN_CLASSES}
        self.assertEqual(sum(counts.values()), 200)
        self.assertEqual(counts["page_browser"], 70)
        self.assertTrue(all(n >= 1 for n in counts.values()))
        self.assertAlmostEqual(sum(c.rate_share for c in P.BENIGN_CLASSES), 1.0)
        self.assertAlmostEqual(sum(c.id_share for c in P.BENIGN_CLASSES), 1.0)
        self.assertEqual(len(P.BENIGN_CLASSES), 8)

    def test_the_legit_rate_is_rho(self):
        total = sum(POP.route_rates("legit").values())
        self.assertAlmostEqual(total, RHO, delta=0.02 * RHO)         # a pulse sends whole requests per period

    def test_the_aggregate_route_mix_is_within_3_pp_of_the_calibration(self):
        rates = POP.route_rates("legit")
        total = sum(rates.values())
        self.assertLessEqual(set(rates), set(CAL["mix"]))
        for klass, weight in CAL["mix"].items():
            with self.subTest(route=klass):
                self.assertAlmostEqual(rates.get(klass, 0.0) / total, weight, delta=0.03)

    def test_the_attack_intensity_is_a_cost_rate_and_knows_no_threshold(self):
        self.assertEqual(list(inspect.signature(P.attack_rate).parameters), ["level", "spare_cpu_s", "cost_ms"])
        one = P.attack_rate(1.0, SPARE, COST_C3)
        self.assertAlmostEqual(one * COST_C3 / 1000, SPARE)             # the rate costs S CPU-seconds a second
        self.assertAlmostEqual(P.attack_rate(2.0, SPARE, COST_C3), 2 * one)
        self.assertAlmostEqual(sum(POP.route_rates("attack").values()), one, places=5)

    def test_the_number_of_sources_changes_the_per_source_rate_not_the_total(self):
        totals = {}
        for n in (5, 20, 100):
            pop = P.draw("calib", 1, RHO, 200, attack(n))
            totals[n] = sum(s.rate for s in pop.of_kind("attack"))
            self.assertEqual(sum(len(s.addresses) for s in pop.of_kind("attack")), n)
        self.assertAlmostEqual(totals[5], totals[100], places=5)
        self.assertAlmostEqual(totals[20], totals[100], places=5)

    def test_a_control_has_no_attack_streams_and_the_same_legit_ones(self):
        control = P.draw("calib", 1, RHO, 200)
        self.assertEqual(control.of_kind("attack"), ())
        self.assertEqual(control.of_kind("legit"), POP.of_kind("legit"))

    def test_the_timeline_places_the_streams(self):
        for s in POP.of_kind("legit"):
            self.assertEqual((s.start_s, s.duration_s), (0.0, 105.0))
        for s in POP.of_kind("attack"):
            self.assertEqual((s.start_s, s.duration_s), (30.0, 45.0))
        pop = P.draw("calib", 1, RHO, 60, attack(10), P.Timeline(10, 20, 5))
        self.assertEqual({(s.start_s, s.duration_s) for s in pop.of_kind("legit")}, {(0.0, 35.0)})
        self.assertEqual({(s.start_s, s.duration_s) for s in pop.of_kind("attack")}, {(10.0, 20.0)})

    def test_a_stream_above_the_engine_ceiling_is_split(self):
        one = P.draw("calib", 1, RHO, 200, ("cheap_static_flood", 100, 12_000.0)).of_kind("attack")
        self.assertEqual(len(one), 4)                                  # no profile reaches 5,000 a second: no split
        pop = P.draw("calib", 1, RHO, 200, ("cheap_static_flood", 100, 30_000.0))
        streams = pop.of_kind("attack")
        self.assertGreaterEqual(len(streams), 7)                       # 9,000 / 10,500 / 7,500 / 3,000 over 4 profiles
        self.assertTrue(all(s.rate <= P.ENGINE_CEILING_RPS for s in streams))
        self.assertAlmostEqual(sum(s.rate for s in streams), 30_000.0, places=3)
        addresses = list(itertools.chain.from_iterable(s.addresses for s in streams))
        self.assertEqual(len(addresses), len(set(addresses)))
        self.assertEqual(len({s.id for s in streams}), len(streams))

    def test_a_pulse_stream_sends_whole_requests_every_period(self):
        pulses = [s for s in POP.of_kind("legit") if s.process == "pulse"]
        self.assertTrue(pulses)
        for s in pulses:
            with self.subTest(stream=s.id):
                self.assertAlmostEqual(s.rate * s.period, round(s.rate * s.period), places=4)
                self.assertGreaterEqual(s.rate * s.period, 1)
                self.assertEqual((s.period, s.duty), (P.PULSE_PERIOD, P.PULSE_DUTY))

    def test_ids_seeds_cpu_classes_and_pools(self):
        ids = [s.id for s in POP.streams]
        self.assertEqual(len(ids), len(set(ids)))
        seeds = [s.seed for s in POP.streams]
        self.assertEqual(len(seeds), len(set(seeds)))
        self.assertTrue(all(0 <= x < 2**31 for x in seeds))
        for s in POP.streams:
            self.assertEqual(s.cpu, "legit" if s.kind == "legit" else "attack")
            self.assertEqual(s.pool, P.POOL[s.kind])
            self.assertEqual(len(s.paths), 20 if s.route_class == "C0" else P.PATHS_PER_STREAM)
            self.assertEqual(len(set(s.paths)), len(s.paths))

    def test_the_process_count_is_modest(self):
        # legit: at most 3 pulse routes + 5 poisson routes over 4 link profiles; attack: one route over 4 profiles
        self.assertLessEqual(len(POP.of_kind("legit")), (3 + 5) * len(P.NETEM_MIX))
        self.assertEqual(len(POP.of_kind("attack")), len(P.NETEM_MIX))


class NetemTest(unittest.TestCase):
    def test_the_mix_is_the_suites_own(self):
        with open(os.path.join(REPO, "test_distributed_suite.py"), encoding="utf-8") as fh:
            source = fh.read()
        profiles = re.search(r'profiles = \[("[a-z_0-9]+"(?:, "[a-z_0-9]+")*)\]', source).group(1)
        weights = re.search(r"weights\s*=\s*\[([0-9., ]+)\]", source).group(1)
        self.assertEqual([p.strip('"') for p in profiles.split(", ")], [p for p, _ in P.NETEM_MIX])
        self.assertEqual([float(w) for w in weights.split(",")], [w for _, w in P.NETEM_MIX])
        self.assertAlmostEqual(sum(w for _, w in P.NETEM_MIX), 1.0)

    def test_attackers_and_benign_identities_draw_from_one_distribution(self):
        benign, attackers = [], []
        for seed in range(1, 21):
            pop = P.draw("calib", seed, RHO, 200, attack(100))
            benign += [i.netem for i in pop.identities if i.role.startswith("benign:")]
            attackers += [i.netem for i in pop.identities if i.role.startswith("attack:")]
        for profile, weight in P.NETEM_MIX:
            with self.subTest(profile=profile):
                b, a = benign.count(profile) / len(benign), attackers.count(profile) / len(attackers)
                self.assertAlmostEqual(b, weight, delta=0.03)
                self.assertAlmostEqual(a, weight, delta=0.04)
                self.assertAlmostEqual(a, b, delta=0.05)

    def test_a_namespace_carries_one_profile_and_an_identity_lives_in_its_own(self):
        self.assertEqual([n.netem for n in P.namespaces(1)], [p for p, _ in P.NETEM_MIX])
        self.assertEqual(len(P.namespaces(2)), 8)
        pop = P.draw("calib", 1, RHO, 200, attack(), per_profile=2)
        by_index = {n.index: n.netem for n in pop.namespaces}
        self.assertTrue(all(by_index[i.ns_index] == i.netem for i in pop.identities))
        self.assertEqual({i.ns_index for i in pop.identities}, set(by_index))


class AddressTest(unittest.TestCase):
    def test_addresses_are_distinct_in_their_networks_and_inside_the_scope_lock(self):
        addresses = [i.address for i in POP.identities]
        self.assertEqual(len(addresses), len(set(addresses)))
        for ident in POP.identities:
            LT.check_address(ident.address, False)
            net = P.ATTACK_NETS[0] if ident.role.startswith("attack:") else P.BENIGN_NETS[0]
            self.assertIn(P.ipaddress.ip_address(ident.address), net)

    def test_benign_identities_overflow_into_the_second_network_and_then_stop(self):
        pop = P.draw("calib", 1, RHO, 300)
        nets = [P.ipaddress.ip_address(i.address) in P.BENIGN_NETS[0] for i in pop.identities]
        self.assertEqual((sum(nets), len(nets) - sum(nets)), (254, 46))
        with self.assertRaises(ValueError):
            P.draw("calib", 1, RHO, 600)

    def test_the_alias_plan_places_every_identity_once_in_a_namespace_of_its_profile(self):
        plan = POP.alias_plan()
        placed = list(itertools.chain.from_iterable(plan.values()))
        self.assertEqual(sorted(placed), sorted(i.address for i in POP.identities))
        by_ns = {n.index: n.netem for n in POP.namespaces}
        for index, addresses in plan.items():
            for address in addresses:
                ident = next(i for i in POP.identities if i.address == address)
                self.assertEqual((ident.ns_index, ident.netem), (index, by_ns[index]))


class CommandTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.m = fake_root(self.tmp)
        self.addCleanup(self._tmp.cleanup)

    def argv_of(self, stream):
        spec = P.to_load_spec(stream, "http://10.0.0.1/")
        argv = LT.build_plan("loadgen", spec, os.path.join(self.tmp, stream.id), self.m, self.tmp).steps[0].argv
        return spec, argv

    def test_the_real_engine_accepts_the_command_of_every_stream_and_plans_its_rate(self):
        for stream in POP.streams:
            with self.subTest(stream=stream.id):
                _, argv = self.argv_of(stream)
                tail = argv[argv.index(os.path.join(REPO, "bench", "loadgen.py")) + 1:]
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(LG.main([*tail, "--plan"]), 0)
                n = int(re.search(r"(\d+) requests over", out.getvalue()).group(1))
                expected = stream.rate * stream.duration_s
                self.assertLessEqual(abs(n - expected), 6 * expected ** 0.5 + 5)

    def test_the_command_carries_every_address_and_path_and_the_pin_of_its_class(self):
        for stream in (POP.of_kind("legit")[0], POP.of_kind("attack")[0]):
            spec, argv = self.argv_of(stream)
            with self.subTest(stream=stream.id):
                self.assertEqual(argv.count("--local-addr"), len(stream.addresses))
                self.assertEqual(argv.count("--path"), len(stream.paths))
                self.assertEqual(spec.cpus, P.PIN_PLAN[stream.cpu])
                self.assertEqual(argv[:3], ["taskset", "-c", P.PIN_PLAN[stream.cpu]])
                self.assertEqual(argv[argv.index("--pool") + 1], str(P.POOL[stream.kind]))

    def test_the_legit_streams_have_the_healthy_vcpu_to_themselves(self):
        def cpus(spec):
            out = set()
            for part in spec.split(","):
                lo, _, hi = part.partition("-")
                out |= set(range(int(lo), int(hi or lo) + 1))
            return out
        self.assertEqual(cpus(P.PIN_PLAN["legit"]), {6})                  # the healthy vCPU (D14)
        for other in ("server", "daemon", "attack"):
            self.assertFalse(cpus(P.PIN_PLAN["legit"]) & cpus(P.PIN_PLAN[other]), other)
        self.assertEqual(cpus(P.PIN_PLAN["attack"]), {3, 4, 5, 7})

    def test_a_stream_outside_the_testbed_is_refused_by_the_wrapper(self):
        with self.assertRaises(LT.ScopeError):
            LT.validate(P.to_load_spec(POP.streams[0], "http://8.8.8.8/"))


if __name__ == "__main__":
    unittest.main()

"""D-073 (4) (2026-11-07T08:33Z; R-021): P4's benign clients run on CPU 7, the CPU the timer gate probes at the record's limit; the attack
generators and the runner on CPUs 3-6, as P1 and HG pin them (T-074). Nothing touches the machine."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "eval"), os.path.join(REPO, "ml"), os.path.join(REPO, "bench")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import p4_fake_host as F
import p4_runner as R
import population as POP

LORIS = ("loris",)


class PinsTest(unittest.TestCase):
    def test_the_layout(self):
        self.assertEqual(R.PINS, {"server": "0-1", "daemon": "2", "benign": "7", "attack": "3-6", "runner": "3-6", "timer": "7"})
        self.assertEqual(R.PINS["timer"], R.PINS["benign"], "the gate probes the CPU of the clients whose requests are judged")
        self.assertEqual((R.PINS["timer"], R.PINS["server"], R.PINS["daemon"]),
                         (POP.PIN_PLAN_DAEMON["legit"], POP.PIN_PLAN_DAEMON["server"], POP.PIN_PLAN_DAEMON["daemon"]))
        cpus = lambda text: {int(x) for part in text.split(",") for x in range(int(part.split("-")[0]), int(part.split("-")[-1]) + 1)}
        self.assertFalse(cpus(R.PINS["benign"]) & cpus(R.PINS["attack"]))
        self.assertFalse((cpus(R.PINS["benign"]) | cpus(R.PINS["attack"])) & (cpus(R.PINS["server"]) | cpus(R.PINS["daemon"])))

    def test_every_launch_on_its_roles_cpus(self):
        block = R.plan_block("campaign", 3101, "/r", sources={"loris": 100, "post": 5}, thresholds=(5, 256, 2), families=("loris", "post"))
        for run in block["runs"]:
            for x in run["launches"]:
                self.assertEqual(x["argv"][:3], ["taskset", "-c", R.PINS[x["role"]]], (run["arm"], x["entity_id"]))
            self.assertEqual(run["provenance"]["pins"], R.PINS)
            self.assertEqual(run["nginx"]["start"][:3], ["taskset", "-c", "0-1"])

    def test_the_runner_pins_itself_and_the_gate_probes_the_benign_cpu(self):
        with tempfile.TemporaryDirectory() as root:
            host = F.FakeHost()
            R.run_block(host, R.plan_block("smoke", 9101, root, arms=["C"], label="pins", families=LORIS))
        self.assertEqual(host.commands[0], ("", ("pin", "3-6"), ""))
        probes = [argv for _ns, argv, _in in host.commands if "timer-probe" in argv]
        self.assertTrue(probes)
        self.assertTrue(all(argv[:3] == ("taskset", "-c", "7") for argv in probes))

    def test_p1_passes_its_own_cpus(self):
        """eval/p1_runner.py calls gen_argv with its own `cpus`: they are taken as given."""
        block = R.plan_block("validation", 4001, "/r", sources={"loris": 100}, families=LORIS)
        e = next(e for e in block["runs"][0]["entities"] if e["role"] == "benign")
        self.assertEqual(R.gen_argv(e, "/o", "/py", cpus="3-5")[:3], ["taskset", "-c", "3-5"])
        self.assertEqual(R.gen_argv(e, "/o", "/py")[:3], ["taskset", "-c", "7"])


if __name__ == "__main__":
    unittest.main()

"""The trainer's default selection rule depends on its input (review T-029 P3-01): the commands documented in the
published READMEs pass no --selection and must still reproduce the published reports, while P3 (schema-2) captures
select on validation only. The reproduction test runs the documented P5c.3 command (seed 0, 25 epochs) for the
variant the published run chose, and compares the GRU report with results/2026-10-16_l7-p5c3-train/l7_metrics.json.
Offline; the package goes to a temporary directory."""
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p3_fixtures as FX

sys.path.insert(0, os.path.join(FX.REPO, "ml"))
import train_l7 as T
from test_l7_train import synth_dataset

CAPTURE = os.path.join(FX.REPO, "results", "2026-10-16_l7-p5c3-capture")
PUBLISHED = os.path.join(FX.REPO, "results", "2026-10-16_l7-p5c3-train", "l7_metrics.json")
READMES = ("results/2026-10-16_l7-p5c3-train/README.md", "results/2026-10-15_l7-p4-train/README.md")


def documented_argv(readme):
    """The train_l7.py command a README documents, as argv after the script name (continuation lines joined)."""
    with open(os.path.join(FX.REPO, readme), encoding="utf-8") as fh:
        text = fh.read().replace("\\\n", " ")
    line = next(x for x in text.splitlines() if re.search(r"python\S* ml/train_l7\.py ", x))
    argv = shlex.split(line.strip().lstrip("$ "))
    return argv[argv.index("ml/train_l7.py") + 1:]


class DefaultRuleTest(unittest.TestCase):
    def test_the_rule_follows_the_input(self):
        root = tempfile.mkdtemp(prefix="l7def_")
        self.addCleanup(shutil.rmtree, root, True)
        legacy = os.path.join(root, "legacy")
        synth_dataset(legacy)
        v = "2026-11-t1"
        p3 = FX.capture(os.path.join(root, v), v, 1001, "train", FX.entities(v, 1001))[0]
        self.assertEqual(T.default_selection([legacy]), "p5c")
        self.assertEqual(T.default_selection([p3]), "val")
        self.assertEqual(T.default_selection([legacy], val_dirs=[p3]), "val")
        self.assertEqual(T.default_selection([CAPTURE]), "p5c")       # the published capture is schema 1

    def test_the_documented_commands_pass_no_selection_and_name_legacy_datasets(self):
        for readme in READMES:
            argv = documented_argv(readme)
            self.assertNotIn("--selection", argv, readme)
            dataset = os.path.join(FX.REPO, argv[0])
            self.assertTrue(re.fullmatch(r"results/2026-10-1[56]_l7-p[35]c?3?-capture", argv[0]), argv[0])
            self.assertEqual(T.default_selection([dataset]), "p5c", readme)


class DocumentedP5cCommandTest(unittest.TestCase):
    """`ml/train_l7.py results/2026-10-16_l7-p5c3-capture --out <pkg> --seed 0 --epochs 25 --variants no_size
    no_size_no_server_timing`, run for the published choice only and without the HGB baseline (the GRU report is
    what reproduces; the HGB's depends on the sklearn version)."""

    def test_reproduces_the_published_gru_report(self):
        argv = documented_argv(READMES[0])
        self.assertEqual(argv[argv.index("--seed") + 1], "0")
        self.assertEqual(argv[argv.index("--epochs") + 1], "25")
        with open(PUBLISHED, encoding="utf-8") as fh:
            pub = json.load(fh)
        chosen = pub["selection"]["chosen"]
        self.assertIn(chosen, argv)
        out = tempfile.mkdtemp(prefix="l7p5c_")
        self.addCleanup(shutil.rmtree, out, True)
        report, best = T.run(CAPTURE, out, seed=0, epochs=25, variants=(chosen,), do_baseline=False)
        self.assertIsNotNone(best)
        self.assertNotIn("selection_rule", report)                   # the published rule, not "val"
        for key in ("seed", "epochs", "seq", "stride", "threshold", "consecutive", "held_out_families",
                    "dataset_manifest_sha_families"):
            self.assertEqual(report[key], pub[key], key)
        new, old = report["variants"][chosen], pub["variants"][chosen]
        for key in ("columns", "val_loss", "ip_split", "counts", "gru", "probes", "probe_gate_pass"):
            self.assertEqual(json.loads(json.dumps(new[key])), old[key], key)
        self.assertEqual(report["selection"]["chosen"], chosen)
        self.assertEqual(report["selection"]["rule"], pub["selection"]["rule"])
        self.assertEqual(json.loads(json.dumps(report["probes"])), pub["probes"])


if __name__ == "__main__":
    unittest.main()

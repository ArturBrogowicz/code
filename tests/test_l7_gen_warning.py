"""ml/l7_gen.py on port 443 (T063-03): urllib3 warns on every unverified HTTPS request, and the testbed's certificate is self-signed.
PYTHONWARNINGS set in os.environ does nothing to a running interpreter, so the generator installs a filter for that one category. Each check
runs in a fresh interpreter, as a generator does; nothing is sent anywhere, the traffic function is a stub."""
import os
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WARN = ("import warnings, urllib3\n"
        "for _ in range(3):\n"
        "    warnings.warn('unverified', urllib3.exceptions.InsecureRequestWarning)\n"
        "warnings.warn('another security warning', urllib3.exceptions.SecurityWarning)\n"
        "warnings.warn('a user warning', UserWarning)\n")


def child(code):
    """`code` in a fresh interpreter, in ml/ and with no PYTHONWARNINGS of the caller's: its exit code and its stderr."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONWARNINGS"}
    r = subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, '.')\n" + code], cwd=os.path.join(REPO, "ml"), env=env,
                       capture_output=True, text=True, timeout=600, check=False)
    return r.returncode, r.stderr


def generator(port):
    """l7_gen.main on `port` with its traffic stubbed, and then the warnings, with requests imported after it as a session does."""
    return child("from unittest import mock\nimport l7_gen\n"
                 "with mock.patch.object(l7_gen, 'resolve', return_value=lambda *a: {}):\n"
                 f"    assert l7_gen.main(['--role', 'benign', '--kind', 'curl_oneshot', '--host', '10.0.0.1', '--port', '{port}',"
                 " '--duration', '0.1']) == 0\n"
                 "import requests\n" + WARN)


class InsecureRequestWarningTest(unittest.TestCase):
    def test_the_filter_drops_that_warning_and_no_other(self):
        code, err = child("import os; os.environ.setdefault('PYTHONWARNINGS', 'ignore')\nimport requests\n" + WARN)
        self.assertEqual((code, err.count("unverified")), (0, 3), "what the generator did before: urllib3 warns every time")
        code, err = child("import requests, l7_gen\nl7_gen.quiet_insecure_warning()\n" + WARN)
        self.assertEqual(code, 0, err)
        self.assertNotIn("unverified", err)
        self.assertIn("another security warning", err)
        self.assertIn("a user warning", err)

    def test_the_generator_installs_it_on_port_443_and_not_on_80(self):
        code, err = generator(443)
        self.assertEqual(code, 0, err)
        self.assertNotIn("unverified", err)
        self.assertIn("another security warning", err)
        code, err = generator(80)
        self.assertEqual((code, err.count("unverified")), (0, 3), err)


if __name__ == "__main__":
    unittest.main()

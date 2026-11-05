"""The L7 v2 log fields (docs/L7V2_DESIGN.md 8.3, 8.4): the l7json format of the capture conf and of the deployed nginx.conf
(the daemon's sink in the mitigated runs) logs the Referer, the session cookie the client sends and the one the server
sets, in one identical format. Static: no nginx is started.

nginx_unprotected.conf keeps its format: it is the harm benchmark's stack (bench/executor.py renders it, and its sha256
is in the executor's golden plans and in a frozen calibration record's host block), so a run that needs these fields
over the unprotected stack renders them into its own copy."""
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFS = ("nginx_l7capture.conf", "nginx.conf")
NEW = {"ref": "$http_referer", "sid": "$cookie_sid", "sid_set": "$upstream_cookie_sid"}


def l7json(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fh:
        text = fh.read()
    block = re.search(r"log_format l7json escape=json\n(.*?)'}';", text, re.DOTALL).group(1)
    return re.findall(r"'\"(\w+)\":\"?(\$\w+)\"?,?'", block)


class LogFieldsTest(unittest.TestCase):
    def test_the_three_fields_are_logged_last(self):
        for name in CONFS:
            fields = l7json(name)
            self.assertEqual(fields[-3:], list(NEW.items()), name)
            self.assertEqual(fields[-4], ("ua", "$http_user_agent"), name)

    def test_the_capture_and_the_deployed_format_are_identical(self):
        self.assertEqual(l7json("nginx_l7capture.conf"), l7json("nginx.conf"))
        self.assertEqual(len(l7json("nginx.conf")), 23)


if __name__ == "__main__":
    unittest.main()

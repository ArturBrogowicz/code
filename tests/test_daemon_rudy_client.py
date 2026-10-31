"""H-26 (review of 2026-10-29): the R.U.D.Y. rule bans nginx's own client field, never an
address that the request names.

nginx writes a request error as `<time> [<level>] <pid>#<tid>: *<conn> <message> while <action>,
client: <addr>, server: <name>, request: "<request line>", host: "<Host>", referrer: "<Referer>"`
(ngx_log_error_core, src/core/ngx_log.c:117-149; ngx_http_log_error and ngx_http_log_error_handler,
src/http/ngx_http_request.c:3918-4007, nginx 1.28.3). The client field follows the action at
once; the fields the client writes come after it. The old pattern took the last `client:` of the
line, so an address in the URI, the Host or the Referer was counted and banned instead of the
client (T-013, rudy_regex_probe.log).

The real tail_nginx_error_logs runs against the fakes of tests/daemon_harness.py, as in
tests/test_daemon_rules.py: nothing is imported from control_plane.py. Each test fails on the
daemon before the fix (da8cca7).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import daemon_harness as H

CLIENT = "10.0.2.9"                    # the client, as nginx writes it
DECOY = "10.0.1.5"                     # an address the request names
ARABIC_DECOY = "١٠.٠.١.٥"   # 10.0.1.5 in Arabic-Indic digits

TIMED_OUT = "client timed out (110: Connection timed out)"
BODY = "reading client request body"
HEADERS = "reading client request headers"


def nginx_line(message, action, client=CLIENT, request="POST /?r=1 HTTP/1.1", host="10.0.0.1",
               referrer=None, level="info"):
    """One error-log line in nginx's order: the prefix, the message, ' while <action>' (none
    once the request runs its phases: ngx_http_core_module.c:831), the client and server
    fields, then the request line, the Host and the Referer."""
    during = f" while {action}" if action else ""
    line = (f"2026/10/30 09:00:00 [{level}] 1234#1234: *5 {message}{during}, "
            f'client: {client}, server: _, request: "{request}", host: "{host}"')
    if referrer is not None:
        line += f', referrer: "{referrer}"'
    return line + "\n"


def body_timeout(**fields):
    return nginx_line(TIMED_OUT, BODY, **fields)


class RudyClientFieldTest(unittest.TestCase):
    def daemon(self):
        d = H.Daemon({})
        self.addCleanup(d.close)
        return d

    @staticmethod
    def bans(d):
        return [(b["ip"], b["engine"], b["value"]) for b in d.bans()]

    @staticmethod
    def skipped(d):
        return [(e["where"], e["error"], e["action"]) for e in d.events("daemon_error")]

    @staticmethod
    def run_thread(d, lines):
        """The R.U.D.Y. thread's own target, supervise('rudy', tail_nginx_error_logs, path),
        over `lines`. Its first sleep (end of file, or the 1-s backoff of a restart) stops it."""
        d._fake_logs.append(H.FakeLogFile([(0, line) for line in lines], d.clock))
        d.stop_event.clear()
        d.clock.on_sleep = lambda _k: d.stop_event.set()
        try:
            d.call("supervise", "rudy", d.tail_nginx_error_logs, d.error_log)
        finally:
            d.clock.on_sleep = None
            d.stop_event.clear()

    @staticmethod
    def tail_file(d, chunks):
        """The real tail_nginx_error_logs over a real file that starts empty: at each sleep at
        end of file the next chunk of bytes is appended, and the sleep after the last stops it."""
        path = os.path.join(d._tmp.name, "tailed_error.log")
        with open(path, "wb"):
            pass
        pending = list(chunks)

        def on_sleep(_k):
            if pending:
                with open(path, "ab") as fh:
                    fh.write(pending.pop(0))
            else:
                d.stop_event.set()

        d.stop_event.clear()
        d.clock.on_sleep = on_sleep
        try:
            d.call("tail_nginx_error_logs", path)
        finally:
            d.clock.on_sleep = None
            d.stop_event.clear()

    def test_an_address_in_the_uri_the_host_or_the_referer_is_never_banned(self):
        # T-013's probe: the old pattern captured the URI's or the Host's address. nginx accepts
        # both without spaces (ngx_http_validate_host refuses a space in the Host); the Referer
        # is logged as sent. 'plain' is the control: a line without a decoy bans as before.
        cases = {
            "plain": {},
            "uri": {"request": f"POST /?x=,client:{DECOY} HTTP/1.1"},
            "host": {"host": f"x,client:{DECOY}"},
            "referer": {"referrer": f"http://x/, client: {DECOY}, server: _"},
        }
        for name, fields in cases.items():
            with self.subTest(name):
                d = self.daemon()
                d.rudy_lines([(0, body_timeout(**fields))] * 3)
                self.assertEqual(self.bans(d), [(CLIENT, "l7_rudy", 3)])
                self.assertEqual(d.blacklist.ips(), {CLIENT})
                self.assertEqual(d.proc.matching("ss", "-K"), [["ss", "-K", "dst", CLIENT]])
                self.assertEqual(dict(d.rudy_tracker), {})
                self.assertEqual(self.skipped(d), [])

    def test_a_body_timeout_the_client_writes_into_another_line_does_not_count(self):
        # Only nginx's own message counts. A Slowloris header timeout with the text in its
        # Referer made the old pattern count the decoy; an ignored header line, which nginx logs
        # as sent before its own client field (ngx_http_request.c:1484-1487), made it count the
        # client, for a request that never sent a body.
        forged = f"{TIMED_OUT} while {BODY}, client: {DECOY}, server: _"
        lines = {
            "header timeout": nginx_line(TIMED_OUT, HEADERS, referrer=f"http://x/ {forged}"),
            "ignored header line": nginx_line(f'client sent invalid header line: "X(: {forged}"',
                                              HEADERS, request="GET / HTTP/1.1"),
        }
        for name, line in lines.items():
            with self.subTest(name):
                d = self.daemon()
                d.rudy_lines([(0, line)] * 3)
                self.assertEqual(d.bans(), [])
                self.assertEqual(dict(d.rudy_tracker), {})

    def test_non_ascii_digits_neither_ban_nor_restart_the_thread(self):
        # In the URI (T-013's probe), the old pattern took them as an address and inet_aton
        # raised in ban_ip, so the thread restarted after a 1-s backoff (its log reopened at the
        # end) and the client was not banned. Now the client is.
        d = self.daemon()
        self.run_thread(d, [body_timeout(request=f"POST /?x=,client:{ARABIC_DECOY} HTTP/1.1")] * 3)
        self.assertEqual(self.bans(d), [(CLIENT, "l7_rudy", 3)])
        self.assertEqual(d.events("daemon_error"), [])
        self.assertAlmostEqual(d.clock.now, 1000.1)                 # end of file, no backoff
        # As the client field itself (nginx writes ASCII): skipped and reported, no restart.
        d = self.daemon()
        self.run_thread(d, [body_timeout(client=ARABIC_DECOY)] * 3)
        self.assertEqual(d.bans(), [])
        self.assertEqual(self.skipped(d), [(
            "error_log", f"R.U.D.Y. client field {ARABIC_DECOY!r} is not an IPv4 address",
            "line skipped")] * 3)
        self.assertAlmostEqual(d.clock.now, 1000.1)

    def test_a_client_field_that_is_not_an_ipv4_address_is_skipped_and_reported(self):
        # IPv6 and a unix socket (the XDP ban path takes IPv4 only), an empty or long field, and
        # forms that inet_aton reads otherwise than the string kept in banned_ips: an octet over
        # 255 raised in ban_ip, and a leading zero is octal to it (010.0.2.1 blocked 8.0.2.1).
        for client in ("2001:db8::1", "unix:", "", "x" * 100, "10.0.2.999", "010.0.2.1"):
            with self.subTest(client[:12]):
                d = self.daemon()
                d.rudy_lines([(0, body_timeout(client=client))] * 3)
                self.assertEqual(d.bans(), [])
                self.assertEqual(d.blacklist.entries, {})
                self.assertEqual(self.skipped(d), [(
                    "error_log", f"R.U.D.Y. client field {client[:64]!r} is not an IPv4 address",
                    "line skipped")] * 3)
                self.assertEqual(dict(d.rudy_tracker), {})

    def test_a_carriage_return_inside_a_field_cannot_start_a_line(self):
        # nginx ends its lines with LF and writes a CR inside a field as it is: in the decoded
        # URI of an open() error, for one (ngx_http_static_module.c:137-138, where files are
        # served). Python's universal newlines ended the line at that CR, so the client wrote
        # the next one: the old pattern counted the client's open() errors as body timeouts, and
        # a pattern anchored at the start of a line would count the forged line's decoy.
        forged = (f"2026/10/30 09:00:00 [info] 1#1: *6 {TIMED_OUT} while {BODY}, client: {DECOY}, "
                  "server: _")
        line = nginx_line(f'open() "/usr/share/nginx/html/x\r{forged}" failed (2: No such file or '
                          "directory)", None, request="GET /x%0D... HTTP/1.1", level="error")
        d = self.daemon()
        self.tail_file(d, [line.encode() * 3])
        self.assertEqual(d.bans(), [])
        self.assertEqual(dict(d.rudy_tracker), {})


if __name__ == "__main__":
    unittest.main()

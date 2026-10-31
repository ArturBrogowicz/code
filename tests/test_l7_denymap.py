"""The L7 v2 deny map (l7_denymap.py; docs/L7V2_DESIGN.md 9.2 and 9.4, F-V7): what may be written into nginx's
configuration. Hostile User-Agents and session ids are fed to the writer, and the file is read back twice: with the
exact line pattern, and with a port of nginx's own tokenizer, so that "one `"key" 1;` line per entry" is checked the
way nginx reads it. Offline: no nginx runs.
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
import l7_denymap as D

IP = "10.0.2.1"
SID = "0123456789abcdef0123456789abcdef"


def nginx_directives(text):
    """The directives nginx's tokenizer reads from `text` (a port of ngx_conf_read_token, src/core/ngx_conf_file.c of
    nginx 1.28.3, for what a file included inside a map block may hold): a list of parameter lists. A `{` or `}`
    outside quotes, or text left over at the end of the file, raises ValueError, as nginx refuses them there."""
    directives, args = [], []
    last_space, need_space, quoted, d_quoted, s_quoted, sharp, variable = True, False, False, False, False, False, False
    start = 0
    for i, ch in enumerate(text):
        if ch == "\n" and sharp:
            sharp = False
        if sharp:
            continue
        if quoted:
            quoted = False
            continue
        if need_space:
            if ch in " \t\r\n":
                last_space, need_space = True, False
                continue
            if ch == ";":
                directives.append(args)
                args, last_space, need_space = [], True, False
                continue
            raise ValueError(f"unexpected {ch!r} at {i}")
        if last_space:
            start = i
            if ch in " \t\r\n":
                continue
            if ch == ";" and args:
                directives.append(args)
                args = []
                continue
            if ch in ";{":
                raise ValueError(f"unexpected {ch!r} at {i}")
            if ch == "}":
                raise ValueError(f"unexpected '}}' at {i}")
            if ch == "#":
                sharp = True
                continue
            last_space = False
            if ch == "\\":
                quoted = True
            elif ch == '"':
                start, d_quoted = i + 1, True
            elif ch == "'":
                start, s_quoted = i + 1, True
            elif ch == "$":
                variable = True
            continue
        if ch == "{" and variable:
            continue
        variable = False
        if ch == "\\":
            quoted = True
            continue
        if ch == "$":
            variable = True
            continue
        found = False
        if d_quoted:
            if ch == '"':
                d_quoted, need_space, found = False, True, True
        elif s_quoted:
            if ch == "'":
                s_quoted, need_space, found = False, True, True
        elif ch in " \t\r\n;{":
            last_space, found = True, True
        if found:
            args.append(_unescape(text[start:i]))
            if ch == ";":
                directives.append(args)
                args = []
            elif ch == "{":
                raise ValueError(f"unexpected '{{' at {i}")
    if args or d_quoted or s_quoted or not last_space and not need_space:
        raise ValueError("unexpected end of file")
    return directives


def _unescape(raw):
    out, i = [], 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in "\"'\\":
                out.append(nxt)
                i += 2
                continue
            if nxt in "trn":
                out.append({"t": "\t", "r": "\r", "n": "\n"}[nxt])
                i += 2
                continue
        out.append(raw[i])
        i += 1
    return "".join(out)


class TokenizerPortTest(unittest.TestCase):
    """The port reads what nginx reads (cases worked out from ngx_conf_file.c:640-800)."""

    def test_quotes_escapes_and_terminators(self):
        self.assertEqual(nginx_directives('"a;b{c}$d#e" 1;\n'), [["a;b{c}$d#e", "1"]])
        self.assertEqual(nginx_directives('"a\\"b" 1;'), [['a"b', "1"]])
        self.assertEqual(nginx_directives('"a\nb" 1;'), [["a\nb", "1"]])          # a quoted string may span lines
        self.assertEqual(nginx_directives('a 1; # x"y\nb 2;'), [["a", "1"], ["b", "2"]])
        self.assertEqual(nginx_directives(""), [])
        for bad in ('"a"b 1;', 'a 1', '"a 1;', "} ", '"a" 1; }', "a {"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                nginx_directives(bad)


# Hostile User-Agents and the rule each one fails. Newline escapes appear both as the logged JSON text decodes them
# (a control character) and as literal backslash sequences; bytes >= 0x80 both as the daemon decodes them (U+FFFD) and
# as single characters.
HOSTILE = {
    'x" 0; "y': "ua_forbidden_char",
    'x\\" 0; default 1; #': "ua_forbidden_char",
    "x\\n\"y": "ua_forbidden_char",
    "a\\u000ab": "ua_forbidden_char",
    json.loads('"a\\u000ab"'): "ua_not_printable_ascii",
    "a\nb": "ua_not_printable_ascii",
    "a\r\n\"10.0.2.9||\" 1;": "ua_not_printable_ascii",
    "a\tb": "ua_not_printable_ascii",
    "a\x00b": "ua_not_printable_ascii",
    "a\x7fb": "ua_not_printable_ascii",
    "café": "ua_not_printable_ascii",
    "bot�": "ua_not_printable_ascii",
    "ÿ\u0080": "ua_not_printable_ascii",
    "Mozilla/5.0 (X11; Linux x86_64)": "ua_forbidden_char",
    "x { return 200; }": "ua_forbidden_char",
    "}": "ua_forbidden_char",
    "${http_host}": "ua_forbidden_char",
    "x" * 257: "ua_too_long",
    7: "ua_type",
}
# Characters that are ordinary inside nginx's double quotes; such User-Agents are written as they are.
TRICKY_BUT_WRITABLE = ("~Opera Mini", "~*x", "#not a comment", "include", "default", "it's", " spaced ",
                       "a|b|c", "", "x" * 256, "%00%0a", "(KHTML, like Gecko)")


class WriteRulesTest(unittest.TestCase):
    def test_hostile_user_agents_are_refused_with_the_rule_they_fail(self):
        for ua, rule in HOSTILE.items():
            with self.subTest(ua=ua):
                self.assertEqual(D.key_problem(IP, ua, ""), rule)
                with self.assertRaises(ValueError):
                    D.map_key(IP, ua, "")

    def test_sids_are_empty_or_the_servers_format(self):
        for sid in ("", SID):
            self.assertIsNone(D.sid_problem(sid))
        for sid in ("-", SID.upper(), SID[:-1], SID + "0", " " + SID, SID + "\n", "g" * 32, None):
            with self.subTest(sid=sid):
                self.assertEqual(D.key_problem(IP, "ua", sid), "sid_format")

    def test_the_sid_format_is_the_servers(self):
        import l7_backend
        self.assertEqual(D.SID_RE.pattern, l7_backend.SID_RE.pattern)

    def test_only_canonical_dotted_ipv4_addresses(self):
        self.assertIsNone(D.ip_problem("255.255.255.255"))
        for ip in ("010.0.2.1", "10.0.2.256", "10.0.2", "::1", "2001:db8::1", " 10.0.2.1", "10.0.2.1\n",
                   "١٠.0.2.1", "10.0.2.1|x", "", None):
            with self.subTest(ip=ip):
                self.assertEqual(D.key_problem(ip, "ua", ""), "ip_format")

    def test_the_longest_key_is_305_bytes(self):
        self.assertEqual(len(D.map_key("255.255.255.255", "x" * D.MAX_UA_BYTES, SID)), 305)


class FileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "run")

    def deny_map(self, **kw):
        D.prepare_run_dir(self.dir)
        return D.DenyMap(self.dir, **kw)

    def read(self):
        with open(os.path.join(self.dir, D.DENY_FILE), encoding="ascii") as fh:
            return fh.read()

    def test_the_file_stays_one_key_line_per_entry_whatever_the_clients_send(self):
        dm = self.deny_map()
        written = []
        for n, ua in enumerate(list(HOSTILE) + list(TRICKY_BUT_WRITABLE)):
            ip = f"10.0.{2 + n // 200}.{n % 200 + 1}"
            status, detail = dm.add(ip, ua, SID if n % 2 else "", 1000.0)
            if ua in TRICKY_BUT_WRITABLE:
                self.assertEqual(status, "added", ua)
                written.append(f"{ip}|{ua}|{SID if n % 2 else ''}")
            else:
                self.assertEqual((status, detail), ("refused", HOSTILE[ua]), ua)
        dm.write()
        text = self.read()
        lines = text.splitlines(keepends=True)
        self.assertEqual(len(lines), len(written))
        for ln in lines:
            self.assertTrue(ln.endswith("\n"))
            self.assertRegex(ln[:-1], f"^{D.LINE_RE.pattern}$")
        parsed = nginx_directives(text)
        self.assertEqual(sorted(parsed), sorted([k, "1"] for k in written))
        self.assertTrue(all(k[0].isdigit() for k, _v in parsed))          # never a ~ regex, never a special word

    def test_keys_that_differ_only_in_case_are_one_entry(self):
        # nginx lower-cases the keys of a map and refuses a map that lists one twice ("conflicting parameter").
        dm = self.deny_map()
        status, first = dm.add(IP, "Bot/1.0", "", 1.0)
        self.assertEqual(status, "added")
        self.assertEqual(dm.add(IP, "bot/1.0", "", 2.0), ("present", first))
        self.assertEqual(dm.add(IP, "BOT/1.0", SID, 3.0)[0], "added")          # another sid: another key
        dm.write()
        keys = [k for k, _v in nginx_directives(self.read())]
        self.assertEqual(len(keys), len({k.lower() for k in keys}))
        self.assertEqual(len(keys), 2)

    def test_at_most_2000_active_denies(self):
        dm = self.deny_map()
        for n in range(D.MAX_DENIES):
            self.assertEqual(dm.add(f"10.1.{n // 250}.{n % 250 + 1}", "ua", "", 1.0)[0], "added")
        self.assertEqual(dm.add("10.9.9.9", "ua", "", 1.0), ("capped", None))
        self.assertEqual(len(dm), 2000)
        dm.write()
        self.assertEqual(len(nginx_directives(self.read())), 2000)

    def test_an_entry_expires_strictly_after_the_ttl(self):
        dm = self.deny_map()
        self.assertEqual(D.DENY_TTL_S, 300)
        dm.add(IP, "a", "", 1000.0)
        dm.add(IP, "b", "", 1100.0)
        dm.loaded(1005.0)
        self.assertFalse(dm.dirty)
        self.assertEqual(dm.expire(1300.0), [])
        self.assertFalse(dm.dirty)
        [gone] = dm.expire(1300.5)
        self.assertEqual((gone.ua, gone.t_added, gone.t_loaded), ("a", 1000.0, 1005.0))
        self.assertTrue(dm.dirty)
        self.assertEqual([e.ua for e in dm], ["b"])
        dm.add(IP, "c", "", 1301.0)
        dm.loaded(1302.0)
        self.assertEqual({e.ua: e.t_loaded for e in dm}, {"b": 1005.0, "c": 1302.0})
        self.assertEqual(sorted(e.ua for e in dm.clear()), ["b", "c"])
        dm.write()
        self.assertEqual(self.read(), "")

    def test_the_file_is_replaced_atomically(self):
        dm = self.deny_map()
        path = os.path.join(self.dir, D.DENY_FILE)
        before = os.stat(path).st_ino
        dm.add(IP, "a", "", 1.0)
        dm.write()
        self.assertNotEqual(os.stat(path).st_ino, before)
        self.assertEqual(self.read(), f'"{IP}|a|" 1;\n')
        dm.add(IP, "b", "", 1.0)
        with mock.patch.object(D.os, "replace", side_effect=OSError(28, "No space left on device")), \
                self.assertRaises(OSError):
            dm.write()
        self.assertEqual(self.read(), f'"{IP}|a|" 1;\n')                  # the old map, whole
        self.assertEqual(os.listdir(self.dir), [D.DENY_FILE])              # no temporary file left

    def test_the_run_directory_is_private_to_the_daemon(self):
        path = D.prepare_run_dir(self.dir)
        self.assertEqual((path, self.read()), (os.path.join(self.dir, D.DENY_FILE), ""))
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        with open(path, "w", encoding="ascii") as fh:
            fh.write(f'"{IP}|a|" 1;\n')
        D.prepare_run_dir(self.dir)                                        # an existing map is left alone
        self.assertEqual(self.read(), f'"{IP}|a|" 1;\n')
        os.chmod(self.dir, 0o777)
        with self.assertRaises(ValueError):
            D.prepare_run_dir(self.dir)
        os.chmod(self.dir, 0o700)
        with self.assertRaises(ValueError):
            D.prepare_run_dir(path)                                        # not a directory


if __name__ == "__main__":
    unittest.main()

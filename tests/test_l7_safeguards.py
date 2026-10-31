"""The L7 v2 enforcing arm's safeguards (docs/L7V2_DESIGN.md 9.3): the kill switch, the rate caps, and no deny outliving
its daemon. On the arm with fakes (tests/test_l7_enforce.py's), and in the daemon (tests/daemon_harness.py), where the
kill switch must lift the arm's XDP bans and leave every other engine's alone. Offline."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)
import test_daemon_l7_enforce as DE
import test_l7_enforce as T

import l7_denymap as D
import l7_enforce as A

BOT, UA, SID = T.BOT, T.UA, T.SID


class KillSwitchTest(T.ArmCase):
    def setUp(self):
        super().setUp()
        self.kill = False
        self.lifted = []
        self.arm.killed = lambda: self.kill
        self.arm.lift = lambda bans: self.lifted.append(list(bans)) or [ip for ip, _t in bans]

    def test_it_stops_new_actions_empties_the_map_with_one_reload_and_lifts_the_arms_bans(self):
        self.see(start=990.0)
        self.arm.submit(T.would_ban())
        self.step(1010.0)
        self.see(start=1040.0)
        self.see(ip="10.0.17.6", start=1035.0)
        self.arm.submit(T.would_ban(ip="10.0.17.6"))                    # 6 s old: waits for the key-age gate
        self.step(1041.0)                                              # level 2 for the bot
        self.assertEqual(([b["ip"] for b in self.f.bans], self.map_lines()), ([BOT], [f'"{BOT}|{UA}|{SID}" 1;']))
        self.kill = True
        self.step(1042.0)                                              # 1 s after the last reload: forced
        self.assertEqual(self.map_lines(), [])
        self.assertEqual(self.f.reloads, [1010.0, 1042.0])
        self.assertEqual(self.lifted, [[(BOT, 1041.0)]])
        [kill] = self.f.read("l7_kill")
        self.assertEqual((kill["on"], kill["denies"], kill["bans_lifted"]), (True, 1, [BOT]))
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["kill"])
        skipped = [(s["reason"], s["ip"]) for s in self.f.read("l7_enforce_skip")]
        self.assertIn(("killed", "10.0.17.6"), skipped)                 # the decision that waited is dropped
        self.arm.submit(T.would_ban(ip="10.0.17.6"))
        self.see(start=1060.0)
        for t in (1050.0, 1070.0, 1090.0):
            self.step(t)
        self.assertEqual(self.f.read("l7_enforce_skip")[-1]["reason"], "killed")
        self.assertEqual((len(self.f.bans), self.f.read("l7_deny")[1:], len(self.f.reloads)), (1, [], 2))
        self.kill = False
        self.step(1100.0)
        self.assertEqual([k["on"] for k in self.f.read("l7_kill")], [True, False])
        self.arm.submit(T.would_ban(ip="10.0.17.6"))
        self.step(1101.0)
        self.assertEqual(len(self.f.read("l7_deny")), 2)                # new actions again

    def test_a_kill_reload_waits_for_the_spacing_and_a_failed_one_is_retried(self):
        self.see(start=990.0)
        self.arm.submit(T.would_ban())
        self.step(1010.0)
        self.kill = True
        self.step(1011.0)                                              # emptied now, reloaded when the spacing allows
        self.step(1015.0)
        self.assertEqual((self.map_lines(), self.f.reloads), ([f'"{BOT}|{UA}|{SID}" 1;'], [1010.0]))
        self.f.reload_ok = False
        self.step(1020.0)
        self.f.reload_ok = True
        self.step(1025.0)
        self.step(1030.0)
        self.assertEqual(self.f.reloads, [1010.0, 1020.0, 1030.0])
        self.assertEqual([(r["ok"], r["entries"]) for r in self.f.read("l7_reload")],
                         [(True, 1), (False, 0), (True, 0)])

    def test_a_flapping_kill_file_reloads_at_most_once_per_10_s(self):
        # T-042 E04: the file toggled every second for a minute, new decisions in between
        for n in range(60):
            self.see(ip=f"10.0.60.{n + 1}", start=900.0)
        for n in range(60):
            self.kill = n % 2 == 1
            self.arm.submit(T.would_ban(ip=f"10.0.60.{n + 1}", t=1000.0 + n))
            self.step(1000.0 + n)
        gaps = [b - a for a, b in zip(self.f.reloads, self.f.reloads[1:])]
        self.assertGreaterEqual(min(gaps), 10.0)
        self.assertLessEqual(len(self.f.reloads), 6)
        self.assertGreaterEqual(len(self.f.read("l7_kill")), 59)


class CapsTest(T.ArmCase):
    def test_at_most_20_level_2_bans_in_any_60_s_beyond_them_capped_and_tried_again(self):
        ips = [f"10.0.20.{n}" for n in range(1, 26)]
        for ip in ips:
            self.see(ip=ip, start=990.0)
            self.arm.submit(T.would_ban(ip=ip))
        self.step(1010.0)
        for ip in ips:
            self.see(ip=ip, start=1040.0)
        self.step(1041.0)
        self.assertEqual(len(self.f.bans), A.MAX_LEVEL2_PER_MIN)
        self.step(1100.9)                                              # 59.9 s later: still 20 in the last minute
        capped = self.f.read("l7_enforce_capped")
        self.assertEqual([(c["what"], c["n"], c["cap"], c["level"]) for c in capped], [("ban", 5, 20, 2)] * 2)
        self.assertEqual(capped[0]["ips"], sorted(ips[20:]))
        self.step(1101.0)
        self.assertEqual(sorted(b["ip"] for b in self.f.bans), sorted(ips))

    def test_at_most_2000_denies_beyond_them_capped(self):
        self.arm.denies = D.DenyMap(self.run_dir, cap=2)
        for n in range(3):
            self.see(ip=f"10.0.21.{n}", start=990.0)
            self.arm.submit(T.would_ban(ip=f"10.0.21.{n}"))
        self.step(1010.0)
        [c] = self.f.read("l7_enforce_capped")
        self.assertEqual((c["what"], c["cap"], c["active"], c["ip"], c["level"]), ("deny", 2, 2, "10.0.21.2", 1))
        self.assertEqual((len(self.map_lines()), len(self.f.read("l7_deny"))), (2, 2))
        self.assertEqual(D.MAX_DENIES, 2000)


class LifetimeTest(T.ArmCase):
    def test_a_map_left_by_an_earlier_daemon_is_emptied_at_start_with_one_reload(self):
        with open(os.path.join(self.run_dir, D.DENY_FILE), "w", encoding="ascii") as fh:
            fh.write(f'"{BOT}|{UA}|" 1;\n"10.0.17.6|x|" 1;\n')
        self.f.now = 500.0
        self.arm.start(500.0)
        self.assertEqual((self.map_lines(), self.f.reloads), ([], [500.0]))
        [r] = self.f.read("l7_reload")
        self.assertEqual((r["ok"], r["entries"], r["changes"]), (True, 0, 2))
        self.f.now = 501.0
        self.arm.start(501.0)                                          # an empty map: nothing to do
        self.assertEqual(self.f.reloads, [500.0])

    def test_the_map_is_emptied_when_the_daemon_stops(self):
        self.see(start=990.0)
        self.arm.submit(T.would_ban())
        self.step(1010.0)
        self.f.now = 1012.0
        self.arm.stop(1012.0)                                          # 2 s after the last reload: forced
        self.assertEqual((self.map_lines(), self.f.reloads), ([], [1010.0, 1012.0]))
        self.assertEqual([e["reason"] for e in self.f.read("l7_deny_end")], ["stop"])


class DaemonKillTest(DE.L7Case):
    def test_the_kill_file_lifts_the_arms_bans_and_no_other_engines(self):
        d = self.daemon(**DE.ENFORCE)
        kill = os.path.join(d._tmp.name, "kill")
        d.ns["L7_KILL_FILE"] = kill
        d.call("l7_enforce_init")
        d.call("ban_ip", "10.0.2.1", reason="Per-IP SYN flood (300 SYN/s)", engine="l4_syn")
        d.call("ban_ip", "10.0.3.1", reason="Per-connection slow rule (6 connections closed in 60 s)",
               engine="l4_slowconn_pc")
        self.shadow(d, DE.bot(), until=1100.0)
        self.assertEqual(d.banned_ips, {"10.0.2.1", "10.0.3.1", DE.BOT})
        with open(kill, "w", encoding="ascii"):
            pass
        reloads = len(d.proc.matching("nginx"))
        d.call("l7_enforce_poll")
        self.assertEqual(d.banned_ips, {"10.0.2.1", "10.0.3.1"})
        self.assertEqual(d.blacklist.ips(), {"10.0.2.1", "10.0.3.1"})
        self.assertNotIn(DE.BOT, d.ban_timestamps)
        [unban] = d.events("unban")
        self.assertEqual((unban["ip"], unban["lifted_by"], unban["backend"]), (DE.BOT, "l7_kill", "xdp"))
        self.assertEqual(len(d.proc.matching("nginx")), reloads + 1)
        self.assertEqual(self.map_lines(d), [])
        self.assertEqual(d.L7_KILL_FILE, kill)
        self.assertEqual(self.daemon().L7_KILL_FILE, self.daemon().SLOW_PC_KILL_FILE)   # one file stops both

    def test_a_ban_another_engine_made_since_is_not_lifted(self):
        d = self.daemon(**DE.ENFORCE)
        d.call("l7_enforce_init")
        d.call("ban_ip", DE.BOT, reason="r", engine="l4_syn")
        self.assertEqual(d.call("l7_lift_bans", [(DE.BOT, 12.0), ("10.0.9.9", 1.0), ("10.0.9.8", None)]), [])
        self.assertEqual((d.banned_ips, d.events("unban")), ({DE.BOT}, []))

    def test_the_daemons_stop_empties_the_map_after_detaching_xdp(self):
        from test_daemon_robustness import MainRun
        d = self.daemon(**DE.ENFORCE)
        main = MainRun(d)
        order = []
        main.bpf.remove_xdp = lambda dev, flags: order.append("xdp")
        d.proc.failures = {}
        real = d.proc.run

        def run(argv, **kw):
            if argv[:1] == ["nginx"]:
                order.append("reload")
            return real(argv, **kw)
        d.proc.run = run

        def tailer(_path):
            d.l7_arm.denies.add(DE.BOT, DE.BOT_UA, DE.SID, 1000.0)
            d.stop_event.set()
            return
            yield                                                       # a generator, like the real one
        main.run(tailer)
        self.assertEqual(order, ["xdp", "reload"])
        self.assertEqual(self.map_lines(d), [])
        self.assertEqual([e["reason"] for e in d.events("l7_deny_end")], [])   # added behind the arm's back
        self.assertEqual([r["entries"] for r in d.events("l7_reload")], [0])


class StopRaceTest(T.ArmCase):
    """T-042 E03: the daemon's stop runs while the arm's thread may be in a step; after stop() returns the map must be
    empty. The review's probe found 65 of 300 trials with a non-empty map; the same shape, seeded."""

    def test_after_stop_returns_the_map_is_empty_300_trials(self):
        import random
        import threading
        import time
        rng = random.Random(42)
        for trial in range(300):
            with self.subTest(trial=trial):
                self.setUp()
                for n in range(60):
                    self.see(ip=f"10.0.50.{n + 1}", start=900.0)
                self.arm.reload = lambda: (time.sleep(rng.random() * 0.0005), (True, ""))[1]
                done = threading.Event()

                def stepper(arm=self.arm, done=done):
                    for n in range(60):
                        if done.is_set():
                            break
                        arm.submit(T.would_ban(ip=f"10.0.50.{n + 1}", t=1000.0 + 11 * n))
                        arm.step(1000.0 + 11 * n)
                thread = threading.Thread(target=stepper)
                thread.start()
                time.sleep(rng.random() * 0.002)
                self.arm.stop(5000.0)
                done.set()
                thread.join()
                self.assertEqual((self.map_lines(), len(self.arm.denies)), ([], 0))


if __name__ == "__main__":
    unittest.main()

"""A fake host for eval/p1_runner.py, on tests/p4_fake_host.py's clock and processes. Nothing here touches the machine.

What it models, as far as the runner's and the analysis's inputs need it:
  * nginx: the run's own conf is read for its file sink and its socket sink (T050-01); every generator's requests, and each second a
    monitoring line and one from the plan's first benign address, go to that sink, in completion order, when nginx stops (`quiet_from`
    silences the monitoring and the clients from then on);
  * a generator exits 0 at the end of its duration (`gen_code` for the addresses in `gen_fails`), and 1, as the real one does, if it
    cannot write its --stats file (T050-02). A benign plan kind writes
    its client-side rows and its requests from its own plan (ml/l7_benign.plan_client with its seed); an attack family its
    requests (ml/l7_bots.plan_bot); a kind without a plan one line. A request is answered 200 in 30 ms, except a share
    `fail_share(run, block_dir, t)` of the benign ones, which fail (nginx logs a 503, so the server-side Q agrees);
  * the daemon: `daemon_startup_s` after its start it prints its ready line and XDP's and writes its start event from its
    environment (`start_overrides` to make it lie), with L7_ENFORCE=1 an l7_enforce_arm event (`arm_overrides`), and then the events
    `acts(run, block_dir)` gives as (seconds after its start, event). When it stops, with L7_SHADOW=1, an l7_shadow report: what it received
    and parsed is what the socket sink carried, every line if nginx's conf has the sink, `parsed_share` of them, and nothing if it has none;
  * an address in `silent` sends nothing, whatever its generator says (T050-08);
  * the timer probe of bench/executor.py answers with `timer_p99`, a value or a list taken in turn, the last one repeating.
frozen_inputs() writes the frozen items a campaign checks: a frozen record with the placeholder's numbers, knees bound to it,
and small but well-formed selections. They are fixtures, not results.
"""
import csv
import hashlib
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
for _p in (HERE, REPO, os.path.join(REPO, "ml"), os.path.join(REPO, "bench"), os.path.join(REPO, "eval")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import calibration_fixtures
import l7_benign
import l7_bots
import l7_gen
import p4_fake_host as F

import l7_webapp

SINK = re.compile(r"access_log\s+(\S+)\s+l7json;")
SOCKET_SINK = "syslog:server=unix:"
MONITOR = "10.0.0.1"


def _sid(seed, user):
    return hashlib.md5(f"{seed}|{user}".encode()).hexdigest()        # a fixture's id, 32 hex digits


class P1FakeHost(F.FakeHost):
    def __init__(self, *, fail_share=None, acts=None, quiet_from=None, armed=True, start_overrides=None, arm_overrides=None,
                 rule_arm="cost_budget", parsed_share=1.0, silent=(), timer_p99=2.0, **kw):
        super().__init__(**kw)
        self.fail_share = fail_share or (lambda _run, _block, _t: 0.0)
        self.acts, self.quiet_from = acts or (lambda _run, _block: []), quiet_from
        self.armed, self.start_overrides, self.arm_overrides = armed, dict(start_overrides or {}), dict(arm_overrides or {})
        self.rule_arm, self.parsed_share, self.silent = rule_arm, parsed_share, set(silent)
        self.socket_sink, self.heartbeat = False, None
        self.timer_p99 = list(timer_p99) if isinstance(timer_p99, (list, tuple)) else [timer_p99]
        self.sink, self.lines, self.run_name, self.block_dir, self.n_request = None, [], None, None, 0

    def run(self, argv, ns="", stdin="", env=None, timeout=None):
        argv = list(argv)
        if "timer-probe" in argv:
            p99 = self.timer_p99.pop(0) if len(self.timer_p99) > 1 else self.timer_p99[0]
            return F.X.Result(0, "" if p99 is None else json.dumps({"p50_ms": 1.0, "p99_ms": p99, "max_ms": p99 + 1.0}), "")
        if "nginx" in argv and "-s" not in argv:
            conf = argv[argv.index("nginx") + 2]
            with open(conf, encoding="utf-8") as fh:
                text = fh.read()
            found = SINK.findall(text)
            self.sink = found[0] if found else None
            self.socket_sink = SOCKET_SINK in text
            self.run_name, self.block_dir = os.path.basename(os.path.dirname(conf)), os.path.dirname(os.path.dirname(conf))
            with open(os.path.join(os.path.dirname(conf), "plan.json"), encoding="utf-8") as fh:
                benign = [e["address"] for e in json.load(fh)["entities"] if e["role"] == "benign"]
            self.heartbeat = benign[0] if benign else None
            self.lines, self.n_request = [], 0
            res = super().run(argv, ns, stdin, env, timeout)
            self.stack_t0 = self.t
            self._monitor(self.world)
            return res
        if "nginx" in argv and "quit" in argv and self.sink:
            self.lines.sort(key=lambda o: o["msec"])
            with open(self.sink, "w", encoding="utf-8") as fh:
                fh.writelines(json.dumps(o) + "\n" for o in self.lines)
            return F.X.Result(0, "", "")
        return super().run(argv, ns, stdin, env, timeout)

    def pin(self, cpus):
        self.pinned = cpus

    def _quiet(self, t):
        return self.quiet_from is not None and t - self.stack_t0 >= self.quiet_from

    def _monitor(self, world):
        if world != self.world:
            return
        if not self._quiet(self.t):
            self._line(MONITOR, "curl", "/", F.BASE_EPOCH + self.t, 200, None)
            if self.heartbeat:
                self._line(self.heartbeat, "curl", "/", F.BASE_EPOCH + self.t, 200, None)
        self.at(self.t + 1.0, lambda: self._monitor(world))

    def _line(self, ip, ua, path, sent, status, sid, ref=None):
        self.lines.append({"msec": round(sent + 0.03, 6), "rt": 0.03, "ip": ip, "port": 40000, "conn": 1, "creq": 2, "method": "GET",
                           "uri": path, "status": status, "ua": ua, "ref": ref or "", "sid": sid or "", "lreq": "", "lconn": "",
                           "compl": "OK", "proto": "HTTP/1.1", "rlen": 100, "bsent": 500, "urt": "0.02", "reused": "."})

    # --- generators ------------------------------------------------------------------------------
    def _start_gen(self, p):
        if self.run_t0 is None:
            self.run_t0 = self.t
        a = p.argv
        p.role, p.ip, p.port = F._opt(a, "--role"), F._opt(a, "--source"), int(F._opt(a, "--port"))
        p.name = F._opt(a, "--kind") or F._opt(a, "--family")
        p.params, p.seed, p.dur = json.loads(F._opt(a, "--params")), int(F._opt(a, "--seed")), float(F._opt(a, "--duration"))
        p.records, p.start, p.world = F._opt(a, "--records"), self.t, self.world
        code = self.gen_code if p.ip in self.gen_fails else 0
        self.at(self.t + p.dur + 0.5, lambda: self.end(p, self._stats_code(a, code)))

    @staticmethod
    def _stats_code(argv, code):
        """The real generator writes --stats at its exit: FileNotFoundError, exit 1, when the runner made no directory for it."""
        path = F._opt(argv, "--stats") if "--stats" in argv else None
        if path is None:
            return code
        if not os.path.isdir(os.path.dirname(path)):
            return 1
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        return code

    def end(self, proc, code):
        if proc.kind == "daemon" and proc.returncode is None and proc.env.get("L7_SHADOW") == "1":
            n = round(len(self.lines) * self.parsed_share) if self.socket_sink else 0
            self._emit(proc, "l7_shadow", received=n, parsed=n, active_keys=1, distinct_ips=1)
        super().end(proc, code)

    def _gen_exit(self, p):
        if p.ip in self.silent:
            return
        if p.role == "attack":
            self._requests(p, l7_bots.plan_bot(p.name, p.params, p.dur, random.Random(p.seed)), None)
        elif p.records:
            os.makedirs(os.path.dirname(p.records), exist_ok=True)
            with open(p.records, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(l7_gen.RECORD_COLUMNS)
                self._requests(p, l7_benign.plan_client(p.name, p.params, p.dur, random.Random(p.seed)), w)
        elif not self._quiet(p.start + 60.0):
            self._line(p.ip, "curl/8", "/", F.BASE_EPOCH + p.start + 60.0, 200, None)

    def _requests(self, p, plan, writer):
        origin = F.BASE_EPOCH + p.start
        for u, user in enumerate(plan["users"]):
            items = []
            if "views" in user:
                for vi, v in enumerate(user["views"]):
                    for wi, wave in enumerate(v["waves"]):
                        items += [(v["t"] + 0.05 * wi, vi, wi, path, v.get("ref") if wi == 0 else v.get("doc")) for path in wave]
            else:
                t = 0.0
                for vi, (path, gap, *rest) in enumerate(user["requests"]):
                    items.append((t, vi, 0, path, rest[0] if rest else None))
                    t += gap
            sid, paged = _sid(p.seed, u), False
            for t_nom, vi, wi, path, ref in items:
                if t_nom >= p.dur or self._quiet(p.start + t_nom):
                    continue
                self.n_request += 1
                share = self.fail_share(self.run_name, self.block_dir, p.start + t_nom - self.stack_t0) if writer else 0.0
                bad = (self.n_request * 0.6180339887) % 1.0 < share
                sent = origin + t_nom
                klass = l7_webapp.route_class("GET", path)
                paged = paged or klass == "C1"
                self._line(p.ip, user["ua"], path, sent, 503 if bad else 200, sid if paged else None, ref)
                if writer:
                    writer.writerow([f"{sent:.6f}", f"{sent:.6f}", f"{sent + (0.1 if bad else 0.03):.6f}",
                                     "nan" if bad else 200, "conn" if bad else "", klass or "", u, vi, wi,
                                     f"{sent:.6f}", f"{origin:.6f}"])

    # --- the daemon ------------------------------------------------------------------------------
    def _start_daemon(self, p):
        def ready():
            if p.returncode is not None:
                return
            p.stdout.write("[+] Successfully attached XDP program to interface veth_server.\n"
                           "[*] Listening for Nginx logs (heuristic engine): /var/log/nginx/ddos_ml_access.log\n")
            p.stdout.flush()
            start = {"heuristic_profile": p.env.get("HEURISTIC_PROFILE"), "l7_enforce": p.env.get("L7_ENFORCE") == "1",
                     "l7_shadow": p.env.get("L7_SHADOW") == "1", "l7_arm": p.env.get("L7_ARM") or None,
                     "l7_selection_sha256": p.env.get("L7_SELECTION_SHA256") or None, **self.start_overrides}
            self._emit(p, "start", **start)
            if p.env.get("L7_ENFORCE") == "1":
                self._emit(p, "l7_enforce_arm", **{"armed": self.armed, "reason": None if self.armed else "fixture says no",
                                                   "arm": p.env.get("L7_ARM"), "selection_sha256": p.env.get("L7_SELECTION_SHA256"),
                                                   **({"rule_arm": self.rule_arm} if p.env.get("L7_ARM") == "R*" else {}),
                                                   **self.arm_overrides})
            for t, ev in self.acts(self.run_name, self.block_dir):
                self.at(self.t + t, lambda ev=ev: p.returncode is None and self._emit(p, ev["kind"], **{
                    k: v for k, v in ev.items() if k != "kind"}))
        self.at(self.t + self.daemon_startup_s, ready)
        if self.daemon_dies_at is not None:
            self.at(self.t + self.daemon_dies_at, lambda: self.end(p, 1))


def thin_benign(counts=None):
    """A small benign mix with one or a few entities of each kind that records, for whole blocks on the fake."""
    import l7_pools as LP
    counts = counts or {"tpcw_browsing": 6, "search_user": 3, "exporter": 1, "crawler_polite": 1, "curl_oneshot": 1,
                        "tpcw_shopping": 1, "zipf_browser": 1, "flash_crowd": 1, "api_bulk": 1, "cgnat_browsers": 1}
    out, seen = [], {}
    for s in LP.POPULATIONS["l7v2"]["benign"]:
        n = counts.get(s["kind"], 0)
        if n and s["kind"] not in seen:
            seen[s["kind"]] = True
            out.append(dict(s, count=n))
    return out


def frozen_inputs(d, *, record_status="frozen", knees=None, valid=True):
    """The frozen items of a campaign under directory `d`: {calibration, knees, health, selection, selection_sha256, rules,
    rules_sha256}. The health file freezes no halving; the selections are well-formed (formats, artifacts, operating points);
    nothing is trained."""
    import l7v2_rules as R
    import train_l7v2 as V
    os.makedirs(d, exist_ok=True)
    rec = calibration_fixtures.frozen() if record_status == "frozen" else calibration_fixtures.placeholder()
    cal = os.path.join(d, "record.json")
    with open(cal, "w", encoding="utf-8") as fh:
        json.dump(rec, fh)
    knee_path = os.path.join(d, "knees.json")
    with open(knee_path, "w", encoding="utf-8") as fh:
        json.dump({"benign_halvings": 0, **(knees or {"status": "frozen", "record_sha256": rec["sha256"], "C2": 4.0, "C3a": 1.0,
                                                      "C3b": 50})}, fh)
    health_path = os.path.join(d, "health.json")
    with open(health_path, "w", encoding="utf-8") as fh:
        json.dump({"format": "p1-health/1", "record_sha256": rec["sha256"], "decision": "frozen", "benign_halvings": 0,
                   "why": "fixture", "steps": []}, fh)
    sel_dir, rule_dir = os.path.join(d, "sel"), os.path.join(d, "rules")
    os.makedirs(os.path.join(rule_dir, "rules"), exist_ok=True)
    os.makedirs(sel_dir, exist_ok=True)

    def artifact(name, text="fixture\n"):
        path = os.path.join(sel_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return {"artifact": name, "artifact_sha256": V._sha_file(path)}

    def point(recall):
        return {"threshold": 0.9, "consecutive": 2, "recall": recall, "caught": 8, "attack_entities": 10}

    sel = {"format": V.SEL_FORMAT, "source": "fixture", "valid_for_claims": valid, "arms": {
               "view_gru": {**artifact("view_gru.bin"), "operating_point": point(0.9)},
               "hgb": {**artifact("hgb.pkl"), "operating_point": point(0.6)},
               "gru_shuffled": {**artifact("view_gru2.bin"), "operating_point": point(0.9)}},
           "baselines": {"age_only": {**artifact("age_only.json", json.dumps({"benign_train_ages": [1.0, 2.0]})),
                                      "operating_point": point(0.1), "val_auc": 0.52, "reading": "near chance"}}}
    sel_path = os.path.join(sel_dir, "selection.json")
    with open(sel_path, "w", encoding="utf-8") as fh:
        json.dump(sel, fh)
    costs = rec["route_costs_ms"]
    cal_block = {"sha256": rec.get("sha256"), "status": rec["status"]}
    op = {"params": {"window_s": 60, "level": "q_0.995"}, "columns": ["key:cost_60"], "thresholds": [400.0], "threshold": 0.5,
          "consecutive": 3, "caught": 8, "benign_units_flagged": 0, "median_ttd_s": 30.0, "recall": 0.8}
    pkg = R.make_package("cost_budget", op, costs, cal_block)
    pkg_path = os.path.join(rule_dir, "rules", "cost_budget.json")
    R.save_package(pkg_path, pkg)
    arms = {"cost_budget": {"operating_point": op, "artifact": "rules/cost_budget.json", "artifact_sha256": V._sha_file(pkg_path)}}
    rules = {"format": R.SELECTION_FORMAT, "valid_for_claims": valid, "calibration": cal_block, "arms": arms,
             "r_star": "cost_budget", "source": "fixture"}
    rules_path = os.path.join(rule_dir, "rules_selection.json")
    with open(rules_path, "w", encoding="utf-8") as fh:
        json.dump(rules, fh)
    points_path = os.path.join(d, "points.json")
    with open(points_path, "w", encoding="utf-8") as fh:
        json.dump({"format": "p1-points/1", "record_sha256": rec["sha256"], "selection_sha256": V._sha_file(sel_path),
                   "rules_sha256": V._sha_file(rules_path), "benign_halvings": 0, "status": "pass", "over_budget": [],
                   "missing_seeds": []}, fh)
    return {"calibration": cal, "knees": knee_path, "health": health_path, "points": points_path, "selection": sel_path,
            "selection_sha256": V._sha_file(sel_path),
            "rules": rules_path, "rules_sha256": V._sha_file(rules_path)}

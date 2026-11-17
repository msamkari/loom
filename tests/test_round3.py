"""Regression tests for the 0.1.2 fix batch (round-3 trust-model and operator-misuse reports).

Everything runs in temp folders with LOOM_HOME relocated. No sleeps; no real C: paths; the
Windows-only checks are guarded."""
import json
import os
import shutil
import subprocess
import sys
import unittest

from helpers import Base, demo_config, loom, SCRIPT, HERE
from test_adapters import AdapterBase

ROOT = os.path.dirname(HERE)
CHECK = "import io\nio.open('ran.txt','a').write('x')\n"


def cfg_with(argv, **extra):
    c = demo_config()
    c["formats"]["demo"]["stages"][0]["checks"] = [dict(type="command", argv=argv, **extra)]
    return c


def read(rel):
    with open(os.path.join(ROOT, *rel.split("/")), "rb") as f:
        return f.read().decode("utf-8")


class PinContentTests(Base):
    """L-H1: the pin covers the content of the scripts and -m modules that a command runs."""

    def setUp(self):
        super().setUp()
        self.auto_trust = False

    def project(self, argv):
        self.make_project(cfg_with(argv))
        self.add_item("ep1")

    def ran(self):
        return self.r("ran.txt") if self.exists("ran.txt") else ""

    def test_editing_a_pinned_script_makes_gate_refuse_until_trust(self):
        self.project(["{python}", "tools/check.py", "{item}"])
        self.w("tools/check.py", CHECK)
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.assertEqual(self.ran(), "x")
        self.w("tools/check.py", CHECK + "# changed\n")
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("tools/check.py", e)
        self.assertNotIn("--yes", e)
        self.assertEqual(self.ran(), "x")  # the edited script never ran
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.assertEqual(self.ran(), "xx")

    def test_module_run_with_m_is_pinned_and_so_is_its_absence(self):
        self.project(["{python}", "-m", "lintmod"])
        self.w("lintmod.py", CHECK)
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.w("lintmod.py", CHECK + "# changed\n")
        self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2)
        self.assertEqual(self.ran(), "x")
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.w("lintmod/__init__.py", CHECK)  # a package planted next to the module
        self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2)

    def test_absence_of_a_project_file_for_a_stdlib_module_is_pinned(self):
        self.project(["{python}", "-m", "json.tool", "-h"])
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.w("json/__init__.py", "import io\nio.open('ran.txt','a').write('P')\n")
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertEqual(self.ran(), "")

    def test_attached_option_forms_do_not_skip_pinning(self):
        self.w("lintmod.py", CHECK)
        self.w("tools/check.py", CHECK)
        for argv, key in ((["{python}", "-Bm", "lintmod"], "lintmod.py"),
                          (["{python}", "-mlintmod"], "lintmod.py"),
                          (["{python}", "-B", "-u", "tools/check.py"], "tools/check.py"),
                          (["{python}", "-X", "utf8", "-W", "ignore", "tools/check.py"], "tools/check.py"),
                          (["{python}", "--", "tools/check.py"], "tools/check.py")):
            e = loom.pin_entries(self.root, cfg_with(argv))
            hit = [x for x in e if x["label"].startswith("gate demo/script")][0]
            self.assertIn(key, hit["files"], argv)
            self.assertIsNotNone(hit["files"][key], argv)
            self.assertEqual(hit["problems"], [], argv)

    def test_unknown_interpreter_options_cannot_be_pinned(self):
        for argv in (["{python}", "--foo", "x.py"], ["{python}", "-Q", "x.py"], ["{python}", "-m"],
                     ["{python}", "{item}"]):
            tearDown_home = os.path.join(self.home, "trust.json")
            self.make_project(cfg_with(argv))
            rc, o, e = self.run_loom("trust", "--yes")
            self.assertEqual(rc, 2, argv)
            self.assertIn("PROBLEM", o)
            self.assertFalse(os.path.exists(tearDown_home), argv)

    def test_other_files_named_in_the_args_are_pinned(self):
        self.project(["{python}", "-c", "import sys", "tools/rules.json"])
        self.w("tools/rules.json", "{}")
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")
        self.w("tools/rules.json", '{"a": 1}')
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("tools/rules.json", e)

    def test_script_in_a_denied_folder_is_a_problem(self):
        self.project(["{python}", "private/x.py"])
        self.w("private/x.py", CHECK)
        rc, o, e = self.run_loom("trust", "--yes")
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(self.home, "trust.json")))


class PinDisplayTests(Base):
    """L-H2: the review shows every pinned argv in full, expanded, never truncated."""

    def setUp(self):
        super().setUp()
        self.auto_trust = False

    def test_named_command_payload_is_shown(self):
        c = demo_config()
        c["commands"] = {"lint": ["{python}", "-c", "print('SENTINEL_PAYLOAD_77')"]}
        c["formats"]["demo"]["stages"][0]["checks"] = [{"type": "command", "argv": ["{cmd:lint}", "--strict"]}]
        self.make_project(c)
        o = self.run_ok("trust")
        argv_lines = [ln for ln in o.splitlines() if ln.strip().startswith("argv:") and "--strict" in ln]
        self.assertTrue(argv_lines)
        self.assertIn("SENTINEL_PAYLOAD_77", argv_lines[0])
        self.assertIn("named command lint = ", o)
        self.assertIn("SENTINEL_PAYLOAD_77", [ln for ln in o.splitlines() if ln.startswith("named command")][0])

    def test_long_argv_below_the_limit_is_printed_whole(self):
        toks = ["-W" + "i" * 900 for _ in range(3)]
        argv = ["{python}"] + toks + ["-c", "print('tail_marker_9')"]
        c = cfg_with(argv)
        self.make_project(c)
        o = self.run_ok("trust")
        shown = json.dumps(loom.static_argv(argv, {}), ensure_ascii=False)
        self.assertLess(len(shown), loom.ARGV_PRINT_MAX)
        self.assertIn(shown, o)
        self.assertIn("tail_marker_9", o)

    def test_argv_over_4000_is_refused_and_says_why(self):
        toks = ["-W" + "i" * 900 for _ in range(5)]
        self.make_project(cfg_with(["{python}"] + toks + ["-c", "print('hidden_tail')"]))
        rc, o, e = self.run_loom("trust", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("refusing to pin", o)
        self.assertIn("over the 4000", o)
        self.assertFalse(os.path.exists(os.path.join(self.home, "trust.json")))


class PinDiffTests(Base):
    """B11: a pin mismatch says what changed and never suggests the flag."""

    def setUp(self):
        super().setUp()
        self.auto_trust = False
        self.make_project(cfg_with(["{python}", "tools/check.py"]))
        self.w("tools/check.py", CHECK)
        self.add_item("ep1")
        self.run_ok("trust", "--yes")

    def test_record_holds_absolute_interpreter_and_its_identity(self):
        with open(os.path.join(self.home, "trust.json"), encoding="utf-8") as f:
            d = json.load(f)
        rec = list(d["projects"].values())[0]
        e = [x for x in rec["entries"] if x["label"].startswith("gate demo/script")][0]
        self.assertTrue(os.path.isabs(e["program"]) or e["program"].startswith("/"))
        self.assertEqual(len(e["program_sha"]), 64)
        self.assertIn("tools/check.py", e["files"])
        self.assertEqual(rec["entries"][0]["argv"][0], sys.executable)

    def test_path_resolved_program_change_prints_a_diff(self):
        cfg = loom.load_config(self.root)
        orig = loom.resolved_programs
        loom.resolved_programs = lambda r, c: [(l, "/other/shell/python") for l, _ in orig(r, c)]
        try:
            with self.assertRaises(loom.Refused) as c:
                loom.require_trust(self.root, cfg, "gate")
        finally:
            loom.resolved_programs = orig
        text = " ".join([str(c.exception)] + list(c.exception.details))
        self.assertIn("program found on PATH changed", text)
        self.assertIn(os.path.normcase("/other/shell/python"), text)
        self.assertNotIn("--yes", text)
        self.assertIn("defeats the pin", text)

    def test_script_hash_and_env_and_argv_changes_are_named(self):
        self.w("tools/check.py", CHECK + "#\n")
        cfg = loom.load_config(self.root)
        with self.assertRaises(loom.Refused) as c:
            loom.require_trust(self.root, cfg, "gate")
        self.assertTrue(any("tools/check.py" in d and "content changed" in d for d in c.exception.details))
        self.w("tools/check.py", CHECK)
        cfg = cfg_with(["{python}", "tools/check.py", "extra"], env=["ABC_X"])
        self.w("loom.config.json", json.dumps(cfg))
        with self.assertRaises(loom.Refused) as c:
            loom.require_trust(self.root, loom.load_config(self.root), "gate")
        d = "\n".join(c.exception.details)
        self.assertIn("argv changed", d)
        self.assertIn("env names changed", d)

    def test_cli_refusal_lists_changes_on_separate_lines_without_the_flag(self):
        self.w("tools/check.py", CHECK + "#\n")
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertNotIn("--yes", e)
        self.assertGreater(len(e.strip().splitlines()), 1)
        rc, o, e = self.run_loom("trust")
        self.assertIn("What changed", o)
        self.assertIn("tools/check.py", o)

    def test_old_string_pin_is_refused_with_a_clear_reason(self):
        key = loom.root_key(self.root)
        with open(os.path.join(self.home, "trust.json"), "w", encoding="utf-8") as f:
            json.dump({"schema": 1, "projects": {key: "a" * 64}}, f)
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("older loom", e)
        self.assertNotIn("--yes", e)

    def test_not_trusted_message_does_not_name_the_flag(self):
        os.remove(os.path.join(self.home, "trust.json"))
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertNotIn("--yes", e)


class StructurePinTests(Base):
    """Low: the set of stages and checks is part of the pin, even for a stage without commands."""

    def setUp(self):
        super().setUp()
        self.auto_trust = False
        self.make_project(demo_config())
        self.add_item("ep1")
        self.run_ok("trust", "--yes")

    def test_removing_the_checks_of_a_stage_makes_gate_refuse(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][0]["checks"] = []
        self.w("loom.config.json", json.dumps(c))
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("settings of the config changed", e)

    def test_changing_shadow_mode_or_ttl_makes_gate_refuse(self):
        for k, v in (("shadow_mode", True), ("approval_ttl_hours", 720)):
            c = demo_config()
            c[k] = v
            self.w("loom.config.json", json.dumps(c))
            self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2, k)

    def test_unchanged_config_still_gates(self):
        self.w("Loom/items/ep1/script.md", "x")
        self.run_ok("gate", "ep1", "script")


class SystemToolTests(Base):
    """L-M1 / B1: helpers come from the Windows system folder by absolute path."""

    def test_source_never_names_a_helper_bare(self):
        src = read("scripts/loom.py")
        for bad in ('["icacls"', '["taskkill"', "'icacls'", "'taskkill'"):
            self.assertNotIn(bad, src)

    @unittest.skipUnless(os.name == "nt", "Windows helpers")
    def test_icacls_is_started_by_absolute_system_path(self):
        seen = []
        orig = subprocess.run
        subprocess.run = lambda argv, **kw: seen.append((argv, kw))
        target = os.path.join(self.tmp, "f.json")
        with open(target, "w") as f:
            f.write("{}")
        try:
            loom.private_file(target)
        finally:
            subprocess.run = orig
        argv, kw = seen[0]
        base = os.environ.get("SystemRoot") or os.environ.get("windir")
        self.assertEqual(os.path.normcase(argv[0]),
                         os.path.normcase(os.path.join(base, "System32", "icacls.exe")))
        self.assertTrue(os.path.isabs(argv[0]))
        self.assertEqual(os.path.normcase(kw.get("cwd")), os.path.normcase(os.path.dirname(argv[0])))

    @unittest.skipUnless(os.name == "nt", "Windows helpers")
    def test_missing_system_helper_refuses_before_writing(self):
        empty = os.path.join(self.tmp, "fakeroot")
        os.makedirs(os.path.join(empty, "System32"))
        for k in ("SystemRoot", "windir", "WINDIR"):
            os.environ[k] = empty
        self.make_project(demo_config())
        rc, o, e = self.run_loom("trust", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("icacls", e)
        self.assertFalse(os.path.exists(os.path.join(self.home, "trust.json")))

    @unittest.skipUnless(os.name == "nt", "Windows helpers")
    def test_taskkill_fallback_uses_absolute_path(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
        seen = []
        orig = subprocess.run
        subprocess.run = lambda argv, **kw: seen.append(argv)
        try:
            loom._kill_tree(proc, None)
        finally:
            subprocess.run = orig
            proc.kill()
            proc.wait(timeout=20)
        self.assertTrue(seen and os.path.isabs(seen[0][0]))
        self.assertTrue(seen[0][0].lower().endswith("taskkill.exe"))
        self.assertIn("system32", seen[0][0].lower())

    def test_no_helper_off_windows(self):
        if os.name != "nt":
            self.assertIsNone(loom.system_tool("icacls"))


class SpentReserveTests(AdapterBase):
    """B6: the spent record is written BEFORE the adapter runs; if it cannot be, nothing runs."""

    def pub(self):
        return self.run_loom("publish", "ep1", "--channel", "chan1")

    def appr(self):
        return self.ledger()["items"][0]["approvals"]

    def test_unwritable_spent_record_refuses_and_runs_nothing(self):
        self.ready()
        self.approve("publish")
        orig = loom.atomic_write

        def bad(path, data, bak=False):
            if os.path.basename(path) == "spent.json":
                raise PermissionError(13, "locked by a scanner")
            return orig(path, data, bak)
        loom.atomic_write = bad
        try:
            rc, o, e = self.pub()
        finally:
            loom.atomic_write = orig
        self.assertEqual(rc, 1)
        self.assertIn("refusing to run", e)
        self.assertEqual(self.log(), "")
        self.assertFalse(self.appr()[0].get("used"))
        self.assertFalse(self.appr()[0].get("claimed"))
        self.assertEqual(self.pub()[0], 0)  # once the record can be written it works, once
        self.assertEqual(self.log().count("publish ep1"), 1)

    def test_reservation_exists_while_the_adapter_runs(self):
        self.ready()
        self.approve("publish")
        sig = self.appr()[0]["sig"]
        seen = []
        orig = loom.run_command

        def fake(argv, root, spec):
            seen.append(sig in loom.spent_sigs())
            return 0, "ok", False
        loom.run_command = fake
        try:
            self.assertEqual(self.pub()[0], 0)
        finally:
            loom.run_command = orig
        self.assertEqual(seen, [True])

    def test_restored_older_ledger_cannot_publish_twice(self):
        self.ready()
        self.approve("publish")
        before = self.r("Loom/ledger.json")
        self.assertEqual(self.pub()[0], 0)
        self.w("Loom/ledger.json", before)  # a restored backup, a sync "previous version"
        rc, o, e = self.pub()
        self.assertEqual(rc, 2)
        self.assertEqual(self.log().count("publish ep1"), 1)

    def test_failed_adapter_releases_the_reservation(self):
        c = demo_config()
        c["adapters"]["publish"]["post"]["argv"] = ["{python}", "-c", "import sys;sys.exit(3)"]
        self.set_config(c)
        self.ready()
        self.approve("publish")
        sig = self.appr()[0]["sig"]
        self.assertEqual(self.pub()[0], 2)
        self.assertNotIn(sig, loom.spent_sigs())
        self.assertFalse(self.appr()[0].get("used"))

    def test_spent_file_is_keyed_by_signature_and_legacy_list_is_read(self):
        self.ready()
        self.approve("publish")
        sig = self.appr()[0]["sig"]
        with open(os.path.join(self.home, "spent.json"), "w", encoding="utf-8") as f:
            json.dump({"schema": 1, "sigs": [sig]}, f)
        rc, o, e = self.pub()
        self.assertEqual(rc, 2)
        self.assertEqual(self.log(), "")
        os.remove(os.path.join(self.home, "spent.json"))
        self.assertEqual(self.pub()[0], 0)
        with open(os.path.join(self.home, "spent.json"), encoding="utf-8") as f:
            d = json.load(f)
        self.assertIsInstance(d["sigs"], dict)
        self.assertIn(sig, d["sigs"])

    def test_old_entries_are_pruned_by_age_not_by_count(self):
        os.environ["LOOM_NOW"] = "2026-11-01T00:00:00Z"
        loom.write_home_json("spent.json", {"schema": 2, "sigs": {}})
        old, new = "a" * 64, "b" * 64
        loom.spent_write({old: "2026-01-01T00:00:00Z", new: "2026-10-30T00:00:00Z", "c" * 64: None})
        cur = loom.spent_load()
        self.assertNotIn(old, cur)
        self.assertIn(new, cur)
        self.assertIn("c" * 64, cur)  # legacy entry: kept, retention starts now
        many = dict(("%064x" % i, "2026-10-30T00:00:00Z") for i in range(4500))
        loom.spent_write(many)
        self.assertEqual(len(loom.spent_load()), 4500)

    def test_advance_approval_is_reserved_and_replay_refused(self):
        self.to_stage("ep1", "voice")
        self.w("Loom/items/ep1/pre_voice.md", "- [x] ok\n")
        self.run_ok("gate", "ep1", "voice")
        self.approve("advance:voice", channel="none")
        sig = self.appr()[0]["sig"]
        self.run_ok("advance", "ep1")
        self.assertIn(sig, loom.spent_sigs())


class LockOwnerTests(Base):
    """B2 (and B3): a reused pid does not keep a stale lock alive; the message is honest."""

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.root, "Loom"))
        self.lp = os.path.join(self.root, "Loom", loom.LOCK_NAME)
        self.host = loom.Lock(self.root).host
        os.environ["LOOM_LOCK_TIMEOUT"] = "0.2"
        os.environ["LOOM_LOCK_STALE"] = "5"

    def make_lock(self, age, **owner):
        os.mkdir(self.lp)
        rec = {"token": "x", "pid": os.getpid(), "host": self.host}
        rec.update(owner)
        with open(os.path.join(self.lp, "owner"), "w") as f:
            f.write(json.dumps(rec))
        t = loom.time.time() - age
        os.utime(self.lp, (t, t))

    def test_proc_start_is_stable_for_a_live_process(self):
        s = loom.proc_start(os.getpid())
        if s is None:
            self.skipTest("process start time not readable here")
        self.assertEqual(s, loom.proc_start(os.getpid()))
        self.assertIsNone(loom.proc_start(0))

    def test_owner_file_records_the_start_time(self):
        with loom.Lock(self.root) as lk:
            with open(os.path.join(lk.path, "owner")) as f:
                rec = json.load(f)
        self.assertIn("start", rec)
        self.assertEqual(rec["start"], loom.proc_start(os.getpid()))

    def test_reused_pid_with_another_start_time_is_taken_over(self):
        if loom.proc_start(os.getpid()) is None:
            self.skipTest("process start time not readable here")
        self.make_lock(3600, start="bogus-start")  # the pid is alive but it is another process
        with loom.Lock(self.root):
            self.assertTrue(os.path.isdir(self.lp))

    def test_same_process_and_start_is_not_robbed(self):
        s = loom.proc_start(os.getpid())
        if s is None:
            self.skipTest("process start time not readable here")
        self.make_lock(3600, start=s)
        with self.assertRaises(loom.LoomError) as c:
            with loom.Lock(self.root):
                pass
        self.assertTrue(os.path.isdir(self.lp))
        msg = str(c.exception)
        self.assertIn("stale", msg)
        self.assertIn(loom.LOCK_NAME, msg)
        self.assertIn("delete that lock folder", msg)
        self.assertNotIn("becomes stale after", msg)

    def test_without_a_start_time_only_the_hard_age_frees_a_live_pid(self):
        self.make_lock(3600)  # no start recorded (old format), pid alive, older than the stale limit
        with self.assertRaises(loom.LoomError):
            with loom.Lock(self.root):
                pass
        os.environ["LOOM_LOCK_MAX_AGE"] = "100"
        with loom.Lock(self.root):
            self.assertTrue(os.path.isdir(self.lp))

    def test_lock_dated_in_the_future_ages_out_when_its_owner_is_gone(self):
        self.make_lock(-7200, pid=2 ** 22 + 12345)  # a pid that is not alive
        if loom.pid_alive(2 ** 22 + 12345):
            self.skipTest("odd pid is alive here")
        with loom.Lock(self.root):
            pass


class HomeWriteSerialisationTests(Base):
    """B16: read-modify-write of the home files is serialised."""

    def run_all(self, jobs):
        env = dict(os.environ, LOOM_LOCK_TIMEOUT="120")
        procs = [subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                 for argv, cwd in jobs]
        res = []
        for p in procs:
            o, e = p.communicate()
            res.append((p.returncode, e.decode("utf-8", "replace")))
        return res

    def test_twelve_parallel_trusts_keep_twelve_pins(self):
        jobs = []
        for i in range(12):
            d = os.path.join(self.tmp, "p%d" % i)
            os.makedirs(os.path.join(d, "tools"))
            with open(os.path.join(d, "loom.config.json"), "w") as f:
                json.dump(cfg_with(["{python}", "-c", "print(%d)" % i]), f)
            jobs.append(([sys.executable, SCRIPT, "trust", "--yes"], d))
        res = self.run_all(jobs)
        self.assertEqual([r[0] for r in res], [0] * 12, res)
        with open(os.path.join(self.home, "trust.json"), encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)["projects"]), 12)
        self.assertFalse(os.path.exists(os.path.join(self.home, loom.LOCK_NAME)))

    def test_twelve_parallel_manifest_records_are_all_kept(self):
        loom.get_secret(create=True)
        code = ("import importlib.util as u,sys;s=u.spec_from_file_location('l',sys.argv[1]);"
                "m=u.module_from_spec(s);s.loader.exec_module(m);"
                "m.record_manifest_mac(sys.argv[2], b'raw'+sys.argv[2].encode())")
        jobs = []
        roots = []
        for i in range(12):
            d = os.path.join(self.tmp, "m%d" % i)
            os.makedirs(d)
            roots.append(d)
            jobs.append(([sys.executable, "-c", code, SCRIPT, d], self.tmp))
        res = self.run_all(jobs)
        self.assertEqual([r[0] for r in res], [0] * 12, res)
        with open(os.path.join(self.home, "manifests.json"), encoding="utf-8") as f:
            self.assertEqual(len(json.load(f)["roots"]), 12)

    def test_two_first_time_secret_creations_both_get_the_same_key(self):
        code = ("import importlib.util as u,sys;s=u.spec_from_file_location('l',sys.argv[1]);"
                "m=u.module_from_spec(s);s.loader.exec_module(m);print(m.get_secret(create=True).hex())")
        env = dict(os.environ, LOOM_LOCK_TIMEOUT="120")
        procs = [subprocess.Popen([sys.executable, "-c", code, SCRIPT], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env) for _ in range(6)]
        keys = set()
        for p in procs:
            o, e = p.communicate()
            self.assertEqual(p.returncode, 0, e)
            keys.add(o.strip())
        self.assertEqual(len(keys), 1)


class HardLinkTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")
        self.outside = os.path.join(self.tmp, "outside.txt")

    def link(self, target, data):
        """Make `target` a second name of a file outside the project (skip where unsupported)."""
        with open(self.outside, "wb") as f:
            f.write(data)
        if os.path.exists(target):
            os.remove(target)
        try:
            os.link(self.outside, target)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("hard links not available here")

    def outside_bytes(self):
        with open(self.outside, "rb") as f:
            return f.read()

    def test_hard_linked_ledger_is_refused_and_untouched(self):
        led = os.path.join(self.root, "Loom", "ledger.json")
        with open(led, "rb") as f:
            data = f.read()
        self.link(led, data)
        rc, o, e = self.run_loom("add", "ep2", "--format", "demo")
        self.assertEqual(rc, 1)
        self.assertIn("hard link", e)
        self.assertEqual(self.outside_bytes(), data)

    def test_hard_linked_config_is_refused(self):
        cfg = os.path.join(self.root, "loom.config.json")
        with open(cfg, "rb") as f:
            data = f.read()
        self.link(cfg, data)
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("hard link", e)

    def test_hard_linked_backup_file_is_not_overwritten(self):
        bak = os.path.join(self.root, "Loom", "ledger.json.bak")
        self.link(bak, b"keep me")
        rc, o, e = self.run_loom("add", "ep2", "--format", "demo")
        self.assertEqual(rc, 1)
        self.assertIn("hard link", e)
        self.assertEqual(self.outside_bytes(), b"keep me")


class SanitiserTests(unittest.TestCase):
    def test_invisible_letters_marks_and_selectors_are_removed(self):
        for cp in (0xFE0F, 0xFE00, 0xE0100, 0xE0041, 0xE0001, 0xE000, 0xF8FF, 0xF0000, 0x3164, 0x115F,
                   0x1160, 0xFFA0, 0x2800, 0x17B4, 0x17B5, 0x034F, 0x180B, 0x200B, 0x202E, 0xFEFF):
            self.assertEqual(loom.clean("a%sb" % chr(cp)), "ab", hex(cp))
            self.assertEqual(loom.strip_invisible("a%sb" % chr(cp)), "ab", hex(cp))

    def test_arabic_tashkeel_and_real_letters_are_kept(self):
        word = u"مَرْحَبًا ّ"
        self.assertEqual(loom.clean(word), word)
        self.assertEqual(loom.strip_invisible(word), word)
        for s in (u"café", u"é", u"ก๊", u"中文", u"हिन्दी"):
            self.assertEqual(loom.clean(s), s)


class TimeFlagTests(Base):
    def test_loom_now_needs_loom_test(self):
        os.environ["LOOM_NOW"] = "2000-01-01T00:00:00Z"
        os.environ.pop("LOOM_TEST", None)
        self.assertNotEqual(loom.now_utc(), "2000-01-01T00:00:00Z")
        os.environ["LOOM_TEST"] = "0"
        self.assertNotEqual(loom.now_utc(), "2000-01-01T00:00:00Z")
        os.environ["LOOM_TEST"] = "1"
        self.assertEqual(loom.now_utc(), "2000-01-01T00:00:00Z")


class NextAtPublishTests(AdapterBase):
    def nxt(self):
        o = json.loads(self.run_ok("next", "--format", "json"))
        return o["items"][0]

    def test_next_does_not_recommend_advance_before_publishing(self):
        self.ready()
        r = self.nxt()
        self.assertNotEqual(r["next"], "advance")
        self.assertIn("needs your approval", r["detail"])
        self.assertIn("do not advance", r["detail"])
        self.approve("publish")
        r = self.nxt()
        self.assertEqual(r["next"], "publish")
        self.assertIn("publish --dry-run", r["detail"])
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan1")[0], 0)
        self.assertNotEqual(self.nxt()["next"], "publish")

    def test_after_publish_the_item_may_be_closed(self):
        self.ready()
        self.approve("publish")
        self.run_ok("publish", "ep1", "--channel", "chan1")
        self.approve("advance:publish", channel="none")
        self.assertEqual(self.nxt()["next"], "advance")

    def test_shadow_mode_and_no_adapter_keep_the_plain_advice(self):
        c = demo_config()
        c["shadow_mode"] = True
        self.set_config(c)
        self.ready()
        self.assertIn("advance:publish", self.nxt()["detail"])
        c = demo_config()
        c["adapters"] = {}
        self.set_config(c)
        self.approve("advance:publish", channel="none")
        self.assertEqual(self.nxt()["next"], "advance")


class DocsAndLayoutTests(unittest.TestCase):
    def test_no_tracked_text_file_has_crlf(self):
        bad = []
        for dp, dns, fns in os.walk(ROOT):
            dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
            for f in fns:
                if f.endswith((".png", ".pyc")) or f.startswith(".loom"):
                    continue
                with open(os.path.join(dp, f), "rb") as fh:
                    if b"\r" in fh.read():
                        bad.append(os.path.relpath(os.path.join(dp, f), ROOT))
        self.assertEqual(bad, [])

    def test_gitattributes_forces_lf_and_keeps_png_binary(self):
        t = read(".gitattributes")
        self.assertIn("* text=auto eol=lf", t)
        self.assertIn("*.png binary", t)

    def test_plugin_folder_holds_only_the_manifest_and_a_square_png_icon(self):
        import struct
        names = sorted(os.listdir(os.path.join(ROOT, ".claude-plugin")))
        self.assertEqual(names, ["icon.png", "plugin.json"])
        with open(os.path.join(ROOT, ".claude-plugin", "icon.png"), "rb") as f:
            head = f.read(24)
        self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
        w, h = struct.unpack(">II", head[16:24])
        self.assertEqual(w, h)

    def test_readme_tells_which_commands_write(self):
        r = read("README.md")
        self.assertNotIn("every writing command prints its plan and writes nothing", r)
        for s in ("`add`, `attach`, `approve` and `advance` write", "no dry run", "`trust`, `init`, `adopt`"):
            self.assertIn(s, r)

    def test_readme_command_examples_use_the_real_invocation(self):
        r = read("README.md")
        self.assertNotIn("\n    python scripts/loom.py", r)
        self.assertIn("python <plugin folder>/scripts/loom.py", r)
        self.assertIn("$env:CLAUDE_PLUGIN_ROOT", r)

    def test_readme_states_the_new_limits_in_both_languages(self):
        for rel, needles in (("README.md", ("WMI", "258", "can still do anything", "hard link", "-c")),
                             ("README.ar.md", ("WMI", "258", "hard link", "$env:CLAUDE_PLUGIN_ROOT"))):
            t = read(rel)
            for n in needles:
                self.assertIn(n, t, (rel, n))
        self.assertNotIn("No icon yet", read("README.md"))

    def test_skill_documents_spaces_and_powershell_without_changing_the_commands(self):
        t = read("skills/loom/SKILL.md")
        self.assertIn("contains a space", t)
        self.assertIn("$env:CLAUDE_PLUGIN_ROOT", t)

    def test_changelog_has_the_new_release_and_limits(self):
        t = read("CHANGELOG.md")
        self.assertIn("## [0.1.2]", t)
        self.assertIn("Known limits", t.split("## [0.1.1]")[0])


if __name__ == "__main__":
    unittest.main()

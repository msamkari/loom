"""Regression tests for the 0.1.1 trust pin (H1) and signed approvals (M5, M6)."""
import json
import os
import subprocess
import sys
import unittest

from helpers import Base, demo_config, loom, SCRIPT
from test_adapters import AdapterBase


def tree(root):
    res = {}
    for dp, dns, fns in os.walk(root):
        for f in fns:
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                res[os.path.relpath(p, root).replace("\\", "/")] = fh.read()
    return res


def lint_cfg(code="print('ok')"):
    c = demo_config()
    c["formats"]["demo"]["stages"][0]["checks"] = [
        {"type": "command", "argv": ["{python}", "-c", code]}]
    return c


class TrustPinTests(Base):
    def setUp(self):
        super().setUp()
        self.auto_trust = False

    def project(self, cfg=None):
        self.make_project(cfg or lint_cfg())
        self.add_item("ep1")

    def test_gate_refuses_untrusted_command_and_writes_nothing(self):
        self.project()
        before = tree(self.root)
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("trust", e)
        self.assertEqual(tree(self.root), before)

    def test_trust_without_yes_prints_commands_and_writes_nothing(self):
        self.project()
        o = self.run_ok("trust")
        self.assertIn("argv:", o)
        self.assertIn("print('ok')", o)
        self.assertFalse(os.path.exists(os.path.join(self.home, "trust.json")))

    def test_trust_yes_then_gate_runs(self):
        self.project()
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")

    def test_changed_argv_needs_new_trust(self):
        self.project()
        self.run_ok("trust", "--yes")
        self.set_config(lint_cfg("print('changed')"))
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("changed", e)
        self.run_ok("trust", "--yes")
        self.run_ok("gate", "ep1", "script")

    def test_changed_timeout_env_or_adapter_needs_new_trust(self):
        for edit in (lambda c: c["formats"]["demo"]["stages"][0]["checks"][0].update({"timeout": 5}),
                     lambda c: c["formats"]["demo"]["stages"][0]["checks"][0].update({"env": ["FOO_X"]}),
                     lambda c: c["adapters"]["publish"]["post"].update({"timeout": 7}),
                     lambda c: c.update({"commands": {"lint": ["{python}", "tools/other.py"]}}),
                     lambda c: c.update({"channels": ["chan1", "chan2", "chan3"]})):
            self.tearDown()
            self.setUp()
            self.project()
            self.run_ok("trust", "--yes")
            c = lint_cfg()
            edit(c)
            self.set_config(c)
            self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2)

    def test_trust_is_per_absolute_root(self):
        self.project()
        self.run_ok("trust", "--yes")
        other = os.path.join(self.tmp, "copy")
        os.makedirs(other)
        for rel, data in tree(self.root).items():
            p = os.path.join(other, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        os.chdir(other)
        try:
            rc, o, e = self.run_loom("gate", "ep1", "script", cwd=other)
        finally:
            os.chdir(self._cwd)
        self.assertEqual(rc, 2)

    def test_trust_file_lives_in_home_never_in_project(self):
        self.project()
        self.run_ok("trust", "--yes")
        self.assertTrue(os.path.isfile(os.path.join(self.home, "trust.json")))
        self.assertFalse([k for k in tree(self.root) if "trust" in k.lower()])

    def test_home_inside_project_refused(self):
        self.project()
        os.environ["LOOM_HOME"] = os.path.join(self.root, ".loomhome")
        rc, o, e = self.run_loom("trust", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("LOOM_HOME", e)
        self.assertFalse(os.path.exists(os.path.join(self.root, ".loomhome")))

    def test_stage_without_commands_gates_untrusted(self):
        c = lint_cfg()
        self.project(c)
        self.w("Loom/items/ep1/pre.md", "x")
        c["formats"]["demo"]["stages"][1]["checks"] = [{"type": "files", "paths": ["Loom/items/{item}/pre.md"]}]
        self.set_config(c)
        self.to_stage("ep1", "language")
        self.run_ok("gate", "ep1", "language")

    def test_gate_has_no_root_option(self):
        self.project()
        self.run_ok("trust", "--yes")
        self.assertEqual(self.run_loom("gate", "ep1", "script", "--root", self.tmp)[0], 1)
        self.assertEqual(self.run_loom("status", "--root", self.tmp)[0], 1)
        self.assertEqual(self.run_loom("next", "--root", self.tmp)[0], 1)

    def test_status_and_next_write_nothing(self):
        self.project()
        before = tree(self.root)
        self.run_ok("status", "--format", "text")
        self.run_ok("next", "--format", "json")
        self.assertEqual(tree(self.root), before)

    def test_gate_writes_only_under_loom(self):
        self.project()
        self.run_ok("trust", "--yes")
        before = tree(self.root)
        self.run_ok("gate", "ep1", "script")
        after = tree(self.root)
        changed = [k for k in set(before) | set(after) if before.get(k) != after.get(k)]
        self.assertTrue(changed)
        self.assertTrue(all(k.startswith("Loom/") for k in changed), changed)

    def test_gate_command_rewriting_config_is_not_recorded(self):
        code = ("import io;p='loom.config.json';s=io.open(p,encoding='utf-8').read();"
                "io.open(p,'w',encoding='utf-8').write(s+' ')")
        self.project(lint_cfg(code))
        self.run_ok("trust", "--yes")
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("changed while the gate ran", e)
        self.assertEqual(self.ledger()["items"][0]["gates"], [])

    def test_gate_command_forging_approval_is_not_recorded(self):
        code = ("import json;p='Loom/ledger.json';d=json.load(open(p));"
                "d['items'][0]['approvals'].append(dict(what='publish',channel='chan1',when='now',"
                "date='2026-11-16T00:00:00Z'));json.dump(d,open(p,'w'))")
        self.project(lint_cfg(code))
        self.run_ok("trust", "--yes")
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.assertIn("approvals changed", e)

    def test_adapters_refuse_untrusted_but_dry_run_shows_state(self):
        self.project()
        self.to_stage("ep1", "publish")
        c = lint_cfg()
        for args in (("build", "ep1", "render"), ("stage", "ep1", "--channel", "chan1"),):
            rc, o, e = self.run_loom(*args)
            self.assertIn(rc, (2,), (args, e))
            self.assertIn("trust", e)
        o = self.run_ok("build", "ep1", "render", "--dry-run")
        self.assertIn("pinned with `trust`: NO", o)
        self.assertFalse(self.exists("Loom/items/ep1/out.txt"))

    def test_trust_prints_every_command_sanitised(self):
        c = lint_cfg()
        self.project(c)
        o = self.run_ok("trust")
        for needle in ("gate demo/script check 1", "build adapter render", "publish adapter post",
                       "schedule adapter sched", "stage adapter draft"):
            self.assertIn(needle, o)
        self.assertNotIn("\x1b", o)

    def test_control_characters_in_argv_refused_at_validation(self):
        c = demo_config()
        for bad in ("a\x1b[2Jb", "a\nb", "a‮b", "a​b"):
            c["adapters"]["build"]["render"]["argv"] = ["{python}", bad]
            with self.assertRaises(loom.LoomError):
                loom.validate_config(c)

    def test_trust_hash_covers_resolved_program(self):
        self.project()
        cfg = loom.load_config(self.root)
        h1 = loom.trust_hash(self.root, cfg)
        orig = loom.resolved_programs
        loom.resolved_programs = lambda r, c: [(l, "/other/python") for l, _ in orig(r, c)]
        try:
            self.assertNotEqual(h1, loom.trust_hash(self.root, cfg))
        finally:
            loom.resolved_programs = orig


class SignedApprovalTests(AdapterBase):
    def pub(self, *extra):
        return self.run_loom("publish", "ep1", "--channel", "chan1", *extra)

    def appr(self):
        return self.ledger()["items"][0]["approvals"]

    def test_approval_is_signed_and_secret_stays_out_of_project(self):
        self.ready()
        o = self.run_ok("approve", "ep1", "--what", "publish", "--channel", "chan1")
        a = self.appr()[0]
        self.assertEqual(len(a["sig"]), 64)
        key = os.path.join(self.home, "secret.key")
        self.assertTrue(os.path.isfile(key))
        with open(key) as f:
            sec = f.read().strip()
        self.assertNotIn(sec, o)
        self.assertNotIn(sec, self.r("Loom/ledger.json"))
        self.assertFalse([k for k in os.listdir(self.root) if "secret" in k.lower()])

    def test_unsigned_forged_approval_refused(self):
        self.ready()
        led = self.ledger()
        led["items"][0]["approvals"].append({"what": "publish", "channel": "chan1", "when": "now",
                                             "date": loom.now_utc(), "used": None})
        self.set_ledger(led)
        rc, o, e = self.pub()
        self.assertEqual(rc, 2)
        self.assertEqual(self.log(), "")

    def test_edited_approval_refused(self):
        self.ready()
        self.approve("publish", channel="chan2")
        for field, val in (("channel", "chan1"), ("date", "2099-01-01T00:00:00Z"), ("what", "schedule")):
            led = self.ledger()
            led["items"][0]["approvals"][0][field] = val
            self.set_ledger(led)
            rc, o, e = self.pub()
            self.assertEqual(rc, 2, field)
            self.assertEqual(self.log(), "")
            led["items"][0]["approvals"][0][field] = {"channel": "chan2", "what": "publish"}.get(field, val)
        self.assertEqual(self.log(), "")

    def test_approval_not_transferable_between_items(self):
        self.add_item("ep2")
        self.to_stage("ep1", "publish")
        self.to_stage("ep2", "publish")
        self.approve("publish")
        led = self.ledger()
        led["items"][1]["approvals"] = led["items"][0]["approvals"]
        led["items"][0]["approvals"] = []
        self.set_ledger(led)
        self.assertEqual(self.run_loom("publish", "ep2", "--channel", "chan1")[0], 2)

    def test_approval_from_another_secret_refused(self):
        self.ready()
        self.approve("publish")
        os.remove(os.path.join(self.home, "secret.key"))
        loom.get_secret(create=True)
        self.assertEqual(self.pub()[0], 2)

    def test_publish_never_creates_the_secret(self):
        self.ready()
        self.assertEqual(self.pub()[0], 2)
        self.assertFalse(os.path.exists(os.path.join(self.home, "secret.key")))

    def test_approve_when_is_validated(self):
        self.ready()
        for w in ("9", "2099-01-01", "2099-01-01T10:00", "1999-01-01T00:00:00Z", "2099-13-01T10:00:00Z",
                  "2099-01-01T10:00:00+25:00", "tomorrow", "2099-01-01T10:00:00Z\n"):
            rc = self.run_loom("approve", "ep1", "--what", "schedule", "--channel", "chan1", "--when", w)[0]
            self.assertEqual(rc, 1, w)
        self.assertEqual(self.appr(), [])
        self.run_ok("approve", "ep1", "--what", "schedule", "--channel", "chan1", "--when", "2099-01-01T10:00:00+03:00")

    def test_publish_approval_must_be_now(self):
        self.ready()
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "publish", "--channel", "chan1",
                                       "--when", "2099-01-01T10:00:00Z")[0], 1)

    def test_schedule_in_the_past_refused_even_if_approved(self):
        self.ready()
        os.environ["LOOM_NOW"] = "2026-06-01T00:00:00Z"
        self.approve("schedule", when="2026-06-02T09:00:00Z")
        os.environ["LOOM_NOW"] = "2026-06-03T00:00:00Z"
        rc, o, e = self.run_loom("schedule", "ep1", "--channel", "chan1", "--when", "2026-06-02T09:00:00Z")
        self.assertEqual(rc, 2)
        self.assertIn("past", e)
        self.assertEqual(self.log(), "")

    def test_approval_survives_missing_placeholder_and_failure(self):
        c = demo_config()
        del c["pack"]
        c["adapters"]["publish"]["post"]["argv"] = ["{python}", "tools/post.py", "{pack}"]
        self.set_config(c)
        self.ready()
        self.approve("publish")
        self.assertEqual(self.pub()[0], 1)
        self.assertFalse(self.appr()[0]["used"])
        self.assertFalse(self.appr()[0].get("claimed"))
        c = demo_config()
        c["adapters"]["publish"]["post"]["argv"] = ["{python}", "-c", "import sys;sys.exit(3)"]
        self.set_config(c)
        self.assertEqual(self.pub()[0], 2)
        self.assertFalse(self.appr()[0]["used"])
        self.assertFalse(self.appr()[0].get("claimed"))

    def test_success_consumes_and_replay_by_reset_is_refused(self):
        self.ready()
        self.approve("publish")
        self.assertEqual(self.pub()[0], 0)
        self.assertTrue(self.appr()[0]["used"])
        self.assertEqual(self.pub()[0], 2)
        led = self.ledger()
        led["items"][0]["approvals"][0]["used"] = None  # attacker resets the flag
        self.set_ledger(led)
        self.assertEqual(self.pub()[0], 2)
        self.assertEqual(self.log().count("publish ep1"), 1)

    def test_publish_only_at_publish_stage(self):
        self.to_stage("ep1", "voice")
        self.approve("publish")
        rc, o, e = self.pub()
        self.assertEqual(rc, 2)
        self.assertEqual(self.log(), "")

    def test_allowed_stages_can_only_narrow(self):
        c = demo_config()
        c["adapters"]["publish"]["post"]["allowed_stages"] = ["script", "publish"]
        self.set_config(c)
        self.to_stage("ep1", "script")
        self.approve("publish")
        self.assertEqual(self.pub()[0], 2)
        c["adapters"]["publish"]["post"]["allowed_stages"] = ["script"]
        self.set_config(c)
        self.to_stage("ep1", "publish")
        self.assertEqual(self.pub()[0], 2)
        c["adapters"]["publish"]["post"]["allowed_stages"] = ["publish"]
        self.set_config(c)
        self.assertEqual(self.pub()[0], 0)

    def test_loom_now_ignored_outside_tests(self):
        self.ready()
        rc, o, e = self.run_sub("approve", "ep1", "--what", "publish", "--channel", "chan1",
                                env={"LOOM_TEST": "0", "LOOM_NOW": "2000-01-01T00:00:00Z"})
        self.assertEqual(rc, 0, e)
        self.assertGreaterEqual(self.appr()[0]["date"][:4], "2026")

    def test_forged_advance_approval_ignored_by_next_and_advance(self):
        self.to_stage("ep1", "publish")
        led = self.ledger()
        led["items"][0]["approvals"].append({"what": "advance:publish", "channel": "none", "when": "now",
                                             "date": loom.now_utc(), "used": None})
        self.set_ledger(led)
        self.assertIn("needs your approval", self.run_ok("next"))
        self.assertEqual(self.run_loom("advance", "ep1")[0], 2)

    def test_next_ignores_expired_advance_approval(self):
        self.to_stage("ep1", "publish")
        os.environ["LOOM_NOW"] = "2026-01-01T00:00:00Z"
        self.approve("advance:publish", channel="none")
        os.environ["LOOM_NOW"] = "2026-11-01T00:00:00Z"
        self.assertIn("needs your approval", self.run_ok("next"))

    def test_parallel_publish_runs_once(self):
        self.ready()
        self.approve("publish")
        env = dict(os.environ)
        procs = [subprocess.Popen([sys.executable, SCRIPT, "publish", "ep1", "--channel", "chan1"], cwd=self.root,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) for _ in range(4)]
        codes = []
        for p in procs:
            p.communicate()
            codes.append(p.returncode)
        self.assertEqual(self.log().count("publish ep1"), 1, codes)
        self.assertEqual(codes.count(0), 1)


if __name__ == "__main__":
    unittest.main()

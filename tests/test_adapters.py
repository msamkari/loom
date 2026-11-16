import json
import os
import sys
import unittest

from helpers import Base, demo_config, py


class AdapterBase(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")

    def ready(self, stage="publish"):
        self.to_stage("ep1", stage)

    def approve(self, what, channel="chan1", when=None):
        a = ["approve", "ep1", "--what", what, "--channel", channel]
        if when:
            a += ["--when", when]
        self.run_ok(*a)

    def log(self):
        return self.r("posted.log") if self.exists("posted.log") else ""


class BuildTests(AdapterBase):
    def test_build_runs_adapter_and_registers_artifact(self):
        o = self.run_ok("build", "ep1", "render")
        self.assertIn("built ep1", o)
        self.assertEqual(self.r("Loom/items/ep1/out.txt"), "built ep1")
        it = self.ledger()["items"][0]
        self.assertIn("Loom/items/ep1/out.txt", it["artifacts"])
        self.assertEqual(it["events"][-1]["result"], "ok")

    def test_unknown_adapter(self):
        self.assertEqual(self.run_loom("build", "ep1", "ghost")[0], 1)

    def test_nothing_hard_coded_no_adapters(self):
        c = demo_config()
        c["adapters"] = {}
        self.set_config(c)
        self.assertEqual(self.run_loom("build", "ep1", "render")[0], 2)

    def test_failed_build_exit_2_and_recorded(self):
        c = demo_config()
        c["adapters"]["build"]["bad"] = {"argv": ["{python}", "-c", "import sys; print('boom'); sys.exit(3)"]}
        self.set_config(c)
        rc, o, e = self.run_loom("build", "ep1", "bad")
        self.assertEqual(rc, 2)
        self.assertIn("failed rc=3", self.ledger()["items"][0]["events"][-1]["result"])

    def test_dry_run_does_not_run(self):
        o = self.run_ok("build", "ep1", "render", "--dry-run")
        self.assertIn("dry run", o)
        self.assertFalse(self.exists("Loom/items/ep1/out.txt"))

    def test_build_registers_no_artifact_on_failure(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["argv"] = ["{python}", "-c", "import sys; sys.exit(1)"]
        self.set_config(c)
        self.run_loom("build", "ep1", "render")
        self.assertEqual(self.ledger()["items"][0]["artifacts"], [])


class SafetyTests(AdapterBase):
    def adapter(self, code, **kw):
        c = demo_config()
        spec = {"argv": ["{python}", "-c", code]}
        spec.update(kw)
        c["adapters"]["build"]["x"] = spec
        self.set_config(c)

    def test_no_shell_metacharacters_interpreted(self):
        self.adapter("import sys; print(sys.argv[1:])", )
        c = demo_config()
        c["adapters"]["build"]["x"] = {"argv": ["{python}", "-c", "import sys; print(sys.argv[1:])",
                                                "; echo INJECTED > pwn.txt", "&& dir", "$(x)", "`x`"]}
        self.set_config(c)
        o = self.run_ok("build", "ep1", "x")
        self.assertIn("; echo INJECTED > pwn.txt", o)
        self.assertFalse(self.exists("pwn.txt"))

    def test_cwd_is_project_root(self):
        self.adapter("import os; print(os.getcwd())")
        o = self.run_ok("build", "ep1", "x", "--root", self.root, cwd=self.tmp)
        self.assertEqual(os.path.realpath(o.splitlines()[0]), os.path.realpath(self.root))

    def test_env_allowlist_filters_secrets(self):
        os.environ["LOOM_TEST_SECRET"] = "supersecretvalue123"
        os.environ["LOOM_TEST_ALLOWED"] = "allowedvalue456"
        self.adapter("import os; print(os.environ.get('LOOM_TEST_SECRET','absent'),"
                     " os.environ.get('LOOM_TEST_ALLOWED','absent'))", env=["LOOM_TEST_ALLOWED"])
        o = self.run_ok("build", "ep1", "x")
        self.assertIn("absent", o)
        self.assertNotIn("supersecretvalue123", o)
        # allowed var is passed to the child but its value is redacted from loom's output
        self.assertNotIn("allowedvalue456", o)
        self.assertIn("[redacted]", o)

    def test_never_prints_env_values_in_ledger(self):
        os.environ["LOOM_TEST_ALLOWED"] = "allowedvalue456"
        self.adapter("import os; print(os.environ['LOOM_TEST_ALLOWED'])", env=["LOOM_TEST_ALLOWED"])
        self.run_ok("build", "ep1", "x")
        self.assertNotIn("allowedvalue456", self.r("Loom/ledger.json"))

    def test_output_cap(self):
        self.adapter("print('A'*500000)", max_output=1000)
        o = self.run_ok("build", "ep1", "x")
        self.assertLess(len(o), 1500)
        self.assertIn("truncated", o)

    def test_output_sanitised(self):
        self.adapter("import sys; sys.stdout.write('ok\\x1b[31mRED\\x1b[0m\\x00\\x07bell\\r\\n')")
        o = self.run_ok("build", "ep1", "x")
        self.assertNotIn("\x1b", o)
        self.assertNotIn("\x00", o)
        self.assertNotIn("\x07", o)

    def test_invalid_utf8_output(self):
        self.adapter("import sys; sys.stdout.buffer.write(b'caf\\xff\\xfe ok')")
        o = self.run_ok("build", "ep1", "x")
        self.assertIn("ok", o)

    def test_timeout(self):
        self.adapter("import time; time.sleep(30)", timeout=1)
        rc, o, e = self.run_loom("build", "ep1", "x")
        self.assertEqual(rc, 2)
        self.assertEqual(self.ledger()["items"][0]["events"][-1]["result"], "timeout")

    def test_stdin_is_closed(self):
        self.adapter("import sys; print(repr(sys.stdin.read()))")
        self.assertIn("''", self.run_ok("build", "ep1", "x"))

    def test_item_id_cannot_inject_flags(self):
        self.assertEqual(self.run_loom("build", "-rf", "render")[0], 1)
        self.assertEqual(self.run_loom("build", "a;b", "render")[0], 1)

    def test_unicode_item_artifacts_output_arabic(self):
        self.adapter("print('تم البناء')")
        self.assertIn("تم البناء", self.run_ok("build", "ep1", "x"))

    def test_gate_cannot_reach_adapters(self):
        # gate takes a stage name only; adapters are not a gate namespace
        self.assertEqual(self.run_loom("gate", "ep1", "render")[0], 1)


class StageTests(AdapterBase):
    def test_stage_draft_runs_and_needs_channel(self):
        self.ready()
        self.assertEqual(self.run_loom("stage", "ep1")[0], 1)  # --channel required
        self.run_ok("stage", "ep1", "--channel", "chan1")
        self.assertEqual(self.log().strip(), "draft ep1 chan1")

    def test_stage_unknown_channel(self):
        self.assertEqual(self.run_loom("stage", "ep1", "--channel", "zzz")[0], 1)

    def test_stage_refused_when_gate_not_passed(self):
        rc, o, e = self.run_loom("stage", "ep1", "--channel", "chan1")
        self.assertEqual(rc, 2)
        self.assertEqual(self.log(), "")


class PublishTests(AdapterBase):
    def test_publish_refused_without_approval(self):
        self.ready()
        rc, o, e = self.run_loom("publish", "ep1", "--channel", "chan1")
        self.assertEqual(rc, 2)
        self.assertIn("approve", e)
        self.assertEqual(self.log(), "")

    def test_publish_with_approval_then_consumed(self):
        self.ready()
        self.approve("publish")
        self.run_ok("publish", "ep1", "--channel", "chan1")
        self.assertEqual(self.log().strip(), "publish ep1 chan1")
        rc, o, e = self.run_loom("publish", "ep1", "--channel", "chan1")
        self.assertEqual(rc, 2)
        self.assertEqual(len(self.log().strip().splitlines()), 1)

    def test_approval_is_per_channel(self):
        self.ready()
        self.approve("publish", "chan1")
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan2")[0], 2)
        self.assertEqual(self.log(), "")

    def test_approval_is_per_item(self):
        self.add_item("ep2")
        self.to_stage("ep2", "publish")
        self.ready()
        self.approve("publish")
        self.assertEqual(self.run_loom("publish", "ep2", "--channel", "chan1")[0], 2)

    def test_schedule_needs_exact_when(self):
        self.ready()
        self.approve("schedule", when="2026-12-01T09:00+03:00")
        self.assertEqual(self.run_loom("schedule", "ep1", "--channel", "chan1")[0], 1)  # --when missing
        self.assertEqual(self.run_loom("schedule", "ep1", "--channel", "chan1", "--when", "2026-12-01T10:00+03:00")[0], 2)
        self.assertEqual(self.log(), "")
        self.run_ok("schedule", "ep1", "--channel", "chan1", "--when", "2026-12-01T09:00+03:00")
        self.assertIn("schedule ep1 chan1 2026-12-01T09:00+03:00", self.log())

    def test_publish_approval_cannot_schedule(self):
        self.ready()
        self.approve("publish")
        self.assertEqual(self.run_loom("schedule", "ep1", "--channel", "chan1", "--when", "now")[0], 2)

    def test_expired_approval(self):
        self.ready()
        os.environ["LOOM_NOW"] = "2026-01-01T00:00:00Z"
        self.approve("publish")
        os.environ["LOOM_NOW"] = "2026-01-10T00:00:00Z"
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan1")[0], 2)

    def test_unattended_refuses_publish_even_with_approval(self):
        self.ready()
        self.approve("publish")
        os.environ["LOOM_NO_PUBLISH"] = "1"
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan1")[0], 2)
        self.assertEqual(self.log(), "")

    def test_no_publish_adapter_configured(self):
        c = demo_config()
        del c["adapters"]["publish"]
        self.set_config(c)
        self.ready()
        self.approve("publish")
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan1")[0], 2)

    def test_dry_run_shows_approval_state_and_consumes_nothing(self):
        self.ready()
        o = self.run_ok("publish", "ep1", "--channel", "chan1", "--dry-run")
        self.assertIn("NO", o)
        self.approve("publish")
        o = self.run_ok("publish", "ep1", "--channel", "chan1", "--dry-run")
        self.assertIn("yes", o)
        self.assertIsNone(self.ledger()["items"][0]["approvals"][0]["used"])
        self.assertEqual(self.log(), "")

    def test_approval_consumed_even_if_adapter_fails(self):
        c = demo_config()
        c["adapters"]["publish"]["post"]["argv"] = ["{python}", "-c", "import sys; sys.exit(9)"]
        self.set_config(c)
        self.ready()
        self.approve("publish")
        self.assertEqual(self.run_loom("publish", "ep1", "--channel", "chan1")[0], 2)
        self.assertTrue(self.ledger()["items"][0]["approvals"][0]["used"])

    def test_shadow_mode_refuses_stage_publish_schedule(self):
        c = demo_config(shadow_mode=True)
        self.set_config(c)
        self.ready()
        self.approve("publish")
        for k in (("publish", "--channel", "chan1"), ("stage", "--channel", "chan1"),
                  ("schedule", "--channel", "chan1", "--when", "now")):
            self.assertEqual(self.run_loom(k[0], "ep1", *k[1:])[0], 2, k)
        self.assertEqual(self.log(), "")

    def test_allowed_stages_enforced(self):
        c = demo_config()
        c["adapters"]["publish"]["post"]["allowed_stages"] = ["voice"]
        self.set_config(c)
        self.ready()
        self.approve("publish")
        rc, o, e = self.run_loom("publish", "ep1", "--channel", "chan1")
        self.assertEqual(rc, 2)
        self.assertIn("runs only at", e)
        self.assertEqual(self.log(), "")

    def test_event_trail_recorded(self):
        self.ready()
        self.approve("publish")
        self.run_ok("publish", "ep1", "--channel", "chan1")
        ev = [e["result"] for e in self.ledger()["items"][0]["events"]]
        self.assertEqual(ev[-2:], ["started", "ok"])


if __name__ == "__main__":
    unittest.main()

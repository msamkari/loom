import json
import os
import unittest

from helpers import Base, demo_config


class StatusNextTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()

    def test_status_empty(self):
        o = self.run_ok("status")
        self.assertIn("0 item", o)

    def test_status_text_and_json(self):
        self.add_item("ep1")
        self.add_item("ep2")
        o = self.run_ok("status")
        self.assertIn("[script]", o)
        self.assertIn("ep1", o)
        j = json.loads(self.run_ok("status", "--format", "json"))
        self.assertEqual(j["by_stage"]["script"], ["ep1", "ep2"])

    def test_status_readonly_no_writes(self):
        self.add_item("ep1")
        before = self.r("Loom/ledger.json")
        self.run_ok("status")
        self.run_ok("next")
        self.assertEqual(self.r("Loom/ledger.json"), before)
        self.assertFalse(self.exists("Loom/ledger.json.tmp"))

    def test_status_without_config(self):
        os.remove(os.path.join(self.root, "loom.config.json"))
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("init", e)

    def test_next_advises_gate_then_blocker(self):
        self.add_item("ep1")
        self.assertIn("gate", self.run_ok("next"))
        self.run_loom("gate", "ep1", "script")  # fails: no script file
        o = self.run_ok("next")
        self.assertIn("blocked", o)
        self.assertIn("missing or empty", o)

    def test_next_ready_to_advance(self):
        self.add_item("ep1")
        self.w("Loom/items/ep1/script.md", "hello")
        self.run_ok("gate", "ep1", "script")
        self.assertIn("advance", self.run_ok("next"))

    def test_status_has_no_root_or_command_flags(self):
        for sub in ("status", "next"):
            rc, o, e = self.run_loom(sub, "--root", self.root)
            self.assertEqual(rc, 1)
        rc, o, e = self.run_loom("gate", "ep1", "script", "--root", self.root)
        self.assertEqual(rc, 1)
        rc, o, e = self.run_loom("gate", "ep1", "script", "--argv", "x")
        self.assertEqual(rc, 1)

    def test_gate_uses_cwd_config_only(self):
        # cwd is the project; a config elsewhere cannot be selected by flag
        self.add_item("ep1")
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        rc, o, e = self.run_loom("gate", "ep1", "script", cwd=other)
        self.assertEqual(rc, 1)

    def test_abbreviated_flags_not_accepted(self):
        rc, o, e = self.run_loom("status", "--form", "json")
        self.assertEqual(rc, 1)

    def test_shadow_flag_shown(self):
        c = demo_config(shadow_mode=True)
        self.make_project(c)
        self.assertIn("shadow", self.run_ok("status"))


class GateTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")

    def test_files_gate_fail_then_pass(self):
        rc, o, e = self.run_loom("gate", "ep1", "script")
        self.assertEqual(rc, 2)
        self.w("Loom/items/ep1/script.md", "text")
        self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 0)
        g = self.ledger()["items"][0]["gates"]
        self.assertEqual([x["result"] for x in g], ["fail", "pass"])
        self.assertTrue(g[1]["date"].endswith("Z"))

    def test_empty_file_counts_missing(self):
        self.w("Loom/items/ep1/script.md", "")
        self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2)

    def test_gate_never_advances(self):
        self.w("Loom/items/ep1/script.md", "text")
        self.run_ok("gate", "ep1", "script")
        self.assertEqual(self.ledger()["items"][0]["stage"], "script")

    def test_command_gate_exit_semantics(self):
        self.w("Loom/items/ep1/script.md", "clean text")
        self.assertEqual(self.run_loom("gate", "ep1", "language")[0], 0)
        self.w("Loom/items/ep1/script.md", "this is BAD")
        rc, o, e = self.run_loom("gate", "ep1", "language")
        self.assertEqual(rc, 2)
        self.assertIn("exit 2", o)
        g = self.ledger()["items"][0]["gates"][-1]
        self.assertEqual(g["result"], "fail")
        self.assertIn("command", g)

    def test_command_gate_arabic_and_bom_crlf(self):
        self.w("Loom/items/ep1/script.md", "مرحبا يا شباب\nهذا نص تجريبي", newline="\r\n", enc="utf-8-sig")
        self.assertEqual(self.run_loom("gate", "ep1", "language")[0], 0)

    def test_pass_codes_configurable(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][1]["checks"][0]["pass_codes"] = [0, 2]
        self.set_config(c)
        self.w("Loom/items/ep1/script.md", "BAD")
        self.assertEqual(self.run_loom("gate", "ep1", "language")[0], 0)

    def test_missing_program_fails_not_crashes(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][1]["checks"][0] = {"type": "command", "argv": ["no-such-program-xyz"]}
        self.set_config(c)
        rc, o, e = self.run_loom("gate", "ep1", "language")
        self.assertEqual(rc, 2)
        self.assertIn("could not start", o)

    def test_timeout_kills_command(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][1]["checks"][0] = {
            "type": "command", "timeout": 1,
            "argv": ["{python}", "-c", "import time; time.sleep(30)"]}
        self.set_config(c)
        rc, o, e = self.run_loom("gate", "ep1", "language")
        self.assertEqual(rc, 2)
        self.assertIn("timed out", o)

    def test_facts_ok(self):
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "f1", "source": "a source", "verified": "2026-01-01", "expires": "2999-01-01"}]}))
        self.assertEqual(self.run_loom("gate", "ep1", "research")[0], 0)

    def test_facts_expired_missing_source_future(self):
        os.environ["LOOM_NOW"] = "2026-06-01T00:00:00Z"
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "old", "source": "s", "verified": "2026-01-01", "expires": "2026-02-01"}]}))
        rc, o, e = self.run_loom("gate", "ep1", "research")
        self.assertEqual(rc, 2)
        self.assertIn("expired", o)
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "ns", "source": " ", "verified": "2026-01-01", "expires": "2999-01-01"}]}))
        self.assertIn("no source", self.run_loom("gate", "ep1", "research")[1])
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "fut", "source": "s", "verified": "2030-01-01", "expires": "2999-01-01"}]}))
        self.assertIn("future", self.run_loom("gate", "ep1", "research")[1])

    def test_facts_malformed(self):
        for txt in ('{"facts": []}', '{"facts": [1]}', '{"nope": 1}', '{"facts":[{"source":"s",'
                    '"verified":"2026-13-45","expires":"x"}]}'):
            self.w("Loom/items/ep1/facts.json", txt)
            self.assertEqual(self.run_loom("gate", "ep1", "research")[0], 2, txt)

    def test_facts_corrupt_json_is_error(self):
        self.w("Loom/items/ep1/facts.json", "{nope")
        self.assertEqual(self.run_loom("gate", "ep1", "research")[0], 1)

    def test_checklist(self):
        self.w("Loom/items/ep1/pre_voice.md", "- [x] a\n- [ ] b\n")
        rc, o, e = self.run_loom("gate", "ep1", "voice")
        self.assertEqual(rc, 2)
        self.assertIn("line(s) 2", o)
        self.w("Loom/items/ep1/pre_voice.md", "- [x] a\r\n* [X] b\r\n", newline="")
        self.assertEqual(self.run_loom("gate", "ep1", "voice")[0], 0)
        self.w("Loom/items/ep1/pre_voice.md", "no items here")
        self.assertEqual(self.run_loom("gate", "ep1", "voice")[0], 2)

    def test_unknown_stage_or_item(self):
        self.assertEqual(self.run_loom("gate", "ep1", "nope")[0], 1)
        self.assertEqual(self.run_loom("gate", "zzz", "script")[0], 1)
        self.assertEqual(self.run_loom("gate", "../x", "script")[0], 1)

    def test_gate_json_output(self):
        self.w("Loom/items/ep1/script.md", "x")
        j = json.loads(self.run_ok("gate", "ep1", "script", "--format", "json"))
        self.assertEqual(j["result"], "pass")

    def test_gate_history_capped(self):
        self.w("Loom/items/ep1/script.md", "x")
        led = self.ledger()
        led["items"][0]["gates"] = [{"stage": "script", "result": "pass", "date": "2026-01-01T00:00:00Z"}] * 200
        self.set_ledger(led)
        self.run_ok("gate", "ep1", "script")
        self.assertEqual(len(self.ledger()["items"][0]["gates"]), 200)

    def test_item_path_traversal_blocked_via_ledger(self):
        led = self.ledger()
        led["items"][0]["artifacts"] = ["../outside"]
        self.set_ledger(led)
        self.assertEqual(self.run_loom("status")[0], 1)


class AdvanceTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")

    def test_advance_refused_without_gate(self):
        rc, o, e = self.run_loom("advance", "ep1")
        self.assertEqual(rc, 2)
        self.assertIn("gate", e)

    def test_advance_refused_after_failed_gate(self):
        self.run_loom("gate", "ep1", "script")
        self.assertEqual(self.run_loom("advance", "ep1")[0], 2)
        self.assertEqual(self.ledger()["items"][0]["stage"], "script")

    def test_advance_after_pass(self):
        self.w("Loom/items/ep1/script.md", "x")
        self.run_ok("gate", "ep1", "script")
        self.run_ok("advance", "ep1")
        self.assertEqual(self.ledger()["items"][0]["stage"], "language")

    def test_later_failure_blocks_again(self):
        self.w("Loom/items/ep1/script.md", "x")
        self.run_ok("gate", "ep1", "script")
        os.remove(os.path.join(self.root, "Loom/items/ep1/script.md"))
        self.run_loom("gate", "ep1", "script")
        self.assertEqual(self.run_loom("advance", "ep1")[0], 2)

    def test_approval_required_to_advance(self):
        self.to_stage("ep1", "voice")
        self.w("Loom/items/ep1/pre_voice.md", "- [x] ok\n")
        self.run_ok("gate", "ep1", "voice")
        rc, o, e = self.run_loom("advance", "ep1")
        self.assertEqual(rc, 2)
        self.assertIn("approval", e)
        self.run_ok("approve", "ep1", "--what", "advance:voice")
        self.run_ok("advance", "ep1")
        it = self.ledger()["items"][0]
        self.assertEqual(it["stage"], "publish")
        self.assertTrue(it["approvals"][0]["used"])

    def test_approval_not_replayable_for_advance(self):
        self.to_stage("ep1", "voice")
        self.w("Loom/items/ep1/pre_voice.md", "- [x] ok\n")
        self.run_ok("gate", "ep1", "voice")
        self.run_ok("approve", "ep1", "--what", "advance:voice")
        self.run_ok("advance", "ep1")
        self.to_stage("ep1", "voice")
        self.assertEqual(self.run_loom("advance", "ep1")[0], 2)

    def test_last_stage_marks_done(self):
        self.to_stage("ep1", "publish")
        self.run_ok("approve", "ep1", "--what", "advance:publish")
        self.run_ok("advance", "ep1")
        self.assertEqual(self.ledger()["items"][0]["status"], "done")
        self.assertEqual(self.run_loom("advance", "ep1")[0], 1)

    def test_expired_approval_refused(self):
        self.to_stage("ep1", "publish")
        os.environ["LOOM_NOW"] = "2026-01-01T00:00:00Z"
        self.run_ok("approve", "ep1", "--what", "advance:publish")
        os.environ["LOOM_NOW"] = "2026-03-01T00:00:00Z"
        self.assertEqual(self.run_loom("advance", "ep1")[0], 2)


class ApproveTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")

    def test_needs_known_channel(self):
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "publish", "--channel", "nope")[0], 1)
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "publish")[0], 1)

    def test_what_restricted(self):
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "delete all", "--channel", "chan1")[0], 1)

    def test_schedule_requires_when(self):
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "schedule", "--channel", "chan1")[0], 1)
        self.run_ok("approve", "ep1", "--what", "schedule", "--channel", "chan1", "--when", "2026-12-01T09:00+03:00")
        a = self.ledger()["items"][0]["approvals"][0]
        self.assertEqual((a["what"], a["channel"], a["when"]), ("schedule", "chan1", "2026-12-01T09:00+03:00"))

    def test_refused_when_unattended(self):
        os.environ["LOOM_NO_PUBLISH"] = "1"
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "publish", "--channel", "chan1")[0], 2)

    def test_advance_stage_must_exist(self):
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "advance:ghost")[0], 1)

    def test_note_recorded_and_injection_chars_refused(self):
        self.run_ok("approve", "ep1", "--what", "publish", "--channel", "chan1", "--note", "yes in chat")
        self.assertEqual(self.ledger()["items"][0]["approvals"][0]["note"], "yes in chat")
        self.assertEqual(self.run_loom("approve", "ep1", "--what", "publish", "--channel", "chan1",
                                       "--note", "a\x1b[31mb")[0], 1)


class AddAttachTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()

    def test_add_duplicate_and_bad(self):
        self.add_item("ep1")
        self.assertEqual(self.run_loom("add", "ep1", "--format", "demo")[0], 1)
        self.assertEqual(self.run_loom("add", "bad id", "--format", "demo")[0], 1)
        self.assertEqual(self.run_loom("add", "ep2", "--format", "ghost")[0], 1)

    def test_add_scaffold_never_overwrites(self):
        self.w("Loom/templates/script.md", "# template")
        self.w("Loom/items/ep1/script.md", "mine")
        self.run_ok("add", "ep1", "--format", "demo", "--scaffold")
        self.assertEqual(self.r("Loom/items/ep1/script.md"), "mine")

    def test_add_scaffold_copies(self):
        self.w("Loom/templates/caption.md", "# cap")
        self.run_ok("add", "ep1", "--format", "demo", "--scaffold")
        self.assertEqual(self.r("Loom/items/ep1/caption.md"), "# cap")

    def test_add_artifact_validation(self):
        self.assertEqual(self.run_loom("add", "ep1", "--format", "demo", "--artifact", "../x")[0], 1)
        self.assertEqual(self.run_loom("add", "ep1", "--format", "demo", "--artifact", "/abs")[0], 1)
        self.assertFalse(any(i["id"] == "ep1" for i in self.ledger()["items"]))

    def test_attach(self):
        self.add_item("ep1")
        self.w("out/a.txt", "x")
        self.run_ok("attach", "ep1", "out/a.txt")
        self.run_ok("attach", "ep1", "out/a.txt")
        self.assertEqual(self.ledger()["items"][0]["artifacts"], ["out/a.txt"])
        self.assertEqual(self.run_loom("attach", "ep1", "nothere.txt")[0], 1)
        self.assertEqual(self.run_loom("attach", "ep1", "Prompts/a.txt")[0], 1)


if __name__ == "__main__":
    unittest.main()

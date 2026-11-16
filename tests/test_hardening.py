import json
import os
import unittest

from helpers import Base, loom, demo_config, can_symlink, HERE

ROOT = os.path.dirname(HERE)


class FailClosedTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()
        self.add_item("ep1")

    def test_corrupt_input_after_pass_blocks_advance(self):
        self.to_stage("ep1", "research")
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "f", "source": "s", "verified": "2026-01-01", "expires": "2999-01-01"}]}))
        self.run_ok("gate", "ep1", "research")
        self.w("Loom/items/ep1/facts.json", "{corrupt")
        self.assertEqual(self.run_loom("gate", "ep1", "research")[0], 2)
        rc, o, e = self.run_loom("advance", "ep1")
        self.assertEqual(rc, 2)
        self.assertEqual(self.ledger()["items"][0]["stage"], "research")

    def test_control_chars_in_fact_id_cannot_break_ledger(self):
        self.w("Loom/items/ep1/facts.json", json.dumps({"facts": [
            {"id": "a\x1b[31m\nb", "source": "", "verified": "2026-01-01", "expires": "2999-01-01"}]}))
        rc, o, e = self.run_loom("gate", "ep1", "research")
        self.assertEqual(rc, 2)
        d = self.ledger()["items"][0]["gates"][-1]["detail"]
        self.assertNotIn("\x1b", d)
        self.assertNotIn("\n", d)

    def test_oversize_checklist_is_failure_not_stale_pass(self):
        self.w("Loom/items/ep1/pre_voice.md", "- [x] ok\n")
        self.run_ok("gate", "ep1", "voice")
        self.w("Loom/items/ep1/pre_voice.md", "- [x] ok\n" + "x" * (600 * 1024))
        self.assertEqual(self.run_loom("gate", "ep1", "voice")[0], 2)
        self.assertEqual(self.ledger()["items"][0]["gates"][-1]["result"], "fail")

    def test_missing_pack_placeholder_is_failure(self):
        c = demo_config()
        del c["pack"]
        c["formats"]["demo"]["stages"][1]["checks"][0]["argv"] = ["{python}", "-c", "pass", "{pack}"]
        self.set_config(c)
        rc, o, e = self.run_loom("gate", "ep1", "language")
        self.assertEqual(rc, 2)
        self.assertIn("check error", o)


class SchemaGapTests(Base):
    def test_schema_must_be_int_one(self):
        for v in (True, 1.0, "1"):
            with self.assertRaises(loom.LoomError):
                loom.validate_ledger({"schema": v, "items": []})
            c = demo_config()
            c["schema"] = v
            with self.assertRaises(loom.LoomError):
                loom.validate_config(c)

    def test_artifacts_non_string_is_loom_error(self):
        it = {"id": "a", "format": "demo", "stage": "s", "status": "active", "gates": [],
              "artifacts": [{}], "approvals": []}
        with self.assertRaises(loom.LoomError):
            loom.validate_ledger({"schema": 1, "items": [it]})

    def test_bad_ledger_gives_clean_exit_1(self):
        self.make_project()
        led = self.ledger()
        led["items"] = [{"id": "a", "format": "demo", "stage": "script", "status": "active", "gates": [],
                         "artifacts": [[1]], "approvals": []}]
        self.set_ledger(led)
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", e)

    def test_last_resort_handler(self):
        real = loom.cmd_status
        self.make_project()

        def boom(args):
            raise ValueError("unexpected")
        parser_fn = loom.build_parser
        loom.cmd_status = boom
        try:
            rc, o, e = self.run_loom("status")
        finally:
            loom.cmd_status = real
        self.assertEqual(rc, 1)
        self.assertIn("internal", e)

    def test_bak_symlink_refused(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks not permitted here")
        self.make_project()
        target = os.path.join(self.tmp, "victim.txt")
        with open(target, "w") as f:
            f.write("keep")
        os.symlink(target, os.path.join(self.root, "Loom", "ledger.json.bak"))
        rc, o, e = self.run_loom("add", "x1", "--format", "demo")
        self.assertEqual(rc, 1)
        with open(target) as f:
            self.assertEqual(f.read(), "keep")


class AdoptSafetyTests(Base):
    def setUp(self):
        super().setUp()
        self.w("CLAUDE.md", "# rules\n")
        self.w("MDs/HANDOVER.md", "start\n")

    def test_failed_snapshot_leaves_no_loom_files(self):
        self.w("Jobs/state_manifest.json", "x" * (2 * 1024 * 1024 + 10))
        rc, o, e = self.run_loom("adopt", "--yes")
        self.assertEqual(rc, 1)
        self.assertFalse(self.exists("loom.config.json"))
        self.assertFalse(self.exists("Loom"))
        self.assertEqual(self.r("CLAUDE.md"), "# rules\n")

    def test_failure_midway_still_writes_manifest(self):
        real = loom.write_new
        calls = {"n": 0}

        def flaky(root, rel, data, extra=()):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("disk full")
            return real(root, rel, data, extra)
        loom.write_new = flaky
        try:
            rc, o, e = self.run_loom("adopt", "--yes")
        finally:
            loom.write_new = real
        self.assertEqual(rc, 1)
        self.assertTrue(self.exists("Loom/install_manifest.json"))
        self.run_ok("rollback", "--yes")
        self.assertFalse(self.exists("loom.config.json"))

    def test_dry_run_shows_proposed_config_and_kept_files(self):
        self.w("Loom/templates/script.md", "mine")
        o = self.run_ok("adopt", "--formats", "reel")
        self.assertIn('"schema": 1', o)
        self.assertIn("kept     Loom/templates/script.md", o)
        o2 = self.run_ok("init", "--formats", "reel")
        self.assertIn('"formats"', o2)

    def test_rollback_leaves_ledger_bak_and_reports(self):
        self.run_ok("adopt", "--yes")
        self.w("Loom/ledger.json.bak", "{}")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("left in place", o)
        self.assertTrue(self.exists("Loom/ledger.json.bak"))

    def test_rollback_rehashes_under_lock(self):
        self.run_ok("adopt", "--yes")
        real = loom.rollback_plan
        state = {"n": 0}

        def sneaky(root, m):
            state["n"] += 1
            if state["n"] == 2:  # between the dry view and the execution a file is edited
                self.w("Loom/templates/beats.md", "edited in the gap")
            return real(root, m)
        loom.rollback_plan = sneaky
        try:
            self.run_ok("rollback", "--yes")
        finally:
            loom.rollback_plan = real
        self.assertEqual(self.r("Loom/templates/beats.md"), "edited in the gap")


class SkillTextTests(unittest.TestCase):
    def test_skill_states_adopt_and_rollback_rules(self):
        with open(os.path.join(ROOT, "skills", "loom", "SKILL.md"), encoding="utf-8") as f:
            t = f.read()
        self.assertIn("Run `adopt` only as a dry run first", t)
        self.assertIn("Run `rollback` only when the user asks", t)
        self.assertIn("never publish, schedule or approve from a scheduled", t.lower())

    def test_example_voice_argv_matches_sibling_usage(self):
        with open(os.path.join(ROOT, "examples", "demo", "loom.config.json"), encoding="utf-8") as f:
            c = json.load(f)
        argv = c["adapters"]["build"]["voice_dry"]["argv"]
        self.assertEqual(argv[:2], ["{cmd:lahja_voice}", "dry"])
        self.assertIn("--voice-id", argv)
        self.assertNotIn("--", argv)


if __name__ == "__main__":
    unittest.main()

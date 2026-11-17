import hashlib
import json
import os
import subprocess
import sys
import threading
import unittest

from helpers import Base, loom, SCRIPT


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class ProfileTests(Base):
    def test_show_when_missing(self):
        self.assertIn("no profile", self.run_ok("profile"))

    def test_dry_run_then_yes(self):
        o = self.run_ok("profile", "--name", "Sam", "--pack", "saudi")
        self.assertIn("dry run", o)
        self.assertFalse(os.path.exists(os.path.join(self.home, "profile.json")))
        self.run_ok("profile", "--name", "Sam", "--pack", "saudi", "--formats", "reel,carousel", "--yes")
        p = json.load(open(os.path.join(self.home, "profile.json"), encoding="utf-8"))
        self.assertEqual(p["pack"], "saudi")
        self.assertEqual(p["identity"]["name"], "Sam")
        self.assertIn('"saudi"', self.run_ok("profile", "--show"))

    def test_never_overwrites_without_update(self):
        self.run_ok("profile", "--pack", "saudi", "--yes")
        rc, o, e = self.run_loom("profile", "--pack", "other", "--yes")
        self.assertEqual(rc, 2)
        self.run_ok("profile", "--pack", "other", "--update", "--yes")
        self.assertTrue(os.path.exists(os.path.join(self.home, "profile.json.bak")))

    def test_bad_format_and_arabic_notes(self):
        self.assertEqual(self.run_loom("profile", "--formats", "nonsense", "--yes")[0], 1)
        self.run_ok("profile", "--notes", "نبرة ودية", "--yes")
        self.assertIn("نبرة ودية", self.run_ok("profile", "--show"))

    def test_corrupt_profile_loud(self):
        os.makedirs(self.home)
        with open(os.path.join(self.home, "profile.json"), "w") as f:
            f.write("{bad")
        self.assertEqual(self.run_loom("profile", "--show")[0], 1)

    def test_profile_pack_feeds_init_default(self):
        self.run_ok("profile", "--pack", "saudi", "--yes")
        self.run_ok("init", "--yes")
        self.assertEqual(self.jr("loom.config.json")["pack"], "saudi")


class InitTests(Base):
    def test_dry_run_writes_nothing(self):
        o = self.run_ok("init", "--formats", "reel")
        self.assertIn("dry run", o)
        self.assertEqual(os.listdir(self.root), [])

    def test_yes_writes_everything(self):
        self.run_ok("init", "--formats", "reel,carousel", "--pack", "saudi", "--channels", "ig,tt", "--yes")
        for rel in ("loom.config.json", "Loom/ledger.json", "Loom/install_manifest.json",
                    "Loom/templates/script.md", "Loom/templates/facts.json", "Loom/templates/caption.md",
                    "Loom/templates/pre_voice.md", "Loom/templates/pre_render.md",
                    "Loom/templates/pre_publish.md", "Loom/templates/beats.md"):
            self.assertTrue(self.exists(rel), rel)
        cfg = loom.load_config(self.root)
        self.assertEqual(sorted(cfg["formats"]), ["carousel", "reel"])
        self.assertEqual(cfg["channels"], ["ig", "tt"])
        self.assertFalse(cfg["shadow_mode"])
        self.assertEqual(self.ledger(), {"schema": 1, "items": []})

    def test_never_overwrites_config(self):
        self.run_ok("init", "--yes")
        before = self.r("loom.config.json")
        rc, o, e = self.run_loom("init", "--formats", "thread", "--yes")
        self.assertEqual(rc, 1)
        self.assertEqual(self.r("loom.config.json"), before)

    def test_keeps_existing_template_files(self):
        self.w("Loom/templates/script.md", "my own script template")
        self.run_ok("init", "--yes")
        self.assertEqual(self.r("Loom/templates/script.md"), "my own script template")
        m = self.jr("Loom/install_manifest.json")
        self.assertNotIn("Loom/templates/script.md", [f["path"] for f in m["files"]])

    def test_answers_file(self):
        self.w("answers.json", json.dumps({"kind": "demo", "formats": ["thread"], "pack": "saudi",
                                           "channels": ["x"], "identity": {"voice": "MDs/voice.md"},
                                           "commands": {"lahja": ["{python}", "lahja.py"]}}))
        self.run_ok("init", "--answers", os.path.join(self.root, "answers.json"), "--yes")
        cfg = self.jr("loom.config.json")
        self.assertEqual(cfg["identity"], {"voice": "MDs/voice.md"})
        lang = [s for s in cfg["formats"]["thread"]["stages"] if s["name"] == "language"][0]
        self.assertEqual(lang["checks"][1]["type"], "command")

    def test_answers_unknown_key_rejected(self):
        self.w("answers.json", json.dumps({"formats": ["reel"], "evil": 1}))
        rc, o, e = self.run_loom("init", "--answers", os.path.join(self.root, "answers.json"), "--yes")
        self.assertEqual(rc, 1)
        self.assertFalse(self.exists("loom.config.json"))

    def test_answers_denied_identity_pointer(self):
        self.w("answers.json", json.dumps({"identity": {"x": "Characters/who.md"}}))
        self.assertEqual(self.run_loom("init", "--answers", os.path.join(self.root, "answers.json"), "--yes")[0], 1)

    def test_unknown_format(self):
        self.assertEqual(self.run_loom("init", "--formats", "hologram", "--yes")[0], 1)

    def test_answers_bom_crlf_arabic(self):
        self.w("answers.json", json.dumps({"kind": "مشروع تجريبي", "formats": ["post"]}, ensure_ascii=False),
               newline="\r\n", enc="utf-8-sig")
        self.run_ok("init", "--answers", os.path.join(self.root, "answers.json"), "--yes")
        self.assertEqual(self.jr("loom.config.json")["project_kind"], "مشروع تجريبي")

    def test_generated_config_gates_work_end_to_end(self):
        self.run_ok("init", "--formats", "post", "--yes")
        self.run_ok("add", "p1", "--format", "post", "--scaffold")
        self.run_ok("gate", "p1", "idea")
        self.run_ok("advance", "p1")
        self.run_ok("gate", "p1", "script")

    def test_preset_voice_requires_approval(self):
        self.run_ok("init", "--formats", "reel", "--yes")
        st = {s["name"]: s for s in self.jr("loom.config.json")["formats"]["reel"]["stages"]}
        self.assertTrue(st["voice"]["requires_approval"])
        self.assertTrue(st["publish"]["requires_approval"])

    def test_manifest_hashes(self):
        self.run_ok("init", "--yes")
        m = self.jr("Loom/install_manifest.json")
        for f in m["files"]:
            self.assertEqual(f["sha256_after"], sha(os.path.join(self.root, *f["path"].split("/"))))

    def test_templates_have_no_private_markers(self):
        self.run_ok("init", "--yes")
        for n in os.listdir(os.path.join(self.root, "Loom", "templates")):
            txt = self.r("Loom/templates/" + n)
            self.assertNotIn("@", txt.replace("#", ""))


class AdoptTests(Base):
    def setUp(self):
        super().setUp()
        self.w("CLAUDE.md", "# project rules\n")
        self.w("MDs/HANDOVER.md", "start here\n")
        self.w("Jobs/state_manifest.json", '{"a": 1}')
        self.w(".claude/settings.json", '{"x": 1}')
        self.w(".claude/settings.local.json", '{"y": 2}')
        self.w("Reel_Templates/a.txt", "x")
        self.w("Episodes/secret_ep.md", "PRIVATE-EPISODE-MARKER")
        self.w("Followers/list.csv", "PRIVATE-FOLLOWER-MARKER")
        self.w(".env", "KEY=PRIVATE-KEY-MARKER")

    def test_dry_run_default_writes_nothing(self):
        before = sorted(os.listdir(self.root))
        o = self.run_ok("adopt")
        self.assertIn("dry run", o)
        self.assertEqual(sorted(os.listdir(self.root)), before)
        self.assertIn("shadow mode ON", o)
        self.assertIn("reel", o)

    def test_dry_run_never_mentions_private_names(self):
        o = self.run_ok("adopt")
        for marker in ("secret_ep", "list.csv", "PRIVATE", ".env"):
            self.assertNotIn(marker, o.replace("denied folders", ""))

    def test_yes_creates_snapshot_and_manifest(self):
        self.run_ok("adopt", "--yes")
        snaps = [d for d in os.listdir(os.path.join(self.root, "Jobs", "_Archive")) if d.startswith("loom_pre_adopt_")]
        self.assertEqual(len(snaps), 1)
        base = "Jobs/_Archive/" + snaps[0] + "/"
        for rel in ("CLAUDE.md", "MDs/HANDOVER.md", "Jobs/state_manifest.json", ".claude/settings.json"):
            self.assertEqual(self.r(base + rel), self.r(rel))
        self.assertFalse(self.exists(base + ".claude/settings.local.json"))  # secret-like: never copied
        self.assertTrue(self.jr("loom.config.json")["shadow_mode"])
        m = self.jr("Loom/install_manifest.json")
        self.assertEqual(m["mode"], "adopt")
        self.assertTrue(m["snapshot_dir"].startswith("Jobs/_Archive/loom_pre_adopt_"))

    def test_snapshot_never_includes_denied_content(self):
        self.run_ok("adopt", "--yes")
        for dp, dns, fns in os.walk(os.path.join(self.root, "Jobs", "_Archive")):
            for f in fns:
                self.assertNotIn("PRIVATE", open(os.path.join(dp, f), encoding="utf-8").read())

    def test_existing_files_untouched_by_default(self):
        hashes = dict((r, sha(os.path.join(self.root, *r.split("/")))) for r in
                      ("CLAUDE.md", "MDs/HANDOVER.md", "Jobs/state_manifest.json", "Episodes/secret_ep.md", ".env"))
        self.run_ok("adopt", "--yes")
        for r, h in hashes.items():
            self.assertEqual(sha(os.path.join(self.root, *r.split("/"))), h, r)

    def test_second_snapshot_gets_suffix(self):
        os.environ["LOOM_NOW"] = "2026-05-05T00:00:00Z"
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes")
        self.run_ok("adopt", "--yes")
        names = sorted(os.listdir(os.path.join(self.root, "Jobs", "_Archive")))
        self.assertEqual(names, ["loom_pre_adopt_2026-05-05", "loom_pre_adopt_2026-05-05a"])

    def test_refuses_if_already_adopted(self):
        self.run_ok("adopt", "--yes")
        self.assertEqual(self.run_loom("adopt", "--yes")[0], 1)

    def test_snapshot_extra_file_rules(self):
        self.w("Scheduled/task1/SKILL.md", "task")
        self.run_ok("adopt", "--yes", "--snapshot", "Scheduled/task1/SKILL.md")
        snap = [d for d in os.listdir(os.path.join(self.root, "Jobs", "_Archive"))][0]
        self.assertTrue(self.exists("Jobs/_Archive/%s/Scheduled/task1/SKILL.md" % snap))

    def test_snapshot_extra_denied_or_traversal_refused(self):
        for bad in ("Episodes/secret_ep.md", "../x", ".env", "/abs/x"):
            rc, o, e = self.run_loom("adopt", "--yes", "--snapshot", bad)
            self.assertEqual(rc, 1, bad)
        self.assertFalse(self.exists("loom.config.json"))

    def test_excluded_folders_never_in_formats_guess(self):
        self.w("Prompts/carousel_secret.md", "x")
        self.w("Research/thread_notes.md", "x")
        o = self.run_ok("adopt")
        self.assertNotIn("carousel", o.split("denied folders")[0].split("formats:")[1].split("\n")[0])

    def test_claude_block_modifies_and_is_recorded(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        self.assertIn("loom:begin", self.r("CLAUDE.md"))
        m = self.jr("Loom/install_manifest.json")
        e = [f for f in m["files"] if f["path"] == "CLAUDE.md"][0]
        self.assertEqual(e["action"], "modified")
        self.assertEqual(e["sha256_after"], sha(os.path.join(self.root, "CLAUDE.md")))

    def test_empty_folder_adopt(self):
        os.makedirs(os.path.join(self.tmp, "empty"))
        self.run_ok("adopt", "--yes", "--root", os.path.join(self.tmp, "empty"))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "empty", "loom.config.json")))


class RollbackTests(Base):
    def setUp(self):
        super().setUp()
        self.w("CLAUDE.md", "# rules\n")
        self.w("MDs/HANDOVER.md", "start\n")

    def test_dry_run_changes_nothing(self):
        self.run_ok("adopt", "--yes")
        snap = sorted(os.listdir(self.root))
        o = self.run_ok("rollback")
        self.assertIn("dry run", o)
        self.assertEqual(sorted(os.listdir(self.root)), snap)
        self.assertTrue(self.exists("loom.config.json"))

    def test_clean_rollback_removes_everything_added(self):
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes")
        self.assertFalse(self.exists("loom.config.json"))
        self.assertFalse(self.exists("Loom"))
        self.assertTrue(self.exists("CLAUDE.md"))
        self.assertTrue(any(d.startswith("loom_pre_adopt_") for d in os.listdir(os.path.join(self.root, "Jobs", "_Archive"))))

    def test_edited_file_is_kept_and_reported(self):
        self.run_ok("adopt", "--yes")
        self.w("Loom/templates/script.md", "I edited this")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("KEEP", o)
        self.assertEqual(self.r("Loom/templates/script.md"), "I edited this")
        self.assertFalse(self.exists("loom.config.json"))
        self.assertTrue(self.exists("Loom/install_manifest.json"))  # kept so it can be re-run

    def test_ledger_with_items_is_kept(self):
        self.run_ok("adopt", "--yes")
        self.add_item("ep1", "post")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("KEEP", o)
        self.assertEqual(self.ledger()["items"][0]["id"], "ep1")

    def test_restore_modified_claude_md(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        self.run_ok("rollback", "--yes")
        self.assertEqual(self.r("CLAUDE.md"), "# rules\n")

    def test_edited_claude_md_left_alone(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        with open(os.path.join(self.root, "CLAUDE.md"), "a") as f:
            f.write("\nmore notes by the user\n")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("KEEP", o)
        self.assertIn("more notes by the user", self.r("CLAUDE.md"))
        self.assertIn("loom:begin", self.r("CLAUDE.md"))

    def test_handover_moved_on_is_never_restored(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        self.w("MDs/HANDOVER.md", "newer state written after adopt\n")
        self.run_ok("rollback", "--yes")
        self.assertEqual(self.r("MDs/HANDOVER.md"), "newer state written after adopt\n")

    def test_altered_snapshot_blocks_restore(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        snap = [d for d in os.listdir(os.path.join(self.root, "Jobs", "_Archive"))][0]
        self.w("Jobs/_Archive/%s/CLAUDE.md" % snap, "tampered")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("KEEP", o)
        self.assertIn("loom:begin", self.r("CLAUDE.md"))

    def test_already_removed_files_ok(self):
        self.run_ok("adopt", "--yes")
        os.remove(os.path.join(self.root, "Loom", "templates", "beats.md"))
        o = self.run_ok("rollback", "--yes")
        self.assertIn("already gone", o)

    def test_no_manifest(self):
        self.assertEqual(self.run_loom("rollback", "--yes")[0], 1)

    def test_tampered_manifest_traversal_refused(self):
        self.run_ok("adopt", "--yes")
        m = self.jr("Loom/install_manifest.json")
        m["files"][0]["path"] = "../victim.txt"
        self.w("Loom/install_manifest.json", json.dumps(m))
        outside = os.path.join(self.tmp, "victim.txt")
        open(outside, "w").write("keep me")
        self.assertEqual(self.run_loom("rollback", "--yes")[0], 1)
        self.assertTrue(os.path.exists(outside))

    def test_tampered_manifest_denied_path_refused(self):
        self.run_ok("adopt", "--yes")
        m = self.jr("Loom/install_manifest.json")
        m["files"][0]["path"] = "Episodes/x.md"
        self.w("Loom/install_manifest.json", json.dumps(m))
        self.assertEqual(self.run_loom("rollback", "--yes")[0], 1)

    def test_rollback_after_init(self):
        self.run_ok("init", "--yes")
        self.run_ok("rollback", "--yes")
        self.assertFalse(self.exists("Loom"))
        self.assertFalse(self.exists("loom.config.json"))

    def test_untouched_user_files_survive(self):
        self.w("Loom/items/ep1/script.md", "user content")
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes")
        self.assertEqual(self.r("Loom/items/ep1/script.md"), "user content")


class ConcurrencyTests(Base):
    def setUp(self):
        super().setUp()
        self.make_project()

    def test_threads_add_items_no_lost_updates(self):
        errs = []

        def work(i):
            try:
                cfg = loom.load_config(self.root)
                with loom.Lock(self.root):
                    led = loom.load_ledger(self.root)
                    led["items"].append({"id": "t%d" % i, "format": "demo", "stage": "script",
                                         "status": "active", "gates": [], "artifacts": [], "approvals": []})
                    loom.save_ledger(self.root, led)
            except Exception as e:  # pragma: no cover
                errs.append(repr(e))
        ts = [threading.Thread(target=work, args=(i,)) for i in range(12)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errs, [])
        self.assertEqual(len(self.ledger()["items"]), 12)

    def test_processes_add_items_no_lost_updates(self):
        procs = [subprocess.Popen([sys.executable, SCRIPT, "add", "p%d" % i, "--format", "demo",
                                   "--root", self.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for i in range(8)]
        codes = []
        for p in procs:
            p.communicate()
            codes.append(p.returncode)
        self.assertEqual(codes, [0] * 8)
        ids = sorted(i["id"] for i in self.ledger()["items"])
        self.assertEqual(ids, sorted("p%d" % i for i in range(8)))
        self.assertFalse(os.path.exists(os.path.join(self.root, "Loom", loom.LOCK_NAME)))

    def test_processes_race_on_one_approval(self):
        self.add_item("ep1")
        self.to_stage("ep1", "publish")
        self.run_ok("approve", "ep1", "--what", "publish", "--channel", "chan1")
        procs = [subprocess.Popen([sys.executable, SCRIPT, "publish", "ep1", "--channel", "chan1",
                                   "--root", self.root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for _ in range(4)]
        codes = []
        for p in procs:
            p.communicate()
            codes.append(p.returncode)
        self.assertEqual(sorted(codes), [0, 2, 2, 2])
        self.assertEqual(len(self.r("posted.log").strip().splitlines()), 1)

    def test_stale_lock_recovered_by_cli(self):
        import time
        lp = os.path.join(self.root, "Loom", loom.LOCK_NAME)
        os.mkdir(lp)
        old = time.time() - 600
        os.utime(lp, (old, old))
        rc, o, e = self.run_sub("add", "s1", "--format", "demo", "--root", self.root,
                                env={"LOOM_LOCK_STALE": "30"})
        self.assertEqual(rc, 0, e)

    def test_live_lock_times_out_cleanly(self):
        os.mkdir(os.path.join(self.root, "Loom", loom.LOCK_NAME))
        rc, o, e = self.run_sub("add", "s1", "--format", "demo", "--root", self.root,
                                env={"LOOM_LOCK_TIMEOUT": "0.5"})
        self.assertEqual(rc, 1)
        self.assertIn("lock", e)
        self.assertEqual(self.ledger()["items"], [])


class CliTests(Base):
    def test_version_and_help(self):
        rc, o, e = self.run_sub("--version")
        self.assertEqual(rc, 0)
        self.assertIn("0.1.2", o)

    def test_no_subcommand_is_error(self):
        self.assertEqual(self.run_sub()[0], 1)

    def test_arabic_output_utf8_pipe(self):
        self.make_project()
        self.run_ok("add", "ep1", "--format", "demo", "--note", "ملاحظة عربية")
        rc, o, e = self.run_sub("status", "--format", "json")
        self.assertEqual(rc, 0, e)


if __name__ == "__main__":
    unittest.main()

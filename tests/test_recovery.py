"""Regression tests for crash-safe adopt, tamper-proof rollback, snapshot hygiene and lock
takeover (0.1.1)."""
import hashlib
import json
import os
import subprocess
import sys
import time
import unittest

from helpers import Base, loom, SCRIPT, can_symlink

SECRET = "s" + "k-test-LOCALSECRET-123"


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class AdoptBase(Base):
    def setUp(self):
        super().setUp()
        self.w("CLAUDE.md", "# project\nrules\n")
        self.w("MDs/HANDOVER.md", "handover\n")
        self.w(".claude/settings.json", '{"permissions": {}}\n')
        self.w(".claude/settings.local.json", json.dumps({"env": {"FAKE_API_KEY": SECRET}}))
        self.w("src/main.py", "print('user code')\n")

    def manifest(self):
        return self.jr("Loom/install_manifest.json")

    def snap_dirs(self):
        base = os.path.join(self.root, "Jobs", "_Archive")
        return sorted(os.listdir(base)) if os.path.isdir(base) else []

    def crash_after(self, n, name="write_new"):
        """Make the nth call of loom.<name> raise, like a kill at that point."""
        real = getattr(loom, name)
        self.real = real
        calls = [0]

        def boom(*a, **k):
            calls[0] += 1
            if calls[0] == n:
                raise OSError(28, "simulated crash")
            return real(*a, **k)
        setattr(loom, name, boom)
        self.addCleanup(setattr, loom, name, real)


class CrashSafeTests(AdoptBase):
    def test_complete_manifest_after_clean_adopt(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        self.assertEqual(self.manifest()["status"], "complete")

    def test_manifest_is_written_first_and_pending(self):
        seen = []
        real = loom.write_new

        def spy(root, rel, data, extra=()):
            if not seen:
                seen.append(self.exists("Loom/install_manifest.json") and self.manifest()["status"])
            return real(root, rel, data, extra)
        loom.write_new = spy
        self.addCleanup(setattr, loom, "write_new", real)
        self.run_ok("adopt", "--yes")
        self.assertEqual(seen, ["pending"])

    def test_crash_at_every_step_leaves_a_pending_manifest_and_rollback_cleans(self):
        for n in range(1, 12):
            self.tearDown()
            self.setUp()
            self.crash_after(n)
            rc, o, e = self.run_loom("adopt", "--yes", "--claude-block")
            if rc == 0:
                break
            self.assertEqual(rc, 1, e)
            self.assertEqual(self.manifest()["status"], "pending", n)
            loom.write_new = self.real
            self.run_ok("rollback", "--yes")
            self.assertFalse(self.exists("loom.config.json"), n)
            self.assertFalse(self.exists("Loom"), n)
            self.assertEqual(self.r("CLAUDE.md"), "# project\nrules\n")
        self.assertGreater(n, 3)

    def test_re_adopt_resumes_after_a_crash(self):
        self.crash_after(3)
        self.assertEqual(self.run_loom("adopt", "--yes")[0], 1)
        loom.write_new = self.real
        self.run_ok("adopt", "--yes")
        self.assertEqual(self.manifest()["status"], "complete")
        self.assertTrue(self.exists("loom.config.json"))

    def test_crash_while_marking_complete_is_resumable(self):
        real = loom.write_manifest

        def boom(root, m):
            if m["status"] == "complete":
                raise OSError(28, "simulated crash")
            return real(root, m)
        loom.write_manifest = boom
        self.addCleanup(setattr, loom, "write_manifest", real)
        self.assertEqual(self.run_loom("adopt", "--yes")[0], 1)
        loom.write_manifest = real
        self.assertEqual(self.manifest()["status"], "pending")
        self.run_ok("rollback", "--yes")
        self.assertFalse(self.exists("loom.config.json"))

    def test_claude_block_is_atomic_and_restored(self):
        self.run_ok("adopt", "--yes", "--claude-block")
        self.assertIn("loom:begin", self.r("CLAUDE.md"))
        self.run_ok("rollback", "--yes")
        self.assertEqual(self.r("CLAUDE.md"), "# project\nrules\n")

    def test_second_init_after_config_deleted_refused_not_untracked(self):
        self.run_ok("init", "--yes")
        os.remove(os.path.join(self.root, "loom.config.json"))
        rc, o, e = self.run_loom("init", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("rollback", e)
        self.assertEqual(self.manifest()["status"], "complete")


class TamperTests(AdoptBase):
    def tamper(self, fn):
        m = self.manifest()
        fn(m)
        self.w("Loom/install_manifest.json", json.dumps(m))

    def test_edited_manifest_refused_and_user_file_survives(self):
        self.run_ok("adopt", "--yes")
        h = sha(os.path.join(self.root, "src", "main.py"))
        self.tamper(lambda m: m["files"].append(
            {"path": "src/main.py", "action": "created", "sha256_before": None, "sha256_after": h,
             "snapshot": None}))
        rc, o, e = self.run_loom("rollback", "--yes")
        self.assertEqual(rc, 1)
        self.assertTrue(self.exists("src/main.py"))
        self.assertTrue(self.exists("loom.config.json"))

    def test_manifest_without_record_refused(self):
        self.run_ok("adopt", "--yes")
        os.remove(os.path.join(self.home, "manifests.json"))
        rc, o, e = self.run_loom("rollback", "--yes")
        self.assertEqual(rc, 1)
        self.assertIn("not recorded", e)
        self.assertTrue(self.exists("loom.config.json"))

    def test_manifest_from_another_folder_refused(self):
        self.run_ok("adopt", "--yes")
        other = os.path.join(self.tmp, "other")
        os.makedirs(os.path.join(other, "Loom"))
        with open(os.path.join(other, "Loom", "install_manifest.json"), "wb") as f:
            f.write(self.r("Loom/install_manifest.json").encode("utf-8"))
        rc, o, e = self.run_loom("rollback", "--yes", cwd=other)
        self.assertEqual(rc, 1)

    def test_path_policy_table(self):
        good = {"schema": 1, "mode": "adopt", "date": "2026-11-16T00:00:00Z", "files": []}
        h = "a" * 64

        def f(path, action, snap=None):
            return {"path": path, "action": action, "sha256_before": h, "sha256_after": h, "snapshot": snap}
        for bad in (f("src/main.py", "created"), f(".git/hooks/pre-commit", "created"),
                    f(".git/hooks/pre-commit", "modified"), f("Loom/.git/x", "created"),
                    f("../x", "created"), f("/etc/x", "created"), f("C:/x", "created"),
                    f("CLAUDE.md", "created"), f("Loom/ledger.json.bak", "created"),
                    f("Loom/install_manifest.json", "created"),
                    f("src/main.py", "modified"), f(".claude/settings.json", "modified"),
                    f("CLAUDE.md", "modified", "docs/evil.txt"),
                    f("CLAUDE.md", "modified", "Jobs/_Archive/other/CLAUDE.md"),
                    f("Loom/x\\y", "created")):
            m = dict(good)
            m["files"] = [bad]
            with self.assertRaises(loom.LoomError, msg=bad):
                loom.validate_manifest(m)
        for ok in (f("loom.config.json", "created"), f("Loom/templates/script.md", "created"),
                   f("CLAUDE.md", "modified", "Jobs/_Archive/loom_pre_adopt_2026-11-16/CLAUDE.md")):
            m = dict(good)
            m["files"] = [ok]
            loom.validate_manifest(m)

    def test_bad_snapshot_dir_and_copies_refused(self):
        m = {"schema": 1, "mode": "adopt", "date": "x", "files": [], "snapshot_dir": "docs"}
        with self.assertRaises(loom.LoomError):
            loom.validate_manifest(m)
        m = {"schema": 1, "mode": "adopt", "date": "x", "files": [],
             "snapshot_dir": "Jobs/_Archive/loom_pre_adopt_2026-11-16",
             "snapshots": [{"path": "src/main.py", "sha256": "a" * 64}]}
        with self.assertRaises(loom.LoomError):
            loom.validate_manifest(m)

    def test_pre_existing_user_file_in_loom_is_never_removed(self):
        self.w("Loom/templates/script.md", "my own script template\n")
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes")
        self.assertEqual(self.r("Loom/templates/script.md"), "my own script template\n")

    def test_edited_created_file_kept(self):
        self.run_ok("adopt", "--yes")
        with open(os.path.join(self.root, "Loom", "templates", "beats.md"), "a") as fh:
            fh.write("mine\n")
        o = self.run_ok("rollback", "--yes")
        self.assertIn("KEEP", o)
        self.assertTrue(self.exists("Loom/templates/beats.md"))

    def test_symlinked_component_refused(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks not available")
        self.run_ok("adopt", "--yes")
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        for n in os.listdir(os.path.join(self.root, "Loom", "templates")):
            with open(os.path.join(outside, n), "wb") as f:
                f.write(self.r("Loom/templates/" + n).encode("utf-8"))
        import shutil
        shutil.rmtree(os.path.join(self.root, "Loom", "templates"))
        os.symlink(outside, os.path.join(self.root, "Loom", "templates"), target_is_directory=True)
        rc, o, e = self.run_loom("rollback", "--yes")
        self.assertEqual(rc, 1)
        self.assertEqual(len(os.listdir(outside)), 7)


class SnapshotTests(AdoptBase):
    def test_secret_like_files_are_not_copied(self):
        o = self.run_ok("adopt", "--yes")
        found = []
        for dp, dns, fns in os.walk(os.path.join(self.root, "Jobs")):
            for fn in fns:
                with open(os.path.join(dp, fn), "rb") as fh:
                    if SECRET.encode() in fh.read():
                        found.append(fn)
        self.assertEqual(found, [])
        self.assertIn("NOT copied", self.run_ok("rollback") + "NOT copied")
        m = self.manifest()
        names = [s["name"] for s in m["skipped_secrets"]]
        self.assertEqual(names, [".claude/settings.local.json"])
        self.assertEqual(m["skipped_secrets"][0]["sha256"], sha(os.path.join(self.root, ".claude", "settings.local.json")))
        self.assertNotIn(SECRET, self.r("Loom/install_manifest.json"))

    def test_dry_run_says_secret_like_file_is_not_copied(self):
        o = self.run_ok("adopt")
        self.assertIn("NOT copied", o)
        self.assertIn("settings.local.json", o)

    def test_extra_snapshot_with_secret_like_name_only_hashed(self):
        self.w("Jobs/tokens_store.json", json.dumps({"t": SECRET}))
        self.run_ok("adopt", "--yes", "--snapshot", "Jobs/tokens_store.json")
        self.assertIn("Jobs/tokens_store.json", [s["name"] for s in self.manifest()["skipped_secrets"]])
        for dp, dns, fns in os.walk(os.path.join(self.root, "Jobs", "_Archive")):
            for fn in fns:
                self.assertNotIn("tokens_store", fn)

    def test_is_secret_name_table(self):
        for n in ("settings.local.json", "settings.local.yml", ".env", ".env.prod", "a.key", "x.pem",
                  "credentials.json", "tokens.txt", ".claude/settings.local.json"):
            self.assertTrue(loom.is_secret_name(n), n)
        for n in ("settings.json", "CLAUDE.md", "HANDOVER.md", "state_manifest.json"):
            self.assertFalse(loom.is_secret_name(n), n)

    def test_rollback_keeps_snapshot_by_default(self):
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes")
        self.assertEqual(len(self.snap_dirs()), 1)

    def test_purge_snapshot_removes_unchanged_copies_and_folder(self):
        self.run_ok("adopt", "--yes")
        self.run_ok("rollback", "--yes", "--purge-snapshot")
        self.assertEqual(self.snap_dirs(), [])
        self.assertTrue(self.exists("Jobs/_Archive"))

    def test_purge_never_removes_edited_snapshot_copy(self):
        self.run_ok("adopt", "--yes")
        d = self.manifest()["snapshot_dir"]
        p = os.path.join(self.root, *(d + "/CLAUDE.md").split("/"))
        with open(p, "a") as fh:
            fh.write("my note\n")
        self.run_ok("rollback", "--yes", "--purge-snapshot")
        self.assertTrue(os.path.exists(p))
        self.assertFalse(os.path.exists(os.path.join(self.root, *(d + "/MDs/HANDOVER.md").split("/"))))

    def test_rollback_dry_run_changes_nothing(self):
        self.run_ok("adopt", "--yes")
        before = sorted(os.listdir(self.root))
        o = self.run_ok("rollback", "--purge-snapshot")
        self.assertIn("dry run", o)
        self.assertTrue(self.exists("loom.config.json"))
        self.assertEqual(sorted(os.listdir(self.root)), before)


class LockTests(Base):
    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.root, "Loom"))
        self.lp = os.path.join(self.root, "Loom", loom.LOCK_NAME)
        os.environ["LOOM_LOCK_STALE"] = "1"
        os.environ["LOOM_LOCK_TIMEOUT"] = "0.5"

    def old_lock(self, owner=None, age=3600):
        os.mkdir(self.lp)
        if owner is not None:
            with open(os.path.join(self.lp, "owner"), "w") as f:
                f.write(json.dumps(owner))
        old = time.time() - age
        os.utime(self.lp, (old, old))

    def host(self):
        return loom.Lock(self.root).host

    def dead_pid(self):
        p = subprocess.Popen([sys.executable, "-c", "pass"])
        p.wait()
        return p.pid

    def test_pid_alive(self):
        self.assertTrue(loom.pid_alive(os.getpid()))
        self.assertFalse(loom.pid_alive(self.dead_pid()))
        self.assertFalse(loom.pid_alive(0))
        self.assertFalse(loom.pid_alive(-5))
        self.assertFalse(loom.pid_alive("x"))

    def test_old_lock_of_a_live_process_is_not_taken(self):
        self.old_lock({"token": "t", "pid": os.getpid(), "host": self.host()})
        with self.assertRaises(loom.LoomError) as c:
            with loom.Lock(self.root):
                pass
        self.assertIn("holds", str(c.exception))

    def test_old_lock_of_a_dead_process_is_taken(self):
        self.old_lock({"token": "t", "pid": self.dead_pid(), "host": self.host()})
        with loom.Lock(self.root):
            pass
        self.assertFalse(os.path.exists(self.lp))

    def test_old_lock_without_owner_is_taken(self):
        self.old_lock(None)
        with loom.Lock(self.root):
            pass

    def test_other_host_needs_ten_times_the_limit(self):
        self.old_lock({"token": "t", "pid": 1, "host": "elsewhere-host"}, age=5)
        with self.assertRaises(loom.LoomError):
            with loom.Lock(self.root):
                pass
        for n in os.listdir(self.lp):
            os.unlink(os.path.join(self.lp, n))
        os.rmdir(self.lp)
        self.old_lock({"token": "t", "pid": 1, "host": "elsewhere-host"}, age=50)
        with loom.Lock(self.root):
            pass

    def test_takeover_never_deletes_user_files(self):
        self.old_lock(None)
        os.makedirs(os.path.join(self.lp, "keep"))
        with open(os.path.join(self.lp, "keep", "user.txt"), "w") as f:
            f.write("mine")
        old = time.time() - 3600
        os.utime(self.lp, (old, old))
        with loom.Lock(self.root):
            pass
        kept = []
        for dp, dns, fns in os.walk(os.path.join(self.root, "Loom")):
            kept += [fn for fn in fns if fn == "user.txt"]
        self.assertEqual(kept, ["user.txt"])

    def test_bad_stale_or_timeout_value_is_a_clean_error(self):
        for var in ("LOOM_LOCK_STALE", "LOOM_LOCK_TIMEOUT"):
            for bad in ("abc", "nan", "-1", "inf"):
                os.environ[var] = bad
                with self.assertRaises(loom.LoomError, msg=(var, bad)):
                    with loom.Lock(self.root):
                        pass
            os.environ[var] = "1"

    def test_cli_bad_stale_value_one_line_rc1(self):
        self.make_project()
        rc, o, e = self.run_sub("add", "z1", "--format", "demo", "--root", self.root,
                                env={"LOOM_LOCK_STALE": "abc"})
        self.assertEqual(rc, 1)
        self.assertEqual(len(e.strip().splitlines()), 1)
        self.assertNotIn("Traceback", e)

    def test_lost_lock_blocks_the_write(self):
        target = os.path.join(self.root, "Loom", "x.json")
        with loom.Lock(self.root):
            with open(os.path.join(self.lp, "owner"), "w") as f:
                f.write(json.dumps({"token": "someone-else"}))
            with self.assertRaises(loom.LoomError) as c:
                loom.atomic_write(target, b"{}")
        self.assertIn("lock was lost", str(c.exception))
        self.assertFalse(os.path.exists(target))
        self.assertEqual([n for n in os.listdir(os.path.join(self.root, "Loom")) if n.endswith(".tmp")], [])

    def test_slow_live_holder_is_not_robbed_by_other_processes(self):
        self.make_project()
        code = ("import importlib.util as u,sys,time;s=u.spec_from_file_location('l',sys.argv[1]);"
                "m=u.module_from_spec(s);s.loader.exec_module(m);"
                "lk=m.Lock(sys.argv[2]);lk.__enter__();print('ready',flush=True);time.sleep(4);lk.__exit__()")
        env = dict(os.environ)
        p = subprocess.Popen([sys.executable, "-c", code, SCRIPT, self.root], stdout=subprocess.PIPE, env=env)
        try:
            self.assertEqual(p.stdout.readline().strip(), b"ready")
            lock_dir = os.path.join(self.root, "Loom", loom.LOCK_NAME)
            old = time.time() - 3600  # older than the stale limit, but the holder is alive
            os.utime(lock_dir, (old, old))
            rc, o, e = self.run_sub("add", "z1", "--format", "demo", "--root", self.root,
                                    env={"LOOM_LOCK_STALE": "0.2", "LOOM_LOCK_TIMEOUT": "0.5"})
            self.assertEqual(rc, 1, e)
            self.assertIn("holds", e)
        finally:
            p.communicate()
        self.assertEqual(self.ledger()["items"], [])

    def test_many_parallel_adds_lose_nothing(self):
        self.make_project()
        procs = [subprocess.Popen([sys.executable, SCRIPT, "add", "p%d" % i, "--format", "demo"],
                                  cwd=self.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env=dict(os.environ, LOOM_LOCK_STALE="1", LOOM_LOCK_TIMEOUT="30"))
                 for i in range(12)]
        codes = []
        for p in procs:
            p.communicate()
            codes.append(p.returncode)
        self.assertEqual(codes, [0] * 12)
        self.assertEqual(len(self.ledger()["items"]), 12)

    def test_gate_leaves_no_lock_in_project_root(self):
        self.make_project()
        self.add_item("ep1")
        self.assertEqual(self.run_loom("gate", "ep1", "script")[0], 2)
        self.assertFalse(self.exists(loom.LOCK_NAME))
        self.assertFalse(self.exists("Loom/" + loom.LOCK_NAME))


if __name__ == "__main__":
    unittest.main()

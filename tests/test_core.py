import json
import os
import time
import unittest

from helpers import Base, loom, demo_config, can_symlink


class PathTests(Base):
    def test_safe_rel_ok(self):
        self.assertEqual(loom.safe_rel("Loom/items/a/script.md"), "Loom/items/a/script.md")

    def test_traversal_refused(self):
        for bad in ("../x", "a/../b", "a//b", "./a", "a/", "", "a/."):
            with self.assertRaises(loom.LoomError, msg=bad):
                loom.safe_rel(bad)

    def test_absolute_refused(self):
        for bad in ("/etc/passwd", "C:/x", "c:\\x", "~/x", "\\\\srv\\share"):
            with self.assertRaises(loom.LoomError, msg=bad):
                loom.safe_rel(bad)

    def test_backslash_and_ads_refused(self):
        for bad in ("a\\b", "a/b:stream", "a/b*", "a/b?", "a\x00b", "a/b."):
            with self.assertRaises(loom.LoomError, msg=repr(bad)):
                loom.safe_rel(bad)

    def test_deny_list_dirs_case_insensitive(self):
        for bad in ("Episodes/a.md", "x/CHARACTERS/a", "followers/a", "Analytics/x.csv",
                    "a/Research/b", "Prompts/p.md", "private/x"):
            with self.assertRaises(loom.LoomError, msg=bad):
                loom.safe_rel(bad)

    def test_deny_list_files(self):
        for bad in (".env", ".env.local", "a/key.pem", "my.key", "id_rsa", "api_secret.txt",
                    "credentials.json", "x/.npmrc", "t.token"):
            self.assertTrue(loom.is_denied(bad), bad)
        self.assertFalse(loom.is_denied("Loom/items/a/script.md"))

    def test_extra_excluded_folder(self):
        with self.assertRaises(loom.LoomError):
            loom.safe_rel("Drafts/a.md", ["drafts"])

    @unittest.skipUnless(os.name == "nt" or True, "")
    def test_symlink_refused(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks not permitted here")
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        os.symlink(real, os.path.join(self.root, "Loom"), target_is_directory=True)
        with self.assertRaises(loom.LoomError):
            loom.abs_in(self.root, "Loom/ledger.json")

    @unittest.skipUnless(os.name == "nt", "junctions are Windows only")
    def test_junction_refused(self):
        import subprocess
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        r = subprocess.run(["cmd", "/c", "mklink", "/J", os.path.join(self.root, "Loom"), real],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            self.skipTest("cannot create junction")
        with self.assertRaises(loom.LoomError):
            loom.abs_in(self.root, "Loom/ledger.json")


class IoTests(Base):
    def test_bom_and_crlf_json(self):
        p = self.w("a.json", '{"a": 1}', newline="\r\n", enc="utf-8-sig")
        self.assertEqual(loom.read_json(p, 1000, "t"), {"a": 1})

    def test_invalid_utf8(self):
        p = os.path.join(self.root, "a.json")
        with open(p, "wb") as f:
            f.write(b'{"a": "\xff\xfe"}')
        with self.assertRaises(loom.LoomError):
            loom.read_json(p, 1000, "t")

    def test_duplicate_keys_and_nan(self):
        for txt in ('{"a":1,"a":2}', '{"a": NaN}', '{"a": Infinity}', '[1,'):
            with self.assertRaises(loom.LoomError, msg=txt):
                loom.parse_json(txt, "t")

    def test_deep_nesting(self):
        with self.assertRaises(loom.LoomError):
            loom.parse_json("[" * 100000 + "]" * 100000, "t")

    def test_size_cap_before_parse(self):
        p = self.w("big.json", '{"a": "%s"}' % ("x" * 5000))
        with self.assertRaises(loom.LoomError) as c:
            loom.read_json(p, 100, "t")
        self.assertIn("too large", str(c.exception))

    def test_atomic_write_keeps_bak(self):
        p = os.path.join(self.root, "d", "f.json")
        loom.atomic_write(p, b"one")
        loom.atomic_write(p, b"two", bak=True)
        self.assertEqual(open(p, "rb").read(), b"two")
        self.assertEqual(open(p + ".bak", "rb").read(), b"one")
        self.assertEqual([n for n in os.listdir(os.path.dirname(p)) if n.endswith(".tmp")], [])

    def test_arabic_roundtrip(self):
        p = os.path.join(self.root, "ar.json")
        loom.atomic_write(p, loom.dumps({"t": "مرحبا بالعالم"}))
        self.assertEqual(loom.read_json(p, 1000, "t")["t"], "مرحبا بالعالم")
        self.assertIn("مرحبا", open(p, encoding="utf-8").read())


class LockTests(Base):
    def test_lock_excludes_and_releases(self):
        with loom.Lock(self.root):
            os.environ["LOOM_LOCK_TIMEOUT"] = "0.3"
            with self.assertRaises(loom.LoomError):
                with loom.Lock(self.root):
                    pass
        with loom.Lock(self.root):
            pass
        self.assertFalse(os.path.exists(os.path.join(self.root, loom.LOCK_NAME)))

    def test_stale_lock_is_broken(self):
        lp = os.path.join(self.root, loom.LOCK_NAME)
        os.mkdir(lp)
        old = time.time() - 3600
        os.utime(lp, (old, old))
        os.environ["LOOM_LOCK_STALE"] = "5"
        with loom.Lock(self.root):
            self.assertTrue(os.path.isdir(lp))
        self.assertFalse(os.path.exists(lp))
        self.assertEqual([n for n in os.listdir(self.root) if "stale" in n], [])

    def test_fresh_lock_not_broken(self):
        os.mkdir(os.path.join(self.root, loom.LOCK_NAME))
        os.environ["LOOM_LOCK_TIMEOUT"] = "0.3"
        with self.assertRaises(loom.LoomError) as c:
            with loom.Lock(self.root):
                pass
        self.assertIn("stale", str(c.exception))

    def test_lock_not_removed_by_non_owner(self):
        a = loom.Lock(self.root)
        a.__enter__()
        a.token = "someone-else"
        a.__exit__()
        self.assertTrue(os.path.isdir(os.path.join(self.root, loom.LOCK_NAME)))


class ConfigSchemaTests(Base):
    def bad(self, cfg, frag=None):
        with self.assertRaises(loom.LoomError) as c:
            loom.validate_config(cfg)
        if frag:
            self.assertIn(frag, str(c.exception))

    def test_demo_config_valid(self):
        loom.validate_config(demo_config())

    def test_unknown_top_field(self):
        c = demo_config()
        c["surprise"] = 1
        self.bad(c, "unknown")

    def test_bad_schema(self):
        c = demo_config()
        c["schema"] = 2
        self.bad(c)

    def test_placeholder_must_be_whole_token(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["argv"] = ["{python}", "x", "--a={item}"]
        self.bad(c, "whole tokens")

    def test_unknown_placeholder(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["argv"] = ["{python}", "{secret}"]
        self.bad(c)

    def test_channel_placeholder_not_in_build_or_gate(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["argv"] = ["{python}", "{channel}"]
        self.bad(c)

    def test_shell_refused_as_command(self):
        for sh in ("bash", "sh", "cmd", "cmd.exe", "powershell", "pwsh", "/bin/sh"):
            c = demo_config()
            c["adapters"]["build"]["render"]["argv"] = [sh, "-c", "echo hi"]
            self.bad(c, "shell")

    def test_abs_path_in_check_refused(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][0]["checks"][0]["paths"] = ["/etc/passwd"]
        self.bad(c)

    def test_denied_path_in_check_refused(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][0]["checks"][0]["paths"] = ["Episodes/{item}.md"]
        self.bad(c, "deny")

    def test_identity_pointer_denied(self):
        c = demo_config()
        c["identity"] = {"voice": "Characters/a.md"}
        self.bad(c)

    def test_timeout_bounds(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["timeout"] = 100000
        self.bad(c)

    def test_env_name_format(self):
        c = demo_config()
        c["adapters"]["build"]["render"]["env"] = ["bad name"]
        self.bad(c)

    def test_duplicate_stage_names(self):
        c = demo_config()
        c["formats"]["demo"]["stages"].append({"name": "script"})
        self.bad(c, "duplicate")

    def test_unknown_cmd_reference(self):
        c = demo_config()
        c["formats"]["demo"]["stages"][1]["checks"][0]["argv"] = ["{cmd:nope}"]
        self.bad(c, "unknown command")


class LedgerSchemaTests(Base):
    def item(self, **kw):
        it = {"id": "a1", "format": "demo", "stage": "script", "status": "active",
              "gates": [], "artifacts": [], "approvals": []}
        it.update(kw)
        return {"schema": 1, "items": [it]}

    def bad(self, led, frag=None):
        with self.assertRaises(loom.LoomError) as c:
            loom.validate_ledger(led)
        if frag:
            self.assertIn(frag, str(c.exception))

    def test_valid(self):
        loom.validate_ledger(self.item())

    def test_unknown_item_field(self):
        self.bad(self.item(extra=1), "unknown")

    def test_unknown_top_field(self):
        led = self.item()
        led["x"] = 1
        self.bad(led, "unknown")

    def test_bad_id(self):
        for i in ("../x", "a b", "-a", "a/b", "", "a" * 70, "a..b"):
            self.bad(self.item(id=i))

    def test_duplicate_ids(self):
        led = self.item()
        led["items"].append(dict(led["items"][0]))
        self.bad(led, "duplicate")

    def test_artifact_traversal_and_absolute(self):
        for a in ("../x", "/abs", "C:/x", "a\\b", "Episodes/x"):
            self.bad(self.item(artifacts=[a]))

    def test_bad_status_and_result(self):
        self.bad(self.item(status="weird"))
        self.bad(self.item(gates=[{"stage": "script", "result": "maybe", "date": "2026-01-01T00:00:00Z"}]))

    def test_bad_date(self):
        self.bad(self.item(gates=[{"stage": "script", "result": "pass", "date": "yesterday"}]))

    def test_approval_what_restricted(self):
        self.bad(self.item(approvals=[{"what": "delete everything", "channel": "none", "when": "now",
                                       "date": "2026-01-01T00:00:00Z"}]))

    def test_too_many_gates(self):
        g = {"stage": "script", "result": "pass", "date": "2026-01-01T00:00:00Z"}
        self.bad(self.item(gates=[g] * 201))

    def test_control_chars_in_detail(self):
        self.bad(self.item(gates=[{"stage": "script", "result": "pass", "date": "2026-01-01T00:00:00Z",
                                   "detail": "a\x1b[31mred"}]))

    def test_corrupt_ledger_fails_loudly_and_is_untouched(self):
        self.make_project()
        bad = "{ this is not json"
        self.w("Loom/ledger.json", bad)
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("corrupt", e)
        self.assertEqual(self.r("Loom/ledger.json"), bad)
        rc, o, e = self.run_loom("add", "x1", "--format", "demo")
        self.assertEqual(rc, 1)
        self.assertEqual(self.r("Loom/ledger.json"), bad)

    def test_corrupt_ledger_mentions_bak(self):
        self.make_project()
        self.run_ok("add", "x1", "--format", "demo")
        self.run_ok("add", "x2", "--format", "demo")  # creates .bak of good version
        self.w("Loom/ledger.json", "garbage")
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn(".bak", e)
        self.assertTrue(self.exists("Loom/ledger.json.bak"))

    def test_oversize_ledger_refused(self):
        self.make_project()
        self.w("Loom/ledger.json", '{"schema":1,"items":[],"pad":"%s"}' % ("x" * (1024 * 1024 + 10)))
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("too large", e)

    def test_bom_crlf_ledger_ok(self):
        self.make_project()
        self.w("Loom/ledger.json", json.dumps({"schema": 1, "items": []}, indent=2), newline="\r\n",
               enc="utf-8-sig")
        self.run_ok("status")

    def test_invalid_utf8_ledger(self):
        self.make_project()
        with open(os.path.join(self.root, "Loom", "ledger.json"), "wb") as f:
            f.write(b'{"schema":1,"items":[],"x":"\xff"}')
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("UTF-8", e)

    def test_ledger_symlinked_dir_refused(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks not permitted here")
        self.make_project()
        real = os.path.join(self.tmp, "elsewhere")
        os.rename(os.path.join(self.root, "Loom"), real)
        os.symlink(real, os.path.join(self.root, "Loom"), target_is_directory=True)
        rc, o, e = self.run_loom("status")
        self.assertEqual(rc, 1)
        self.assertIn("symlink", e)


if __name__ == "__main__":
    unittest.main()

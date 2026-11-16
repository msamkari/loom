"""Regression tests for command execution: no shell, PATH-only programs, env allow-list,
secret redaction forms, whole-tree kill (0.1.1)."""
import os
import stat
import sys
import time
import unittest

from helpers import Base, demo_config, loom, can_symlink

REFUSED = ["cmd", "cmd.exe", "cmd.exe.", "CMD.EXE ", "Cmd.Exe", "powershell", "powershell.exe", "pwsh",
           "bash", "sh", "zsh", "dash", "forfiles", "wscript", "cscript", "mshta", "rundll32", "env",
           "env.exe", "busybox", "x.bat", "x.BAT", "x.cmd", "x.com", "x.ps1", "x.vbs", "x.js", "x.wsf",
           "x.bat.", "tools/x", "./x", ".\\x", "C:\\Windows\\x", "x.", "x ", "", "a:b", "a|b", "a*b",
           "sh.exe", "bash.exe", "wsl"]
ALLOWED = ["git", "python", "python3.11", "node", "ffmpeg", "lahja", "ffmpeg.exe", "my-tool_2"]


def spawn_code(detached, marker, delay):
    """Python source for a command that starts a grandchild writing `marker` after `delay` s."""
    kw = ("creationflags=0x8|0x200" if (detached and os.name == "nt") else "")
    child = "import time;time.sleep(%s);open(%r,'w').write('x')" % (delay, marker)
    return ("import subprocess,sys;subprocess.Popen([sys.executable,'-c',%r]%s)"
            % (child, (", " + kw) if kw else ""))


class ProgramRulesTests(Base):
    def test_refused_names(self):
        for n in REFUSED:
            self.assertIsNotNone(loom.program_problem(n), repr(n))

    def test_allowed_names(self):
        for n in ALLOWED:
            self.assertIsNone(loom.program_problem(n), repr(n))

    def test_config_refuses_them_everywhere(self):
        for n in ("cmd.exe.", "x.bat", "forfiles", "env", "./tool"):
            for place in ("adapter", "check", "command"):
                c = demo_config()
                if place == "adapter":
                    c["adapters"]["build"]["render"]["argv"] = [n, "x"]
                elif place == "check":
                    c["formats"]["demo"]["stages"][1]["checks"] = [{"type": "command", "argv": [n, "x"]}]
                else:
                    c["commands"]["lint"] = [n, "x"]
                with self.assertRaises(loom.LoomError, msg=(n, place)):
                    loom.validate_config(c)

    def test_python_and_cmd_placeholders_still_allowed(self):
        loom.validate_config(demo_config())

    def test_unresolvable_program_does_not_start(self):
        rc, text, to = loom.run_command(["zz-no-such-tool-xyz", "a"], self.root, {})
        self.assertIsNone(rc)
        self.assertIn("not found", text)


class ResolutionTests(Base):
    def make_tool(self, folder, name):
        os.makedirs(folder, exist_ok=True)
        p = os.path.join(folder, name + (".exe" if os.name == "nt" else ""))
        with open(p, "wb") as f:
            f.write(b"x")
        os.chmod(p, 0o755)
        return p

    def with_path(self, *dirs):
        os.environ["PATH"] = os.pathsep.join(dirs)

    def test_found_on_path_outside_project(self):
        t = self.make_tool(os.path.join(self.tmp, "bin"), "zztool")
        self.with_path(os.path.join(self.tmp, "bin"))
        self.assertEqual(os.path.normcase(loom.find_program("zztool", self.root)), os.path.normcase(t))

    def test_project_folder_never_searched(self):
        self.make_tool(self.root, "zztool")
        self.make_tool(os.path.join(self.root, "bin"), "zztool")
        self.with_path(self.root, os.path.join(self.root, "bin"), ".", "")
        with self.assertRaises(loom.LoomError):
            loom.find_program("zztool", self.root)

    def test_current_folder_and_relative_entries_excluded(self):
        other = os.path.join(self.tmp, "cwdfolder")
        self.make_tool(other, "zztool")
        os.chdir(other)
        try:
            self.with_path(other, "relative/bin", ".")
            with self.assertRaises(loom.LoomError):
                loom.find_program("zztool", self.root)
        finally:
            os.chdir(self._cwd)

    def test_trailing_dot_and_script_names_not_resolved(self):
        self.make_tool(os.path.join(self.tmp, "bin"), "zztool")
        self.with_path(os.path.join(self.tmp, "bin"))
        for n in ("zztool.", "zztool.bat", "zztool ", "../bin/zztool"):
            with self.assertRaises(loom.LoomError):
                loom.find_program(n, self.root)

    @unittest.skipIf(os.name == "nt", "POSIX symlink to a shell")
    def test_symlink_to_shell_refused(self):
        if not can_symlink(self.tmp) or not os.path.exists("/bin/sh"):
            self.skipTest("no symlinks or /bin/sh")
        d = os.path.join(self.tmp, "bin")
        os.makedirs(d)
        os.symlink(os.path.realpath("/bin/sh"), os.path.join(d, "zzlink"))
        self.with_path(d)
        with self.assertRaises(loom.LoomError):
            loom.find_program("zzlink", self.root)

    def test_run_command_uses_resolved_absolute_path(self):
        rc, text, to = loom.run_command([sys.executable, "-c", "print('hi')"], self.root, {})
        self.assertEqual((rc, text.strip()), (0, "hi"))


class EnvTests(Base):
    CODE = "import os;print(','.join(sorted(os.environ)))"

    def run_env(self, names):
        rc, text, to = loom.run_command([sys.executable, "-c", self.CODE], self.root, {"env": names})
        self.assertEqual(rc, 0, text)
        return set(text.strip().upper().split(","))

    def test_only_allow_list_reaches_child(self):
        os.environ["LOOM_X_SECRET"] = "s3cr3t-value-1"
        os.environ["HOME"] = "/x"
        os.environ["USERPROFILE"] = "C:/x"
        got = self.run_env([])
        base = set(["PATH", "TEMP", "TMP", "TMPDIR", "LANG", "PYTHONIOENCODING", "SYSTEMROOT", "WINDIR",
                    "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_COLLATE", "LC_NUMERIC", "LC_TIME",
                    "LC_MONETARY", "SYSTEMDRIVE"])
        extra = got - base - set(["__PYVENV_LAUNCHER__", "PYTHONUTF8", "PYTHONHOME"])
        self.assertEqual(extra, set(), extra)
        self.assertNotIn("HOME", got)
        self.assertNotIn("USERPROFILE", got)
        self.assertNotIn("LOOM_X_SECRET", got)

    def test_config_name_alone_is_not_enough(self):
        os.environ["LOOM_X_SECRET"] = "s3cr3t-value-1"
        self.assertNotIn("LOOM_X_SECRET", self.run_env(["LOOM_X_SECRET"]))

    def test_allow_file_alone_is_not_enough(self):
        os.environ["LOOM_X_SECRET"] = "s3cr3t-value-1"
        self.allow_env("LOOM_X_SECRET")
        self.assertNotIn("LOOM_X_SECRET", self.run_env([]))

    def test_both_lists_pass_it(self):
        os.environ["LOOM_X_SECRET"] = "s3cr3t-value-1"
        self.allow_env("LOOM_X_SECRET")
        self.assertIn("LOOM_X_SECRET", self.run_env(["LOOM_X_SECRET"]))

    def test_bad_allow_file_names_ignored(self):
        self.allow_env("lower", "BAD NAME", "OK_NAME")
        self.assertEqual(loom.env_allow(), set(["OK_NAME"]))


class RedactionTests(Base):
    def test_forms_cover_reverse_base64_hex(self):
        import base64
        v = "sk-test-ABCDEFGH"
        f = loom.secret_forms(v)
        for x in (v, v[::-1], base64.b64encode(v.encode()).decode(), v.encode().hex(), v.encode().hex().upper(),
                  base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")):
            self.assertIn(x, f)

    def test_sanitise_hides_all_forms(self):
        import base64
        v = "sk-test-ABCDEFGH"
        raw = ("plain %s rev %s b64 %s hex %s" % (v, v[::-1], base64.b64encode(v.encode()).decode(),
                                                   v.encode().hex())).encode()
        text = loom.sanitise(raw, len(raw), 10000, [v])
        for x in (v, v[::-1], base64.b64encode(v.encode()).decode(), v.encode().hex()):
            self.assertNotIn(x, text)
        self.assertEqual(text.count("[redacted]"), 4)

    def test_zero_width_interleaved_secret_still_hidden(self):
        v = "sk-test-ABCDEFGH"
        raw = "\u200b".join(v).encode("utf-8")
        text = loom.sanitise(raw, len(raw), 10000, [v])
        self.assertNotIn(v, text)
        self.assertIn("[redacted]", text)

    def test_end_to_end_child_prints_reversed_secret(self):
        os.environ["LOOM_X_SECRET"] = "sk-test-ABCDEFGH"
        self.allow_env("LOOM_X_SECRET")
        code = "import os;v=os.environ['LOOM_X_SECRET'];print(v[::-1]);print(v)"
        rc, text, to = loom.run_command([sys.executable, "-c", code], self.root, {"env": ["LOOM_X_SECRET"]})
        self.assertNotIn("HGFEDCBA", text)
        self.assertNotIn("ABCDEFGH", text)


class TreeKillTests(Base):
    def setUp(self):
        super().setUp()
        if os.name == "nt":
            try:
                loom.WinJob().close()
            except Exception:
                self.skipTest("job objects unavailable here")

    def marker(self):
        return os.path.join(self.tmp, "marker.txt")

    def test_grandchild_does_not_survive_normal_exit(self):
        code = spawn_code(True, self.marker().replace("\\", "/"), 3)
        t0 = time.time()
        rc, text, to = loom.run_command([sys.executable, "-c", code], self.root, {"timeout": 20})
        self.assertEqual(rc, 0, text)
        self.assertFalse(to)
        time.sleep(6)
        self.assertFalse(os.path.exists(self.marker()), "a detached grandchild outlived the command")
        self.assertLess(time.time() - t0, 30)

    def test_grandchild_does_not_survive_timeout(self):
        inner = spawn_code(True, self.marker().replace("\\", "/"), 3)
        code = inner + ";import time;time.sleep(30)"
        rc, text, to = loom.run_command([sys.executable, "-c", code], self.root, {"timeout": 2})
        self.assertTrue(to)
        time.sleep(6)
        self.assertFalse(os.path.exists(self.marker()))

    def test_plain_child_dies_on_timeout(self):
        child = "import time;time.sleep(3);open(%r,'w').write('x')" % self.marker().replace("\\", "/")
        code = ("import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(30)" % child)
        rc, text, to = loom.run_command([sys.executable, "-c", code], self.root, {"timeout": 2})
        self.assertTrue(to)
        time.sleep(5)
        self.assertFalse(os.path.exists(self.marker()))

    def test_timeout_returns_promptly(self):
        t0 = time.time()
        rc, text, to = loom.run_command([sys.executable, "-c", "import time;time.sleep(60)"], self.root,
                                        {"timeout": 1})
        self.assertTrue(to)
        self.assertLess(time.time() - t0, 15)

    def test_exit_code_and_output_still_reported(self):
        rc, text, to = loom.run_command([sys.executable, "-c", "print('out');import sys;sys.exit(4)"],
                                        self.root, {})
        self.assertEqual((rc, text.strip(), to), (4, "out", False))

    def test_output_cap_and_flood(self):
        rc, text, to = loom.run_command([sys.executable, "-c", "print('A'*3000000)"], self.root,
                                        {"max_output": 1000})
        self.assertIn("truncated", text)
        self.assertLess(len(text), 1300)


if __name__ == "__main__":
    unittest.main()

import json
import os
import re
import shutil
import unittest

from helpers import Base, loom, HERE

ROOT = os.path.dirname(HERE)


def read(rel):
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


class ExampleTests(Base):
    def test_example_config_and_ledger_validate(self):
        cfg = json.loads(read("examples/demo/loom.config.json"))
        loom.validate_config(cfg)
        loom.validate_ledger(json.loads(read("examples/demo/Loom/ledger.json")), loom.config_extra(cfg))

    def test_status_and_next_on_example_copy(self):
        dst = os.path.join(self.tmp, "demo")
        shutil.copytree(os.path.join(ROOT, "examples", "demo"), dst)
        rc, o, e = self.run_loom("status", cwd=dst)
        self.assertEqual(rc, 0, e)
        self.assertIn("demo-001", o)
        rc, o, e = self.run_loom("next", cwd=dst)
        self.assertIn("demo-002 [script]: gate", o)
        self.assertIn("demo-001 [language]: blocked", o)


class PackageTests(unittest.TestCase):
    def test_manifest(self):
        m = json.loads(read(".claude-plugin/plugin.json"))
        self.assertEqual(m["name"], "loom")
        self.assertEqual(m["version"], "0.1.2")
        self.assertEqual(m["license"], "MIT")
        self.assertNotIn("icon", m)

    def test_skill_allowed_tools_exact(self):
        t = read("skills/loom/SKILL.md")
        line = [l for l in t.splitlines() if l.startswith("allowed-tools:")][0]
        entries = [x.strip() for x in line[len("allowed-tools:"):].split(",")]
        self.assertEqual(entries, [
            "Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/loom.py status *)",
            "Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/loom.py next *)",
            "Bash(python ${CLAUDE_PLUGIN_ROOT}/scripts/loom.py gate *)"])

    def test_adopt_skill_pre_approves_nothing(self):
        self.assertNotIn("allowed-tools", read("skills/loom-adopt/SKILL.md"))

    def test_skill_commands_match_allowed_form(self):
        t = read("skills/loom/SKILL.md")
        for sub in ("status", "next", "gate"):
            self.assertIn("python ${CLAUDE_PLUGIN_ROOT}/scripts/loom.py %s " % sub, t)

    def test_skills_mention_key_rules(self):
        t = read("skills/loom/SKILL.md")
        for s in ("data", "never run", "LOOM_NO_PUBLISH", "approve", "dry-run"):
            self.assertIn(s.lower(), t.lower())

    def test_no_personal_paths_emails_or_keys(self):
        drive = "C" + ":"
        pat = re.compile(drive + r"\\Users|" + drive + r"/Users|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}|"
                         r"(^|[^A-Za-z0-9])(sk-|ghp_|github_pat_|AIza|xox[bp]-|AKIA)[A-Za-z0-9_-]{16,}")
        for dp, dns, fns in os.walk(ROOT):
            dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
            for f in fns:
                if f.endswith((".pyc", ".png")):
                    continue
                p = os.path.join(dp, f)
                if ".github" in p.split(os.sep):
                    continue
                with open(p, encoding="utf-8") as fh:
                    self.assertIsNone(pat.search(fh.read()), p)

    def test_script_py38_syntax_markers(self):
        src = read("scripts/loom.py")
        for bad in ("removeprefix", "removesuffix", "match ", ":= "):
            self.assertNotIn(bad, src.replace("# ", ""))
        self.assertIsNone(re.search(r"\bdict\[|\blist\[|\btuple\[", src))

    def test_python38_grammar_for_script_and_tests(self):
        import ast
        for rel in ("scripts/loom.py", "tests/helpers.py", "tests/test_trust.py", "tests/test_exec.py",
                    "tests/test_output.py", "tests/test_recovery.py", "tests/test_round3.py"):
            ast.parse(read(rel), feature_version=(3, 8))

    def test_skills_document_trust_and_keep_allowed_tools(self):
        t = read("skills/loom/SKILL.md")
        self.assertIn("`trust`", t)
        self.assertIn("not pre-approved", t)
        self.assertIn("reviewed", t)
        self.assertNotIn("loom.py trust", t.split("---", 2)[1])
        self.assertIn("trust", read("skills/loom-adopt/SKILL.md"))

    def test_readme_claims_and_install_line(self):
        r = read("README.md")
        self.assertIn("/plugin marketplace add msamkari/samkari-plugins", r)
        self.assertIn("/plugin install loom@samkari-plugins", r)
        self.assertIn("trust", r)
        self.assertNotIn("never a shell (a shell as the program is refused)", r)
        self.assertIn("Known limits", read("CHANGELOG.md"))

    def test_no_third_party_imports(self):
        import sys
        src = read("scripts/loom.py")
        mods = set(re.findall(r"^import (\w+)", src, re.M)) | set(re.findall(r"^from (\w+) import", src, re.M))
        std = set(getattr(sys, "stdlib_module_names", mods))
        self.assertTrue(mods <= std, mods - std)

    def test_does_not_read_whole_environ(self):
        src = read("scripts/loom.py")
        self.assertNotIn("dict(os.environ)", src)
        self.assertNotIn("os.environ.copy", src)
        self.assertNotIn("os.environ.items", src)
        self.assertNotIn("**os.environ", src)

    def test_no_shell_true(self):
        self.assertNotIn("shell=True", read("scripts/loom.py"))
        self.assertNotIn("os.system", read("scripts/loom.py"))


if __name__ == "__main__":
    unittest.main()

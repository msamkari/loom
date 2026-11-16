"""Shared test helpers. Everything runs in temp folders with LOOM_HOME relocated."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "loom.py")

spec = importlib.util.spec_from_file_location("loom", SCRIPT)
loom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loom)

LINT = (
    "import sys,io\n"
    "t=io.open(sys.argv[-1],encoding='utf-8-sig').read()\n"
    "print('found BAD word' if 'BAD' in t else 'clean')\n"
    "sys.exit(2 if 'BAD' in t else 0)\n"
)
BUILD = (
    "import sys,os\n"
    "item=sys.argv[1]\n"
    "os.makedirs('Loom/items/'+item,exist_ok=True)\n"
    "open('Loom/items/'+item+'/out.txt','w').write('built '+item)\n"
    "print('built',item)\n"
)
POST = (
    "import sys\n"
    "open('posted.log','a').write(' '.join(sys.argv[1:])+'\\n')\n"
    "print('posted', ' '.join(sys.argv[1:]))\n"
)


def py(script, *extra):
    return ["{python}", script] + list(extra)


def demo_config(**over):
    cfg = {
        "schema": 1, "pack": "demo", "shadow_mode": False,
        "channels": ["chan1", "chan2"],
        "commands": {"lint": ["{python}", "tools/lint.py"]},
        "formats": {"demo": {"stages": [
            {"name": "script", "checks": [{"type": "files", "paths": ["Loom/items/{item}/script.md"]}]},
            {"name": "language", "checks": [{"type": "command",
                                             "argv": ["{cmd:lint}", "{itempath:script.md}"]}]},
            {"name": "research", "checks": [{"type": "facts", "file": "Loom/items/{item}/facts.json"}]},
            {"name": "voice", "requires_approval": True,
             "checks": [{"type": "checklist", "file": "Loom/items/{item}/pre_voice.md"}]},
            {"name": "publish", "requires_approval": True},
        ]}},
        "adapters": {
            "build": {"render": {"argv": py("tools/build.py", "{item}"), "produces": ["Loom/items/{item}/out.txt"]}},
            "stage": {"draft": {"argv": py("tools/post.py", "draft", "{item}", "{channel}")}},
            "publish": {"post": {"argv": py("tools/post.py", "publish", "{item}", "{channel}")}},
            "schedule": {"sched": {"argv": py("tools/post.py", "schedule", "{item}", "{channel}", "{when}")}},
        },
    }
    cfg.update(over)
    return cfg


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="loomtest_")
        self.root = os.path.join(self.tmp, "proj")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.root)
        self._env = dict(os.environ)
        os.environ["LOOM_HOME"] = self.home
        for k in ("LOOM_NOW", "LOOM_NO_PUBLISH", "LOOM_LOCK_STALE", "LOOM_LOCK_TIMEOUT"):
            os.environ.pop(k, None)
        self._cwd = os.getcwd()

    def tearDown(self):
        os.chdir(self._cwd)
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- files
    def w(self, rel, text, root=None, newline="\n", enc="utf-8"):
        p = os.path.join(root or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(text.replace("\n", newline).encode(enc))
        return p

    def r(self, rel, root=None):
        with open(os.path.join(root or self.root, *rel.split("/")), "rb") as f:
            return f.read().decode("utf-8")

    def exists(self, rel):
        return os.path.lexists(os.path.join(self.root, *rel.split("/")))

    def jr(self, rel):
        return json.loads(self.r(rel))

    # --- project
    def make_project(self, cfg=None, tools=True):
        self.w("loom.config.json", json.dumps(cfg or demo_config(), indent=2))
        self.w("Loom/ledger.json", json.dumps({"schema": 1, "items": []}))
        if tools:
            self.w("tools/lint.py", LINT)
            self.w("tools/build.py", BUILD)
            self.w("tools/post.py", POST)

    def set_config(self, cfg):
        self.w("loom.config.json", json.dumps(cfg, indent=2))

    def ledger(self):
        return self.jr("Loom/ledger.json")

    def set_ledger(self, led):
        self.w("Loom/ledger.json", json.dumps(led))

    def add_item(self, iid="ep1", fmt="demo"):
        self.run_ok("add", iid, "--format", fmt, "--root", self.root)

    # --- running (in-process)
    def run_loom(self, *args, cwd=None):
        os.chdir(cwd or self.root)
        o, e = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                rc = loom.main(list(args))
            except SystemExit as x:
                rc = x.code
        os.chdir(self._cwd)
        return rc, o.getvalue(), e.getvalue()

    def run_ok(self, *args, **kw):
        rc, o, e = self.run_loom(*args, **kw)
        self.assertEqual(rc, 0, "rc=%s out=%s err=%s" % (rc, o, e))
        return o

    def run_sub(self, *args, cwd=None, env=None):
        e = dict(os.environ)
        e.update(env or {})
        p = subprocess.run([sys.executable, SCRIPT] + list(args), cwd=cwd or self.root,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
        return p.returncode, p.stdout.decode("utf-8"), p.stderr.decode("utf-8")

    def to_stage(self, iid, stage):
        """Force an item to a stage in the ledger (test shortcut)."""
        led = self.ledger()
        for it in led["items"]:
            if it["id"] == iid:
                it["stage"] = stage
        self.set_ledger(led)


def can_symlink(tmp):
    t = os.path.join(tmp, "_lnk_t")
    try:
        os.symlink(tmp, t)
    except (OSError, NotImplementedError, AttributeError):
        return False
    os.unlink(t)
    return True

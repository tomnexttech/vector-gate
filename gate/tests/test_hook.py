# -*- coding: utf-8 -*-
"""Hook and CLI tests. State goes to a temporary VGATE_HOME; nothing outside it is touched."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from vector_gate import cli, hook  # noqa: E402


class HookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.home = hook.Home(self.t / "home")
        self.ws = self.t / "ws"
        self.ws.mkdir()
        (self.ws / "a.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, tool, inp, prompt="p1", session="s1"):
        ev = {"session_id": session, "prompt_id": prompt, "cwd": str(self.ws), "permission_mode": "default",
              "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp, "tool_use_id": "tu"}
        out = hook.run(json.dumps(ev), self.home)
        if not out:
            return None, ""
        h = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(h["hookEventName"], "PreToolUse")
        return h["permissionDecision"], h["permissionDecisionReason"]

    def test_hard_denials_deny_and_soft_ones_ask(self):
        self.assertEqual(self.call("Read", {"file_path": str(self.ws / ".env")})[0], "deny")
        self.assertEqual(self.call("Bash", {"command": "format c: /q"})[0], "deny")
        self.assertEqual(self.call("Edit", {"file_path": "~/.claude/settings.json"})[0], "deny")
        self.assertEqual(self.call("Bash", {"command": "vgate resume"})[0], "deny")
        self.assertEqual(self.call("Bash", {"command": "rm -rf build"})[0], "ask")
        self.assertEqual(self.call("Bash", {"command": "git push origin main"})[0], "ask")
        self.assertEqual(self.call("Write", {"file_path": str(self.t / "elsewhere.txt"), "content": "x"})[0], "ask")

    def test_ordinary_work_stays_silent(self):
        for tool, inp in (("Read", {"file_path": str(self.ws / "a.py")}),
                          ("Edit", {"file_path": str(self.ws / "a.py"), "old_string": "1", "new_string": "2"}),
                          ("Write", {"file_path": str(self.ws / "new.py"), "content": "y"}),
                          ("Bash", {"command": "python -m pytest -q"}),
                          ("Bash", {"command": "git status"})):
            self.assertEqual(self.call(tool, inp), (None, ""), (tool, inp))

    def test_high_risk_asks(self):
        self.assertEqual(self.call("Bash", {"command": "echo hi > a.py"})[0], "ask")       # overwrite, no backup
        final = self.ws / "final"
        final.mkdir()
        (final / "report.md").write_text("x", encoding="utf-8")
        self.assertEqual(self.call("Edit", {"file_path": str(final / "report.md"), "old_string": "x",
                                            "new_string": "y"})[0], "ask")

    def test_outside_text_raises_the_rest_of_the_turn(self):
        self.assertEqual(self.call("Bash", {"command": "make"}, prompt="t1"), (None, ""))
        self.assertEqual(self.call("WebFetch", {"url": "https://example.com"}, prompt="t1"), (None, ""))
        d, why = self.call("Bash", {"command": "make"}, prompt="t1")
        self.assertEqual(d, "ask")
        self.assertIn("outside text", why)
        self.assertEqual(self.call("Bash", {"command": "make"}, prompt="t2"), (None, ""))   # a new turn starts clean
        web = [r for r in self.home.ledger.tail(20) if r["tool"] == "WebFetch"][0]
        self.assertEqual((web["code"], web["summary"]), ("web", "Fetch https://example.com"))

    def test_first_call_of_a_turn_records_taint_as_unknown(self):
        self.call("Bash", {"command": "make"}, prompt="fresh")
        self.call("Bash", {"command": "make"}, prompt="fresh")
        recs = [r for r in self.home.ledger.tail(10) if r.get("prompt") == "fresh"]
        self.assertEqual([r["tainted"] for r in recs], [None, False])

    def test_stop_denies_everything_but_reading(self):
        self.home.path.mkdir(parents=True, exist_ok=True)
        self.home.stop_file.write_text("1", encoding="utf-8")
        self.assertEqual(self.call("Read", {"file_path": str(self.ws / "a.py")}), (None, ""))
        self.assertEqual(self.call("Bash", {"command": "git status"}), (None, ""))
        for tool, inp in (("Edit", {"file_path": str(self.ws / "a.py")}), ("Bash", {"command": "make"}),
                          ("mcp__cad__create_wall", {})):
            d, why = self.call(tool, inp)
            self.assertEqual(d, "deny")
            self.assertIn("STOP", why)

    def test_every_call_is_recorded_and_the_chain_holds(self):
        self.call("Read", {"file_path": str(self.ws / "a.py")})
        self.call("Bash", {"command": "rm -rf build"})
        self.call("Read", {"file_path": str(self.ws / ".env")})
        recs = self.home.ledger.tail(10)
        self.assertEqual([r["decision"] for r in recs], ["pass", "ask", "deny"])
        self.assertEqual([r["level"] for r in recs], ["L0", "L2", "L3"])
        self.assertTrue(self.home.ledger.verify()["ok"])

    def test_secrets_never_reach_the_record(self):
        key = "sk-" + "ant-" + "abcdefghijklmnopqrstuvwx"
        self.call("Bash", {"command": f"python tool.py --key={key}"})
        raw = "".join(p.read_text(encoding="utf-8") for p in self.home.ledger.files())
        self.assertNotIn("abcdefghijklmnopqrstuvwx", raw)

    def test_failures_lean_towards_asking(self):
        out = json.loads(hook.run("not json", self.home))["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "ask")
        with mock.patch.object(hook, "judge", side_effect=RuntimeError("boom")):
            self.assertEqual(hook.run(json.dumps({"tool_name": "Read", "tool_input": {}}), self.home), "")
            out = json.loads(hook.run(json.dumps({"tool_name": "Bash", "tool_input": {}}), self.home))
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        with mock.patch.object(self.home.ledger, "append", side_effect=OSError("disk full")):
            d, why = self.call("Bash", {"command": "make"})
            self.assertEqual(d, "ask")
            self.assertIn("audit", why)

    def test_config_adds_workspaces_and_protected_places(self):
        other = self.t / "other"
        self.home.path.mkdir(parents=True, exist_ok=True)
        (self.home.path / "config.json").write_text(json.dumps({"workspaces": [str(other)],
                                                                "protected": [r"\\keep\\"]}), encoding="utf-8")
        self.assertEqual(self.call("Write", {"file_path": str(other / "x.txt"), "content": "x"}), (None, ""))
        (self.ws / "keep").mkdir()
        (self.ws / "keep" / "k.md").write_text("x", encoding="utf-8")
        self.assertEqual(self.call("Edit", {"file_path": str(self.ws / "keep" / "k.md")})[0], "ask")


class ProcessTest(unittest.TestCase):
    """The real thing: separate processes, as Claude Code runs them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = dict(os.environ, VGATE_HOME=str(Path(self.tmp.name) / "home"), PYTHONPATH=str(ROOT))

    def tearDown(self):
        self.tmp.cleanup()

    def test_hook_process_speaks_the_protocol(self):
        ev = {"session_id": "s", "prompt_id": "p", "cwd": self.tmp.name, "tool_name": "Bash",
              "tool_input": {"command": "format c: /q"}}
        r = subprocess.run([sys.executable, "-m", "vector_gate", "hook"], input=json.dumps(ev).encode(), env=self.env,
                           capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_parallel_hooks_keep_one_chain(self):
        code = ("import json,sys; from vector_gate import hook\n"
                "for i in range(15):\n"
                "    hook.run(json.dumps({'session_id':'s','prompt_id':sys.argv[1],'cwd':'.',"
                "'tool_name':'Bash','tool_input':{'command':'make'}}))\n")
        ps = [subprocess.Popen([sys.executable, "-c", code, str(i)], env=self.env) for i in range(4)]
        for p in ps:
            self.assertEqual(p.wait(timeout=120), 0)
        home = hook.Home(self.env["VGATE_HOME"])
        v = home.ledger.verify()
        self.assertEqual((v["ok"], v["n"]), (True, 60), v)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = str(Path(self.tmp.name) / "home")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = cli.main(["--home", self.home, *args])
        return rc, buf.getvalue()

    def test_stop_then_resume_needs_a_human(self):
        self.assertEqual(self.run_cli("stop")[0], 0)
        self.assertTrue(hook.Home(self.home).stopped())
        with mock.patch("sys.stdin", io.StringIO("RESUME\n")):            # not a terminal: an agent's pipe
            rc, out = self.run_cli("resume")
        self.assertEqual(rc, 2)
        self.assertTrue(hook.Home(self.home).stopped())
        self.assertEqual(self.run_cli("verify")[0], 0)

    def test_verify_reports_tampering(self):
        h = hook.Home(self.home)
        for i in range(3):
            h.ledger.append({"kind": "decision", "ts": 1.0e9 + i, "n": i})
        self.assertEqual(self.run_cli("verify")[0], 0)
        f = h.ledger.files()[0]
        f.write_bytes(f.read_bytes().replace(b'"n":1', b'"n":9'))
        rc, out = self.run_cli("verify")
        self.assertEqual(rc, 1)
        self.assertIn("BROKEN", out)

    def test_check_and_settings(self):
        rc, out = self.run_cli("check", "Bash", json.dumps({"command": "rm -rf x"}), "--cwd", self.tmp.name)
        self.assertEqual(json.loads(out)["decision"], "ask")
        self.assertEqual(hook.Home(self.home).ledger.files(), [])                # a dry run records nothing
        def args_of(out):
            s = json.loads(out)
            self.assertEqual(s["hooks"]["PreToolUse"][0]["matcher"], "*")
            return s["hooks"]["PreToolUse"][0]["hooks"][0]["args"]
        with mock.patch.object(cli, "importable", return_value=True):            # installed: run the module
            self.assertEqual(args_of(self.run_cli("settings")[1]), ["-I", "-m", "vector_gate", "hook"])
        with mock.patch.object(cli, "importable", return_value=False):           # not installed: the launcher
            self.assertEqual(args_of(self.run_cli("settings")[1]), ["-I", str(cli.LAUNCHER), "hook"])
        self.assertTrue(cli.LAUNCHER.is_file())

    def test_probe_is_not_fooled_by_the_current_folder(self):
        old = os.getcwd()
        os.chdir(str(ROOT))                    # vector_gate imports from here; Claude Code starts hooks elsewhere
        try:
            probed = cli.importable(sys.executable, False)
        finally:
            os.chdir(old)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        truth = subprocess.run([sys.executable, "-c", "import vector_gate"], cwd=self.tmp.name, env=env,
                               capture_output=True, timeout=60).returncode == 0
        self.assertEqual(probed, truth)

    def test_launcher_runs_the_hook_without_install(self):
        ev = {"session_id": "s", "prompt_id": "p", "cwd": self.tmp.name, "tool_name": "Read",
              "tool_input": {"file_path": ".env"}}
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["VGATE_HOME"] = self.home
        r = subprocess.run([sys.executable, "-I", str(cli.LAUNCHER), "hook"], input=json.dumps(ev).encode(),
                           env=env, capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()

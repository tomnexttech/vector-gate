# -*- coding: utf-8 -*-
"""vgate — command line.

  vgate hook                 the PreToolUse hook (Claude Code runs this; reads the event from stdin)
  vgate check TOOL JSON      dry run: what would the gate say? (nothing is recorded)
  vgate verify               check the audit chain
  vgate status               STOP or running, the chain, the last decisions
  vgate stop                 deny everything except reading, in every session, until resumed
  vgate resume               end STOP mode (only from a real terminal: an agent cannot resume)
  vgate settings             print the hook block for ~/.claude/settings.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import __version__, hook


def _home(a) -> hook.Home:
    return hook.Home(a.home)


def cmd_hook(a) -> int:
    return hook.main()


def cmd_check(a) -> int:
    try:
        inp = json.loads(a.input or "{}")
    except ValueError as e:
        print(f"input is not JSON: {e}")
        return 2
    ev = {"tool_name": a.tool, "tool_input": inp, "cwd": a.cwd or os.getcwd(), "session_id": "check",
          "prompt_id": f"check-{time.time()}"}
    j = hook.judge(ev, _home(a))
    r = j["record"]
    print(json.dumps({"decision": j["decision"] or "pass (Claude Code decides)", "reason": j["reason"],
                      "risk": r["risk"], "reversible": r["reversible"], "level": r["level"], "code": r["code"]},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_verify(a) -> int:
    v = _home(a).ledger.verify()
    if v["ok"]:
        print(f"OK - {v['n']} records, chain unbroken")
        return 0
    print(f"BROKEN - {v['error']} ({v['file']} line {v['line']}, after {v['n']} good records)")
    return 1


def cmd_status(a) -> int:
    h = _home(a)
    v = h.ledger.verify()
    print(f"vgate {__version__}  home: {h.path}")
    print("mode: " + ("STOP (everything except reading is denied)" if h.stopped() else "running"))
    print(f"audit: {v['n']} records, " + ("chain OK" if v["ok"] else f"chain BROKEN at {v['file']} line {v['line']}"))
    for r in h.ledger.tail(a.n):
        if r.get("kind") != "decision":
            print(f"  {time.strftime('%m-%d %H:%M:%S', time.localtime(r.get('ts') or 0))}  [{r.get('kind')}]")
            continue
        print(f"  {time.strftime('%m-%d %H:%M:%S', time.localtime(r.get('ts') or 0))}  {r.get('decision'):<5} "
              f"{r.get('level')}  {r.get('tool')}: {r.get('summary')}")
    return 0 if v["ok"] else 1


def cmd_stop(a) -> int:
    h = _home(a)
    h.path.mkdir(parents=True, exist_ok=True)
    h.stop_file.write_text(str(time.time()), encoding="utf-8")
    h.ledger.append({"v": 1, "kind": "stop", "ts": time.time(), "by": "cli"})
    print("STOP: every tool except reading is now denied. Run `vgate resume` in your own terminal to continue.")
    return 0


def cmd_resume(a) -> int:
    h = _home(a)
    if not h.stopped():
        print("not stopped")
        return 0
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("refused: resume only from an interactive terminal (an agent cannot lift STOP)")
        return 2
    if input("type RESUME to lift STOP: ").strip() != "RESUME":
        print("cancelled")
        return 1
    h.stop_file.unlink()
    h.ledger.append({"v": 1, "kind": "resume", "ts": time.time(), "by": "cli"})
    print("resumed")
    return 0


def importable(python: str, isolated: bool) -> bool:
    """Can this interpreter import vector_gate on its own, with or without -I? Asked from an empty folder and without
    PYTHONPATH, because Claude Code starts the hook from the session's folder, not from here."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    try:
        with tempfile.TemporaryDirectory(prefix="vgate-probe-") as empty:
            r = subprocess.run([python, *(["-I"] if isolated else []), "-c", "import vector_gate"], env=env, cwd=empty,
                               capture_output=True, timeout=60)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


LAUNCHER = Path(__file__).resolve().parent.parent / "run_vgate.py"


def hook_args(python: str) -> list:
    """How Claude Code should start the hook. -I (ignore PYTHON* variables and the user site) whenever it works:
    the installed module first, else the launcher next to the package (no install needed)."""
    if importable(python, True):
        return ["-I", "-m", "vector_gate", "hook"]
    if importable(python, False):
        return ["-m", "vector_gate", "hook"]
    return ["-I", str(LAUNCHER), "hook"]


def settings_block(python: str = None, args: list = None) -> dict:
    """The hook registration, in exec form (no shell, so paths with spaces are safe)."""
    python = python or sys.executable
    return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": python, "args": args or hook_args(python), "timeout": 10}]}]}}


def cmd_settings(a) -> int:
    s = settings_block()
    args = s["hooks"]["PreToolUse"][0]["hooks"][0]["args"]
    if str(LAUNCHER) in args and not LAUNCHER.is_file():
        print("vector_gate is not installed and run_vgate.py is missing; Claude Code could not run the hook.", file=sys.stderr)
        return 1
    print(json.dumps(s, indent=2))
    return 0


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(prog="vgate", description="VECTOR GATE: stop an AI agent before it does "
                                                           "something it cannot undo.")
    ap.add_argument("--home", help="state folder (default ~/.vector/gate, or $VGATE_HOME)")
    ap.add_argument("--version", action="version", version=f"vgate {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook").set_defaults(fn=cmd_hook)
    c = sub.add_parser("check")
    c.add_argument("tool")
    c.add_argument("input", nargs="?", default="{}")
    c.add_argument("--cwd")
    c.set_defaults(fn=cmd_check)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    s = sub.add_parser("status")
    s.add_argument("-n", type=int, default=10)
    s.set_defaults(fn=cmd_status)
    sub.add_parser("stop").set_defaults(fn=cmd_stop)
    sub.add_parser("resume").set_defaults(fn=cmd_resume)
    sub.add_parser("settings").set_defaults(fn=cmd_settings)
    a = ap.parse_args(argv)
    return a.fn(a)

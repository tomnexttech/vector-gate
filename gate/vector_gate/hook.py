# -*- coding: utf-8 -*-
"""Claude Code PreToolUse hook. Reads one event from stdin, prints a decision (or nothing), records it.

The hook keeps your autonomy: it speaks only when it must.
  hard denial (policy)                       → deny
  soft denial (policy)                       → ask   (a human may approve)
  high risk (assess), e.g. after web text    → ask
  everything else                            → no output: Claude Code's own permission flow decides
Silence never approves anything; it only leaves the decision where it already was.

STOP mode (`vgate stop`): everything except reading is denied until a human runs `vgate resume`.
Internal error: reading tools pass through, everything else is asked (fail towards asking).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

from . import gate, policy

ENV_HOME = "VGATE_HOME"


class Home:
    """~/.vector/gate: audit/, sessions/, STOP, config.json."""

    def __init__(self, path=None):
        self.path = Path(path or os.environ.get(ENV_HOME) or Path.home() / ".vector" / "gate")
        self.ledger = gate.Ledger(self.path / "audit")

    @property
    def stop_file(self) -> Path:
        return self.path / "STOP"

    def stopped(self) -> bool:
        return self.stop_file.exists()

    def config(self) -> dict:
        """{"workspaces": [extra writable folders], "protected": [regex, ...]}. Missing or broken = defaults."""
        try:
            c = json.loads((self.path / "config.json").read_text(encoding="utf-8"))
            return c if isinstance(c, dict) else {}
        except (OSError, ValueError):
            return {}

    def extra_protected(self) -> list:
        out = []
        for p in self.config().get("protected") or []:
            try:
                out.append(re.compile(str(p), re.I))
            except re.error:
                continue
        return out

    # taint is kept per turn (session + prompt)
    def _turn_file(self, session, prompt) -> Path:
        safe = lambda s: re.sub(r"[^A-Za-z0-9_-]", "_", str(s or "-"))[:80]  # noqa: E731
        return self.path / "sessions" / f"{safe(session)}__{safe(prompt)}.json"

    def tainted(self, session, prompt):
        """True / False / None. None: this is the first call of the turn we have seen (earlier ones are unknown)."""
        try:
            d = json.loads(self._turn_file(session, prompt).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return None
        return bool(d.get("taint"))

    def note_turn(self, session, prompt, taint: str = ""):
        p = self._turn_file(session, prompt)
        try:
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                d = {"since": time.time(), "taint": []}
            if taint and taint not in d["taint"]:
                d["taint"].append(taint)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass


def _exists(fp, cwd):
    if not fp:
        return None
    try:
        return os.path.isfile(policy._abs(fp, cwd) if cwd else policy._norm(fp))
    except OSError:
        return None


def judge(ev: dict, home: Home) -> dict:
    """{"decision": "deny"|"ask"|None, "reason": str, "record": dict}. No output is printed here."""
    tool = str(ev.get("tool_name") or "")
    inp = ev.get("tool_input") if isinstance(ev.get("tool_input"), dict) else {}
    cwd = str(ev.get("cwd") or os.getcwd())
    session, prompt = ev.get("session_id"), ev.get("prompt_id")
    cfg = home.config()
    roots = [str(r) for r in cfg.get("workspaces") or []]

    tainted = home.tainted(session, prompt)
    home.note_turn(session, prompt, gate.taint_of(tool, inp))       # this call's own text taints what follows

    d = policy.decide(tool, inp, cwd, roots=roots)
    summ = policy.summarize_input(tool, inp)
    exists = _exists(inp.get("file_path") or inp.get("notebook_path"), cwd) if tool in policy.WRITE_TOOLS else None
    red = None
    over = [str(w)[len("overwrite:"):].strip() for w in d["warn"] if str(w).startswith("overwrite")]
    if over:
        try:
            red = any(os.path.exists(policy._abs(t, cwd)) for t in over)
        except OSError:
            red = None
    a = gate.assess(tool, summ, cwd, exists=exists, backup=None, tainted=tainted, warn=d["warn"],
                    redirect_exists=red, extra_protected=home.extra_protected())
    reading = d["action"] == "allow" and d["code"] == "read"

    if home.stopped() and not reading:
        decision, reason, level = "deny", "VECTOR GATE is in STOP mode. A human must run `vgate resume`.", "L3"
    elif d["action"] == "deny":
        decision = "deny" if d["hard"] else "ask"
        reason, level = d["reason"], ("L3" if d["hard"] else "L2")
    elif d["action"] == "allow":
        decision, reason, level = None, d["reason"], ("L0" if reading else "L1")
    elif a["risk"] == "high":
        decision, reason, level = "ask", f"High risk: {a['why']}", "L2"
    else:
        decision, reason, level = None, a["why"], a["level"] if a["level"] != "L2" else "L1"

    now = time.time()
    rec = {"v": 1, "kind": "decision", "ts": now, "day": time.strftime("%Y-%m-%d", time.localtime(now)),
           "session": session, "prompt": prompt, "tool_use_id": ev.get("tool_use_id"), "tool": tool,
           "mode": ev.get("permission_mode"), "decision": decision or "pass", "level": level,
           "code": d["code"], "reason": gate.redact(reason), "risk": a["risk"], "reversible": a["reversible"],
           "tainted": tainted, "summary": gate.redact(a["summary"]), "target": gate.redact(a["target"]),
           "agent": ev.get("agent_type")}
    return {"decision": decision, "reason": reason, "record": rec}


def output(decision: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                              "permissionDecisionReason": f"VECTOR GATE: {reason}"}})


def run(stdin_text: str, home: Home = None) -> str:
    """The whole hook as a function: event text in, stdout text out ("" = no decision)."""
    home = home or Home()
    try:
        ev = json.loads(stdin_text or "{}")
        if not isinstance(ev, dict):
            raise ValueError("event is not an object")
    except ValueError:
        return output("ask", "the hook could not read the event; asking to be safe")
    tool = str(ev.get("tool_name") or "")
    try:
        j = judge(ev, home)
    except Exception as e:                                        # fail towards asking, never towards silence
        if tool in policy.READ_TOOLS:
            return ""
        return output("ask", f"internal error ({type(e).__name__}); asking to be safe")
    try:
        home.ledger.append(j["record"])
    except Exception:
        if j["decision"] is None and tool not in policy.READ_TOOLS:
            return output("ask", "the audit log could not be written; asking to be safe")
    return output(j["decision"], j["reason"]) if j["decision"] else ""


def main() -> int:
    data = sys.stdin.buffer.read().decode("utf-8", "replace")
    out = run(data)
    if out:
        sys.stdout.write(out + "\n")
    return 0

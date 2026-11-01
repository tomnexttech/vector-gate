# -*- coding: utf-8 -*-
"""Risk of a tool call, and the append-only audit chain. No LLM — everything is deterministic.

  assess()  pure function: risk (low / medium / high) × reversible (True / False / None)
  Ledger    audit-YYYY-MM.jsonl, one decision per line; every line carries the SHA-256 of the line before it,
            so editing or deleting a line breaks the chain. Secret-looking text is masked before it is written.

Risk floor:
  Write to a new file ……………………………… low    / reversible
  Edit or Write an existing file …………… medium / reversible only if a backup is taken first ("fresh");
                                           if today's backup already exists ("stale") or none is taken: unknown
  Command, move, rename, localhost, MCP, unknown tool … medium / unknown
  Command with > overwrite …………………… high   / not reversible (medium / reversible when the target is new)
  Submissions, final, archive, synced folders, config, secrets … high
  After reading outside text in the same turn (tainted) … one level up
Three values: what we cannot know is None ("unknown"). It is never rounded down to "no".
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

from . import policy

ZERO = "0" * 64
RISKS = ("low", "medium", "high")
_UP = {"low": "medium", "medium": "high", "high": "high"}

# ── protected places ─────────────────────────────────────────────────────
_SUBMIT = re.compile(r"(?:^|[\\/])(?:final|finals|submission|submissions|submit|archive|archives)(?=$|[\\/ _\-.0-9（(])|"
                     r"提出|最終", re.I)
_SYNC = re.compile(r"(?:^|[\\/])(?:iclouddrive|icloud drive|com~apple~clouddocs|onedrive(?: - [^\\/]*)?|dropbox|"
                   r"google ?drive)(?=$|[\\/])", re.I)
_CONFIG = re.compile(r"(?:^|[\\/])config[\\/]|(?:^|[\\/])(?:config\.(?:json|ya?ml|toml|ini)|[\w.-]+\.(?:ini|cfg|conf|toml)|"
                     r"\.gitconfig|\.npmrc)$", re.I)

# outside text (web pages, mail, chat, downloads). Operations after it in the same turn go one level up
_TAINT_TOOLS = {"WebFetch", "WebSearch"}
_TAINT_MCP = re.compile(r"fetch|browser|chrome|navigate|get_page_text|web|gmail|mail|imessage|line_|slack|discord", re.I)
_DOWNLOADS = re.compile(r"(?:^|[\\/])downloads(?:[\\/]|$)", re.I)

# masking (no secret-looking text reaches the audit file)
_REDACT = [
    (re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{12,}"), "sk-***"),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{12,}"), "gh_***"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}"), "AKIA***"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "xox-***"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}"), "jwt***"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/\-]{12,}=*"), r"\1***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|auth)(\s*[:=]\s*)[^\s'\"&]+"), r"\1\2***"),
    (re.compile(r"\b[A-Za-z0-9+/_\-]{48,}={0,2}"), "***"),
]


def redact(s) -> str:
    t = "" if s is None else str(s)
    for rx, rep in _REDACT:
        t = rx.sub(rep, t)
    return t


def _name(p: str) -> str:
    n = policy._norm(p or "")
    return n.rsplit("\\", 1)[-1] or n


def protected(path_or_cmd: str, extra=()) -> list:
    """Why a place is protected (empty when it is not): [(kind, reason)]. extra: compiled user patterns."""
    s = str(path_or_cmd or "")
    out = []
    if not s:
        return out
    n = policy._norm(s)
    if policy.is_secret_path(n):
        out.append(("secret", "a secret location (keys, tokens, credentials)"))
    if _SUBMIT.search(n):
        out.append(("submit", "a submission / final / archive location"))
    if _SYNC.search(n):
        out.append(("sync", "a synced folder (changes reach your other devices)"))
    if _CONFIG.search(n) or policy._SETTINGS_PATH.search(n):
        out.append(("config", "a configuration file"))
    for rx in extra or ():
        if rx.search(n):
            out.append(("user", f"protected by your rule {rx.pattern!r}"))
    return out


def tool_label(tool: str) -> str:
    if tool.startswith("mcp__"):
        srv, short = (tool.split("__") + ["", ""])[1:3]
        return f"{srv}: {short}"
    return tool


def summarize(tool: str, inp: dict, exists=None) -> str:
    """One plain line for the approval card."""
    inp = inp or {}
    fp = inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
    if tool == "Write":
        chars = inp.get("chars")
        size = f" ({chars} chars)" if isinstance(chars, int) else ""
        if exists is False:
            return f"Create a new file {_name(fp)}{size}"
        if exists is True:
            return f"Overwrite all of {_name(fp)}{size}"
        return f"Write {_name(fp)}{size}"
    if tool == "Edit":
        old, new = str(inp.get("old") or ""), str(inp.get("new") or "")
        how = "Replace every match in" if inp.get("replace_all") else "Edit part of"
        return f"{how} {_name(fp)} ({len(old)} → {len(new)} chars)"
    if tool == "MultiEdit":
        return f"Edit several places in {_name(fp)}"
    if tool == "NotebookEdit":
        return f"Edit notebook {_name(fp)}"
    if tool in policy.SHELL_TOOLS:
        d = " ".join(str(inp.get("description") or "").split())
        c = " ".join(str(inp.get("command") or "").split())
        return "Run: " + (d[:80] if d else c[:80])
    if tool.startswith("mcp__"):
        return f"Call {tool_label(tool)}"
    if tool == "WebFetch":
        return "Fetch " + str(inp.get("url") or "")[:80]
    if tool == "WebSearch":
        return "Search the web: " + str(inp.get("query") or "")[:80]
    return f"Use {tool}"


def assess(tool: str, inp: dict, cwd: str = "", *, exists=None, backup=None, tainted=None, warn=None,
           redirect_exists=None, extra_protected=()) -> dict:
    """Risk of one call (pure). inp is in policy.summarize_input form (file_path/old/new/chars/head/command…).
    exists: does the target file exist now (True/False/None). backup: "fresh" (a backup is taken before the write),
    "stale" (today's backup already exists, so only the first version of today can be restored) or None (no backup).
    tainted: was outside text read earlier in this turn (True/False/None). warn: policy.decide's warn.
    redirect_exists: does any > target exist (False only when all are known to be new)."""
    inp = inp or {}
    warn = list(warn or [])
    reasons = []
    risk, rev = "medium", None
    fp = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""

    if tool in policy.WRITE_TOOLS:
        target = str(fp)
        if tool == "Write" and exists is False:
            risk, rev = "low", True
            reasons.append("creates a new file (nothing existing changes)")
        elif exists is False:                       # an Edit whose file is missing: the tool will fail, stay unknown
            reasons.append("the file to edit was not found")
        elif exists is None:
            reasons.append("cannot tell whether the target file exists")
        elif backup == "fresh":
            rev = True
            reasons.append("changes an existing file (a backup is taken first)")
        elif backup == "stale":
            reasons.append("changes an existing file; today's backup already exists, so only today's first version "
                           "can be restored")
        else:
            reasons.append("changes an existing file; no backup is taken (rely on version control or undo)")
    elif tool in policy.SHELL_TOOLS:
        cmd = str(inp.get("command") or "")
        target = cmd[:300]
        if [w for w in warn if str(w).startswith("overwrite")]:
            if redirect_exists is False:
                rev = True
                reasons.append("> writes to a new file (nothing existing changes)")
            else:
                risk, rev = "high", False
                reasons.append("> overwrites without a backup and cannot be undone")
        if "move" in warn:
            reasons.append("a move or rename leaves no copy behind")
        if "localhost" in warn:
            reasons.append("connects to a local port; the gate cannot see what happens behind it")
        if not reasons:
            reasons.append("the effect of a command cannot be read from its text (no backup is taken)")
    elif tool.startswith("mcp__"):
        target = tool_label(tool)
        reasons.append("MCP tools rely on the server's own undo (the gate cannot back them up)")
    elif tool in policy.WEB_TOOLS:
        target = str(inp.get("url") or inp.get("query") or "")[:300]
        reasons.append("changes nothing here, but what it sends (the URL or query) cannot be taken back, and the "
                       "text it brings in raises what follows in this turn")
    else:
        target = tool
        reasons.append("unregistered tool; its effect cannot be judged")

    for kind, why in protected(target if tool in policy.SHELL_TOOLS else fp, extra_protected):
        risk = "high"
        if kind == "secret" and rev is not True:
            rev = False
        reasons.append(why)

    if tainted is True:
        risk = _UP[risk]
        reasons.append("comes after reading outside text (web, mail, downloads) in this turn")

    level = "L1" if (tool in policy.WRITE_TOOLS and risk != "high") else "L2"
    why = "; ".join(r.rstrip(".") for r in reasons)
    return {"risk": risk, "reversible": rev, "why": why[:1].upper() + why[1:] + ".", "reasons": reasons,
            "summary": summarize(tool, inp, exists), "target": target, "level": level,
            "diff": diff_of(tool, inp, exists)}


def diff_of(tool: str, inp: dict, exists=None) -> dict:
    inp = inp or {}
    lim = 600
    if tool in ("Edit", "MultiEdit"):
        old, new = str(inp.get("old") or ""), str(inp.get("new") or "")
        return {"kind": "edit", "old": old, "new": new, "replace_all": bool(inp.get("replace_all")),
                "truncated": len(old) >= lim or len(new) >= lim}
    if tool == "Write":
        head = str(inp.get("head") or "")
        chars = inp.get("chars")
        return {"kind": "write", "head": head, "chars": chars, "exists": exists,
                "truncated": isinstance(chars, int) and chars > len(head)}
    if tool in policy.SHELL_TOOLS:
        c = str(inp.get("command") or "")
        return {"kind": "bash", "command": c, "truncated": len(c) >= lim}
    return {"kind": "other", "input": {k: v for k, v in list(inp.items())[:8]}}


def always_scope(tool: str, key: str) -> dict:
    """What "always, this session" really lets through (says exactly what policy.decide does with `always`)."""
    if tool in policy.WRITE_TOOLS:
        text = (f"For this session every {tool} inside the workspace goes through without asking "
                "(outside the workspace, settings and secrets are still refused)")
    elif tool in policy.SHELL_TOOLS:
        head = key[5:-1] if key.startswith("Bash(") and key.endswith(")") else key
        text = (f"For this session commands starting with \"{head}\" go through without asking "
                "(overwrites, moves and local connections are still asked)")
    elif tool.startswith("mcp__"):
        text = f"For this session {tool_label(tool)} goes through without asking"
    else:
        text = f"For this session {tool} goes through without asking"
    return {"key": key, "text": text}


def taint_of(name: str, inp: dict) -> str:
    """Why this call brings outside text in (empty when it does not)."""
    name = str(name or "")
    if name in _TAINT_TOOLS:
        return f"{name} (text from the web)"
    if name.startswith("mcp__") and _TAINT_MCP.search(" ".join(name.split("__")[1:])):
        return f"{tool_label(name)} (outside text)"
    if name in policy.READ_TOOLS:
        for k in ("file_path", "path", "pattern", "glob"):
            v = str((inp or {}).get(k) or "")
            if v and _DOWNLOADS.search(policy._norm(v)):
                return "a downloaded file"
    return ""


# ── append-only audit chain ───────────────────────────────────────────────
def line_hash(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


@contextlib.contextmanager
def file_lock(path: Path, timeout: float = 10.0):
    """Exclusive lock across processes (many hook processes append at once)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "a+b")
    try:
        deadline = time.time() + timeout
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise TimeoutError(f"audit lock busy: {path.name}")
                    time.sleep(0.01)
            try:
                yield
            finally:
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


class Ledger:
    """audit-YYYY-MM.jsonl. One decision per line. "prev" is the SHA-256 of the previous line's bytes, across months."""

    def __init__(self, data_dir):
        self.dir = Path(data_dir)
        self.lock = threading.Lock()

    def files(self) -> list:
        try:
            return sorted(self.dir.glob("audit-????-??.jsonl"))
        except OSError:
            return []

    def path_for(self, ts: float) -> Path:
        return self.dir / f"audit-{time.strftime('%Y-%m', time.localtime(ts))}.jsonl"

    @staticmethod
    def _last_line(p: Path) -> bytes:
        try:
            with open(p, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 65536))
                rows = [r.rstrip(b"\r") for r in f.read().split(b"\n") if r.strip()]
            return rows[-1] if rows else b""
        except OSError:
            return b""

    def last_hash(self) -> str:
        for p in reversed(self.files()):
            ln = self._last_line(p)
            if ln:
                return line_hash(ln)
        return ZERO

    def append(self, rec: dict) -> dict:
        with self.lock, file_lock(self.dir / ".lock"):
            rec = dict(rec)
            rec["prev"] = self.last_hash()             # read under the lock: another process may have just written
            line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.path_for(rec.get("ts") or time.time()), "ab") as f:
                f.write(line + b"\n")
            return rec

    def tail(self, n: int = 200) -> list:
        out = []
        for p in reversed(self.files()[-2:]):
            try:
                with open(p, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 512 * 1024))
                    rows = f.read().split(b"\n")
                    if size > 512 * 1024:
                        rows = rows[1:]
            except OSError:
                continue
            got = []
            for r in rows:
                r = r.rstrip(b"\r")
                if not r.strip():
                    continue
                try:
                    got.append(json.loads(r.decode("utf-8")))
                except ValueError:
                    continue
            out = got + out
            if len(out) >= n:
                break
        return out[-n:]

    def verify(self) -> dict:
        """Walk every month from the oldest and check the chain is unbroken."""
        prev, n = ZERO, 0
        for p in self.files():
            try:
                rows = p.read_bytes().split(b"\n")
            except OSError as e:
                return {"ok": False, "n": n, "file": p.name, "line": None, "error": str(e)}
            for i, r in enumerate(rows, 1):
                r = r.rstrip(b"\r")
                if not r.strip():
                    continue
                try:
                    d = json.loads(r.decode("utf-8"))
                except ValueError:
                    return {"ok": False, "n": n, "file": p.name, "line": i, "error": "not valid JSON"}
                if d.get("prev") != prev:
                    return {"ok": False, "n": n, "file": p.name, "line": i, "error": "the chain is broken here"}
                prev = line_hash(r)
                n += 1
        return {"ok": True, "n": n, "file": None, "line": None, "error": None}

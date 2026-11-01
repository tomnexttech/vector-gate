# -*- coding: utf-8 -*-
"""Tool permission policy. Pure functions — tests in tests/test_policy.py.

decide() returns one of:
  deny  … secrets (.env, keys, tokens, cookies, saved passwords), destructive commands (rm/del/rmdir, format,
          git reset/clean/push, registry, scheduled tasks …), settings files, writes outside the workspace,
          outbound network
  allow … reading (anywhere, unless it is a secret), rules the user said "always" to for this session
  ask   … Edit / Write / commands — a human decides

Every deny carries a "hard" flag. Hard denials are never relaxed (secrets, formatting, the registry, system
settings, admin rights, the gate's own files). Soft denials are things a human may still approve; the hook
turns them into "ask" (see hook.py), while a deck that drives Claude Code headless keeps them denied.

Refusing by mistake is harmless; letting through by mistake is not — so the nets are cast wide.
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import PureWindowsPath

READ_TOOLS = {"Read", "Glob", "Grep", "LS", "NotebookRead"}
WEB_TOOLS = {"WebFetch", "WebSearch"}             # read the web; the URL or query itself leaves this machine
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}

HOME = os.path.expanduser("~")

# ── secrets ─────────────────────────────────────────────────────────────
_SECRET_NAME = re.compile(
    r"(?:^|[\\/])(?:\.env(?:\.[\w.-]+)?|\.envrc|\.netrc|_netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|known_hosts|authorized_keys|"
    r"[^\\/]*\.(?:pem|key|p12|pfx|kdbx|keystore|jks|ppk|asc|gpg)|"
    r"\.?credentials?(?:\.[\w]+)?|\.credentials\.json|\.claude\.json|auth\.json|"
    r"\.?secrets?(?:\.[\w]+)?|client_secrets?[\w.-]*|[\w.-]*api[_-]?keys?(?:\.[\w]+)?|"
    r"\.?tokens?(?:\.(?:json|txt|dat|cache|bin))?|[\w.-]*(?:access|refresh|auth|oauth|bearer|session|api)[_-]tokens?[\w.-]*|"
    r"cookies(?:\.sqlite)?|login data(?: for account)?|web data|local state|key[34]\.db|logins\.json)(?:$|[\\/])", re.I)
_SECRET_DIR = re.compile(r"(?:^|[\\/])(?:\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.docker|"
                         r"microsoft[\\/](?:credentials|protect|crypto|vault)|"
                         r"(?:google[\\/]chrome|microsoft[\\/]edge|bravesoftware[\\/]brave-browser)[\\/]user data|"
                         r"mozilla[\\/]firefox[\\/]profiles)(?:$|[\\/])", re.I)
# secrets inside a command (anything that would print a value)
_SECRET_CMD = re.compile(r"\.env\b|id_(?:rsa|ed25519|ecdsa|dsa)|\.ssh[\\/]|credentials|\.git-credentials|\.netrc|"
                         r"login data|cookies|\btokens?\b|api[_-]?key|secret|password|passwd|\.pem\b|\.kdbx\b|"
                         r"\bprintenv\b|^\s*env\s*$|^\s*set\s*$|\benv\s*\|\s*|get-childitem\s+env:|\bgci\s+env:|"
                         r"\$env:[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASS)|\b(?:ANTHROPIC|OPENAI|GITHUB|AWS)_[A-Z_]*", re.I)

# ── the gate's own floor (hard): Claude Code settings and hooks, managed settings, the gate's state ──
_GUARD_PATH = re.compile(r"(?:^|[\\/])\.claude[\\/]+(?:settings(?:\.local)?\.json$|hooks(?:[\\/]|$))|"
                         r"(?:^|[\\/])managed-settings\.json$|(?:^|[\\/])\.vector[\\/]+gate(?:[\\/]|$)", re.I)
_GUARD_CMD = re.compile(r"\.claude[\\/]+(?:settings(?:\.local)?\.json|hooks[\\/])|managed-settings\.json|"
                        r"\.vector[\\/]+gate|(?:\bvgate(?:\.exe)?|\bvector_gate|\brun_vgate\.py)\s+(?:resume|uninstall)\b",
                        re.I)

# ── destructive commands: (pattern, name, hard) ─────────────────────────
_DESTRUCT_CMD = [
    (r"(?:^|[\s;&|(`])(?:sudo\s+)?rm(?:\s|$)", "rm", False),
    (r"(?:^|[\s;&|(`])rmdir(?:\s|$)", "rmdir", False),
    (r"(?:^|[\s;&|(`])(?:del|erase|rd)(?:\s|$)", "del", False),
    (r"remove-item|(?:^|[\s;&|(`])(?:ri|rni)\s", "Remove-Item", False),
    (r"(?:^|[\s;&|(`])format(?:\.com)?\s+[a-z]:", "format", True),
    (r"\bformat-volume\b|\bclear-disk\b|\bdiskpart\b|\bmkfs\b|\bdd\s+if=", "format", True),
    (r"\bgit\s+(?:-c\s+\S+\s+)*reset\b", "git reset", False),
    (r"\bgit\s+(?:-c\s+\S+\s+)*clean\b", "git clean", False),
    (r"\bgit\s+(?:-c\s+\S+\s+)*push\b", "git push", False),
    (r"\bgit\s+(?:-c\s+\S+\s+)*checkout\s+(?:--\s|\.\s*$|-f\b)|\bgit\s+restore\b|\bgit\s+branch\s+-D\b|"
     r"\bgit\s+stash\s+(?:drop|clear)\b|\bgit\s+rebase\b|\bgit\s+filter-branch\b", "destructive git", False),
    (r"(?:^|[\s;&|(`])reg(?:\.exe)?\s+(?:add|delete|import|load|unload|restore|copy)\b|\bregedit\b|"
     r"(?:set|new|remove)-itemproperty\b|\bhk(?:lm|cu|cr|u|cc):", "registry", True),
    (r"\bschtasks\b|register-scheduledtask|unregister-scheduledtask|set-scheduledtask|\bcrontab\b",
     "scheduled tasks", False),
    (r"\bbcdedit\b|\bshutdown\b|\brestart-computer\b|\bstop-computer\b|\bsc(?:\.exe)?\s+(?:delete|config|stop)\b|"
     r"set-service\b|stop-service\b|\bnet\s+(?:user|stop|localgroup)\b|\bsetx\b|\btakeown\b|\bicacls\b|\bcipher\s+/w",
     "system settings", True),
    (r"\btaskkill\b|\bstop-process\b|\bkillall\b|\bpkill\b|(?:^|[\s;&|(`])kill\s", "killing processes", False),
    (r"(?:^|[\s;&|(`])sudo\s|\brunas\b|start-process\b.*-verb\s+runas", "admin rights", True),
    (r"\bwinget\s+(?:install|uninstall|upgrade)|\bchoco\s+(?:install|uninstall)|\bpip3?\s+(?:install|uninstall)|"
     r"\bnpm\s+(?:i|install|uninstall|remove)\s+-g\b|\bmsiexec\b", "installing software", False),
    (r"settings(?:\.local)?\.json|\.claude[\\/]|\.claude\.json", "settings files", False),
]
_DESTRUCT_CMD = [(re.compile(rx, re.I), name, hard) for rx, name, hard in _DESTRUCT_CMD]

# outbound traffic. Only the local machine (127.0.0.1 / localhost) may be reached, and only after asking
_OUTWARD_CMD = re.compile(r"\b(?:curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|scp|sftp|ftp|ssh|rsync|nc|ncat|"
                          r"telnet|gh\s+(?:pr|issue|release|gist|repo)|send-mailmessage)\b", re.I)
_LOCALHOST = re.compile(r"(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", re.I)
_URL = re.compile(r"https?://[^\s'\"]+", re.I)

# where a > redirect writes (> overwrites, >> appends)
_REDIRECT = re.compile(r"(?<![>&\d])>(?![>&])\s*(\S+)")

# settings files (soft: a human may approve) and system places (hard)
_SETTINGS_PATH = re.compile(r"(?:^|[\\/])(?:settings(?:\.local)?\.json|\.claude\.json|keybindings\.json|\.mcp\.json|"
                            r"claude_desktop_config\.json)$|(?:^|[\\/])\.claude[\\/]|(?:^|[\\/])\.git[\\/]", re.I)
_SYSTEM_PATH = re.compile(r"^[a-z]:[\\/](?:windows|program files(?: \(x86\))?|programdata)(?:[\\/]|$)", re.I)

# commands that only read. Anything that writes, forwards or substitutes is not on this list (it is asked).
# Reading secrets and destructive commands are refused earlier in decide().
_RO_HEADS = {"ls", "dir", "cat", "type", "head", "tail", "wc", "grep", "egrep", "rg", "findstr", "echo", "pwd", "whoami",
             "date", "tree", "stat", "file", "du", "df", "which", "where", "sort", "uniq", "cut", "nl", "basename",
             "dirname", "realpath", "jq", "get-childitem", "gci", "get-content", "gc", "select-string", "sls",
             "get-item", "test-path", "resolve-path", "get-location", "measure-object", "find", "sed", "git"}
_RO_GIT = {"status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "branch", "remote"}
_MCP_READ = re.compile(r"^(?:ping|status|context|info)$|^(?:get|list|find|search|read|query|describe|capture)_", re.I)


def read_only(cmd: str) -> bool:
    """True when every stage joined by |, &&, || or ; only reads. Shapes we cannot read are False (asked)."""
    c = str(cmd or "")
    if not c.strip() or "$(" in c or "`" in c or ">>" in c or re.search(r"<\(|\btee\b", c):
        return False
    for m in _REDIRECT.finditer(c):
        if m.group(1).lower() not in ("/dev/null", "nul", "$null"):
            return False
    for seg in re.split(r"\|\||&&|[|;]", c):
        seg = re.sub(r"\d?>\s*(?:/dev/null|nul|\$null|&1)", "", seg, flags=re.I).strip()
        if not seg:
            continue
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            return False
        if not toks:
            continue
        head = os.path.basename(toks[0]).lower()
        head = head[:-4] if head.endswith(".exe") else head
        if head not in _RO_HEADS:
            return False
        low = [t.lower() for t in toks[1:]]
        if head == "sed" and any(t.startswith("-i") or t == "--in-place" for t in low):
            return False
        if head == "find" and any(t in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls") for t in low):
            return False
        if head == "git" and (not low or low[0] not in _RO_GIT or (low[0] == "branch" and any(t in ("-d", "-D", "-m", "-M") for t in toks[2:]))):
            return False
    return True


# ── PowerShell scripts that only read ─────────────────────────────────────
# Agents write small scripts (variables, if, Get-Item, Get-Content …) just to look at files. These lists say what
# a reading script may contain; anything else — a cmdlet, method, static call or assignment not listed here, a
# redirect, the call operator, dot-sourcing, a here-string with $( ) — makes the script "not read-only" and it is
# judged like any other command.
_PS_RO_COMMANDS = {
    "get-childitem", "get-item", "get-itemproperty", "get-content", "get-location", "get-date", "get-filehash",
    "get-command", "get-member", "get-process", "get-service", "get-acl", "test-path", "resolve-path",
    "split-path", "join-path", "select-object", "select-string", "where-object", "sort-object", "group-object",
    "measure-object", "compare-object", "format-table", "format-list", "format-wide", "out-string", "out-null",
    "write-output", "write-host", "convertto-json", "convertfrom-json", "set-location", "push-location",
    "pop-location",
    # aliases of the above
    "gci", "ls", "dir", "gi", "gp", "gc", "cat", "type", "gl", "pwd", "gcm", "gm", "gps", "gsv", "select", "where",
    "?", "sort", "group", "measure", "compare", "diff", "ft", "fl", "fw", "echo", "write", "sls", "rvpa", "cd", "sl",
    "chdir", "pushd", "popd",
}
_PS_EACH = {"foreach-object", "%", "foreach"}         # only with a { script block }: "| % Delete" calls a method
_PS_KEYWORDS = {"if", "elseif", "else", "for", "while", "do", "until", "switch", "try", "catch", "finally",
                "return", "throw", "in"}              # the token after these is checked as a command too
_PS_METHODS = {"tostring", "trim", "trimstart", "trimend", "split", "substring", "tolower", "toupper", "contains",
               "startswith", "endswith", "indexof", "lastindexof", "padleft", "padright", "gettype", "equals",
               "gethashcode", "where"}
_PS_STATIC = {"readalltext", "readalllines", "readallbytes", "exists", "getfilename", "getfilenamewithoutextension",
              "getextension", "getdirectoryname", "getfullpath", "combine", "join", "isnullorempty",
              "isnullorwhitespace", "now", "utcnow", "today", "format", "round", "max", "min", "abs", "floor",
              "ceiling", "truncate", "parse", "utf8", "ascii", "unicode", "outputencoding", "inputencoding"}
_PS_ASSIGN_OK = re.compile(r"^\$[A-Za-z_]\w*$|^\[(?:System\.)?Console\]::(?:Output|Input)Encoding$", re.I)
_PS_SEP = re.compile(r"[;\n|{}(]|(?<![\w$-])in(?![\w-])|[+\-*/%]?=")
_PS_TOKEN_START = " \t\r\n;{}()|"


def _ps_subexprs(body: str):
    """The code inside $( ) of a double-quoted string (PowerShell runs it). None when it cannot be read safely."""
    out, i = [], 0
    while True:
        i = body.find("$(", i)
        if i < 0:
            return out
        depth, j = 0, i + 1
        while j < len(body):
            if body[j] in "\"'":
                return None                    # a string inside a sub-expression: too clever to judge
            depth += body[j] == "("
            depth -= body[j] == ")"
            if depth == 0:
                break
            j += 1
        if depth:
            return None
        out.append(body[i + 2:j])
        i = j + 1


def _ps_strip(cmd: str):
    """(code, sub-expressions): comments and string literals blanked to spaces (same length, so positions still
    line up with the original), plus the code inside "$( )". None when the text cannot be split safely."""
    out, subs, i, n = [], [], 0, len(cmd)
    while i < n:
        c = cmd[i]
        at_token = i == 0 or cmd[i - 1] in _PS_TOKEN_START
        if c == "#" and at_token:                                   # a comment only where a token can start
            j = cmd.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif cmd.startswith("<#", i) and at_token:
            j = cmd.find("#>", i + 2)
            if j < 0:
                return None
            out.append(" " * (j + 2 - i))
            i = j + 2
        elif cmd.startswith(('@"', "@'"), i):                       # here-string; closes with "@ at a line start
            q = cmd[i + 1]
            j = cmd.find("\n" + q + "@", i + 2)
            if j < 0 or (q == '"' and "$(" in cmd[i + 2:j]):
                return None
            out.append(" " * (j + 3 - i))
            i = j + 3
        elif c == "'":
            j = i + 1
            while True:
                j = cmd.find("'", j)
                if j < 0:
                    return None
                if cmd.startswith("''", j):
                    j += 2
                    continue
                break
            out.append("'" + " " * (j - i - 1) + "'")
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n:
                if cmd[j] == "`":
                    j += 2
                    continue
                if cmd[j] == '"':
                    if cmd.startswith('""', j):
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                return None
            got = _ps_subexprs(cmd[i + 1:j])
            if got is None:
                return None
            subs.extend(got)
            out.append('"' + " " * (j - i - 1) + '"')
            i = j + 1
        elif c == "`":                                              # escape / line continuation
            out.append("  "[: n - i])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out), subs


def _ps_command_ok(code: str, orig: str, pos: int) -> bool:
    """Whatever starts at pos (a statement, a pipeline stage, the inside of ( ) or { }) only reads."""
    i = pos
    while True:
        while i < len(code) and code[i] in " \t\r":
            i += 1
        if i >= len(code) or code[i] in "$\"'[@(){};|,+*/-!0123456789\n.=":
            return True                                             # an expression, a block or nothing
        m = re.compile(r"[^\s;|{}()=,\[\]]+").match(code, i)
        word = m.group(0).lower()
        word = word[:-4] if word.endswith(".exe") else word
        rest = code[m.end():].lstrip(" \t")
        if word in _PS_KEYWORDS:
            i = m.end()
            continue
        if word in _PS_EACH:
            if word == "foreach" and rest.startswith("("):
                return True                                         # the foreach ( … in … ) keyword
            return rest.startswith("{") or bool(re.match(r"-process\s*\{", rest, re.I))
        if word in _PS_RO_COMMANDS:
            return True
        if word in _RO_HEADS:                                       # a native tool such as git: judge it as a shell
            end = re.compile(r"[;|\n]").search(code, m.end())
            return read_only(orig[i:end.start() if end else len(orig)])
        return False


def _ps_part_ro(code: str, orig: str) -> bool:
    code = re.sub(r"(?:\d|\*)?>\s*\$null|\d>&\d", lambda m: " " * len(m.group(0)), code, flags=re.I)
    if ">" in code or "&" in code:                                  # a redirect or the call operator
        return False
    if re.search(r"(?:^|[;\n{(|])\s*\.\s+\S", code):                # dot-sourcing a script
        return False
    if any(m.group(1).lower() not in _PS_STATIC for m in re.finditer(r"\]\s*::\s*([A-Za-z_]\w*)", code)):
        return False
    if any(m.group(1).lower() not in _PS_METHODS for m in re.finditer(r"(?<!:)\.\s*([A-Za-z_]\w*)\s*\(", code)):
        return False
    for m in re.finditer(r"[+\-*/%]?=", code):                      # in PowerShell, = is always assignment
        start = max(code.rfind(ch, 0, m.start()) for ch in ";\n{(|") + 1
        if not _PS_ASSIGN_OK.match(code[start:m.start()].strip()):
            return False
    return all(_ps_command_ok(code, orig, p) for p in [0] + [m.end() for m in _PS_SEP.finditer(code)])


def ps_read_only(cmd: str) -> bool:
    """True when a PowerShell script only reads. Shapes we cannot read are False (judged as a command)."""
    c = str(cmd or "")
    if not c.strip():
        return False
    s = _ps_strip(c)
    if s is None:
        return False
    code, subs = s
    return _ps_part_ro(code, c) and all(_ps_part_ro(x, x) for x in subs)


def _norm(p: str) -> str:
    p = str(p or "").strip().strip('"').strip("'")
    if p.startswith("~"):
        p = HOME + p[1:]
    if re.match(r"^/[a-zA-Z]/", p):            # Git Bash /c/... → C:\...
        p = p[1].upper() + ":" + p[2:]
    return p.replace("/", "\\")


def _abs(p: str, cwd: str) -> str:
    n = _norm(p)
    if not n:
        return n
    if not re.match(r"^[a-zA-Z]:\\|^\\\\", n):
        n = str(PureWindowsPath(_norm(cwd)) / n)
    parts = []                                 # fold .. by hand (PureWindowsPath does not)
    for seg in n.split("\\"):
        if seg == "..":
            if len(parts) > 1:
                parts.pop()
        elif seg not in (".",):
            parts.append(seg)
    return "\\".join(parts)


def is_secret_path(p: str) -> bool:
    n = _norm(p)
    return bool(n) and bool(_SECRET_NAME.search(n) or _SECRET_DIR.search(n))


def inside(p: str, root: str) -> bool:
    a = _abs(p, root).lower().rstrip("\\")
    r = _abs(root, root).lower().rstrip("\\")
    return bool(r) and (a == r or a.startswith(r + "\\"))


def inside_any(p: str, cwd: str, roots=()) -> bool:
    return any(inside(_abs(p, cwd), r) for r in [cwd, *(roots or ())] if r)


def bash_rule_key(cmd: str) -> str:
    """The "always this session" key: the first word (two words for git/npm/python and the like)."""
    try:
        toks = shlex.split(str(cmd or ""), posix=True)
    except ValueError:
        toks = str(cmd or "").split()
    if not toks:
        return "Bash()"
    head = os.path.basename(toks[0]).lower()
    if head.endswith(".exe"):
        head = head[:-4]
    if head in ("git", "npm", "npx", "pip", "pip3", "python", "python3", "py", "node", "uv", "cargo", "dotnet",
                "pytest", "ollama") and len(toks) > 1:
        sub = toks[1]
        if head in ("python", "python3", "py"):
            rest, i = toks[1:], 0
            sub = ""
            while i < len(rest):
                a = rest[i]
                if a == "-m" and i + 1 < len(rest):
                    sub = "-m " + rest[i + 1]
                    break
                if a in ("-X", "-W") and i + 1 < len(rest):
                    i += 2
                    continue
                if a.startswith("-"):
                    i += 1
                    continue
                sub = os.path.basename(a)
                break
            sub = sub or "-"
        return f"Bash({head} {sub})"
    return f"Bash({head})"


def rule_key(tool: str, inp: dict) -> str:
    if tool in SHELL_TOOLS:
        return bash_rule_key((inp or {}).get("command", ""))
    return tool


def _paths_of(tool: str, inp: dict) -> list:
    inp = inp or {}
    out = [str(inp[k]) for k in ("file_path", "path", "notebook_path") if inp.get(k)]
    if tool == "Glob" and inp.get("pattern"):
        out.append(str(inp["pattern"]))
    if tool in ("Glob", "Grep") and inp.get("glob"):
        out.append(str(inp["glob"]))
    return out


def path_class(ap: str):
    """(code, hard) for a place that must not be written to, else None."""
    if _GUARD_PATH.search(ap):
        return "guard", True
    if _SYSTEM_PATH.search(ap):
        return "system", True
    if _SETTINGS_PATH.search(ap):
        return "settings", False
    return None


_PATH_REASON = {"guard": "Claude Code settings, hooks and the gate's own files are never written",
                "system": "System locations are never written",
                "settings": "Settings files are not rewritten"}


def decide(tool: str, inp: dict, cwd: str, always: set | None = None, roots=()) -> dict:
    """{"action": "allow"|"deny"|"ask", "reason", "key", "warn": [..], "code", "hard"}
    roots: extra folders where writing is allowed besides cwd."""
    inp = inp or {}
    always = always or set()
    key = rule_key(tool, inp)
    warn = []

    def res(action, reason="", code="", hard=False):
        return {"action": action, "reason": reason, "key": key, "warn": warn, "code": code, "hard": hard}

    paths = _paths_of(tool, inp)
    for p in paths:
        if is_secret_path(p):
            return res("deny", f"Secret location ({os.path.basename(_norm(p)) or p}) is never touched", "secret", True)

    if tool in READ_TOOLS:
        return res("allow", "Read", "read")

    if tool in WRITE_TOOLS:
        for p in paths:
            ap = _abs(p, cwd)
            pc = path_class(ap)
            if pc:
                return res("deny", _PATH_REASON[pc[0]], *pc)
            if not inside_any(ap, cwd, roots):
                return res("deny", "Writing outside the workspace", "outside", False)
        if tool in always:
            return res("allow", "Always allowed this session", "always")
        return res("ask", "Edit", "write")

    if tool in SHELL_TOOLS:
        cmd = str(inp.get("command") or "")
        if _SECRET_CMD.search(cmd):
            return res("deny", "Commands that touch secrets (keys, tokens, environment) are never run", "secret", True)
        ro = read_only(cmd) or (tool == "PowerShell" and ps_read_only(cmd))
        if not ro and _GUARD_CMD.search(cmd):
            return res("deny", "Commands that change Claude Code settings or the gate itself are never run", "guard", True)
        for rx, name, hard in _DESTRUCT_CMD:
            if name == "settings files" and ro:          # only reading a settings place is not destructive
                continue
            if rx.search(cmd):
                return res("deny", f"Destructive command ({name})", "destructive", hard)
        if _OUTWARD_CMD.search(cmd):
            if re.search(r"\b(?:scp|sftp|ftp|ssh|rsync|telnet|send-mailmessage|gh)\b", cmd, re.I):
                return res("deny", "Sending or fetching outside this machine", "outward", False)
            urls = _URL.findall(cmd)
            local_only = all(_LOCALHOST.match(u.split("//", 1)[-1]) for u in urls) if urls else bool(_LOCALHOST.search(cmd))
            if not local_only:
                return res("deny", "Sending or fetching outside this machine (only 127.0.0.1 is allowed)", "outward", False)
            warn.append("localhost")
        for m in _REDIRECT.finditer(cmd):
            tgt = m.group(1)
            if tgt.lower() in ("/dev/null", "nul", "$null"):
                continue
            ap = _abs(tgt, cwd)
            pc = path_class(ap)
            if pc:
                return res("deny", _PATH_REASON[pc[0]], *pc)
            if not inside_any(ap, cwd, roots):
                return res("deny", "Writing outside the workspace", "outside", False)
            warn.append(f"overwrite: {tgt}")
        if re.search(r"(?:^|[\s;&|(`])(?:mv|move|ren|rename|move-item|rename-item)\s", cmd, re.I):
            warn.append("move")
        if ro and not warn:
            return res("allow", "Read-only command", "read")
        if key in always and not warn:
            return res("allow", "Always allowed this session", "always")
        return res("ask", "Command", "command")

    if tool.startswith("mcp__"):
        if _MCP_READ.search(tool.split("__")[-1]):
            return res("allow", "MCP read", "read")
        if tool in always:
            return res("allow", "Always allowed this session", "always")
        return res("ask", "MCP tool", "mcp")

    if tool in WEB_TOOLS:                          # asked in a deck; in the hook, Claude Code's own rules decide
        if tool in always:
            return res("allow", "Always allowed this session", "always")
        return res("ask", "Reads the web (the URL or query leaves this machine)", "web")

    if tool in always:
        return res("allow", "Always allowed this session", "always")
    return res("ask", "Unregistered tool", "unknown")


def summarize_input(tool: str, inp: dict, limit: int = 600) -> dict:
    """What an approval card shows (never the full content; long text is cut)."""
    inp = inp or {}
    if tool in SHELL_TOOLS:
        return {"command": str(inp.get("command") or "")[:limit], "description": str(inp.get("description") or "")[:200]}
    if tool in ("Edit", "MultiEdit"):
        return {"file_path": inp.get("file_path"), "old": str(inp.get("old_string") or "")[:limit],
                "new": str(inp.get("new_string") or "")[:limit], "replace_all": bool(inp.get("replace_all"))}
    if tool == "Write":
        c = str(inp.get("content") or "")
        return {"file_path": inp.get("file_path"), "chars": len(c), "head": c[:limit]}
    out = {}
    for k, v in inp.items():
        out[k] = v if isinstance(v, (int, float, bool)) or v is None else str(v)[:limit]
    return out


def settings_json() -> dict:
    """Settings for a deck that runs `claude -p --settings ...`: ask on every tool so each call reaches the host's
    can_use_tool, and a second floor of deny rules that Claude Code enforces even if the host is never asked."""
    deny = ["Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)", "Read(**/id_rsa*)",
            "Read(**/id_ed25519*)", "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(**/.git-credentials)",
            "Read(**/.netrc)", "Read(~/.claude/.credentials.json)", "Read(~/.claude.json)",
            "Edit(~/.claude/**)", "Edit(**/settings.json)", "Edit(**/settings.local.json)",
            "Write(~/.claude/**)", "Write(**/settings.json)", "Write(**/settings.local.json)",
            "Bash(rm:*)", "Bash(rmdir:*)", "Bash(del:*)", "Bash(git reset:*)", "Bash(git clean:*)",
            "Bash(git push:*)", "Bash(reg:*)", "Bash(schtasks:*)", "Bash(format:*)", "Bash(sudo:*)",
            "Bash(taskkill:*)", "Bash(shutdown:*)"]
    return {"permissions": {"ask": ["Read", "Glob", "Grep", "Edit", "Write", "Bash"], "deny": deny}}

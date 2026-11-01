# -*- coding: utf-8 -*-
"""Leak gate: refuse to ship a tree that carries personal data, secrets or names that are not ours.

Usage:
    python -I tools/leak_gate.py [ROOT] [--denylist PATH] [--generic-only]

Two kinds of rules:
  generic   built in: user home paths, e-mail addresses, Japanese mobile numbers, API keys and private keys,
            Tailscale (CGNAT) addresses.
  denylist  owner-only terms (names, family, devices, accounts, brands) read from a file that lives OUTSIDE
            the repository (default ~/.vector/leak_denylist.txt). The file is required unless --generic-only.

Negative controls run first, rule by rule: every generic rule and every denylist term is planted in a
throw-away tree (in several file types, a nested folder, UTF-16, cp932 and a file name) and must be caught.
A clean sample must stay clean, and a binary file must be reported as unscanned. If any control fails, the
gate refuses to give a verdict: zero findings only mean something when each rule is shown to fire.

Exit codes: 0 clean / 1 findings / 2 controls failed, denylist missing, or files that could not be scanned.
Findings are printed masked; denylist hits print the term's line number, never the term.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".mp3", ".wav", ".mp4", ".mov", ".webm",
              ".zip", ".7z", ".gz", ".tar", ".exe", ".dll", ".pyd", ".so", ".pyc", ".pdf", ".ttf", ".otf", ".woff",
              ".woff2", ".pml", ".db", ".sqlite"}

# Placeholders that may follow \Users\ or /home/ in docs and tests.
ALLOWED_USERS = {"you", "<you>", "user", "username", "%username%", "$env:username", "public", "default", "example"}
ALLOWED_MAIL_DOMAINS = re.compile(r"(?:^|\.)example\.(?:com|org|net)$", re.I)

GENERIC = [
    ("user-path", re.compile(r"[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}([^\\/\s\"'<>|:*?]+)|"
                             r"(?<![\w.])/(?:[a-zA-Z]/)?(?:Users|home)/([^/\s\"'<>]+)", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")),
    ("phone-jp", re.compile(r"(?<!\d)(?:0[789]0-?\d{4}-?\d{4}|\+81[-\s]?[789]0[-\s]?\d{4}[-\s]?\d{4})(?!\d)")),
    ("api-key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}|\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}|"
                           r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|"
                           r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("tailscale-ip", re.compile(r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\d.])")),
]


def _generic_hit(rule: str, m: re.Match) -> bool:
    if rule == "user-path":
        name = (m.group(1) or m.group(2) or "").strip().lower()
        return name not in ALLOWED_USERS
    if rule == "email":
        return not ALLOWED_MAIL_DOMAINS.search(m.group(1))
    return True


# ── denylist ───────────────────────────────────────────────────────────
def load_denylist(path: Path) -> list:
    """[(line_no, compiled, term)] — one literal per line. 'cs:' makes it case-sensitive; otherwise case is
    ignored. A plain ASCII word only matches as a whole word. No regexes: every term must be plantable."""
    out = []
    for no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        t = raw.strip()
        if not t or t.startswith("#"):
            continue
        term = t[3:] if t.startswith("cs:") else t
        body = re.escape(term)
        if re.fullmatch(r"[A-Za-z0-9_]+", term):
            body = r"(?<![A-Za-z0-9_])" + body + r"(?![A-Za-z0-9_])"
        out.append((no, re.compile(body, 0 if t.startswith("cs:") else re.I), term))
    return out


# ── scanning ───────────────────────────────────────────────────────────
def read_text(p: Path):
    """Text of the file, or None when it cannot be scanned as text."""
    if p.suffix.lower() in BINARY_EXT:
        return None
    try:
        b = p.read_bytes()
    except OSError:
        return None
    if b.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return b.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in b[:8192]:
        return None
    for enc in ("utf-8-sig", "cp932"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def walk(root: Path):
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.endswith(".egg-info"))
        for fn in sorted(fns):
            yield Path(dp) / fn


def _mask(s: str) -> str:
    s = s.strip()
    return (s[:2] + "…" + f"({len(s)})") if len(s) > 2 else "…"


def scan(root: Path, deny: list) -> dict:
    findings, unscanned, n = [], [], 0
    for p in walk(root):
        rel = p.relative_to(root).as_posix()
        # the path itself (a folder or file named after someone)
        for no, rx, _ in deny:
            if rx.search(rel):
                findings.append((rel, 0, f"denylist#{no}", "(in the path)"))
        text = read_text(p)
        if text is None:
            unscanned.append(rel)
            continue
        n += 1
        for i, line in enumerate(text.splitlines(), 1):
            for rule, rx in GENERIC:
                for m in rx.finditer(line):
                    if _generic_hit(rule, m):
                        findings.append((rel, i, rule, _mask(m.group(0))))
            for no, rx, _ in deny:
                if rx.search(line):
                    findings.append((rel, i, f"denylist#{no}", "(term hidden)"))
    return {"files": n, "findings": findings, "unscanned": unscanned}


# ── negative controls ───────────────────────────────────────────────────
def _samples() -> dict:
    """One planted sample per generic rule, assembled at run time so this file never matches itself."""
    at, dash = "@", "-"
    return {
        "user-path": "C:" + "\\Users\\" + "taro\\Documents\\notes.txt",
        "email": "taro.yamada" + at + "mail-" + "provider.jp",
        "phone-jp": "090" + dash + "1234" + dash + "5678",
        "api-key": "sk" + dash + "ant" + dash + "a1b2c3d4e5f6g7h8i9j0",
        "private-key": dash * 5 + "BEGIN OPENSSH " + "PRIVATE KEY" + dash * 5,
        "tailscale-ip": "100" + ".101.20.3",
    }


def controls(deny: list) -> list:
    """Problems found in the controls (empty = the gate is shown to work)."""
    problems = []
    samples = _samples()
    with tempfile.TemporaryDirectory(prefix="leakctl-") as d:
        root = Path(d)
        (root / "nested" / "deeper").mkdir(parents=True)
        kinds = [("a.py", "utf-8"), ("b.md", "utf-8"), ("nested/c.json", "utf-8"), ("nested/deeper/noext", "utf-8")]
        rules = list(samples.items())
        for i, (rule, sample) in enumerate(rules):
            name, enc = kinds[i % len(kinds)]
            with open(root / f"{rule}_{name.replace('/', '_')}", "a", encoding=enc) as f:
                f.write(f"x = '{sample}'\n")
        (root / "u16.txt").write_text("値 = '" + samples["email"] + "'\n", encoding="utf-16")
        (root / "clean.md").write_text("C:\\Users\\you\\Projects\\demo and alice" + "@" + "example.com and "
                                       "/home/user/app and 192.168.1.10\n", encoding="utf-8")
        (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
        for no, _, s in deny:
            enc = "cp932" if no % 3 == 0 and _encodable(s, "cp932") else "utf-8"
            (root / "nested" / f"term_{no}.txt").write_text(f"see {s} here\n", encoding=enc)
        named = next((s for _, _, s in deny if re.fullmatch(r"[\w .-]+", s)), None)
        if named:
            (root / "nested" / f"{named}.log.txt").write_text("nothing\n", encoding="utf-8")
        r = scan(root, deny)
        fired = {f[2] for f in r["findings"]}
        for rule in samples:
            if rule not in fired:
                problems.append(f"generic rule '{rule}' did not fire on its planted sample")
        if not any(f[0] == "u16.txt" and f[2] == "email" for f in r["findings"]):
            problems.append("UTF-16 file was not read")
        for no, _, _ in deny:
            if f"denylist#{no}" not in fired:
                problems.append(f"denylist line {no} did not fire on its planted sample")
        if any(f[0] == "clean.md" for f in r["findings"]):
            problems.append("clean sample produced findings (a rule is too broad)")
        if "image.png" not in r["unscanned"]:
            problems.append("binary file was not reported as unscanned")
        if named and not any(f[3] == "(in the path)" for f in r["findings"]):
            problems.append("file names are not checked against the denylist")
    return problems


def _encodable(s: str, enc: str) -> bool:
    try:
        s.encode(enc)
        return True
    except UnicodeEncodeError:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--denylist", default=str(Path.home() / ".vector" / "leak_denylist.txt"))
    ap.add_argument("--generic-only", action="store_true", help="skip owner terms (CI without the denylist)")
    a = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
    root = Path(a.root).resolve()

    deny = []
    if not a.generic_only:
        dp = Path(a.denylist)
        if not dp.is_file():
            print(f"leak_gate: denylist not found ({dp.name}); refusing to judge. Use --generic-only to skip it.")
            return 2
        deny = load_denylist(dp)
        if not deny:
            print("leak_gate: denylist is empty; refusing to judge.")
            return 2

    problems = controls(deny)
    if problems:
        print("leak_gate: CONTROLS FAILED - no verdict")
        for p in problems:
            print("  - " + p)
        return 2
    print(f"leak_gate: controls OK (generic {len(GENERIC)}/{len(GENERIC)}, denylist {len(deny)}/{len(deny)}"
          f"{' - SKIPPED' if a.generic_only else ''}, clean sample, binary detector, file names)")

    r = scan(root, deny)
    print(f"leak_gate: scanned {r['files']} text files under {root.name}/")
    for rel, line, rule, shown in r["findings"]:
        print(f"  {rel}:{line}: [{rule}] {shown}")
    for rel in r["unscanned"]:
        print(f"  {rel}: [unscanned] not a text file - remove it or scan it by other means")
    if r["unscanned"]:
        print(f"leak_gate: {len(r['findings'])} findings, {len(r['unscanned'])} unscanned - FAIL")
        return 2
    if r["findings"]:
        print(f"leak_gate: {len(r['findings'])} findings - FAIL")
        return 1
    print("leak_gate: 0 findings - PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

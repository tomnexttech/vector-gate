# -*- coding: utf-8 -*-
"""PowerShell scripts that only read must pass as reading; anything that writes, runs code or cannot be read
must not. The first two scripts are the ones an agent really ran in the sandbox trial (2026-10-26)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vector_gate import hook, policy as P  # noqa: E402

CWD = r"C:\Users\you\vgate-trial"

TRIAL_BUILD = (
    '$p = "C:\\Users\\you\\vgate-trial\\build"; if (Test-Path $p) { $items = Get-ChildItem $p -Recurse -Force '
    '-ErrorAction SilentlyContinue; "存在: はい"; "ファイル数: " + ($items | Where-Object { -not $_.PSIsContainer })'
    '.Count; "フォルダ数: " + ($items | Where-Object { $_.PSIsContainer }).Count; "合計サイズ(MB): " + '
    '[math]::Round((($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum '
    '/ 1MB), 2) } else { "存在: いいえ" }')
TRIAL_FINAL = (
    '$f = "C:\\Users\\you\\vgate-trial\\final\\report.md"; if (Test-Path $f) { $i = Get-Item $f; "サイズ(B): " + '
    '$i.Length; "更新: " + $i.LastWriteTime; "行数: " + (Get-Content $f).Count; "--- 先頭3行 ---"; '
    'Get-Content $f -TotalCount 3 } else { "存在しません"; Get-ChildItem (Split-Path $f) -Force }')

READS = [
    TRIAL_BUILD,
    TRIAL_FINAL,
    "Get-ChildItem -Recurse | Measure-Object -Property Length -Sum",
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-Content a.txt -Encoding UTF8 | Select-Object -First 5",
    '$t = [IO.File]::ReadAllText("a.txt"); $t.Length',
    'foreach ($f in Get-ChildItem *.md) { "$($f.Name): $($f.Length)" }',
    'Get-Content a.log | Select-String -Pattern "ERROR" | Select-Object -Last 10',
    "git log --oneline -5",
    r"cd C:\x; gci | sort Length -Descending | select -First 3",
    'if (-not (Test-Path $p)) { "missing" }',
    "# look first\nGet-Item a.txt",
    '"{0:N1} MB" -f ((Get-Item a.zip).Length / 1MB)',
    "Get-Content a.txt 2>$null",
    '$n = (Get-ChildItem).Count; Write-Output "files: $n"',
    "Get-ChildItem | Where-Object { $_.Length -gt 1KB } | Sort-Object Length | Format-Table Name, Length",
    "Get-ChildItem | ForEach-Object { $_.Name.ToUpper() }",
]

NOT_READS = [
    "Get-Content a.txt | Set-Content b.txt",
    "Get-ChildItem *.tmp | Remove-Item",
    '"x" > out.txt',
    '"x" | Out-File out.txt',
    'Add-Content log.txt "x"',
    "Copy-Item a b",
    "Get-Content a | tee b",
    "$i = Get-Item a.txt; $i.Delete()",
    '(Get-Item a.txt).MoveTo("b.txt")',
    "$i = Get-Item a.txt; $i.IsReadOnly = $true",
    '[IO.File]::WriteAllText("a.txt", "x")',
    '[IO.File]::Delete("a.txt")',
    "Get-ChildItem | % Delete",
    "Get-ChildItem | ForEach-Object Delete",
    "gci | foreach Delete",
    '$items.ForEach("Delete")',
    "& { Remove-Item x }",
    "& ./tool.ps1",
    ". ./profile.ps1",
    'Invoke-Expression "Remove-Item x"',
    "iex $code",
    '"$(Remove-Item x)"',
    '@"\n$(New-Item x)\n"@',
    "Start-Process notepad",
    "python app.py",
    "cmd /c dir",
    "New-Object System.Net.WebClient",
    '$env:PATH = "x"',
    "Get-Clipboard",
    '"abc',
    "foreach ($f in Remove-Item x) { }",
    "return Remove-Item x",
    "Get-Item x#; Remove-Item y",
    'if ($a) { "a" } Remove-Item b',
    "Get-ChildItem | Select-Object @{n='a';e={Remove-Item b}}",
    "git push origin main",
]


class PowerShellReadOnlyTest(unittest.TestCase):
    def test_reading_scripts_are_reading(self):
        for c in READS:
            self.assertTrue(P.ps_read_only(c), c)

    def test_anything_else_is_not(self):
        for c in NOT_READS:
            self.assertFalse(P.ps_read_only(c), c)

    def test_policy_lets_powershell_reads_through(self):
        for c in (TRIAL_BUILD, TRIAL_FINAL):
            d = P.decide("PowerShell", {"command": c}, CWD, set())
            self.assertEqual((d["action"], d["code"]), ("allow", "read"))

    def test_the_rule_is_for_the_powershell_tool_only(self):
        self.assertEqual(P.decide("Bash", {"command": TRIAL_FINAL}, CWD, set())["action"], "ask")

    def test_writes_and_secrets_are_unchanged(self):
        self.assertEqual(P.decide("PowerShell", {"command": "Get-Content a | Set-Content b"}, CWD, set())["action"], "ask")
        self.assertEqual(P.decide("PowerShell", {"command": "Get-Content .env"}, CWD, set())["action"], "deny")
        self.assertEqual(P.decide("PowerShell", {"command": "Get-ChildItem | Remove-Item"}, CWD, set())["action"],
                         "deny")


class PowerShellHookTest(unittest.TestCase):
    """The trial again, end to end: reading final/ stays silent, changing it is still asked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.home = hook.Home(t / "home")
        self.ws = t / "ws"
        (self.ws / "final").mkdir(parents=True)
        (self.ws / "final" / "report.md").write_text("# Final report\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, command):
        ev = {"session_id": "s", "prompt_id": "p", "cwd": str(self.ws), "tool_name": "PowerShell",
              "tool_input": {"command": command}}
        out = hook.run(json.dumps(ev), self.home)
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else None

    def test_reading_final_is_silent(self):
        f = str(self.ws / "final" / "report.md")
        script = TRIAL_FINAL.replace("C:\\Users\\you\\vgate-trial\\final\\report.md", f)
        self.assertIsNone(self.call(script))
        self.assertEqual(self.home.ledger.tail(1)[0]["level"], "L0")

    def test_changing_final_is_still_asked(self):
        f = str(self.ws / "final" / "report.md")
        self.assertEqual(self.call(f'(Get-Content "{f}") -replace "Final", "Last" | Set-Content "{f}"'), "ask")


if __name__ == "__main__":
    unittest.main()

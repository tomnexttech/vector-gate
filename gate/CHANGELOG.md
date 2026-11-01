# Changelog

## 0.1.0 — 2026-11-01

First public version. Distribution `vector-gate`, import package `vector_gate`, command `vgate`.

- Policy: deny / ask / allow for every Claude Code tool call, with hard and soft denials.
- Risk: low / medium / high and reversible yes / no / unknown; one level up after outside text in the same turn.
- PowerShell scripts that only read (variables, `if`, `Get-Item`, `Get-Content` …) are recognised as reading.
- `PreToolUse` hook that stays silent unless it must speak, and fails towards asking.
- Append-only audit log with a SHA-256 chain, safe for many hook processes at once; `vgate verify`.
- `vgate stop` / `vgate resume` (resume only from a real terminal).
- Runs without installing (`run_vgate.py`); sandbox trial script; managed-settings template and installer.
- Checked end to end in Claude Code 2.1.310 on Windows 11: secret search denied, `Remove-Item` and editing
  `final/` asked, STOP denies edits.

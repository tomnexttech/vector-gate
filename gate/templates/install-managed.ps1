# VECTOR GATE - install the managed settings for Claude Code. Run from an elevated (Administrator) PowerShell.
# ASCII only on purpose: Windows PowerShell 5.1 misreads UTF-8 scripts without a BOM.
# Managed settings live where only administrators can write, so an agent running as you cannot loosen them.
# Claude Code reads them at the next session start. This script never deletes anything; an existing file is
# kept as managed-settings.json.bak-<timestamp> next to the new one.
param(
  [string]$Python = ""
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$dst  = 'C:\Program Files\ClaudeCode'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'Run this from an Administrator PowerShell.' -ForegroundColor Red; exit 1 }

if (-not $Python) { $Python = (Get-Command python -ErrorAction Stop).Source }
& $Python -I -m vector_gate --version
if ($LASTEXITCODE -ne 0) {
  Write-Host "vector_gate is not importable by $Python with -I. Install it for that Python first (pip install .)." -ForegroundColor Red
  exit 1
}

$text = Get-Content (Join-Path $here 'managed-settings.json') -Raw -Encoding UTF8
$text = $text.Replace('{{PYTHON}}', ($Python -replace '\\', '\\'))
$null = $text | ConvertFrom-Json        # refuse to install broken JSON

New-Item -ItemType Directory -Force -Path $dst | Out-Null
$target = Join-Path $dst 'managed-settings.json'
if (Test-Path $target) {
  Copy-Item $target ($target + '.bak-' + (Get-Date -Format yyyyMMdd-HHmmss))
}
[IO.File]::WriteAllText($target, $text, (New-Object Text.UTF8Encoding $false))
Write-Host "Installed: $target" -ForegroundColor Cyan
Write-Host 'Start a new Claude Code session and run /status to confirm the managed source is loaded.'

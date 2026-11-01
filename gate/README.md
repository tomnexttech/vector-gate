# VECTOR GATE

**Stop an AI coding agent before it does something it cannot undo.**

VECTOR GATE is a small, deterministic permission gate for Claude Code. It runs as a `PreToolUse` hook, looks at
every tool call before it happens, and does one of three things:

| What the call is | What the gate does |
|---|---|
| Reading a secret (`.env`, keys, tokens, saved browser logins), formatting a disk, writing the registry or system settings, asking for admin rights, changing Claude Code's settings or the gate itself | **deny** |
| Deleting, `git push` / `reset` / `clean`, installing software, killing processes, sending data off the machine, writing outside the workspace | **ask** a human |
| High risk by its shape: a `>` that overwrites a file, editing `final/` or a synced folder, any command right after the agent read a web page or a download in the same turn | **ask** a human |
| Everything else | **stays silent** — Claude Code's own permission mode decides, exactly as before |

Silence never approves anything. The gate only adds friction where a mistake is expensive.

Every call is written to an append-only audit log in which each line carries the SHA-256 of the line before it.
Edit or delete one line and `vgate verify` shows where the chain breaks.

No LLM is involved. The rules are plain Python and the standard library only.

## Try it in one folder first (no install)

```powershell
python -I examples	ry_in_sandbox.py
```

This creates `~/vgate-trial` with a few sample files and a `.claude/settings.local.json` that registers the hook
for sessions started in that folder only. Open a terminal there, run `claude`, accept the folder trust prompt and
follow `TRY.md`. Nothing else on your machine changes; delete the folder to undo.

## Install (Windows)

Requires Python 3.9+ and Claude Code installed the official way, signed in with your own account or API key.
VECTOR GATE never touches your credentials: reading `~/.claude/.credentials.json` is one of the things it denies.

```powershell
pip install .
vgate settings
```

`vgate settings` prints a `hooks` block. Add it to `~/.claude/settings.json` (merge it with what is there), start a
new Claude Code session, and check with `/status`.

To make the gate something the agent cannot switch off, install it as **managed settings** instead. Managed
settings live in a folder only an administrator can write. From an Administrator PowerShell:

```powershell
.\templates\install-managed.ps1
```

## Commands

```text
vgate status          STOP or running, the state of the chain, the last decisions
vgate verify          check the audit chain end to end
vgate check TOOL JSON what would the gate say? (dry run, nothing recorded)
                      e.g. vgate check Bash "{\"command\": \"rm -rf build\"}"
vgate stop            deny everything except reading, in every session, until resumed
vgate resume          lift STOP — only from a real terminal; an agent cannot resume
vgate settings        print the hook block for settings.json
```

State lives in `~/.vector/gate` (or `$VGATE_HOME`): `audit/` (the chain), `sessions/` (which turns read outside
text; safe to delete), `STOP`, and an optional `config.json`:

```json
{
  "workspaces": ["D:/work/shared-assets"],
  "protected": ["\\\\thesis\\\\"]
}
```

`workspaces` are extra folders the agent may write to besides the session's folder. `protected` are regular
expressions for places you want asked about every time.

## How a decision is made

1. **Policy** (`vector_gate/policy.py`) sorts the call: allow (reading), ask (editing, commands), or deny. Every denial is
   marked hard or soft. Hard ones are always denied; soft ones become a question for you.
2. **Risk** (`vector_gate/gate.py`) gives the call a risk (low / medium / high) and says whether it can be undone:
   yes, no, or **unknown**. Unknown stays unknown — it is never rounded down to "no".
3. Operations after the agent read outside text (web, mail, chat, downloads) in the same turn go one level up.
4. If anything inside the gate fails, reading passes and everything else is asked. It fails towards asking.

## What it does not do (honest limits)

- It reads the command text. A script that builds a file path at run time and deletes it can slip past the
  pattern rules; those commands are still "medium / unknown" and go to your normal permission mode.
- It does not judge purchases or posts made through a browser tool.
- It takes no backups (yet). "Can this be undone?" is answered honestly, which usually means "unknown".
- Installed in your user settings, a determined agent could try to remove it; that is what managed settings are
  for. An administrator can always remove it — that is the point of an administrator.
- It is software that makes mistakes less likely, not a guarantee. Provided "AS IS" under the Apache License 2.0.

## Development

```bash
python -I -m unittest discover -s tests
python -I ../tools/leak_gate.py ..        # refuses to pass unless every leak rule is shown to fire first
```

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`. The names VECTOR, VECTOR GATE and VECTOR DECK are not licensed
for forks. VECTOR GATE runs alongside Claude Code; it is not made or endorsed by Anthropic.

---

## 日本語

VECTOR GATE は、Claude Code の `PreToolUse` フックとして動く、AI の実行を段階で止める関門です。

- **断る**：秘密の読取り・ディスクの初期化・レジストリとシステム設定・管理者権限・Claude Code の設定と関門自身の書き換え
- **伺う**：削除・`git push`／`reset`／`clean`・ソフトの導入・プロセスの停止・外部への送受信・作業場所の外への書き込み・上書き・提出物や同期フォルダ・外から読んだ文の後の操作
- **黙る**：それ以外。Claude Code の許可の設定がそのまま決めます（黙っても許可はしません）

全ての判定は、各行が前の行の SHA-256 を持つ追記専用の記録に残り、`vgate verify` で改ざんを検出します。
`vgate stop` で読む以外の全てを止め、`vgate resume` は人が端末から打った時だけ効きます。
戻せるかどうかは「はい／いいえ／不明」の三値で、判らない物を「いいえ」に丸めません。

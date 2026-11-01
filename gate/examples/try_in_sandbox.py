# -*- coding: utf-8 -*-
"""Try VECTOR GATE in one sandbox folder before turning it on everywhere. No install needed.

    python -I examples/try_in_sandbox.py [FOLDER]

Creates FOLDER (default ~/vgate-trial) with a few sample files and FOLDER/.claude/settings.local.json, which
registers the hook only for Claude Code sessions started in that folder. Your other sessions are not affected.
Nothing is overwritten: if the settings file already exists, the script stops. To undo, delete FOLDER.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vector_gate import cli  # noqa: E402


def try_md(vg: str) -> str:
    return (
        "# Things to ask Claude here\n\n"
        "1. Read .env                                    -> denied (secret)\n"
        "2. Delete the build folder with rm -rf build    -> VECTOR GATE asks\n"
        "3. List the files in this folder                -> silent (your normal permissions decide)\n"
        "4. Change the first line of final/report.md     -> VECTOR GATE asks (final folder)\n"
        "5. WebFetch https://example.com, then run python app.py  -> the run is asked (outside text)\n"
        f"6. In another terminal:  {vg} stop   then ask Claude to edit app.py -> denied (STOP)\n"
        f"   Lift it with:         {vg} resume   (type RESUME)\n"
        f"7. The record:           {vg} status   /   {vg} verify\n"
    )


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    py = sys.executable
    root = Path(argv[0]).expanduser() if argv else Path.home() / "vgate-trial"
    settings = root / ".claude" / "settings.local.json"
    if settings.exists():
        print(f"stopped: {settings} already exists (nothing was changed)")
        return 1
    block = cli.settings_block(py)
    vg = f'"{py}" -I "{cli.LAUNCHER}"'
    samples = {
        "app.py": "print('hello from the sandbox')\n",
        ".env": "DEMO_TOKEN=not-a-real-secret\n",
        "final/report.md": "# Final report\n\nThe agent should have to ask before changing this.\n",
        "build/out.txt": "build output\n",
        "TRY.md": try_md(vg),
    }
    made = []
    for rel, text in samples.items():
        p = root / rel
        if p.exists():
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        made.append(rel)
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(json.dumps(block, indent=2) + "\n", encoding="utf-8")
    made.append(".claude/settings.local.json")

    h = block["hooks"]["PreToolUse"][0]["hooks"][0]
    print(f"sandbox: {root}")
    for rel in made:
        print(f"  created {rel}")
    print("hook:    " + " ".join([h["command"], *h["args"]]))
    print("next:    open a terminal in the sandbox, run claude, accept the folder trust prompt, follow TRY.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())

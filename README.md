# VECTOR DECK

A personal agent deck that runs alongside Claude Code.

| Folder | What it is | License |
|---|---|---|
| [`gate/`](gate/) | **VECTOR GATE** — the free core: a deterministic permission gate and tamper-evident audit log | Apache-2.0 |
| [`tools/`](tools/) | the release leak gate (refuses to ship personal data, secrets or names that are not ours) | Apache-2.0 |

The paid deck (console, holo window, Windows operations, constitution kit) is built on top of the gate and is not
part of this repository.

```bash
cd gate
python -I -m unittest discover -s tests
python -I ../tools/leak_gate.py ..
```

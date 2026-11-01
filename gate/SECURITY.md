# Security

VECTOR GATE sits between an AI agent and your machine, so a way around it is a security bug.

**Please report privately** through GitHub's "Report a vulnerability" button on this repository (Security →
Advisories). Do not open a public issue for a bypass.

Useful reports include:

- a tool call that should be denied or asked but passes silently (the exact `tool_name` and `tool_input`)
- a way for an agent to lift STOP, change the gate's rules, or edit the audit log without `vgate verify` noticing
- a crash or slowdown that makes the hook fail open

`vgate check TOOL JSON` shows what the gate decides for a call, which makes a report easy to reproduce.

Known limits are listed in the README under "What it does not do". Those are not bugs, but a practical way to
close one is very welcome.

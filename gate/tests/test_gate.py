# -*- coding: utf-8 -*-
"""Risk and audit-chain tests (silent, nothing is executed, records go to a temporary folder only)."""
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vector_gate import gate as G  # noqa: E402
from vector_gate import policy as P  # noqa: E402

CWD = r"C:\Users\you\Projects\demo"


def A(tool, inp, **kw):
    return G.assess(tool, inp, CWD, **kw)


class AssessTest(unittest.TestCase):
    def test_new_file_write_is_low_and_reversible(self):
        a = A("Write", {"file_path": CWD + r"\new.txt", "chars": 10, "head": "0123456789"}, exists=False)
        self.assertEqual((a["risk"], a["reversible"]), ("low", True))
        self.assertIn("new file new.txt", a["summary"])
        self.assertEqual(a["level"], "L1")

    def test_existing_edit_is_medium_and_the_backup_decides_reversible(self):
        inp = {"file_path": CWD + r"\a.py", "old": "a", "new": "bb"}
        self.assertEqual(A("Edit", inp, exists=True, backup="fresh")["reversible"], True)
        b = A("Edit", inp, exists=True, backup="stale")
        self.assertEqual((b["risk"], b["reversible"]), ("medium", None))     # only today's first version
        self.assertIn("today's first version", b["why"])
        n = A("Edit", inp, exists=True)                                      # no backup taken: unknown, not "yes"
        self.assertEqual((n["risk"], n["reversible"]), ("medium", None))
        self.assertIn("no backup", n["why"])
        self.assertEqual(A("Write", {"file_path": CWD + r"\a.py", "chars": 3}, exists=True)["risk"], "medium")

    def test_unknown_existence_is_not_rounded_to_no(self):
        a = A("Write", {"file_path": CWD + r"\x.txt", "chars": 1}, exists=None)
        self.assertEqual((a["risk"], a["reversible"]), ("medium", None))

    def test_bash(self):
        a = A("Bash", {"command": "python build.py"})
        self.assertEqual((a["risk"], a["reversible"]), ("medium", None))
        self.assertEqual(a["level"], "L2")
        for w in (["move"], ["localhost"]):
            self.assertEqual(A("Bash", {"command": "x"}, warn=w)["reversible"], None)
        o = A("Bash", {"command": "echo hi > out.txt"}, warn=["overwrite: out.txt"])
        self.assertEqual((o["risk"], o["reversible"]), ("high", False))
        n = A("Bash", {"command": "echo hi > out.txt"}, warn=["overwrite: out.txt"], redirect_exists=False)
        self.assertEqual((n["risk"], n["reversible"]), ("medium", True))

    def test_mcp_and_unknown(self):
        self.assertEqual(A("mcp__cad__create_wall", {})["risk"], "medium")
        self.assertIn("cad: create_wall", A("mcp__cad__create_wall", {})["summary"])
        self.assertEqual(A("Foo", {})["reversible"], None)

    def test_protected_places_raise_to_high(self):
        for p in (CWD + r"\final\report.docx", CWD + r"\提出\a.pdf", CWD + r"\submission_v2.zip",
                  r"C:\Users\you\iCloudDrive\notes\x.md", CWD + r"\config\app.json", CWD + r"\setup.cfg"):
            a = A("Edit", {"file_path": p, "old": "a", "new": "b"}, exists=True)
            self.assertEqual((a["risk"], a["level"]), ("high", "L2"), p)
        for p in (CWD + r"\finally.py", CWD + r"\finalize_notes.md", CWD + r"\archiver.py"):
            self.assertEqual(A("Edit", {"file_path": p}, exists=True)["risk"], "medium", p)
        self.assertEqual(A("Bash", {"command": r"copy a.txt C:\Users\you\iCloudDrive\x"})["risk"], "high")
        mine = [re.compile(r"\\thesis\\", re.I)]
        self.assertEqual(A("Edit", {"file_path": CWD + r"\thesis\ch1.md"}, exists=True, extra_protected=mine)["risk"],
                         "high")

    def test_taint_raises_one_level(self):
        self.assertEqual(A("Write", {"file_path": CWD + r"\n.txt"}, exists=False, tainted=True)["risk"], "medium")
        self.assertEqual(A("Bash", {"command": "make"}, tainted=True)["risk"], "high")
        self.assertEqual(A("Bash", {"command": "make"}, tainted=None)["risk"], "medium")    # unknown does not raise
        self.assertEqual(G.taint_of("WebFetch", {}), "WebFetch (text from the web)")
        self.assertTrue(G.taint_of("Read", {"file_path": r"C:\Users\you\Downloads\x.html"}))
        self.assertFalse(G.taint_of("Read", {"file_path": CWD + r"\x.py"}))
        self.assertTrue(G.taint_of("mcp__claude-in-chrome__get_page_text", {}))
        self.assertFalse(G.taint_of("mcp__cad__create_wall", {}))

    def test_always_scope_tells_the_truth_of_policy(self):
        self.assertIn("every Edit inside the workspace", G.always_scope("Edit", "Edit")["text"])
        b = G.always_scope("Bash", P.bash_rule_key("python -m unittest discover"))
        self.assertIn("python -m unittest", b["text"])
        self.assertEqual(b["key"], "Bash(python -m unittest)")

    def test_redact(self):
        key = "sk-" + "ant-" + "0123456789abcdefgh"
        s = G.redact("curl -H 'Authorization: Bearer abcdefghijklmnop12345' token=xyz123 " + key)
        self.assertNotIn("abcdefghijklmnop12345", s)
        self.assertNotIn("xyz123", s)
        self.assertNotIn("0123456789abcdefgh", s)
        self.assertEqual(G.redact("python -m unittest"), "python -m unittest")


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_chain_links_and_survives_a_new_instance(self):
        led = G.Ledger(self.dir)
        for i in range(3):
            led.append({"kind": "decision", "ts": time.time(), "n": i})
        lines = [ln for ln in led.files()[0].read_bytes().split(b"\n") if ln.strip()]
        self.assertEqual(json.loads(lines[0])["prev"], G.ZERO)
        self.assertEqual(json.loads(lines[1])["prev"], G.line_hash(lines[0]))
        G.Ledger(self.dir).append({"kind": "decision", "ts": time.time(), "n": 3})
        v = G.Ledger(self.dir).verify()
        self.assertEqual((v["ok"], v["n"]), (True, 4))
        self.assertEqual([r["n"] for r in led.tail(10)], [0, 1, 2, 3])

    def test_tamper_is_detected(self):
        led = G.Ledger(self.dir)
        for i in range(3):
            led.append({"kind": "decision", "ts": time.time(), "decision": "pass"})
        f = led.files()[0]
        rows = f.read_bytes().split(b"\n")
        rows[1] = rows[1].replace(b'"pass"', b'"deny"')
        f.write_bytes(b"\n".join(rows))
        v = led.verify()
        self.assertFalse(v["ok"])
        self.assertEqual(v["line"], 3)

    def test_deleting_a_line_is_detected(self):
        led = G.Ledger(self.dir)
        for i in range(3):
            led.append({"kind": "decision", "ts": time.time(), "n": i})
        f = led.files()[0]
        rows = [r for r in f.read_bytes().split(b"\n") if r.strip()]
        f.write_bytes(b"\n".join([rows[0], rows[2]]) + b"\n")
        self.assertFalse(led.verify()["ok"])


if __name__ == "__main__":
    unittest.main()

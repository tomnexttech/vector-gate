# -*- coding: utf-8 -*-
"""Tests for the leak gate. Every leak is assembled at run time so this file stays clean itself."""
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import leak_gate as L  # noqa: E402

AT = "@"


def _deny(tmp: Path, *terms) -> Path:
    p = tmp / "deny.txt"
    p.write_text("# test\n" + "\n".join(terms) + "\n", encoding="utf-8")
    return p


class ControlsTest(unittest.TestCase):
    def test_controls_pass_with_working_rules(self):
        with tempfile.TemporaryDirectory() as d:
            deny = L.load_denylist(_deny(Path(d), "Zorblax", "cs:QUUX", "架空名"))
        self.assertEqual(L.controls(deny), [])

    def test_a_dead_generic_rule_is_caught(self):
        dead = [(r, re.compile(r"(?!x)x") if r == "email" else rx) for r, rx in L.GENERIC]
        with mock.patch.object(L, "GENERIC", dead):
            problems = L.controls([])
        self.assertTrue(any("'email'" in p for p in problems), problems)

    def test_a_dead_denylist_term_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            deny = L.load_denylist(_deny(Path(d), "Zorblax"))
        deny = [(no, re.compile(r"(?!x)x"), t) for no, _, t in deny]
        self.assertTrue(any("did not fire" in p for p in L.controls(deny)))

    def test_an_over_broad_rule_is_caught(self):
        broad = list(L.GENERIC) + [("everything", re.compile(r"\w+"))]
        with mock.patch.object(L, "GENERIC", broad):
            self.assertTrue(any("clean sample" in p for p in L.controls([])))

    def test_word_terms_do_not_match_inside_words_but_cs_respects_case(self):
        with tempfile.TemporaryDirectory() as d:
            deny = L.load_denylist(_deny(Path(d), "zorb", "cs:QUUX"))
        rx = {t: r for _, r, t in deny}
        self.assertFalse(rx["zorb"].search("zorbly lit"))
        self.assertTrue(rx["zorb"].search("Mr Zorb said"))
        self.assertFalse(rx["QUUX"].search("see you on Quux"))
        self.assertTrue(rx["QUUX"].search("QUUX online"))


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name)
        self.root = self.t / "repo"
        (self.root / "pkg").mkdir(parents=True)
        (self.root / "pkg" / "ok.py").write_text("HOME = r'C:\\Users\\you\\app'\n", encoding="utf-8")
        self.deny = _deny(self.t, "Zorblax")

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *extra):
        with mock.patch("sys.stdout"):
            return L.main([str(self.root), "--denylist", str(self.deny), *extra])

    def test_clean_tree_passes(self):
        self.assertEqual(self.run_main(), 0)

    def test_missing_denylist_refuses(self):
        self.deny = self.t / "nowhere.txt"
        self.assertEqual(self.run_main(), 2)
        self.assertEqual(self.run_main("--generic-only"), 0)

    def test_leaks_fail(self):
        for body in ("mail = 'hanako" + AT + "mail-provider.jp'\n", "who = 'zorblax'\n",
                     "p = 'C:" + "\\Users\\" + "hanako\\x'\n"):
            (self.root / "pkg" / "leak.py").write_text(body, encoding="utf-8")
            self.assertEqual(self.run_main(), 1, body)

    def test_binary_files_are_not_silently_skipped(self):
        (self.root / "pkg" / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00")
        self.assertEqual(self.run_main(), 2)

    def test_names_in_paths_fail(self):
        (self.root / "Zorblax-notes").mkdir()
        (self.root / "Zorblax-notes" / "a.txt").write_text("x\n", encoding="utf-8")
        self.assertEqual(self.run_main(), 1)


if __name__ == "__main__":
    unittest.main()

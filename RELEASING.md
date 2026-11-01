# Releasing VECTOR GATE

Run every step from the repository root. Nothing is published until the push.

1. Tests and the leak gate (on the owner's machine, with the owner's denylist):

   ```bash
   python -I -m unittest discover -s gate/tests
   python -I -m unittest discover -s tools
   python -I tools/leak_gate.py .
   ```

   The leak gate must print `controls OK` and `0 findings - PASS`. Anything else stops the release.

2. Start a fresh history (never copy history from a private project):

   ```bash
   git init -b main
   git config user.name "VECTOR"
   git config user.email "<the VECTOR noreply address>"
   git add .
   git status --short
   git commit -m "VECTOR GATE 0.1.0"
   ```

   Read the `git status --short` list before committing: only files you expect. The author is always "VECTOR";
   no personal name goes into a commit, a file or a comment, and a commit message carries no `Co-Authored-By`
   trailer (GitHub would list that name as a contributor).

3. Create the empty repository on GitHub under the VECTOR account (`tomnexttech`; there is no organisation), then:

   ```bash
   git remote add origin https://github.com/tomnexttech/vector-gate.git
   git push -u origin main
   git tag v0.1.0
   git push origin v0.1.0
   ```

4. On GitHub: turn on private vulnerability reporting (Settings → Security), check that CI is green, and write the
   release notes from `gate/CHANGELOG.md`.

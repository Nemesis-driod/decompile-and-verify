# decompile-and-verify

Agent skills for decompilation. Start with `skills/decompile-and-verify/SKILL.md`; use `skills/decompile-assess/SKILL.md` when the goal is to measure how recoverable a build is.

## Working in this repo

- Scripts live in `skills/*/scripts/` and are stdlib-only Python (3.9+) plus one Ghidra Java script. Every script prints a `RESULT:` verdict; keep that contract.
- Run the tests before and after changes: `python3 -m unittest discover -s tests -v` (needs gcc and objdump; the Ghidra test runs only when `GHIDRA_HOME` and `javac` are present).
- Keep each `SKILL.md` under 500 lines and references one level deep. Add to a skill only what the model would not already know.
- Binaries, decompiled output and logs belong in `work/` (gitignored). Commit scripts, notes and tests.
- Scripts must work on Windows, macOS and Linux: no bash-only code, `encoding="utf-8"` on every `open()`, no hard-coded `/tmp`.

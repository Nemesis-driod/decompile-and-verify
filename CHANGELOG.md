# Changelog

## 0.3.0 (first public release)

Two skills, `decompile-and-verify` and `decompile-assess`, with scripts, tests, evals and examples.

Added
- `triage.py`: format, protector and secret triage (secret values and URL credentials redacted); detects ELF, PE (.NET), Mach-O, JAR, APK, DEX, WebAssembly, `.pyc`, Electron asar, IL2CPP metadata and PyInstaller bundles.
- `ghidra_export.py`: cross-platform Ghidra headless export (function inventory plus decompiled C), with a clear message when only a JRE is installed.
- `rank_functions.py`: cheapest-first worklist, ledger-aware, `--unnamed-only`.
- `verify_match.py` (matching oracle) and `verify_run.py` (differential oracle) with a fixed `RESULT:` vocabulary.
- `ledger.py`: tidy recovery ledger; attempts and seconds accumulate per function.
- `score_exposure.py` and `render_report.py`: Recoverability Index (v0, uncalibrated), cost to recover, and a report rendered only from measured data.
- `evals/`: three cases for `claude plugin eval` (with-and-without-skill ablation, one should-not-fire case).
- Examples: a toy licence check with measured artifacts and a sample report; a Python program decompiled with pycdc, with the measured differences.
- Claude Code plugin manifest, `AGENTS.md`, CI that runs the tests and validates both skills against the Agent Skills spec.

Verified in this release: native ELF and 32-bit PE through Ghidra 12.1.4; Java through jadx, CFR and Vineflower; Electron asar; PyInstaller extraction; WebAssembly through wabt; rizin. Not run: .NET, an APK, Mach-O, Unity IL2CPP, retro ROMs. See `skills/decompile-and-verify/references/routes.md`.

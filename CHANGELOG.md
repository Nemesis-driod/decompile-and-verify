# Changelog

## 0.4.1

Fixed. Most of these came from a public review of the code; each was reproduced before it was fixed, and the Windows path bug was found by this project's own CI.
- `verify_run.py`: two programs that both timed out were reported as `EQUIVALENT_ON`. A timeout is now inconclusive (`INCONCLUSIVE`), a one-sided timeout is a difference, identical failures on every input are flagged, and `--strict` makes `--min-inputs` a requirement (`TOO_FEW_INPUTS`).
- `verify_emulated.py`: `--ret ptr` ended in a `KeyError` (now a clear error). A native candidate that crashed or looped took the verifier down with no verdict; the candidate now runs in its own process and the result is `CANDIDATE_CRASH` or `CANDIDATE_TIMEOUT`, and a Python candidate that raises is reported as a difference. Truncated or malformed ELF and PE files raised raw exceptions, and a tiny file declaring a huge segment could exhaust memory; the image is now built lazily and validated. `--candidate-py` failed on Windows paths because the drive-letter colon was treated as the separator. Negative or non-finite tolerances are rejected. Pairwise boundary combinations of the first three arguments are generated.
- `triage.py`: truncated or corrupt headers raised exceptions (now a result that says so). The 32 MiB scan limit was silent; it is now stated in the output and the JSON and adjustable with `--scan-mib`.
- `ghidra_export.py` and `ExportFunctions.java`: a run that died halfway could print `RESULT: OK`, and files from an earlier run in the same folder could pass for new output. Success now requires the completion marker (`summary.txt`, written last), `RESULT: PARTIAL` is reported otherwise, and old output is deleted first. The summary records the binary's sha256, and CSV fields are quoted when needed.
- `ledger.py`: writes are atomic and invalid values are reported with a line number instead of a traceback. Rows can be bound to the sha256 of the build, the verified candidate and the inputs, and `ledger.py check` reports rows that went stale. `rank_functions.py` and `score_exposure.py` ignore rows verified against a different build, and `render_report.py` shows how well the evidence is pinned.
- `verify_trace.py`: negative, NaN and infinite tolerances are rejected.
- `verify_match.py`: no longer leaves a temporary folder behind on every run.
- 38 new tests (98 in total).

Documented rather than changed: `verify_run.py` compares exit status and stdout only; the emulator's memory model is deliberately incomplete; boundary and random inputs cannot find a bug that needs one specific constant; trace replay cannot see state that was not recorded; the ranking weights are a starting guess; `decompile_status=ok` means Ghidra returned C, not that the C is correct.

Reported but not reproduced: that a negative tolerance crashes `math.isclose`. It ran without error, and negative values are now rejected up front anyway.

## 0.4.0

Added
- `verify_emulated.py`: differential check of ONE function inside the original binary, run under the Unicorn emulator (x86 and x86-64, ELF and PE; SysV, Win64, cdecl, stdcall and fastcall; C or Python candidates; boundary, random and file cases; pointer buffers compared). Verified on stripped x86-64 and 32-bit ELF functions and on a function from a real 32-bit Windows executable. Needs `pip install unicorn`.
- `verify_trace.py`: trace-replay oracle that reports the first diverging tick between an original and a port.
- `examples/real-pe` (one function of a real Windows executable verified against its original machine code) and a function-level step in `examples/sample`.
- 19 new tests (60 in total); CI installs Unicorn.

Changed
- `decompile-and-verify` now says to pin every claim to the build's sha256, to separate observed from inferred statements, and to commit only when the verdict improves.
- README: positioning against related projects (REA, Universal Modder, Melty, recompilation and emulation projects) and the five-oracle summary.
- `routes.md`: an optional "analysis providers" section.

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
- `references/ports-and-recompilation.md`: how static recompilers, translation layers and source ports work, the stub-and-trace loop, a compatibility ladder, and what each check proves.
- Claude Code plugin manifest, `AGENTS.md`, CI that runs the tests and validates both skills against the Agent Skills spec.

Verified in this release: native ELF and 32-bit PE through Ghidra 12.1.4; Java through jadx, CFR and Vineflower; Electron asar; PyInstaller extraction; WebAssembly through wabt; rizin. Not run: .NET, an APK, Mach-O, Unity IL2CPP, retro ROMs. See `skills/decompile-and-verify/references/routes.md`.

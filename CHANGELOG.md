# Changelog

## 0.4.3

Fixed. A third public review, run against real Ghidra, found these; each was reproduced before it was fixed.
- `verify_match.py`: a candidate whose only difference was a data constant or a string (`0.3f` for `0.2f`, `"WORLD"` for `"hello"`) reported `MATCH`, because only the instruction text was compared. The data sections (`.rodata*`, `.data*`, `.rdata`, `.bss*`: sizes, contents, relocations) are now compared for a whole object; with `--func` the MATCH line says that data was not compared, and `--data on` compares it.
- `verify_match.py`: the inline-assembly guard missed `__asm__ __volatile__`, `asm __volatile__` and `asm inline`. It now handles every qualifier spelling, ignores comments and strings, and also scans the preprocessed source (skipping system headers, which use `__asm__` themselves), so a macro cannot hide assembly. It remains a tripwire, not a security boundary.
- `ExportFunctions.java`: one very long function name (C++ templates) made the file name exceed the file-system limit and aborted the whole export with `RESULT: PARTIAL`. Names are now shortened with a hash, and a file that cannot be written is recorded as `write_failed` instead of stopping the export. `ghidra_export.py --decompile-timeout N` sets the per-function limit (it was fixed at 30 seconds and the wrapper never passed it); the summary records it.
- `rank_functions.py`: functions with `decompile_status` timeout, failed or write_failed vanished silently, and `NOTHING_LEFT` was printed (exit 0) when only they remained. They are now named in a NOTE; if only they remain the verdict is `UNDECOMPILED_LEFT` (exit 1) with the fix; `--include-undecompiled` ranks them for work from the disassembly.
- `verify_emulated.py`: the default boundary cases paired a 16-byte buffer with lengths such as 2147483646, so a correct `sum_bytes(p, n)` or `fill(buf, n, v)` produced `EMULATION_ERROR` with a misleading hint, or was blamed with `CANDIDATE_CRASH`. New argument types `len32` and `len64` (right after a `ptr`) generate a buffer and its length together, with empty, partial and full buffers. Without them the error now names the real cause. The skill's own example uses `ptr,len32`.
- `verify_trace.py`: identical traces with an optional key (an `event` on some ticks) failed with `TRACE_DIVERGES`, because a key missing from both sides counted as a difference. A key that only one trace ever logs was silently skipped; it is now named in a WARNING, `--strict` fails on it (`TRACE_KEYS_DIFFER`), and `--keys` makes keys a requirement.
- `triage.py`: Slack, Discord, Telegram and Teams webhook URLs were printed in full (their secret is in the path) and are now redacted in the console and the JSON; JSON-style credentials (`{"password":"..."}`) were not flagged and now are; a 192-byte ELF claiming a 70 TB section-name table raised `MemoryError` and is now reported as malformed; any text file with CR LF at bytes 2-3 was labelled Python bytecode (the marshalled code object is now checked); the WebAssembly route named `wasm-decompile`, which some wabt releases do not ship.
- `verify_run.py`: hidden files (`.gitkeep`, `.DS_Store`) counted as test cases and could satisfy `--min-inputs`; they are now ignored and the run says so.
- 36 new tests (150 in total), including live Ghidra tests for the long-name export and the decompile limit.

## 0.4.2

Fixed. A second public review and this project's own Windows CI found more input-handling gaps. Each was reproduced before it was fixed.
- `verify_emulated.py`: an ELF segment or PE section that declares file data beyond the end of the file was accepted and silently zero-filled, so the verifier could run against a memory image that was never in the binary. It is now rejected as truncated or corrupt (a range ending exactly at the end of the file is still fine).
- `verify_emulated.py`: `--ptr-len` above 256 raised a `ValueError` (`bytes(range(n))`). Pointer buffers of any size work, and buffers that cannot fit in the 1 MiB scratch area are a clear setup error.
- `verify_emulated.py`: `--candidate-timeout nan` and `inf` slipped past validation and raised from `Connection.poll()`. All numeric options are now finite and bounded, including `--max-insns` and `--show`.
- `verify_emulated.py`: values in a `--cases` file were not checked against their declared types, so a string, a float or `null` raised a `TypeError` and `true` or an out-of-range integer was accepted silently. Every value is now validated, with line-numbered messages.
- `triage.py`: `--scan-mib inf` raised an `OverflowError`; a file that cannot be read gave a traceback.
- Same weakness found by sweeping the other scripts: `verify_run.py --timeout nan` and `inf` raised; `ledger.py add --seconds nan` wrote `nan` into the ledger, which then poisoned every total; the scorer and the report renderer accepted non-finite ledger values; `ghidra_export.py` accepted a zero timeout.
- Tests: the colon-in-a-folder-name test cannot run on Windows (such folder names are illegal there), so it is skipped on Windows; drive-letter parsing is covered by its own test, which passes on Windows CI. 16 new tests (114 in total).

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

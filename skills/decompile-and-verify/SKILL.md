---
name: decompile-and-verify
description: Decompiles and reverse engineers compiled software (native ELF/PE/Mach-O, .NET, Java, Android APKs, Python bytecode, Unity, WebAssembly, retro ROMs) into readable source, then proves each recovered function against the original with a matching or differential test instead of trusting the decompiler. Use when the user wants to decompile, disassemble, reverse engineer, port, audit or recover source from a binary, DLL, EXE, APK, JAR, ROM or game, asks "how does this program work", "what does this function do" or "can I rebuild this exactly", or wants decompilation worked through function by function.
license: MIT
compatibility: Needs a shell and Python 3.9+. Native targets need Ghidra and a JDK 21+ with javac; the matching oracle needs gcc and objdump (on Windows, MSYS2 or WSL). Checks what is installed and asks before installing anything.
metadata:
  author: Nemesis-driod
  homepage: https://github.com/Nemesis-driod/decompile-and-verify
  version: "0.3.0"
---

# Decompile and verify

A decompiler's output is a hypothesis. The binary is the only ground truth. Every function you report leaves with a verdict from a check that can fail, so nobody has to guess whether the code is right. Decompilers fail quietly: in a measured case, pycdc turned `tier == 2` into `None == 2` and dropped a `return`, with no warning.

The scripts live in `scripts/` next to this file (paths like `scripts/...` are relative to this skill's folder; `work/...` is relative to the user's project). Run them instead of re-implementing them, with `python3` (on Windows, `python`). Each prints a `RESULT:` line, and that line outranks your own reading of the code.

| Script | Use |
|---|---|
| `triage.py <file> --json work/triage.json` | identity, format, stripped or not, packer hints, endpoints and secret-like strings (redacted), suggested route |
| `ghidra_export.py <bin> work/export` | Ghidra headless: `functions.csv` plus one `decompiled/<addr>_<name>.c` per function |
| `rank_functions.py work/export/functions.csv --ledger work/ledger.csv` | prints `NEXT:`, the cheapest function not yet done (`--unnamed-only` skips code Ghidra already named) |
| `verify_match.py --target t.o --candidate c.c --cc "<original compiler and flags> -c"` | matching oracle |
| `verify_run.py --original A --rewrite B --inputs dir` | differential oracle |
| `ledger.py add work/ledger.csv ...` / `ledger.py summary work/ledger.csv` | one tidy row per function; attempts and seconds accumulate |

Managed and bytecode targets (.NET, Java, Android, Python, WebAssembly) skip Ghidra: see `references/routes.md`, which also says which routes have been run and which have not.

## Workflow

Copy this into `work/DECOMPLOG.md` and tick items off. The log is your memory: anything not written there is lost at the next context compaction. The steps are a default, not a script; skip what does not apply, but never skip the oracle.

```
- [ ] 1. Triage: scripts/triage.py <file> --json work/triage.json   (hash the original, keep it read-only)
- [ ] 2. Export: scripts/ghidra_export.py <file> work/export, or the managed route in references/routes.md
- [ ] 3. Choose the oracle (next section) and write it at the top of the log
- [ ] 4. Loop: NEXT function -> read -> candidate -> verify -> ledger, until the worklist is empty or the budget is spent
- [ ] 5. Clean pass: names, types, structure; re-run the oracle after every cleanup
- [ ] 6. Report (last section)
```

## Choose the oracle first

Pick the strongest check the target allows, and say which one backs each function.

- **Matching**: compile with the original compiler, version and flags and compare instructions. Possible for older toolchains you can identify (retro consoles, some 1990s-2000s PC games); rarely for modern builds (LTO, PGO, unknown flags). `verify_match.py`.
- **Differential**: run original and rewrite on the same inputs and compare outputs. The realistic oracle for modern native code. `verify_run.py`.
- **Round trip or trace replay**: for file formats (decode, encode, decode, compare) and for engine logic (record real traces, replay them against the port). See `references/verification.md`.
- **Reading only**: no oracle. Mark the function `unverified`. Never present it as recovered source.

A match proves the same machine code, not the author's source: different source can compile identically (a `for` and a `while` loop often do). Aim for code a developer would plausibly have written.

## The per-function loop

1. `rank_functions.py` prints `NEXT:`. Take it. Do not choose targets yourself: cheapest first keeps cost predictable and teaches you the compiler's habits before the hard cases.
2. Read that function's `decompiled/*.c`. Ask for disassembly only when you need it; do not dump listings nobody asked for.
3. Write `work/attempts/<function>/attempt_<n>.c`, one file per attempt, so a good attempt is never overwritten by a worse edit.
4. Verify. Before the next attempt, state in one sentence why it failed and what the next change should fix. Change one thing at a time.
5. Same failure three times: change approach (new hypothesis, different oracle, or ask the user). About ten attempts: mark `skipped` with the best diff and move on.
6. Record the result with `ledger.py add work/ledger.csv --address 0x... --name ... --status matched|equivalent-tested|unverified|skipped --oracle "..." --attempts N --seconds S --notes "..."`. Never put secrets in notes. Then commit, and record what you learned in `work/types.h` and `work/symbols.csv`. A shared header makes every later function cheaper.

## Gotchas

- Do not do arithmetic in your head: struct offsets, sizes, sign extension. Compile `offsetof` and `sizeof` checks.
- State the language standard the original used. Old compilers mean C89: declarations at the top of a block.
- The oracle can be gamed. Inline assembly or hard-coded test vectors pass a check without recovering anything. `verify_match.py` rejects inline asm; for differential tests, use inputs you did not derive from the decompiled code.
- Equivalent on a sample is not equivalent. Include boundaries (0, negative, maximum, empty, off-by-one around every comparison). In testing, two easy inputs called an off-by-one "equivalent".
- Names are claims. Keep `FUN_<addr>` until evidence supports a name. Constants identify algorithms: 0x811c9dc5 is FNV-1a. See `references/names-and-types.md`.
- Compilers fold and inline. A function that just returns `DAT_x` may be a constant-folded computation; check its callers before concluding.
- `0.2f` is not `0.2`. Keep float32 constants float32.
- `ctypes` and `dlopen` cannot load a PIE executable. For one function inside an executable, test the whole program or emulate it.
- Ghidra needs a full JDK (21+, with `javac`). With only a JRE it prints a misleading "unsupported java version".
- Go binaries keep function names in `.gopclntab` after `strip`, so stripping does little for them.
- Static first. Running an unknown binary executes its code; use a throwaway VM or container if you must run it. `verify_run.py` runs both programs you give it.
- Decompiler output is a draft: it rarely compiles as-is and is full of `iVar1` and casts.

## Report

End with: what was recovered and counts per status (`ledger.py summary`); which oracle backed each function; what is unverified or skipped and why; tool versions and the exact commands to reproduce; the ledger and the log. Keep binaries and decompiled output under `work/` (gitignored) and commit your own notes, scripts and tests.

## References

- `references/routes.md`: commands per target type, with what has and has not been run.
- `references/verification.md`: oracle recipes, coverage, and keeping the check honest.
- `references/names-and-types.md`: evidence for names, struct recovery, library identification, constants table.
- Assessing a build for its owner (exposure score, cost to recover, report): the `decompile-assess` skill.

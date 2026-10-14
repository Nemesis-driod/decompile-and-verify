# Ports, recompilation and emulation

How the projects that convert games and other software to new platforms work, where verification fits, and which parts of that work these scripts cover. The sources are the projects' own READMEs and published write-ups; commands for those tools are not repeated here, because the tools change quickly.

## Contents
- Ways to convert software
- The pipeline and where verification fits
- Stub and trace: how emulation and recompilation projects progress
- Compatibility ladder and what a percentage claims
- Where agents help and where they do not
- Pitfalls when moving old code to a new platform
- Patching and mods
- What the scripts here cover

## Ways to convert software

| Approach | What it produces | Core trick | What shows it works |
|---|---|---|---|
| Matching decompilation | source that rebuilds the original binary byte for byte | compile, compare, retry; the rebuilt file's hash equals the original's | whole-build hash, per-function instruction match |
| Functional reconstruction | source with the same behaviour, not the same bytes | differential tests and traces | `verify_run.py`, `verify_emulated.py`, `verify_trace.py` |
| Static recompilation | the original machine code translated instruction by instruction into C that an ordinary compiler builds, plus a runtime that replaces the OS, graphics, audio and input | function boundaries and symbols come first (from a disassembly project); each instruction becomes a C statement on register variables; indirect calls go through lookup tables | traces and play-through; per-function checks |
| Emulation or translation layer | the original binary keeps running; a layer supplies the OS and graphics API it expects | PlayStation 5 emulators run the game's native x86-64 code and implement the console's system libraries, translating GPU commands to Vulkan | per-game compatibility labels, not one number |
| Source port | new code built from recovered logic on a new engine or platform | recover and verify the logic first, then replace the platform layers | traces and play-through |

No PlayStation 5 emulator claims full compatibility; the established ones describe themselves as early and experimental, and "boots further" is not "playable". Treat any repository promising 100% compatibility or a ready-to-run download of a console emulator as unverified.

## The pipeline and where verification fits

1. **Pin the build.** Record the sha256 of the exact binary. Every result is about that file.
2. **Recover structure.** Function boundaries, symbols, types. This is the input a static recompiler needs, and it is what `ghidra_export.py`, the ledger and `work/symbols.csv` produce.
3. **Understand and rebuild the logic.** Matching, differential and emulated checks per function.
4. **Translate or reimplement.** Tool-specific (a recompiler, a translation layer, a port).
5. **Replace the platform layers.** OS calls, graphics, audio, input: the stub-and-trace loop below.
6. **Verify the whole.** Replay the same recorded input through original and port and compare traces.
7. **Package without the original assets.** Projects in this space ship tooling and make the user supply their own copy.

## Stub and trace: how emulation and recompilation projects progress

Run the converted program until it reaches the first unimplemented system or library call. Log the call and its arguments, implement the smallest behaviour that satisfies it, and rerun. When a milestone is reached, record the same input in the original and the port and compare traces with `verify_trace.py`. Progress is reported as the furthest milestone reached, not as a percentage of features.

## Compatibility ladder and what a percentage claims

Use these labels, and record the tool version and the game build's hash with each result: boots; initialises graphics; reaches a menu; in game with faults; a playable segment; completable.

A percentage needs a definition. Matching decompilation projects publish separate counters: functions that match the original bytes, functions that are readable (named, typed, cleaned up), and functions actually linked into the port. A function can match and still be unreadable. State which counter you mean, what the counter excludes (hand-written assembly primitives, for example), and whether the comparison checks call and data destinations, or only instruction shapes.

## Where agents help and where they do not

- Helpful: reading decompiled code, naming and typing, writing candidate C, writing platform shims, building test harnesses, keeping the ledger.
- Not a substitute: the instruction lifting itself (deterministic tooling), the oracle, and a project's own rules. Some projects do not accept AI-generated contributions; N64Recomp's contributing guide says so. Read a project's policy before contributing to it.
- Public projects keep a progress file and an oracle description next to the code (what is proven, against which cases). Do the same: the ledger plus a short `ORACLES.md` stating each oracle, its input set and what it proves.

## Pitfalls when moving old code to a new platform

- 32-bit to 64-bit: addresses stored in 32-bit integers, `long` width, struct layout and padding.
- Integer behaviour the old compiler happened to define: overflow, shift counts, signedness, division of negatives. Make the intended arithmetic explicit instead of relying on the new compiler.
- Endianness on big-endian consoles: swap at the edges, not everywhere.
- Floating point: x87 versus SSE, float32 constants, rounding modes.
- Hidden state: RNG seeding, uninitialised memory, frame-time assumptions, save formats.
- Reaching the title screen proves that scene works. Test save and load, rare transitions and long sessions.
- Test error paths as well as success paths, and reproduce the original's quirks before cleaning them up (be bug-compatible first).

## Patching and mods

Static recompilers can emit patched functions into a separate object that the linker prefers over the originals, so only the patch is recompiled when you iterate. Keep patches as source or diffs, never as modified binaries, and re-run the oracles after each patch.

## What the scripts here cover

| Stage | Covered by |
|---|---|
| Pin and identify the build | `triage.py` (sha256, format, packers) |
| Function inventory and symbols | `ghidra_export.py`, `ledger.py`, `work/symbols.csv` |
| Per-function equivalence | `verify_match.py`, `verify_run.py`, `verify_emulated.py` |
| Whole-behaviour replay | `verify_trace.py` |
| Whole-build match | compare the rebuilt file's sha256 with the original's |
| Progress and cost | `ledger.py`, `decompile-assess` |
| Not covered | the recompiler engine, OS, graphics and audio replacement, launchers and mod orchestration, packaging: use the dedicated projects for those |

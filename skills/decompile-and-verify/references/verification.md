# Verification recipes

## Contents
- What each verdict proves
- Pin the target
- Matching
- Differential testing, whole program
- Differential testing, one function (emulated)
- Round trip
- Trace replay
- Whole-build match
- Keeping the oracle honest

## What each verdict proves

| Verdict | Proves | Does not prove |
|---|---|---|
| `MATCH` (matching) | your source compiles to the same instructions with that toolchain | that it is the author's source, or behaviour under another toolchain |
| `EQUIVALENT_ON n` (`verify_run.py`) | same outputs and exit codes on those n whole-program inputs | anything about other inputs |
| `EQUIVALENT_ON n cases` (`verify_emulated.py`) | the original function's machine code and your candidate agree on those n argument sets (return value and pointer buffers) | behaviour on other arguments, or side effects on memory you did not pass in |
| `TRACE_MATCH n ticks` | the port reproduced the recorded state tick by tick for that recorded input | other inputs, or state you did not record |
| rebuilt file's hash equals the original's | a matching build of the whole file | nothing else is needed; this is the strongest result |
| round trip passes | reader and writer agree with stock files | that new files load in the target program |
| `unverified` | nothing | |

## Pin the target

Record the sha256 of the exact binary in the log and in every report, and say which build a claim is about. A result for one build says nothing about the next release. Separate what you observed (read from the bytes, or seen when run) from what you inferred, and say which each statement is.

## Matching

Use the original compiler, version and flags (`--cc`). `verify_match.py` compares `objdump` output after normalising offsets; function names must match the target's, and relocation lines keep their symbol names, so call and data destinations are compared too. For retro targets prefer asm-differ or objdiff, which understand relocations and register differences. In linked executables, relocations and layout break byte comparison, so use differential testing there.

Read the diff, not just the percentage, and change one thing per attempt. Typical near-misses: signedness, loop form, evaluation order, integer width, a local that should be a parameter, struct field order.

## Differential testing, whole program

```bash
python3 scripts/verify_run.py --original ./orig --rewrite ./new --inputs inputs/ --mode stdin     # or: arg | arg-text   (Windows: python)
```

Choose inputs on purpose: boundaries first (0, negative, maximum, empty, off-by-one around every comparison in the code), then random, then inputs from real usage. Do not derive every input from the decompiled code you are testing. Differential fuzzing (AFL++ or libFuzzer generating inputs, both implementations compared on each) finds what hand-picked inputs miss.

For a Python target, import the original and the rewrite as modules and compare function by function (`examples/python-bundle/diff_funcs.py` in the repository is a ready example). For a shared library, call both through `ctypes` and compare.

## Differential testing, one function (emulated)

`ctypes` and `dlopen` refuse position-independent executables, and many functions cannot be run without the rest of the program. `verify_emulated.py` runs the original function's machine code in the Unicorn emulator, with your arguments, and compares it with a C shared library or a Python function:

```bash
pip install unicorn
python3 scripts/verify_emulated.py --binary app --address 0x1250 --args ptr --ret u32 \
    --candidate-lib cand.so --symbol fnv16 --image-base 0x100000
python3 scripts/verify_emulated.py --binary app.exe --address 0x00406af0 --args ptr --ret i32 --ptr-len 128 \
    --candidate-py recovered.py:validate_image_base --cases header_cases.jsonl
```

Boundary values for every argument and seeded random cases are generated for you; `--cases` adds your own (JSON lines, `ptr` values as hex strings), which you need for functions that only do something interesting on structured input. Pointer arguments get a buffer of `--ptr-len` bytes and the buffer is compared after the call, so output buffers are checked.

Verified on: stripped x86-64 ELF functions (integer, pointer in, pointer out, double), a 32-bit ELF with cdecl, a function from a real 32-bit Windows executable, and hand-built PE32, PE32+ (Win64) and fastcall files. Not supported: ARM, MIPS and other architectures, Mach-O, 32-bit floating-point arguments or returns (x87), stack-passed arguments beyond the registers on x86-64.

Limits: the function must be a leaf, or call only code inside the image. A call into an import or libc ends the run with `EMULATION_ERROR` and a hint. State that persists between calls (globals) is reset for every case, so stateful functions need a whole-program test.

## Round trip

For an unknown file format: collect several stock files and hex-dump the headers; form a hypothesis for header, record layout and compression; parse every stock file without errors; write a decoder whose output you can look at; write the encoder and prove decode, encode, decode against the original; only then write new files, and test one in the real program before converting in bulk. State the tolerance (exact bytes, or mean error for lossy data).

## Trace replay

For engine logic you port (simulators, trainers, recompiled games): record per-tick state from the original (positions, velocities, RNG seed, a frame hash) and from the port, driven by the same recorded input, then compare:

```bash
python3 scripts/verify_trace.py --original original.jsonl --rewrite port.jsonl --tolerance 1e-5 --ignore frame_time
```

It reports the first diverging tick and key. Typical causes: an action applied one tick late, float32 constants (exact comparison fails, a small tolerance passes), hidden state (a buff that multiplies speed), a dropped or duplicated tick (reported as `TRACE_MISALIGNED`). Replays find what reading the code misses.

## Whole-build match

When you can rebuild the whole binary with the original toolchain, compare the rebuilt file's sha256 with the original's. Matching decompilation projects ship this check as their definition of done.

## Keeping the oracle honest

- Reject inline assembly and raw data directives (`verify_match.py` does).
- Hold out inputs. Do not tune the rewrite on the whole test set.
- Make failures loud. The scripts print `RESULT:` with a fixed vocabulary: `MATCH`, `NOT_MATCH`, `BUILD_FAILED`, `REJECTED`, `EQUIVALENT_ON`, `DIFFERS`, `EMULATION_ERROR`, `TRACE_MATCH`, `TRACE_DIVERGES`, `TRACE_MISALIGNED`, `SETUP_ERROR`. Treat anything but a success as a failure.
- Limit output. The first 40 diff lines are enough; ask for more when you need them.
- Re-run the oracle after every cleanup or rename, and commit only when the verdict improves.

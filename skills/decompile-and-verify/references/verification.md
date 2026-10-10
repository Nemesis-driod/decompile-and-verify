# Verification recipes

## Contents
- What each verdict proves
- Matching
- Differential testing
- Round trip
- Trace replay
- Keeping the oracle honest

## What each verdict proves

| Verdict | Proves | Does not prove |
|---|---|---|
| `MATCH` (matching) | your source compiles to the same instructions with that toolchain | that it is the author's source, or behaviour under another toolchain |
| `EQUIVALENT_ON n` (differential) | same outputs on those n inputs | anything about other inputs |
| round trip passes | reader and writer agree with stock files | that new files load in the target program |
| `unverified` | nothing | |

## Matching

Use the original compiler, version and flags (`--cc`). `verify_match.py` compares `objdump` output after normalising offsets; function names must match the target's. For retro targets prefer asm-differ or objdiff, which understand relocations and register differences. In linked executables, relocations and layout break byte comparison, so use differential testing there.

Read the diff, not just the percentage, and change one thing per attempt. Typical near-misses: signedness, loop form, evaluation order, integer width, a local that should be a parameter, struct field order.

## Differential testing

Whole program, any language:

```bash
python3 scripts/verify_run.py --original ./orig --rewrite ./new --inputs inputs/ --mode stdin     # or: arg | arg-text   (Windows: python)
```

One function in a shared library: call both through ctypes.

```python
import ctypes, random
orig, new = ctypes.CDLL("./orig.so"), ctypes.CDLL("./new.so")
for f in (orig.fn, new.fn):
    f.argtypes, f.restype = [ctypes.c_int], ctypes.c_int
cases = [0, 1, -1, 2**31 - 1, -2**31] + [random.randint(-10**6, 10**6) for _ in range(1000)]
bad = [x for x in cases if orig.fn(x) != new.fn(x)]
print("EQUIVALENT_ON" if not bad else f"DIFFERS on {len(bad)} inputs, first {bad[0]}", len(cases))
```

One function inside an executable: `ctypes` and `dlopen` refuse position-independent executables ("cannot dynamically load position-independent executable"), so emulate the function (Unicorn), or test the whole program instead. For a Python target, import the original and the rewrite as modules and compare function by function (a ready example is `examples/python-bundle/diff_funcs.py` in the repository). For larger targets, differential fuzzing (AFL++ or libFuzzer generating inputs, both implementations compared on each) finds what hand-picked inputs miss.

Choose inputs on purpose: boundaries first (0, negative, maximum, empty, off-by-one around every comparison in the code), then random, then inputs from real usage. Do not derive every input from the decompiled code you are testing.

## Round trip

For an unknown file format: collect several stock files and hex-dump the headers; form a hypothesis for header, record layout and compression; parse every stock file without errors; write a decoder whose output you can look at; write the encoder and prove decode, encode, decode against the original; only then write new files, and test one in the real program before converting in bulk. State the tolerance (exact bytes, or mean error for lossy data).

## Trace replay

For engine logic you port (simulators, trainers, reimplementations): record real traces from the original (positions and velocities per tick) and replay them against your port. Mismatches are usually frame ordering (an action applied on the next frame), float32 constants, or hidden state (a buff that multiplies speed). Replays find what reading the code misses.

## Keeping the oracle honest

- Reject inline assembly and raw data directives (`verify_match.py` does).
- Hold out inputs. Do not tune the rewrite on the whole test set.
- Make failures loud. The scripts print `RESULT:` with a fixed vocabulary: `MATCH`, `NOT_MATCH`, `BUILD_FAILED`, `REJECTED`, `EQUIVALENT_ON`, `DIFFERS`, `SETUP_ERROR`. Treat anything but a success as a failure.
- Limit output. The first 40 diff lines are enough; ask for more when you need them.
- Re-run the oracle after every cleanup or rename.

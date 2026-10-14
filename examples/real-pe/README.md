# Example: one function from a real Windows executable

Ghidra ships a small 32-bit Windows program, `WinHelloCPP.exe`, as a training exercise (in your Ghidra folder, under `docs/GhidraClass/ExerciseFiles/WinhelloCPP/`). It contains the Visual Studio 2005 C runtime, including `__ValidateImageBase`, a small pure function that checks a PE header through a pointer. The binary is not part of this repository.

1. Export it and read the function (Ghidra's decompiled C is a hypothesis):

```bash
python3 ../../skills/decompile-and-verify/scripts/ghidra_export.py WinHelloCPP.exe work/export
# work/export/decompiled/00406af0___ValidateImageBase.c
```

2. `candidate.py` is written from that C. Check it against the **original machine code**, emulated:

```bash
pip install unicorn
python3 make_cases.py                       # header buffers that exercise each branch
python3 ../../skills/decompile-and-verify/scripts/verify_emulated.py \
  --binary WinHelloCPP.exe --address 0x00406af0 --args ptr --ret i32 --ptr-len 128 \
  --candidate-py candidate.py:validate_image_base --cases header_cases.jsonl --random 50
# RESULT: EQUIVALENT_ON 66 cases (emulated original vs candidate; 7 boundary, 59 random or from file; a sample, not a proof)
```

3. The negative control must fail:

```bash
python3 ../../skills/decompile-and-verify/scripts/verify_emulated.py \
  --binary WinHelloCPP.exe --address 0x00406af0 --args ptr --ret i32 --ptr-len 128 \
  --candidate-py candidate.py:wrong_magic --cases header_cases.jsonl --random 50
# RESULT: DIFFERS on 5 of 66 cases (treat as a failure)
```

The random buffers almost never start with `MZ`, so they only exercise the "return 0" path. The structured cases in `header_cases.jsonl` are what reach the rest of the function, which is why the oracle accepts a cases file.

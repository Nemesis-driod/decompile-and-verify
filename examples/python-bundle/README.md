# Example: a Python program inside a PyInstaller executable

A 15-line program (`demo.py`, written for this repo) is packed with PyInstaller, unpacked again, decompiled with pycdc, and the result is compared with the original source. It shows why the skills insist on a check.

Versions used for the numbers below: Python 3.12.3, PyInstaller 6.22.3, pyinstxtractor from its `master` branch at the time, pycdc commit `b428976` (2026-04-06), Ubuntu 24.04. This is one small program, not a verdict on pycdc.

```bash
pip install pyinstaller
python3 -m PyInstaller --onefile demo.py                          # dist/demo
python3 ../../skills/decompile-and-verify/scripts/triage.py dist/demo
#   protection : PyInstaller (bundler)
#   route      : PyInstaller bundle -> pyinstxtractor <file>, then pycdc ...

curl -sLO https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py
python3 pyinstxtractor.py dist/demo                               # demo_extracted/demo.pyc

git clone https://github.com/zrax/pycdc && cmake -S pycdc -B pycdc/build && make -C pycdc/build
pycdc/build/pycdc demo_extracted/demo.pyc > demo_pycdc.py
python3 demo_pycdc.py                                             # SyntaxError: 'return' outside function
```

Remove only the stray module-level `return None` lines so the file parses, then compare behaviour:

```bash
python3 diff_funcs.py demo.py demo_pycdc.py
# apply_discount: DIFFERS on 15 of 25 inputs
#    apply_discount(0.0, 0): original=0.0 rewrite=None
# validate: DIFFERS on 2 of 8 inputs
#    validate('AAAAAAAAAAAAAAf',): original=False rewrite=True
```

What the decompiler got wrong, all of it plausible-looking:

- `if tier == 2:` came out as `if None == 2:`, so that branch never runs.
- The final `return price` of `apply_discount` disappeared, so tiers 0 and 1 return `None`.
- `len(key) == 16 and ...` in `validate` became a no-op expression followed by an unconditional return, so wrong-length keys are accepted.
- Two `return None` statements landed at module level, which is a syntax error.

The decompiler printed no warning about any of this. A differential check found all of it in seconds.

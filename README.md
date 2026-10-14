# decompile-and-verify

[![tests](https://github.com/Nemesis-driod/decompile-and-verify/actions/workflows/test.yml/badge.svg)](https://github.com/Nemesis-driod/decompile-and-verify/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Agent skills that decompile compiled software, then prove the result.**

A decompiler's output is a hypothesis. These skills give your coding agent a method, scripts that print a verdict instead of an opinion, and a way to measure how much of a build an agent can recover and at what cost.

> **Status: v0.4.0, beta.** Verified end to end: native ELF and 32-bit PE (Ghidra 12.1.4), Java JARs (jadx, CFR, Vineflower), Electron asar, PyInstaller extraction, WebAssembly (wabt), rizin. The emulated oracle is verified on stripped x86-64 and x86-32 ELF functions and on a function from a real 32-bit Windows executable. **Not run yet:** .NET, an APK, Mach-O, Unity IL2CPP, retro ROMs. [`routes.md`](skills/decompile-and-verify/references/routes.md) has the full table with versions. 60 unit tests, both skills pass the Agent Skills validator, Claude Code's plugin validator passes, and the `npx skills` CLI discovers both skills.

## Why verify

A real run, one small program. A 15-line Python program was packed with PyInstaller, unpacked, and decompiled with pycdc (commit `b428976`, Python 3.12 bytecode). The output was plausible and wrong:

- `if tier == 2:` came out as `if None == 2:`, so that branch never runs.
- A final `return price` vanished, so tiers 0 and 1 return `None` (tier 2 does too, because of the first bug).
- `len(key) == 16 and ...` became a no-op expression plus an unconditional return, so wrong-length keys are accepted.
- Two `return None` lines landed at module level, a syntax error.

The decompiler printed no warning. A differential check against the original found all of it in seconds: `apply_discount` differed on 15 of 25 inputs and `validate` on 2 of 8. Steps and numbers are in [`examples/python-bundle`](examples/python-bundle). It is one program and one tool version, not a verdict on pycdc; the point is that nothing flagged the problem and a check did.

## What it looks like

A toy licence check, built without symbols. Real output, abridged.

```text
$ python3 skills/decompile-and-verify/scripts/triage.py sample_stripped
== triage: sample_stripped ==
size       : 14,472 bytes
format     : ELF 64-bit x86-64
symbols    : stripped (no .symtab); debug info: no
runtime    : GCC; GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
protection : no known packer/protector markers
entropy    : 1.55/8 overall, 0% of 4 KB blocks above 7.5 (high suggests packed or encrypted data)
route      : native -> python3 scripts/ghidra_export.py <file> <outdir>   (references/routes.md: Native)
notable strings:
  url        https://licensing.example-corp.test/v2/activate
  secret     api_ke...(33 chars)  [credential-assignment]

$ python3 skills/decompile-and-verify/scripts/ghidra_export.py sample_stripped work/export
RESULT: OK
functions=24
named_functions=5
decompiled_ok=24

$ python3 skills/decompile-and-verify/scripts/rank_functions.py work/export/functions.csv
NEXT: 00101250 FUN_00101250 (score 14, c file: decompiled/00101250_FUN_00101250.c)

rank  address    name                         score instr  br call
   1  00101250   FUN_00101250                    14    11   1    0
   2  00101190   FUN_00101190                    17     9   2    1
   3  001011c0   FUN_001011c0                    22    14   2    1
```

The cheapest function, with every name stripped, still announces what it is:

```c
uint FUN_00101250(byte *param_1)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  
  pbVar1 = param_1 + 0x10;
  uVar3 = 0x811c9dc5;
  do {
    bVar2 = *param_1;
    param_1 = param_1 + 1;
    uVar3 = (uVar3 ^ bVar2) * 0x1000193;
  } while (param_1 != pbVar1);
  return uVar3 & 0x7fffffff;
}
```

Two constants (`0x811c9dc5`, `0x1000193`) identify FNV-1a. The agent writes a rewrite from what the decompiler shows, then the differential oracle decides whether it is right:

```text
$ python3 skills/decompile-and-verify/scripts/verify_run.py --original ./sample_stripped --rewrite ./rewrite --inputs inputs --mode arg-text
RESULT: EQUIVALENT_ON 40 inputs (a sample, not a proof)

$ # negative control: the same rewrite with one constant changed (97 -> 96)
RESULT: DIFFERS on 8 of 40 inputs (treat as a failure)
```

A check that cannot fail proves nothing, so the repo ships the control.

A function inside a stripped executable can also be checked on its own. `verify_emulated.py` runs the **original machine code** of that one function in an emulator and compares it with your candidate:

```text
$ python3 skills/decompile-and-verify/scripts/verify_emulated.py --binary sample_stripped --address 0x101250 --image-base 0x100000 --args ptr --ret u32 --candidate-lib cand_checksum.so --symbol fnv1a_16
RESULT: EQUIVALENT_ON 207 cases (emulated original vs candidate; 7 boundary, 200 random or from file; a sample, not a proof)

$ # negative control: one constant changed
RESULT: DIFFERS on 207 of 207 cases (treat as a failure)
```

The same oracle checked a candidate written from Ghidra's decompiled C against a function in a real 32-bit Windows executable: [`examples/real-pe`](examples/real-pe).

## Install

| Where | How |
|---|---|
| Claude Code | `/plugin marketplace add Nemesis-driod/decompile-and-verify` then `/plugin install decompile-and-verify@decompile-and-verify` |
| Other agents that read Agent Skills | `npx skills add https://github.com/Nemesis-driod/decompile-and-verify` |
| By hand | copy the two folders under `skills/` into your agent's skills folder (Claude Code: `~/.claude/skills/`) |

Requirements: Python 3.9+. Native targets also need [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a full JDK 21+ with `javac` (a JRE alone fails with a misleading error). The matching oracle needs gcc and objdump; the emulated oracle needs `pip install unicorn`. The skills ask before installing anything.

Context cost, from Claude Code's own estimate (`claude plugin details`): about 319 tokens always on (the two descriptions), and about 2k and 1.3k tokens when `decompile-and-verify` or `decompile-assess` fires.

| | Linux | macOS | Windows |
|---|---|---|---|
| Python scripts | tested | not hand-tested; CI runs the portable tests | not hand-tested; CI runs the portable tests |
| Ghidra export | tested | should work | should work; use `python` instead of `python3` |
| Matching oracle (gcc, objdump) | tested | untested | use WSL or MSYS2 |

## Try it

- "Decompile `./app.exe` and explain how the licence check works. Verify everything you claim."
- "Recover source for the functions in `libfoo.so`. Use differential testing against the original."
- "Assess `./build/app.apk`: how exposed is our logic to AI-assisted reverse engineering? Crown jewels: licence check and pricing."

## Two skills

| Skill | What it does |
|---|---|
| `decompile-and-verify` | triage, Ghidra export, cheapest-first worklist, per-function loop with a matching or differential oracle, ledger, report |
| `decompile-assess` | fixes an engagement sheet and budget, scores symbol exposure, legibility, embedded secrets and measured agent recovery, renders a report mapped to OWASP MASVS-RESILIENCE |

## Can an AI decompile your software?

Nothing shipped to a client device can be made unrecoverable. What an owner controls is the cost. `decompile-assess` measures that cost and reports it with evidence. On the toy sample, with the Recoverability Index (v0, uncalibrated):

| Build | Surface-only | After a recovery pass |
|---|---|---|
| with symbols | 93/100 | not run |
| stripped | 60/100 | 76/100 (4 of 4 functions recovered, 4 attempts) |

Stripping hid the names. It did not hide the licence algorithm, the activation endpoint or the credential-shaped string. The surface score alone understated the exposure; measuring recovery corrected it. [`examples/sample/artifacts/report.md`](examples/sample/artifacts/report.md) is the full report, rendered only from measured files, and you can reproduce the scoring and the report from the artifacts in that folder without installing Ghidra ([instructions](examples/sample/README.md)).

## Evals

`evals/` holds three cases for `claude plugin eval`, which scores the plugin against a no-plugin baseline: a claim that needs an oracle, an assessment plan, and a plain coding task that must not fire the skill. The CLI parses all of them. They have not been scored against a live model yet; run `claude plugin eval . --trust-plugin` with your own credentials and publish what you get.

## How it works

- **Oracle first.** Matching (same instructions under the original compiler), differential (same behaviour on the same inputs, for the whole program or for one function run under emulation), trace replay (a port reproduces the recorded state tick by tick), round trip, or a whole-build hash. Reading alone is marked `unverified`. [`verification.md`](skills/decompile-and-verify/references/verification.md) says what each verdict proves and what it does not.
- **Scripts print verdicts.** `MATCH`, `NOT_MATCH`, `BUILD_FAILED`, `REJECTED`, `EQUIVALENT_ON`, `DIFFERS`, `EMULATION_ERROR`, `TRACE_MATCH`, `TRACE_DIVERGES`, `TRACE_MISALIGNED`, `SETUP_ERROR`. Clear tool output steers an agent better than extra prompt text.
- **Cheapest first.** A ranker picks the next function, so cost stays predictable.
- **Ledger.** Every function leaves a row (status, oracle, attempts, seconds). The same ledger is the cost-to-recover measurement the assessment uses.

## How this fits with other projects

- **[REA](https://github.com/morluto/rea)** is a broad analysis platform: an MCP server and CLI over Hopper, Ghidra, IDA and other providers, with an evidence record for each finding and its own reconstruction check. This repo is smaller and complementary: stdlib scripts that print verdicts, with no server to run, an emulated per-function oracle, a trace oracle, and an assessment method that measures cost to recover. Use both if you like; [`routes.md`](skills/decompile-and-verify/references/routes.md) says how.
- **[Universal Modder](https://github.com/rehan-remade/universal-modder)** is an end-to-end toolkit for modding games with a coding agent. **Melty** is a launcher for AI-built game mashups. Neither is a decompilation toolkit; both are places where recovered and verified knowledge gets used.
- **Recompilation and emulation projects** (N64Recomp and similar static recompilers, PlayStation translation layers such as KytyPS5) convert software to run elsewhere. This repo does not do that conversion. It covers the verification half: pinning the build, recovering structure, proving functions and replaying traces. [`ports-and-recompilation.md`](skills/decompile-and-verify/references/ports-and-recompilation.md) explains how those projects work and where each check fits.

## Credits

The text and scripts here are original. The design leans on prior work worth reading: [Universal Modder](https://github.com/rehan-remade/universal-modder) (MIT; small focused skills, an orchestrator, references, installable everywhere), Chris Lewis's write-ups on agent-driven matching decompilation (defensive tooling, cheapest-first scoring, one-shot loops), Armin Ronacher's Ghidra skill and the SpecterOps reverse-engineering plugin, Anthropic's skill authoring guidance, [OWASP MASVS](https://mas.owasp.org/MASVS/), and [Ghidra](https://ghidra-sre.org/).

## Roadmap

- A field-notes knowledge base: after a decompilation, agents open a pull request recording toolchain, flags and gotchas.
- Run the .NET, APK, Mach-O and Unity routes and publish what happens.
- Extend the emulated oracle to ARM and MIPS, and to stack-passed arguments.
- Calibrate the Recoverability Index against real builds and publish the method.
- A command-line runner that executes the assessment end to end.

## Contributing

Route reports (good and bad), gotchas with a source, and script fixes with a failing test are all welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## Maintainer


MIT licensed. See [CHANGELOG.md](CHANGELOG.md).

# decompile-and-verify

**Agent skills that decompile compiled software, then prove the result.**

A decompiler's output is a hypothesis. These skills make your agent test every recovered function against the original, with scripts that print a verdict instead of an opinion. A second skill measures how recoverable a build is for an AI agent, and what it cost the agent to recover it.

> **Status: v0.3.** The native route is tested end to end (Ghidra 12.1.4, x86-64 ELF, 20 unit tests, validated with the official `skills-ref` checker). The .NET, Java/Android, Python, Unity, WebAssembly and retro-ROM routes use standard tool invocations that this repo's tests do not exercise yet.

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
entropy    : 1.54/8 overall, 0% of 4 KB blocks above 7.5 (high suggests packed or encrypted data)
route      : native -> scripts/ghidra-export.sh <file> <outdir>   (references/routes.md: Native)
notable strings:
  url        https://licensing.example-corp.test/v2/activate
  secret     AKIAIO...(20 chars)  [aws-access-key-id]

$ bash skills/decompile-and-verify/scripts/ghidra-export.sh sample_stripped work/export
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

$ # negative control: the rewrite with one constant changed (97 -> 96)
RESULT: DIFFERS on 8 of 40 inputs (treat as a failure)
```

The control matters. A check that cannot fail proves nothing.

## Install

| Where | How |
|---|---|
| Claude Code | `/plugin marketplace add Nemesis-driod/decompile-and-verify` then `/plugin install decompile-and-verify@decompile-and-verify` |
| Any agent that reads Agent Skills | `npx skills add https://github.com/Nemesis-driod/decompile-and-verify` |
| Anything else | clone the repo and start your agent inside it; `AGENTS.md` points at the skills |

Requirements: Python 3. Native targets also need [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a full JDK 21+ with `javac` (a JRE alone fails with a misleading error). Matching needs gcc and objdump. The skill asks before installing anything.

## Try it

- "Decompile `./app.exe` and explain how the licence check works. Verify everything you claim."
- "Recover source for the functions in `libfoo.so`. Use differential testing against the original."
- "Assess `./build/app.apk`: how exposed is our logic to AI-assisted reverse engineering? Crown jewels: licence check and pricing."

## Two skills

| Skill | What it does |
|---|---|
| `decompile-and-verify` | triage, export, cheapest-first worklist, per-function loop with a matching or differential oracle, ledger and report |
| `decompile-assess` | fixes an engagement sheet and budget, scores symbol exposure, legibility, embedded secrets and measured agent recovery, and writes a report mapped to OWASP MASVS-RESILIENCE |

## Can an AI decompile your software?

Nothing shipped to a client device can be made unrecoverable. What you control is the cost. `decompile-assess` measures that cost and reports it with evidence.

On the toy sample, with the Recoverability Index (v0, uncalibrated):

| Build | Surface-only | After a recovery pass |
|---|---|---|
| with symbols | 93/100 | not run |
| stripped | 60/100 | 76/100 (4 of 4 functions recovered, 4 attempts) |

Stripping hid the names. It did not hide the licence algorithm, the activation endpoint or the key-shaped string. The surface score alone understated the exposure; measuring recovery corrected it.

## How it works

- **Oracle first.** Matching (same instructions under the original compiler), differential (same behaviour on the same inputs), round trip, or trace replay. Reading alone is marked `unverified`.
- **Scripts print verdicts.** `MATCH`, `NOT_MATCH`, `BUILD_FAILED`, `REJECTED`, `EQUIVALENT_ON`, `DIFFERS`, `SETUP_ERROR`. Clear tool output steers an agent better than extra prompt text.
- **Cheapest first.** A ranker picks the next function, so cost stays predictable.
- **Ledger.** Every function leaves a row (status, oracle, attempts, seconds). The same ledger is the cost-to-recover measurement the assessment uses.

## Credits

The text and scripts here are original. The design leans on prior work worth reading: [Universal Modder](https://github.com/rehan-remade/universal-modder) (MIT; small focused skills, an orchestrator, references, installable everywhere), Chris Lewis's write-ups on agent-driven matching decompilation (defensive tooling, cheapest-first scoring, one-shot loops), Armin Ronacher's Ghidra skill and the SpecterOps reverse-engineering plugin, Anthropic's skill authoring guidance, [OWASP MASVS](https://mas.owasp.org/MASVS/), and [Ghidra](https://ghidra-sre.org/).

## Roadmap

- A field-notes knowledge base: after a decompilation, agents open a pull request recording toolchain, flags and gotchas.
- Fixtures and CI for the .NET, Android, Python and WebAssembly routes.
- Calibrate the Recoverability Index against real builds and publish the method.
- A command-line runner that executes the assessment end to end and renders the report.

## Maintainer
Issues and pull requests welcome; see `CONTRIBUTING.md`.

MIT licensed.

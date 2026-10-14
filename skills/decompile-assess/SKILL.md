---
name: decompile-assess
description: Measures how recoverable a software build is for an AI agent and writes an evidence-backed exposure report covering symbols, readable logic, embedded secrets and endpoints, and the cost (attempts, time) to recover the functions that matter, mapped to OWASP MASVS-RESILIENCE. Use when the user or a client asks "can our software be decompiled", "how exposed is our binary, APK or app to reverse engineering", "run a decompile test", "test our obfuscation", "third-party reverse-engineering assessment", or wants before-and-after numbers for a hardening change.
license: MIT
compatibility: Builds on the decompile-and-verify skill installed alongside it. Needs Python 3.9+; native builds also need Ghidra and a JDK 21+ with javac.
metadata:
  author: Nemesis-driod
  homepage: https://github.com/Nemesis-driod/decompile-and-verify
  version: "0.4.0"
---

# Decompile assessment

Nothing shipped to a client device can be made unrecoverable: given enough time and resources, the reverse engineer wins. What an owner can change is the cost. This skill measures that cost for an AI agent, reports it with evidence, and measures again after hardening. The number that matters is cost to recover, not whether recovery is possible.

The recovery work itself is the `decompile-and-verify` skill. Its scripts are in `../decompile-and-verify/scripts/`; this skill adds a budget, a score and a report around it. Run scripts with `python3` (on Windows, `python`). Paths like `scripts/...` and `../decompile-and-verify/scripts/...` are relative to the skill folders; `work/...` is relative to the user's project.

## 1. Fix the engagement sheet before running anything

Write `work/engagement.md`:

- Builds under test: path, sha256, build configuration, and what is out of scope.
- Crown jewels: 3 to 10 behaviours whose recovery would hurt (licence check, pricing or scoring logic, protocol and endpoints, model loading, key handling). Ask the owner; infer candidates from strings and imports and confirm them.
- Budget per crown jewel, fixed up front so reruns are comparable. Default: 10 attempts and 60 minutes each. Record the model and tool versions.
- Owner, contact, and who requested the test (it goes in the report header).

## 2. Surface pass (deterministic, minutes)

```
python3 ../decompile-and-verify/scripts/triage.py <build> --json work/triage.json
python3 ../decompile-and-verify/scripts/ghidra_export.py <build> work/export      # native builds
python3 scripts/score_exposure.py --functions work/export/functions.csv --triage work/triage.json
```

Managed builds (.NET, Java, Android) use the route in `decompile-and-verify/references/routes.md` and omit `--functions`; the score then uses what it can measure and says what it could not.

## 3. Recovery pass (agent, under budget)

For each crown jewel, run the `decompile-and-verify` loop and record it with `ledger.py add`, including attempts and seconds. Count a function as recovered only with both an oracle verdict and a plain-language statement of what the code does in the notes (for example "licence valid iff FNV-1a(key) % 97 == 42"). Never put secret values in notes. Also recover a random sample of about 20 functions to estimate general recoverability. Runs vary, so repeat each crown jewel up to three times when budget allows and report the median and the spread, not one run.

## 4. Score

```
python3 scripts/score_exposure.py --functions work/export/functions.csv --triage work/triage.json \
        --ledger work/ledger.csv --json work/exposure.json
```

The Recoverability Index is 100 times the weighted mean of four components, each 0 to 1 where 1 is most exposed: S symbols (0.2), L legibility of decompiled output (0.2), X embedded secrets, endpoints and build paths (0.2), R share of attempted functions an agent recovered (0.4). Without a ledger, R is dropped and the rest are re-weighted. Bands: 75 and above HIGH exposure, 40 to 74 MEDIUM, below 40 LOW.

RI is a v0, uncalibrated communication device. Always show the components and the cost to recover beside it. If triage reports a packer or protector, or very high entropy, the static surface is inconclusive: test the unpacked or in-memory image.

## 5. Report

```
python3 scripts/render_report.py --triage work/triage.json --exposure work/exposure.json --ledger work/ledger.csv \
        --engagement work/engagement.md --client "<name>" --requested-by "<name>" --tester "<name or agent>" \
        --versions "<tool and model versions>" --out work/report.md
```

Every number and finding in the output comes from those files. Then edit the report: add narrative for each crown jewel, state what was not recovered and why, and state the run-to-run variance. `references/report-template.md` describes the structure. Secret values are redacted (first 6 characters and the length); review the report before it leaves your hands.

## 6. Map findings and recommend

The renderer maps findings to fixes using the table in `references/remediation.md`. Credentials found in a build are already exposed: say "rotate" before anything else. After the owner changes something, repeat steps 2 to 5 with the same engagement sheet and report the delta.

## Scope of what this measures

Static recoverability: MASVS-RESILIENCE-3 (anti-static analysis). Platform integrity, anti-tampering and anti-dynamic analysis (MASVS-RESILIENCE-1, -2, -4) need runtime testing. For managed builds, name obfuscation is only partly detected by static triage, so S is an upper bound. Say so in the report.

## Worked example (a toy, from `examples/sample` in the repository)

A four-function licence check built twice, with and without symbols:

| Build | Surface-only RI | After recovery pass |
|---|---|---|
| unstripped | 93 (HIGH) | not run |
| stripped | 60 (MEDIUM) | 76 (HIGH): 4 of 4 functions recovered in 4 attempts |

Stripping removed the names. It did not hide the licence algorithm (FNV-1a over 16 bytes, modulus 97), the activation endpoint, or the credential-shaped string. The surface score alone understated the exposure; measuring recovery corrected it. That correction is the point of step 3.

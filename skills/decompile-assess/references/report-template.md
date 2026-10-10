# Decompile exposure report

_`scripts/render_report.py` fills this structure from the measured artifacts. Use this file as the reference when you edit the output._

**Client / owner:** <name, contact>  **Requested by:** <name>  **Date:** <date>
**Build(s):** <file, sha256, configuration>  **Tester:** <name or agent, model and tool versions>

## Summary

Recoverability Index: <RI>/100 (<band>) from components S <x>, L <x>, X <x>, R <x>.
Cost to recover: <attempts per function, minutes per function, share of crown jewels recovered within budget>.
Top three findings: <one line each, ordered by effect>.

## Scope and settings

In scope: <builds>. Out of scope: <items>. Budget per crown jewel: <attempts, minutes>. Repeats: <n>.
Crown jewels: <list with why each matters>.

## Surface findings

<triage output: format, stripped or not, protector hints, entropy, notable strings with values redacted to 6 characters and length>

## Recovery results

| Crown jewel | Oracle | Attempts (median, range) | Minutes | Recovered? | What the recovered code does |
|---|---|---|---|---|---|
| | | | | | |

Not recovered, and why: <honest list>.

## Mapping to OWASP MASVS-RESILIENCE

| Control | Evidence | Status |
|---|---|---|
| RESILIENCE-3 anti-static analysis | <symbols, obfuscation, recovery cost> | <met / partly / not met> |
| RESILIENCE-1, -2, -4 | not assessed by this test (needs runtime testing) | n/a |

## Recommendations

| Priority | Finding | Fix | Expected effect | Re-test |
|---|---|---|---|---|

## Limits

Static recoverability only. RI is a v0, uncalibrated index; cost to recover is the measurement. Agent runs vary: <variance>. <Anything else that limits the conclusion.>

## Reproduction

Commands, tool versions, hashes, ledger and log attached.

#!/usr/bin/env python3
"""Render the exposure report (Markdown) from the artifacts of an assessment run.

Usage:
  render_report.py --triage work/triage.json --exposure work/exposure.json [--ledger work/ledger.csv]
                   [--engagement work/engagement.md] [--client NAME] [--requested-by NAME] [--tester NAME]
                   [--versions TEXT] [--date YYYY-MM-DD] [--out work/report.md]

Every number and finding comes from those files; nothing is invented. Secret values are already redacted by
triage.py, and ledger notes are scrubbed again before they are written. Edit the output to add narrative.
"""
import argparse
import csv
import datetime
import json
import re
import signal
import sys

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRUB = [re.compile(p) for p in (
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"\bgh[pousr]_[0-9A-Za-z]{36,}\b",
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")]
MANAGED = {"dotnet", "java", "android", "python"}


def fail(message):
    print(f"RESULT: REPORT_ERROR\n{message}")
    sys.exit(2)


def scrub(text):
    for rx in SCRUB:
        text = rx.sub("[redacted]", text)
    return text


def cell(text):
    return scrub(str(text)).replace("|", "\\|").replace("\n", " ").strip()


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return out


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        fail(f"cannot read {what} ({path}): {e}. Run triage.py --json and score_exposure.py --json first.")


def load_ledger(path):
    if not path:
        return []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except OSError as e:
        fail(f"cannot read ledger ({path}): {e}")


def build_findings(tri, exp):
    comp, rec, f = exp["components"], exp.get("recovery") or {}, tri.get("findings", {})
    out = []
    secrets = f.get("secret_like", [])
    if secrets:
        kinds = ", ".join(sorted({s["type"] for s in secrets}))
        out.append(("secrets", f"{len(secrets)} secret-like string(s) are embedded in the build ({kinds}). Treat them as already exposed.",
                    "Rotate now. Move the secret server-side, or issue short-lived tokens at runtime.",
                    "Removes the exposure; stripping and obfuscation do not.", "triage.py reports none"))
    if "R" in comp and comp["R"] >= 0.25:
        word = "most" if comp["R"] >= 0.75 else "some"
        out.append(("recovery", f"An agent recovered {rec.get('recovered')} of {rec.get('attempted')} attempted functions in "
                    f"{rec.get('attempts_total')} attempts: {word} of the targeted logic is not protected by the current build.",
                    "Move the decision to a server, or split it so the client cannot decide alone. If it must stay client-side, add "
                    "obfuscation or virtualisation and measure the change.",
                    "Only a measured rise in cost to recover counts.", "R component and attempts per function"))
    if comp.get("S", 0) >= 0.8:
        out.append(("symbols", f"Function and member names are largely intact ({exp['notes'].get('S')}).",
                    "Strip native builds; enable R8/ProGuard (Android) or an obfuscator (.NET); keep mapping files private.",
                    "Raises the cost of reading. The logic itself survives.", "S component, then the recovery pass"))
    if f.get("urls") or f.get("ips"):
        out.append(("network", f"{len(f.get('urls', []))} URL(s) and {len(f.get('ips', []))} IP address(es) are visible in the build.",
                    "Put internal hostnames behind authentication and do not ship internal names. Public endpoints stay visible.",
                    "Limits what a recovered URL gives away.", "triage.py URL and IP lists"))
    if f.get("build_paths"):
        out.append(("paths", f"{len(f['build_paths'])} build path(s) leak developer environment details.",
                    "Build in clean CI with path remapping (-ffile-prefix-map, /pathmap, Go -trimpath).",
                    "Removes the leak.", "triage.py build paths"))
    if comp.get("L", 0) >= 0.9:
        out.append(("legibility", "Decompiled output is clean: little control-flow obfuscation slows a reader or an agent.",
                    "Consider control-flow obfuscation for the crown jewels and measure it.",
                    "Raises cost per function if it works; measure, do not assume.", "L component, then the recovery pass"))
    return out


def masvs_line(exp):
    comp = exp["components"]
    if "R" in comp:
        r = comp["R"]
        status = "not met within this budget" if r >= 0.75 else "partly met" if r >= 0.25 else "met within this budget"
        return f"{status} (indicative: agent recovery rate {r:.0%})"
    return f"not assessed (no recovery pass); surface only: S {comp.get('S', 0):.2f}, L {comp.get('L', 0):.2f}" if "L" in comp \
        else f"not assessed (no recovery pass); surface only: S {comp.get('S', 0):.2f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--triage", required=True)
    ap.add_argument("--exposure", required=True)
    ap.add_argument("--ledger")
    ap.add_argument("--engagement")
    ap.add_argument("--client", default="(not provided)")
    ap.add_argument("--requested-by", default="(not provided)")
    ap.add_argument("--tester", default="(not provided)")
    ap.add_argument("--versions", default="(not provided)")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--out", default="report.md")
    args = ap.parse_args()

    tri, exp = load_json(args.triage, "triage"), load_json(args.exposure, "exposure")
    for key in ("components", "ri", "band"):
        if key not in exp:
            fail(f"{args.exposure} lacks '{key}'. Re-run score_exposure.py --json.")
    ledger = load_ledger(args.ledger)
    comp, rec, notes = exp["components"], exp.get("recovery") or {}, exp.get("notes", {})
    f = tri.get("findings", {})

    L = ["# Decompile exposure report", "",
         f"**Client / owner:** {cell(args.client)}  **Requested by:** {cell(args.requested_by)}  **Date:** {args.date}",
         f"**Build:** `{tri.get('file')}` (sha256 `{tri.get('sha256')}`, {tri.get('size_bytes'):,} bytes)  **Tester:** {cell(args.tester)}",
         f"**Tool versions and notes:** {cell(args.versions)}", "", "## Summary", ""]
    parts = ", ".join(f"{k} {comp[k]:.2f}" for k in ("S", "L", "X", "R") if k in comp)
    L.append(f"Recoverability Index: **{exp['ri']:.0f}/100 ({exp['band']})** (v0, uncalibrated), from {parts}.")
    if rec:
        cost = f"{rec['attempts_total']} attempts for {rec['recovered']} recovered function(s)"
        if rec.get("attempts_per_recovered"):
            cost += f" ({rec['attempts_per_recovered']} per function)"
        if rec.get("seconds_total"):
            cost += f", {rec['seconds_total'] / 60:.1f} minutes"
        if rec.get("unverified"):
            cost += f"; {rec['unverified']} unverified"
        L.append(f"Cost to recover: {cost}.")
    else:
        L.append("Cost to recover: not measured (no recovery pass was run).")
    if exp.get("surface_inconclusive"):
        L.append("**Caution:** packer or protector markers, or very high entropy, were found. The static surface is inconclusive; "
                 "test the unpacked or in-memory image before drawing conclusions.")
    findings = build_findings(tri, exp)
    L += ["", "Key findings, in order of effect:" if findings else "No findings were triggered by the measured data.", ""]
    L += [f"{i}. {text}" for i, (_, text, _, _, _) in enumerate(findings, 1)]

    L += ["", "## Scope and settings", ""]
    if args.engagement:
        try:
            with open(args.engagement, encoding="utf-8") as fh:
                L += ["```text", scrub(fh.read().rstrip()), "```"]
        except OSError as e:
            fail(f"cannot read engagement sheet ({args.engagement}): {e}")
    else:
        L.append("No engagement sheet was supplied. State the scope, crown jewels and budget here.")

    L += ["", "## Surface findings", "",
          f"- Format: {tri.get('format')} {tri.get('bits', '')}{'-bit' if tri.get('bits') else ''} {tri.get('arch', '')}".rstrip(),
          f"- Symbols: {'stripped' if tri.get('stripped') else 'present' if tri.get('stripped') is False else 'n/a'}; "
          f"debug info: {'yes' if tri.get('has_debug_info') else 'no'}",
          f"- Protection hints: {', '.join(tri.get('protection_hints') or []) or 'none found'}",
          f"- Entropy: {tri.get('entropy_overall')}/8 overall, {tri.get('high_entropy_block_ratio', 0):.0%} of 4 KB blocks above 7.5"]
    for label, items in (("URLs", f.get("urls", [])), ("IPs", f.get("ips", [])), ("Build paths", f.get("build_paths", []))):
        if items:
            L.append(f"- {label}: " + "; ".join(f"`{cell(i)}`" for i in items[:10]))
    if f.get("secret_like"):
        L.append("- Secret-like strings (values redacted): " + "; ".join(f"{cell(s['redacted'])} [{s['type']}]" for s in f["secret_like"][:10]))

    L += ["", "## Recovery results", ""]
    if ledger:
        rows = []
        for r in ledger:
            secs = float(r.get("seconds") or 0)
            rows.append([r.get("name"), r.get("address"), r.get("oracle") or "", r.get("attempts"),
                         f"{secs / 60:.1f}" if secs else "n/a", r.get("status"), r.get("notes") or ""])
        L += table(["Function", "Address", "Oracle", "Attempts", "Minutes", "Status", "What the recovered code does"], rows)
        open_rows = [r for r in ledger if r.get("status") in ("skipped", "unverified")]
        L += ["", "Not recovered, or recovered without a check: " + (", ".join(f"{r['name']} ({r['status']})" for r in open_rows) or "none") + "."]
    else:
        L.append("No recovery pass was run. Run the decompile-and-verify loop on the crown jewels and re-render this report.")

    L += ["", "## Mapping to OWASP MASVS-RESILIENCE", ""]
    L += table(["Control", "Evidence", "Status"], [
        ["RESILIENCE-3 anti-static analysis", f"symbols, readable logic, recovery cost: {parts}", masvs_line(exp)],
        ["RESILIENCE-1, -2, -4", "not assessed by this test (needs runtime testing)", "n/a"]])

    L += ["", "## Recommendations", ""]
    L += table(["Priority", "Finding", "Fix", "Expected effect", "Re-test"],
               [[i, text, fix, effect, retest] for i, (_, text, fix, effect, retest) in enumerate(findings, 1)]) if findings else ["None."]

    managed_note = " Name obfuscation of managed code (.NET, Java) is only partly detected by static triage, so S is an upper bound for managed builds." \
        if tri.get("kind") in MANAGED else ""
    L += ["", "## Limits", "",
          "Static recoverability only. RI is a v0, uncalibrated index; cost to recover is the measurement. Agent runs vary from run to run; "
          "report the median and spread when you repeat them." + managed_note, "",
          "## Reproduction", "",
          f"Generated by `render_report.py` from `{args.triage}`, `{args.exposure}`" + (f", `{args.ledger}`" if args.ledger else "") + ". "
          "Re-run the same commands, tool versions and engagement sheet to reproduce.", ""]

    with open(args.out, "w", encoding="utf-8") as out:
        out.write("\n".join(L))
    print(f"RESULT: REPORT_WRITTEN {args.out} ({len(L)} lines, {len(findings)} findings)")


if __name__ == "__main__":
    main()

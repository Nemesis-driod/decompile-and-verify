#!/usr/bin/env python3
"""Recoverability (exposure) report from a Ghidra export, triage results and an optional recovery ledger.

Usage: score_exposure.py [--functions functions.csv] --triage triage.json [--ledger ledger.csv] [--json out.json]

The Recoverability Index (RI) is a v0, uncalibrated communication device. The measurement that matters is
cost-to-recover: how many attempts / how much time an agent needed per function (see references/rubric.md).
Components, each 0..1 where 1 means "most exposed":
  S symbol exposure   share of real functions that carry meaningful names (or debug info / unobfuscated managed code)
  L legibility        share of functions that decompile cleanly, penalised by goto density
  X embedded secrets  secret-like strings, endpoints, build paths visible in the binary
  R agent recovery    share of attempted functions an agent recovered (matched or equivalent-tested), from the ledger
"""
import argparse
import csv
import json
import re
import signal
import sys

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

WEIGHTS = {"S": 0.2, "L": 0.2, "X": 0.2, "R": 0.4}
CRT = {"_start", "_init", "_fini", "entry", "frame_dummy", "register_tm_clones", "deregister_tm_clones",
       "__do_global_dtors_aux", "_dl_relocate_static_pie", "__libc_csu_init", "__libc_csu_fini"}
CRT_PATTERN = re.compile(r"^_(DT_)?(INIT|FINI)(_\d+)?$")
RECOVERED = {"matched", "equivalent-tested"}
ATTEMPTED = RECOVERED | {"unverified", "skipped"}


def load_functions(path):
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    real = [r for r in rows if r["is_thunk"] != "true" and r["name"] not in CRT and not CRT_PATTERN.match(r["name"])
            and int(r["instructions"]) >= 3]
    return rows, real


def symbol_exposure(real, tri):
    if tri.get("has_debug_info") or tri.get("kind") in ("dotnet", "java", "android", "python", "wasm"):
        short = tri.get("short_class_names_ratio", 0.0)
        return 1.0 - short, "managed/bytecode or debug info present" + (f"; {short:.0%} short (obfuscated) class names" if short else "")
    if not real:
        return 0.0, "no analyzable functions"
    named = sum(1 for r in real if r["named"] == "true")
    return named / len(real), f"{named} of {len(real)} functions carry names"


def legibility(rows):
    ok = [r for r in rows if r["decompile_status"] == "ok"]
    if not rows:
        return 0.0, "no functions"
    ok_ratio = len(ok) / len(rows)
    lines = sum(int(r["c_lines"]) for r in ok) or 1
    gotos_per_100 = 100 * sum(int(r["gotos"]) for r in ok) / lines
    penalty = min(1.0, gotos_per_100 / 10)
    return ok_ratio * (1 - penalty), f"{len(ok)}/{len(rows)} decompile cleanly, {gotos_per_100:.1f} gotos per 100 lines"


def secret_exposure(tri):
    f = tri.get("findings", {})
    has_secret, has_net, has_paths = bool(f.get("secret_like")), bool(f.get("urls") or f.get("ips")), bool(f.get("build_paths"))
    x = 0.6 * has_secret + 0.2 * has_net + 0.2 * has_paths
    parts = [f"{len(f.get('secret_like', []))} secret-like", f"{len(f.get('urls', []))} URLs", f"{len(f.get('ips', []))} IPs",
             f"{len(f.get('build_paths', []))} build paths"]
    return x, ", ".join(parts)


def recovery(ledger_path):
    with open(ledger_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = {"address", "name", "status", "attempts"} - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"ERROR: ledger {ledger_path} is missing column(s) {sorted(missing)}. "
                     "Expected: address,name,status,oracle,attempts,seconds,notes")
        rows = [r for r in reader if r.get("status", "").strip() in ATTEMPTED]
    if not rows:
        return None, "ledger has no attempted functions", {}
    won = [r for r in rows if r["status"].strip() in RECOVERED]
    attempts = sum(int(r.get("attempts") or 0) for r in rows)
    seconds = sum(float(r.get("seconds") or 0) for r in rows)
    stats = {"attempted": len(rows), "recovered": len(won), "attempts_total": attempts,
             "attempts_per_recovered": round(attempts / len(won), 1) if won else None, "seconds_total": seconds or None,
             "unverified": sum(1 for r in rows if r["status"].strip() == "unverified")}
    return len(won) / len(rows), f"{len(won)} of {len(rows)} attempted functions recovered in {attempts} attempts", stats


def band(ri):
    return "HIGH" if ri >= 75 else "MEDIUM" if ri >= 40 else "LOW"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--functions", help="functions.csv from ghidra_export.py (omit for managed builds)")
    ap.add_argument("--triage", required=True)
    ap.add_argument("--ledger")
    ap.add_argument("--json")
    args = ap.parse_args()
    try:
        rows, real = load_functions(args.functions) if args.functions else ([], [])
        tri = json.load(open(args.triage, encoding="utf-8"))
    except (OSError, KeyError, json.JSONDecodeError) as e:
        sys.exit(f"ERROR: could not read inputs ({e!r}). Run scripts/triage.py --json and scripts/ghidra_export.py first.")

    comp, notes, stats = {}, {}, {}
    comp["S"], notes["S"] = symbol_exposure(real, tri)
    if rows:
        comp["L"], notes["L"] = legibility(rows)
    comp["X"], notes["X"] = secret_exposure(tri)
    if args.ledger:
        r, notes["R"], stats = recovery(args.ledger)
        if r is not None:
            comp["R"] = r

    total_w = sum(WEIGHTS[k] for k in comp)
    ri = 100 * sum(WEIGHTS[k] * v for k, v in comp.items()) / total_w
    inconclusive = bool(tri.get("protection_hints")) or (tri.get("high_entropy_block_ratio", 0) > 0.5 and tri.get("format") not in ("JAR", "APK", "ZIP"))

    print(f"== recoverability: {tri.get('file')} ==")
    for k, label in (("S", "symbol exposure"), ("L", "legibility"), ("X", "embedded secrets"), ("R", "agent recovery")):
        if k in comp:
            print(f"{k} {label:<17}: {comp[k]:.2f}  ({notes[k]})")
        else:
            why = notes.get(k) or ("no ledger" if k == "R" else "no functions.csv")
            print(f"{k} {label:<17}: not measured ({why}); RI uses the other components")
    print(f"RI (v0, uncalibrated): {ri:.0f}/100  band: {band(ri)}")
    if inconclusive:
        print("WARNING: packer/protector markers or very high entropy found. The static surface is inconclusive; run the "
              "recovery test on the unpacked or in-memory image before drawing conclusions.")
    if stats:
        print(f"cost-to-recover    : {stats['attempts_total']} attempts for {stats['recovered']} recovered functions"
              f" ({stats['attempts_per_recovered']} per function)" + (f", {stats['seconds_total']:.0f}s" if stats.get("seconds_total") else "")
              + (f"; {stats['unverified']} unverified" if stats.get("unverified") else ""))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"file": tri.get("file"), "components": comp, "notes": notes, "ri": round(ri, 1), "band": band(ri),
                       "surface_inconclusive": inconclusive, "recovery": stats}, f, indent=2)
        print(f"json               : {args.json}")


if __name__ == "__main__":
    main()

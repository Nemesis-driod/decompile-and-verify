#!/usr/bin/env python3
"""Rank functions cheapest-first for decompilation, so the agent never has to pick the next target itself.

Usage: rank_functions.py functions.csv [--top 20] [--ledger ledger.csv] [--out worklist.csv] [--min-instructions 3]
                         [--unnamed-only] [--include-undecompiled]
Input is the functions.csv written by ghidra_export.py. Functions already marked matched / equivalent-tested /
skipped in the ledger are left out, and so are thunks, C-runtime helpers and functions under --min-instructions.
Functions whose decompile_status is timeout, failed or write_failed have no C to start from: they are listed in a NOTE
(never dropped silently) and ranked only with --include-undecompiled, when you will be working from the disassembly.
If only such functions remain the verdict is UNDECOMPILED_LEFT (exit 1), not NOTHING_LEFT; the fix is usually
`ghidra_export.py --decompile-timeout 120` and re-ranking. NOTHING_LEFT (exit 0) means the work is finished. The weights are a starting guess: retune them from your own ledger once you
have a few hundred results (a small logistic regression on instructions, branches, calls, jumps works well).
"""
import argparse
import csv
import os
import re
import signal
import sys

CRT_NAMES = {"_start", "_init", "_fini", "entry", "frame_dummy", "register_tm_clones", "deregister_tm_clones",
             "__do_global_dtors_aux", "_dl_relocate_static_pie", "__libc_csu_init", "__libc_csu_fini"}
CRT_PATTERN = re.compile(r"^_(DT_)?(INIT|FINI)(_\d+)?$")  # loader stubs Ghidra names _DT_INIT, _FINI_0, ...
WEIGHTS = {"instructions": 1, "branches": 3, "calls": 2, "jumps": 2}
DONE = {"matched", "equivalent-tested", "skipped"}


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped into head
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def build_sha_from_summary(functions_csv):
    """The sha256 that ghidra_export.py recorded in summary.txt next to functions.csv, or ''."""
    summary = os.path.join(os.path.dirname(os.path.abspath(functions_csv)), "summary.txt")
    try:
        with open(summary, encoding="utf-8") as f:
            for line in f:
                if line.startswith("sha256="):
                    return line.split("=", 1)[1].strip().lower()
    except OSError:
        pass
    return ""


def norm_addr(text):
    return int(text.strip().lower().removeprefix("0x"), 16)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("functions_csv")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--ledger")
    ap.add_argument("--out", default="worklist.csv")
    ap.add_argument("--min-instructions", type=int, default=3)
    ap.add_argument("--include-undecompiled", action="store_true",
                    help="also rank functions that failed to decompile (you will work from their disassembly)")
    ap.add_argument("--build-sha256", help="sha256 of the binary under test (default: read from summary.txt next to functions.csv)")
    ap.add_argument("--unnamed-only", action="store_true",
                    help="skip functions Ghidra already named (library code it recognised, or symbols); use on builds with recognised libraries")
    args = ap.parse_args()

    current = (args.build_sha256 or build_sha_from_summary(args.functions_csv)).strip().lower()
    ignored = unpinned = 0
    done = set()
    if args.ledger:
        try:
            with open(args.ledger, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if row.get("status", "").strip() not in DONE:
                        continue
                    pinned = (row.get("build_sha256") or "").strip().lower()
                    if pinned and current and pinned != current:
                        ignored += 1                       # proven against a different build: says nothing about this one
                        continue
                    if not pinned:
                        unpinned += 1
                    done.add(norm_addr(row["address"]))
        except FileNotFoundError:
            print(f"note: ledger {args.ledger} does not exist yet; starting fresh", file=sys.stderr)
        except (KeyError, ValueError) as e:
            sys.exit(f"ERROR: ledger must have columns address,name,status,oracle,attempts,notes ({e!r})")

    if ignored:
        print(f"note: ignored {ignored} ledger row(s) that were verified against a different build", file=sys.stderr)
    if unpinned and current:
        print(f"note: {unpinned} ledger row(s) are not pinned to a build and were trusted; re-add them with --build to pin them",
              file=sys.stderr)
    rows, undecompiled = [], {}
    try:
        with open(args.functions_csv, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["is_thunk"] == "true" or r["name"] in CRT_NAMES or CRT_PATTERN.match(r["name"]):
                    continue
                if args.unnamed_only and r["named"] == "true":
                    continue
                if int(r["instructions"]) < args.min_instructions or norm_addr(r["address"]) in done:
                    continue
                if r["decompile_status"] not in ("ok", "skipped"):
                    undecompiled[r["decompile_status"]] = undecompiled.get(r["decompile_status"], 0) + 1
                    if not args.include_undecompiled:
                        continue
                r["score"] = sum(int(r[k]) * w for k, w in WEIGHTS.items())
                rows.append(r)
    except FileNotFoundError:
        sys.exit(f"ERROR: {args.functions_csv} not found. Run scripts/ghidra_export.py first.")
    except KeyError as e:
        sys.exit(f"ERROR: functions.csv is missing column {e}. Re-run scripts/ghidra_export.py to regenerate it.")

    missing = sum(undecompiled.values())
    detail = ", ".join(f"{k}={v}" for k, v in sorted(undecompiled.items()))
    if not rows:
        if missing:
            print(f"RESULT: UNDECOMPILED_LEFT ({missing} function(s) have no decompiled C ({detail}); everything that does is done or filtered out)")
            print("HINT: re-export with a longer limit, for example `ghidra_export.py <binary> <outdir> --decompile-timeout 120`, "
                  "or add --include-undecompiled to rank them and work from the disassembly.")
            sys.exit(1)
        print("RESULT: NOTHING_LEFT (every candidate function is already in the ledger or filtered out)")
        return
    rows.sort(key=lambda r: (r["score"], norm_addr(r["address"])))
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rank", "address", "name", "score", "instructions", "branches", "calls", "jumps", "c_file"])
        for i, r in enumerate(rows, 1):
            w.writerow([i, r["address"], r["name"], r["score"], r["instructions"], r["branches"], r["calls"], r["jumps"], r["c_file"]])

    first = rows[0]
    print(f"NEXT: {first['address']} {first['name']} (score {first['score']}, c file: {first['c_file'] or 'n/a'})")
    print(f"{len(rows)} candidates ranked cheapest first -> {args.out}")
    if missing and not args.include_undecompiled:
        print(f"NOTE: {missing} more function(s) have no decompiled C ({detail}) and are not ranked. Re-export with "
              "--decompile-timeout N, or add --include-undecompiled.")
    print()
    print(f"{'rank':>4}  {'address':<10} {'name':<28} {'score':>5} {'instr':>5} {'br':>3} {'call':>4}")
    for i, r in enumerate(rows[:args.top], 1):
        print(f"{i:>4}  {r['address']:<10} {r['name'][:28]:<28} {r['score']:>5} {r['instructions']:>5} {r['branches']:>3} {r['calls']:>4}")


if __name__ == "__main__":
    main()

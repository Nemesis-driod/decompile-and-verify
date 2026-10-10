#!/usr/bin/env python3
"""Keep the recovery ledger tidy: one row per function, valid statuses, correctly quoted CSV.

Usage:
  ledger.py add LEDGER --address 0x101250 --name NAME --status STATUS [--oracle TEXT] [--attempts N] [--seconds N] [--notes TEXT]
  ledger.py summary LEDGER

STATUS is one of: matched, equivalent-tested, unverified, skipped. Adding a row for an address that is already in the
ledger replaces it, so a function that was skipped and later recovered ends up with one final row.
Columns: address,name,status,oracle,attempts,seconds,notes
"""
import argparse
import csv
import os
import signal
import sys

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

COLUMNS = ["address", "name", "status", "oracle", "attempts", "seconds", "notes"]
STATUSES = ["matched", "equivalent-tested", "unverified", "skipped"]


def fail(message):
    print(f"RESULT: LEDGER_ERROR\n{message}")
    sys.exit(2)


def norm_address(text):
    try:
        return f"0x{int(text.strip().lower().removeprefix('0x'), 16):x}"
    except ValueError:
        fail(f"address must be hexadecimal like 0x101250 (got {text!r})")


def load(path):
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = {"address", "name", "status", "attempts"} - set(reader.fieldnames or [])
        if missing:
            fail(f"{path} is missing column(s) {sorted(missing)}. Expected: {','.join(COLUMNS)}")
        return [{c: (row.get(c) or "") for c in COLUMNS} for row in reader]


def save(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def cmd_add(args):
    if args.attempts < 0 or args.seconds < 0:
        fail("attempts and seconds cannot be negative")
    row = {"address": norm_address(args.address), "name": args.name, "status": args.status, "oracle": args.oracle,
           "attempts": str(args.attempts), "seconds": f"{args.seconds:g}" if args.seconds else "", "notes": args.notes}
    rows = load(args.ledger)
    for i, existing in enumerate(rows):
        if norm_address(existing["address"]) == row["address"]:
            total_attempts = int(existing["attempts"] or 0) + args.attempts          # cost accumulates across updates
            total_seconds = float(existing["seconds"] or 0) + args.seconds
            row["attempts"] = str(total_attempts)
            row["seconds"] = f"{total_seconds:g}" if total_seconds else ""
            rows[i] = row
            break
    else:
        rows.append(row)
    save(args.ledger, rows)
    print(f"RESULT: LEDGER_OK {row['address']} {row['name']} -> {row['status']} ({len(rows)} rows)")


def cmd_summary(args):
    rows = load(args.ledger)
    if not rows:
        fail(f"{args.ledger} has no rows yet")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    other = [r for r in rows if r["status"] not in STATUSES]
    won = counts["matched"] + counts["equivalent-tested"]
    attempts = sum(int(r["attempts"] or 0) for r in rows)
    seconds = sum(float(r["seconds"] or 0) for r in rows)
    print(f"RESULT: LEDGER_OK {len(rows)} functions")
    for s in STATUSES:
        print(f"  {s:<18} {counts[s]}")
    if other:
        print(f"  WARNING: {len(other)} row(s) have an unknown status (fix them): {sorted({r['status'] for r in other})}")
    oracles = {}
    for r in rows:
        if r["status"] in ("matched", "equivalent-tested") and r["oracle"]:
            oracles[r["oracle"]] = oracles.get(r["oracle"], 0) + 1
    if oracles:
        print("  oracles used: " + "; ".join(f"{k} x{v}" for k, v in sorted(oracles.items())))
    print(f"  attempts: {attempts} total" + (f" ({attempts / won:.1f} per recovered function)" if won else ""))
    if seconds:
        print(f"  time: {seconds / 60:.1f} minutes recorded")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add")
    add.add_argument("ledger")
    add.add_argument("--address", required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--status", required=True, choices=STATUSES)
    add.add_argument("--oracle", default="")
    add.add_argument("--attempts", type=int, default=1)
    add.add_argument("--seconds", type=float, default=0)
    add.add_argument("--notes", default="")
    add.set_defaults(func=cmd_add)
    summ = sub.add_parser("summary")
    summ.add_argument("ledger")
    summ.set_defaults(func=cmd_summary)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

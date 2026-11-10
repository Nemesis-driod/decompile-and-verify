#!/usr/bin/env python3
"""Keep the recovery ledger tidy: one row per function, valid values, correctly quoted CSV, and evidence you can re-check.

Usage:
  ledger.py add LEDGER --address 0x101250 --name NAME --status STATUS [--oracle TEXT] [--attempts N] [--seconds N]
            [--notes TEXT] [--build FILE | --build-sha256 HEX] [--candidate FILE] [--corpus FILE_OR_DIR]
  ledger.py summary LEDGER
  ledger.py check LEDGER [--build FILE | --build-sha256 HEX] [--root DIR]

STATUS is one of: matched, equivalent-tested, unverified, skipped. Adding a row for an address that is already in the
ledger replaces it, so a function that was skipped and later recovered ends up with one final row. Attempts and seconds
accumulate across updates, because the total cost to recover a function is what the assessment measures.

A status is only as good as the evidence behind it. Pass --build (the binary under test, or its sha256), --candidate
(the source you verified) and --corpus (the inputs or cases you verified it with) and the row records their SHA-256.
`check` then reports rows whose build differs, whose candidate or corpus changed since verification, or that were never
pinned, so a status cannot silently outlive the evidence that justified it.

Columns: address,name,status,oracle,attempts,seconds,notes,build_sha256,candidate,candidate_sha256,corpus,corpus_sha256
Exit codes: 0 ok, 1 stale rows found by `check`, 2 setup problem or an invalid ledger.
"""
import argparse
import csv
import hashlib
import math
import os
import re
import signal
import sys
import tempfile

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

COLUMNS = ["address", "name", "status", "oracle", "attempts", "seconds", "notes",
           "build_sha256", "candidate", "candidate_sha256", "corpus", "corpus_sha256"]
REQUIRED = {"address", "name", "status", "attempts"}
STATUSES = ["matched", "equivalent-tested", "unverified", "skipped"]
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message):
    print(f"RESULT: LEDGER_ERROR\n{message}")
    sys.exit(2)


def norm_address(text):
    try:
        return f"0x{int(text.strip().lower().removeprefix('0x'), 16):x}"
    except ValueError:
        fail(f"address must be hexadecimal like 0x101250 (got {text!r})")


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def path_sha256(path):
    """SHA-256 of a file, or of a directory (every file's relative path and content hash, in sorted order)."""
    if os.path.isdir(path):
        h = hashlib.sha256()
        for folder, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(folder, name)
                h.update(f"{os.path.relpath(full, path).replace(os.sep, '/')}\0{file_sha256(full)}\n".encode())
        return h.hexdigest()
    return file_sha256(path)


def problems_in(row):
    """Everything wrong with one ledger row, as short messages."""
    found = []
    try:
        int(row["address"].strip().lower().removeprefix("0x"), 16)
    except ValueError:
        found.append(f"address {row['address']!r} is not hexadecimal")
    if row["status"] not in STATUSES:
        found.append(f"status {row['status']!r} must be one of {', '.join(STATUSES)}")
    if not re.fullmatch(r"\d+", (row["attempts"] or "0").strip()):
        found.append(f"attempts {row['attempts']!r} must be a whole number")
    try:
        seconds = float(row["seconds"] or 0)
        if not math.isfinite(seconds) or seconds < 0:
            found.append(f"seconds {row['seconds']!r} must be a finite number that is not negative")
    except ValueError:
        found.append(f"seconds {row['seconds']!r} must be a number")
    for col in ("build_sha256", "candidate_sha256", "corpus_sha256"):
        if row[col] and not SHA_RE.match(row[col]):
            found.append(f"{col} is not a 64-character hex digest")
    return found


def load(path, must_exist=False):
    if not os.path.isfile(path):
        if must_exist:
            fail(f"{path} does not exist yet")
        return []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            fail(f"{path} is missing column(s) {sorted(missing)}. Expected at least: address,name,status,oracle,attempts,seconds,notes")
        rows = [{c: (row.get(c) or "") for c in COLUMNS} for row in reader]
    errors = []
    for number, row in enumerate(rows, 2):                    # line 1 is the header
        errors += [f"line {number}: {p}" for p in problems_in(row)]
    if errors:
        fail(f"{path} has invalid values; fix them by hand or re-add the rows:\n  " + "\n  ".join(errors[:6])
             + (f"\n  ... and {len(errors) - 6} more" if len(errors) > 6 else ""))
    return rows


def save(path, rows):
    """Write the whole ledger to a temporary file in the same folder, then replace the old one in a single step."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".ledger-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def build_hash(args):
    if getattr(args, "build_sha256", None):
        value = args.build_sha256.strip().lower()
        if not SHA_RE.match(value):
            fail("--build-sha256 must be a 64-character hex digest")
        return value
    if getattr(args, "build", None):
        if not os.path.isfile(args.build):
            fail(f"--build file not found: {args.build}")
        return file_sha256(args.build)
    return ""


def cmd_add(args):
    if args.attempts < 0 or not math.isfinite(args.seconds) or args.seconds < 0:
        fail("attempts must be a whole number and seconds a finite number, neither negative")
    row = {c: "" for c in COLUMNS}
    row.update({"address": norm_address(args.address), "name": args.name, "status": args.status, "oracle": args.oracle,
                "attempts": str(args.attempts), "seconds": f"{args.seconds:g}" if args.seconds else "", "notes": args.notes,
                "build_sha256": build_hash(args)})
    for flag, col in (("candidate", "candidate"), ("corpus", "corpus")):
        value = getattr(args, flag)
        if value:
            if not os.path.exists(value):
                fail(f"--{flag} not found: {value}")
            row[col] = value
            row[f"{col}_sha256"] = path_sha256(value)
    rows = load(args.ledger)
    for i, existing in enumerate(rows):
        if norm_address(existing["address"]) == row["address"]:
            row["attempts"] = str(int(existing["attempts"] or 0) + args.attempts)           # cost accumulates across updates
            total_seconds = float(existing["seconds"] or 0) + args.seconds
            row["seconds"] = f"{total_seconds:g}" if total_seconds else ""
            rows[i] = row
            break
    else:
        rows.append(row)
    save(args.ledger, rows)
    print(f"RESULT: LEDGER_OK {row['address']} {row['name']} -> {row['status']} ({len(rows)} rows)")
    if not row["build_sha256"]:
        print("NOTE: this row is not pinned to a build. Pass --build <binary> so `check` can tell when it goes stale.")


def cmd_summary(args):
    rows = load(args.ledger, must_exist=True)
    if not rows:
        fail(f"{args.ledger} has no rows yet")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    won = counts["matched"] + counts["equivalent-tested"]
    attempts = sum(int(r["attempts"] or 0) for r in rows)
    seconds = sum(float(r["seconds"] or 0) for r in rows)
    print(f"RESULT: LEDGER_OK {len(rows)} functions")
    for s in STATUSES:
        print(f"  {s:<18} {counts[s]}")
    oracles = {}
    for r in rows:
        if r["status"] in ("matched", "equivalent-tested") and r["oracle"]:
            oracles[r["oracle"]] = oracles.get(r["oracle"], 0) + 1
    if oracles:
        print("  oracles used: " + "; ".join(f"{k} x{v}" for k, v in sorted(oracles.items())))
    print(f"  attempts: {attempts} total" + (f" ({attempts / won:.1f} per recovered function)" if won else ""))
    if seconds:
        print(f"  time: {seconds / 60:.1f} minutes recorded")
    builds = sorted({r["build_sha256"] for r in rows if r["build_sha256"]})
    pinned = sum(1 for r in rows if r["build_sha256"])
    print(f"  evidence: {pinned} of {len(rows)} rows pinned to a build; "
          f"{sum(1 for r in rows if r['candidate_sha256'])} with a candidate hash; {sum(1 for r in rows if r['corpus_sha256'])} with a corpus hash")
    if len(builds) > 1:
        print(f"  WARNING: the rows refer to {len(builds)} different builds; results for one build do not carry over to another.")


def cmd_check(args):
    rows = load(args.ledger, must_exist=True)
    if not rows:
        fail(f"{args.ledger} has no rows yet")
    current = build_hash(args)
    stale = []
    for r in rows:
        why = []
        if not r["build_sha256"]:
            why.append("UNPINNED: no build hash was recorded")
        elif current and r["build_sha256"] != current:
            why.append("BUILD_MISMATCH: verified against a different build")
        for col in ("candidate", "corpus"):
            if r[col]:
                full = os.path.join(args.root, r[col])
                if not os.path.exists(full):
                    why.append(f"MISSING: {col} {r[col]} no longer exists")
                elif path_sha256(full) != r[f"{col}_sha256"]:
                    why.append(f"STALE: {col} {r[col]} changed since it was verified")
        if why:
            stale.append((r, why))
    if not stale:
        print(f"RESULT: LEDGER_CURRENT {len(rows)} rows" + (" (pinned to the given build)" if current else " (no build given: build pinning not compared)"))
        return
    print(f"RESULT: LEDGER_STALE {len(stale)} of {len(rows)} rows need attention")
    for r, why in stale[:10]:
        print(f"  {r['address']} {r['name']} ({r['status']}): " + "; ".join(why))
    if len(stale) > 10:
        print(f"  ... {len(stale) - 10} more")
    sys.exit(1)


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
    add.add_argument("--build", help="the binary under test (its sha256 is recorded)")
    add.add_argument("--build-sha256", help="the sha256 of the binary under test, if you already have it (triage.py prints it)")
    add.add_argument("--candidate", help="the source file you verified (its sha256 is recorded)")
    add.add_argument("--corpus", help="the inputs or cases you verified with: a file or a folder (its sha256 is recorded)")
    add.set_defaults(func=cmd_add)
    summ = sub.add_parser("summary")
    summ.add_argument("ledger")
    summ.set_defaults(func=cmd_summary)
    chk = sub.add_parser("check")
    chk.add_argument("ledger")
    chk.add_argument("--build")
    chk.add_argument("--build-sha256")
    chk.add_argument("--root", default=".", help="folder that candidate and corpus paths are relative to (default: current folder)")
    chk.set_defaults(func=cmd_check)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

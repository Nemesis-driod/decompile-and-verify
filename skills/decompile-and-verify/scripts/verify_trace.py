#!/usr/bin/env python3
"""Trace-replay oracle: compare per-tick state recorded from the original with the same state from your port or rewrite.

Usage: verify_trace.py --original original.jsonl --rewrite port.jsonl [--keys x,y,hp] [--tolerance 1e-6]
                       [--key-tolerance hp=0 --key-tolerance x=0.01] [--ignore frame_time] [--show 3]

Each trace is JSON lines: one object per tick, for example {"t": 0, "x": 12.5, "y": 3.0, "hp": 40, "frame": "9f2c1a"}.
Record the original with whatever you have (an emulator's scripting API, a debugger, an instrumented build) and the
port with a logging hook at the same points, driven by the SAME recorded input. Ticks are compared by position; if both
traces carry a "t" field the values must agree, otherwise the traces are misaligned (a dropped or duplicated tick).
Numbers are compared with --tolerance (relative and absolute, default 0 = exact); everything else must be equal.
Hash a framebuffer into a string field to compare frames exactly.

Typical causes of the first divergence: an action applied one tick late, float32 versus float64 constants, a hidden
state variable (a buff, an RNG seed), or an uninitialised value.

Exit codes: 0 TRACE_MATCH, 1 TRACE_DIVERGES or TRACE_MISALIGNED, 2 SETUP_ERROR.
"""
import argparse
import json
import math
import signal
import sys

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def fail(message, code=2):
    print(message)
    sys.exit(code)


def load(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        fail(f"RESULT: SETUP_ERROR\n{path} line {number} is not a JSON object.")
                    rows.append(row)
    except (OSError, ValueError) as e:
        fail(f"RESULT: SETUP_ERROR\ncannot read {path}: {e}")
    if not rows:
        fail(f"RESULT: SETUP_ERROR\n{path} has no ticks.")
    return rows


def numeric(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def close(a, b, tol):
    if numeric(a) and numeric(b):
        if a == b or (isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b)):
            return True
        return tol > 0 and math.isclose(a, b, rel_tol=tol, abs_tol=tol)
    return a == b


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", required=True)
    ap.add_argument("--rewrite", required=True)
    ap.add_argument("--keys", help="comma-separated keys to compare (default: every key both traces share)")
    ap.add_argument("--ignore", action="append", default=[], help="a key to skip; repeatable")
    ap.add_argument("--tolerance", type=float, default=0.0)
    ap.add_argument("--key-tolerance", action="append", default=[], metavar="KEY=TOL")
    ap.add_argument("--show", type=int, default=3, help="how many diverging ticks to print")
    args = ap.parse_args()

    per_key = {}
    for item in args.key_tolerance:
        key, _, tol = item.partition("=")
        try:
            per_key[key] = float(tol)
        except ValueError:
            fail(f"RESULT: SETUP_ERROR\n--key-tolerance expects KEY=NUMBER (got {item!r})")

    a, b = load(args.original), load(args.rewrite)
    shared = sorted(set().union(*[set(r) for r in a]) & set().union(*[set(r) for r in b]))
    keys = [k for k in (args.keys.split(",") if args.keys else shared) if k not in args.ignore and k != "t"]
    if not keys:
        fail("RESULT: SETUP_ERROR\nThe traces share no keys to compare. Check the field names.")

    n = min(len(a), len(b))
    diverging, max_err, first = [], {}, None
    for i in range(n):
        if "t" in a[i] and "t" in b[i] and a[i]["t"] != b[i]["t"]:
            print(f"RESULT: TRACE_MISALIGNED at line {i + 1}: original t={a[i]['t']!r} but rewrite t={b[i]['t']!r}")
            print("HINT: a tick was dropped or duplicated; fix the recording before comparing values.")
            sys.exit(1)
        bad = []
        for k in keys:
            if k not in a[i] or k not in b[i]:
                bad.append((k, a[i].get(k, "<missing>"), b[i].get(k, "<missing>")))
                continue
            x, y = a[i][k], b[i][k]
            if numeric(x) and numeric(y):
                max_err[k] = max(max_err.get(k, 0.0), abs(x - y))
            if not close(x, y, per_key.get(k, args.tolerance)):
                bad.append((k, x, y))
        if bad:
            diverging.append((i, bad))
            first = first or i

    if diverging:
        i, bad = diverging[0]
        tick = a[i].get("t", i)
        print(f"RESULT: TRACE_DIVERGES at tick {tick} ({bad[0][0]}: original={bad[0][1]!r} rewrite={bad[0][2]!r}); "
              f"{len(diverging)} of {n} ticks differ (treat as a failure)")
        for i, bad in diverging[:args.show]:
            print(f"  tick {a[i].get('t', i)}: " + "; ".join(f"{k}: {x!r} vs {y!r}" for k, x, y in bad[:4]))
        if len(diverging) > args.show:
            print(f"  ... {len(diverging) - args.show} more diverging ticks")
        worst = sorted(max_err.items(), key=lambda kv: -kv[1])[:3]
        print("  largest numeric differences: " + ", ".join(f"{k}={v:.6g}" for k, v in worst if v > 0))
        sys.exit(1)
    if len(a) != len(b):
        print(f"RESULT: TRACE_DIVERGES: the traces agree for {n} ticks but have different lengths "
              f"(original {len(a)}, rewrite {len(b)}) (treat as a failure)")
        sys.exit(1)
    tol = f"tolerance {args.tolerance:g}" if args.tolerance else "exact"
    print(f"RESULT: TRACE_MATCH {n} ticks, {len(keys)} keys ({tol}); a recording of one run, not a proof for other inputs")
    sys.exit(0)


if __name__ == "__main__":
    main()

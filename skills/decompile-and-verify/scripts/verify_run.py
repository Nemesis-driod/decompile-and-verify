#!/usr/bin/env python3
"""Differential oracle: run the original and your rewrite on the same inputs and compare behaviour.

Usage: verify_run.py --original ./original --rewrite ./rewrite --inputs inputs/ [--mode stdin|arg|arg-text] [--timeout 10] [--min-inputs 20]
Each file in --inputs is one test case: fed on stdin (default), its path passed as the last argument (--mode arg),
or its text passed as the last argument (--mode arg-text).
Compares stdout and exit code. Exit codes: 0 equivalent on these inputs, 1 differs, 2 setup problem.
Equivalence on a sample is not a proof: choose boundary inputs on purpose (0, negative, max, empty).
"""
import argparse
import difflib
import os
import shlex
import subprocess
import signal
import sys


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped into head
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def split_command(text):
    """shlex.split that keeps Windows backslash paths intact."""
    tokens = shlex.split(text, posix=(os.name != "nt"))
    return [t[1:-1] if os.name == "nt" and len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]

def fail(message):
    print(message)
    sys.exit(2)


def run(cmd, case, mode, timeout):
    extra = []
    if mode == "arg":
        extra = [case]
    elif mode == "arg-text":
        extra = [open(case, encoding="utf-8", errors="replace").read().rstrip("\n")]
    argv = split_command(cmd) + extra
    stdin = open(case, "rb") if mode == "stdin" else subprocess.DEVNULL
    try:
        p = subprocess.run(argv, stdin=stdin, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return "timeout", b""
    except OSError as e:
        fail(f"RESULT: SETUP_ERROR\ncannot run {argv[0]}: {e}")
    finally:
        if mode == "stdin":
            stdin.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", required=True)
    ap.add_argument("--rewrite", required=True)
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--mode", choices=["stdin", "arg", "arg-text"], default="stdin")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--min-inputs", type=int, default=20)
    args = ap.parse_args()

    if not os.path.isdir(args.inputs):
        fail(f"RESULT: SETUP_ERROR\n--inputs must be a directory of test-case files: {args.inputs}")
    cases = sorted(os.path.join(args.inputs, n) for n in os.listdir(args.inputs) if os.path.isfile(os.path.join(args.inputs, n)))
    if not cases:
        fail("RESULT: SETUP_ERROR\nthe inputs directory is empty.")

    bad = []
    for case in cases:
        a, b = run(args.original, case, args.mode, args.timeout), run(args.rewrite, case, args.mode, args.timeout)
        if a != b:
            bad.append((case, a, b))

    if bad:
        print(f"RESULT: DIFFERS on {len(bad)} of {len(cases)} inputs (treat as a failure)")
        for case, (rc_a, out_a), (rc_b, out_b) in bad[:3]:
            print(f"--- {os.path.basename(case)}: exit original={rc_a} rewrite={rc_b}")
            d = difflib.unified_diff(out_a.decode(errors="replace").splitlines(), out_b.decode(errors="replace").splitlines(),
                                     "original", "rewrite", lineterm="", n=1)
            print("\n".join(list(d)[:12]))
        if len(bad) > 3:
            print(f"... {len(bad) - 3} more differing inputs")
        sys.exit(1)

    print(f"RESULT: EQUIVALENT_ON {len(cases)} inputs (a sample, not a proof)")
    if len(cases) < args.min_inputs:
        print(f"WARNING: only {len(cases)} inputs (< {args.min_inputs}). Add boundary cases before trusting this.")
    sys.exit(0)


if __name__ == "__main__":
    main()

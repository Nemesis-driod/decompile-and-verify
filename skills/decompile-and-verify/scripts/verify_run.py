#!/usr/bin/env python3
"""Differential oracle: run the original and your rewrite on the same inputs and compare behaviour.

Usage: verify_run.py --original ./original --rewrite ./rewrite --inputs inputs/ [--mode stdin|arg|arg-text]
                     [--timeout 10] [--min-inputs 20] [--strict]
Each file in --inputs is one test case: fed on stdin (default), its path passed as the last argument (--mode arg),
or its text passed as the last argument (--mode arg-text).

What is compared: the exit status and standard output. NOT compared: standard error, files written, network traffic,
timing or any other side effect. A verdict is only about what was compared.

A timeout is not behaviour. If both programs time out on an input, that input is inconclusive (no evidence either
way). If only one of them times out, that is a difference.
--min-inputs warns when there are fewer inputs than that; with --strict it fails instead (TOO_FEW_INPUTS), and a run
where both programs failed identically on every input is reported as INCONCLUSIVE.
Equivalence on a sample is not a proof: choose boundary inputs on purpose (0, negative, max, empty).

Exit codes: 0 equivalent on these inputs; 1 differs, inconclusive, or too few inputs under --strict; 2 setup problem.
"""
import argparse
import difflib
import math
import os
import shlex
import signal
import subprocess
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
    """Run once. Returns ("ok", exit_status, stdout) or ("timeout", None, b"")."""
    extra = []
    if mode == "arg":
        extra = [case]
    elif mode == "arg-text":
        with open(case, encoding="utf-8", errors="replace") as f:
            extra = [f.read().rstrip("\n")]
    argv = split_command(cmd) + extra
    stdin = open(case, "rb") if mode == "stdin" else subprocess.DEVNULL
    try:
        p = subprocess.run(argv, stdin=stdin, capture_output=True, timeout=timeout)
        return "ok", p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return "timeout", None, b""
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
    ap.add_argument("--min-inputs", type=int, default=20, help="warn when there are fewer inputs (fail with --strict)")
    ap.add_argument("--strict", action="store_true", help="enforce --min-inputs and reject runs where both programs always fail")
    args = ap.parse_args()

    if not (math.isfinite(args.timeout) and 0 < args.timeout <= 86400):
        fail("RESULT: SETUP_ERROR\n--timeout must be a number of seconds greater than 0 and at most 86400.")
    if not os.path.isdir(args.inputs):
        fail(f"RESULT: SETUP_ERROR\n--inputs must be a directory of test-case files: {args.inputs}")
    cases = sorted(os.path.join(args.inputs, n) for n in os.listdir(args.inputs) if os.path.isfile(os.path.join(args.inputs, n)))
    if not cases:
        fail("RESULT: SETUP_ERROR\nthe inputs directory is empty.")

    differs, inconclusive, same_failure = [], [], 0
    for case in cases:
        a = run(args.original, case, args.mode, args.timeout)
        b = run(args.rewrite, case, args.mode, args.timeout)
        if a[0] == "timeout" and b[0] == "timeout":
            inconclusive.append(case)               # a timeout is not behaviour: no evidence either way
        elif a != b:
            differs.append((case, a, b))
        elif a[1] != 0:
            same_failure += 1
    n = len(cases)

    def status(r):
        return "timeout" if r[0] == "timeout" else r[1]

    if differs:
        print(f"RESULT: DIFFERS on {len(differs)} of {n} inputs (treat as a failure)")
        for case, a, b in differs[:3]:
            print(f"--- {os.path.basename(case)}: exit original={status(a)} rewrite={status(b)}")
            d = difflib.unified_diff(a[2].decode(errors="replace").splitlines(), b[2].decode(errors="replace").splitlines(),
                                     "original", "rewrite", lineterm="", n=1)
            print("\n".join(list(d)[:12]))
        if len(differs) > 3:
            print(f"... {len(differs) - 3} more differing inputs")
        if inconclusive:
            print(f"NOTE: both programs also timed out on {len(inconclusive)} other inputs (inconclusive).")
        sys.exit(1)

    if inconclusive:
        print(f"RESULT: INCONCLUSIVE: both programs timed out on {len(inconclusive)} of {n} inputs; "
              "a timeout is not behaviour, so these inputs give no evidence of equivalence")
        print("HINT: raise --timeout, or remove those inputs. First: " + ", ".join(os.path.basename(c) for c in inconclusive[:3]))
        sys.exit(1)

    if args.strict and n < args.min_inputs:
        print(f"RESULT: TOO_FEW_INPUTS {n} (--strict needs at least {args.min_inputs}); the programs matched on all {n}")
        sys.exit(1)
    if args.strict and same_failure == n:
        print("RESULT: INCONCLUSIVE: both programs exited with an error on every input, so nothing about the code under test was compared")
        sys.exit(1)

    print(f"RESULT: EQUIVALENT_ON {n} inputs (exit status and stdout only; a sample, not a proof)")
    if same_failure == n:
        print("WARNING: both programs exited with an error on every input. That says nothing about the code under test; "
              "check the command line and the inputs.")
    elif same_failure:
        print(f"NOTE: both programs exited with the same non-zero status on {same_failure} of {n} inputs.")
    if n < args.min_inputs:
        print(f"WARNING: only {n} inputs (< {args.min_inputs}). Add boundary cases before trusting this (or use --strict to enforce it).")
    sys.exit(0)


if __name__ == "__main__":
    main()

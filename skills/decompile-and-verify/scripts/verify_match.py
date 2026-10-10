#!/usr/bin/env python3
"""Matching oracle: compile a candidate C file and compare its machine code with the original's.

Usage:
  verify_match.py --target target.o --candidate candidate.c [--cc "gcc -O2 -c"] [--func NAME] [--full]
  verify_match.py --target target.o --candidate-obj candidate.o [--func NAME]

Exit codes: 0 MATCH, 1 NOT_MATCH (keep iterating), 2 REJECTED or BUILD_FAILED (fix the setup, not the logic).
Use the ORIGINAL compiler and flags in --cc whenever they are known; the verdict is only as strong as that.
A MATCH proves your source produces the same instructions, not that it is the author's source.
"""
import argparse
import difflib
import os
import re
import shlex
import subprocess
import signal
import sys
import tempfile

ASM_RE = re.compile(r"\b(__asm__|__asm|asm)\b\s*(volatile\b|goto\b|\()|^\s*\.(word|long|byte|quad|incbin)\b", re.M)
MAX_DIFF_LINES = 40


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


def disassemble(obj, objdump, func):
    cmd = [objdump, "-dr", "--no-show-raw-insn"]
    if func:
        cmd.append(f"--disassemble={func}")
    cmd.append(obj)
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        fail(f"RESULT: BUILD_FAILED\n{objdump} failed on {obj}: {p.stderr.strip()[:300]}\n"
                 "HINT: pass --objdump for cross targets (for example mips-linux-gnu-objdump).")
    lines = []
    for raw in p.stdout.splitlines():
        if not raw.strip() or "file format" in raw or raw.startswith("Disassembly of section"):
            continue
        raw = re.sub(r"^\s*[0-9a-f]+:\s*(R_\S+\s+.*)$", r"reloc \1", raw)       # relocation lines: drop the offset
        raw = re.sub(r"^\s*[0-9a-f]+:\s*", "", raw)                               # instruction lines: drop the offset
        raw = re.sub(r"^[0-9a-f]+ (<.*>:)$", r"\1", raw)                          # label lines: drop the address
        lines.append(raw.rstrip())
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--candidate")
    ap.add_argument("--candidate-obj")
    ap.add_argument("--cc", default="gcc -O2 -c")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--func")
    ap.add_argument("--full", action="store_true", help="print the whole diff instead of the first %d lines" % MAX_DIFF_LINES)
    args = ap.parse_args()

    if bool(args.candidate) == bool(args.candidate_obj):
        fail("RESULT: BUILD_FAILED\nGive exactly one of --candidate (C source) or --candidate-obj (object file).")
    for path in (args.target, args.candidate or args.candidate_obj):
        if not os.path.isfile(path):
            fail(f"RESULT: BUILD_FAILED\nfile not found: {path}")

    cand_obj = args.candidate_obj
    if args.candidate:
        src = open(args.candidate, encoding="utf-8", errors="replace").read()
        if ASM_RE.search(src):
            print("RESULT: REJECTED")
            print("The candidate contains inline assembly or raw data directives. Embedding the target's instructions")
            print("is not a decompilation and would satisfy this check trivially. Rewrite it in plain C.")
            sys.exit(2)
        tmp = tempfile.mkdtemp(prefix="verify-match-")
        cand_obj = os.path.join(tmp, "candidate.o")
        p = subprocess.run(split_command(args.cc) + [args.candidate, "-o", cand_obj], capture_output=True, text=True)
        if p.returncode != 0:
            print("RESULT: BUILD_FAILED")
            print("The candidate does not compile. Treat this as a failed attempt. First errors:")
            print("\n".join(p.stderr.strip().splitlines()[:15]))
            sys.exit(2)

    target = disassemble(args.target, args.objdump, args.func)
    cand = disassemble(cand_obj, args.objdump, args.func)
    if not target:
        fail("RESULT: BUILD_FAILED\nNo instructions found in the target. Check --func spelling (symbol names must match).")

    if target == cand:
        print(f"RESULT: MATCH (100%, {len(target)} lines compared)")
        sys.exit(0)

    t_name = re.match(r"<([^>]+)>:", target[0]) if target else None
    c_name = re.match(r"<([^>]+)>:", cand[0]) if cand else None
    if t_name and c_name and t_name.group(1) != c_name.group(1):
        renamed = [line.replace("<" + c_name.group(1), "<" + t_name.group(1)) for line in cand]
        if renamed == target:
            print(f"RESULT: NOT_MATCH score=99.0% (treat as a failure)")
            print(f"HINT: the instructions are identical once the function name is ignored. Rename '{c_name.group(1)}' to "
                  f"'{t_name.group(1)}'; symbol names must match the target.")
            sys.exit(1)

    ratio = difflib.SequenceMatcher(None, target, cand, autojunk=False).ratio() * 100
    diff = list(difflib.unified_diff(target, cand, "target", "candidate", lineterm="", n=2))
    print(f"RESULT: NOT_MATCH score={ratio:.1f}% (treat as a failure; target {len(target)} lines, candidate {len(cand)} lines)")
    if len(target) != len(cand):
        print(f"HINT: line counts differ by {abs(len(target) - len(cand))}: look at loop shape, inlining, or missing/extra statements first.")
    shown = diff if args.full else diff[:MAX_DIFF_LINES]
    print("\n".join(shown))
    if len(shown) < len(diff):
        print(f"... {len(diff) - len(shown)} more diff lines (use --full)")
    sys.exit(1)


if __name__ == "__main__":
    main()

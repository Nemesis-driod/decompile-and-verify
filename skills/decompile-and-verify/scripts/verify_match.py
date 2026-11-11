#!/usr/bin/env python3
"""Matching oracle: compile a candidate C file and compare it with the original's machine code and data.

Usage:
  verify_match.py --target target.o --candidate candidate.c [--cc "gcc -O2 -c"] [--func NAME] [--full] [--data auto|on|off]
  verify_match.py --target target.o --candidate-obj candidate.o [--func NAME]

What is compared: the disassembly (objdump -dr) and, for a whole object, the data sections (.rodata*, .data*, .rdata,
.bss*): their sizes, contents and relocations. Constants, string literals and tables live there, outside the
instruction stream, so a candidate with a different literal (0.3f instead of 0.2f, "WORLD" instead of "hello") is
NOT_MATCH even when every instruction looks the same.
With --func the object may hold other functions' data, so data sections are not compared unless --data on is given
(then ALL data sections are compared, so use it only when the objects hold just that function's data).
The MATCH line says what was compared.

Exit codes: 0 MATCH, 1 NOT_MATCH (keep iterating), 2 REJECTED or BUILD_FAILED (fix the setup, not the logic).
Use the ORIGINAL compiler and flags in --cc whenever they are known; the verdict is only as strong as that.
A MATCH proves your source produces the same instructions and data, not that it is the author's source.
The inline-assembly check is a tripwire on the source and the preprocessed source, not a security boundary.
"""
import argparse
import difflib
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile

# asm(...), asm volatile(...), asm inline(...), asm goto(...), __asm__ __volatile__(...), MSVC __asm { ... }, a bare __asm,
# and raw assembler data directives at the start of a line
ASM_RE = re.compile(r"""
    \b(?:__asm__|__asm|asm)\b(?:\s+(?:__volatile__|__volatile|volatile|__inline__|__inline|inline|goto)\b)*\s*[({]
  | \b__asm\b
  | ^[ \t]*\.(?:word|long|byte|quad|short|octa|incbin|inst|ascii|asciz|string|float|double)\b
""", re.M | re.X)
LITERALS_RE = re.compile(r"""//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""", re.S)
DATA_SECTION_RE = re.compile(r"^\.(?:rodata|rdata|data|bss|tdata|tbss)(?:[.\w]*)$")
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


# ---------------------------------------------------------------- inline assembly guard
def find_inline_asm(source_path, cc):
    """Return the offending text, or None. Checks the source (comments and strings removed) and the preprocessed
    source (so a macro cannot hide asm), ignoring system headers, which legitimately use __asm__ for symbol aliases."""
    with open(source_path, encoding="utf-8", errors="replace") as f:
        source = f.read()
    hit = ASM_RE.search(LITERALS_RE.sub(" ", source))
    if hit:
        return hit.group(0).strip()
    command = [t for t in split_command(cc) if t != "-c"] + ["-E", source_path]
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode != 0:
        return None                                  # the compile step will report the real error
    kept, in_system = [], False
    for line in p.stdout.splitlines():
        marker = re.match(r'#\s+\d+\s+"[^"]*"((?:\s+\d+)*)', line)
        if marker:
            in_system = "3" in marker.group(1).split()
        elif not line.startswith("#") and not in_system:
            kept.append(line)
    hit = ASM_RE.search(LITERALS_RE.sub(" ", "\n".join(kept)))
    return hit.group(0).strip() if hit else None


# ---------------------------------------------------------------- instructions
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


# ---------------------------------------------------------------- data sections
def read_data_sections(path):
    """{name: (is_nobits, size, bytes)} for the data sections of an ELF object, or None when it is not ELF."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        return None
    try:
        is64, endian = data[4] == 2, "<" if data[5] == 1 else ">"
        if is64:
            shoff, = struct.unpack_from(endian + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
        else:
            shoff, = struct.unpack_from(endian + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
        if shoff == 0 or shnum == 0 or shoff + shnum * shentsize > len(data):
            return None
        headers = []
        for i in range(shnum):
            at = shoff + i * shentsize
            if is64:
                name, kind, _, _, offset, size = struct.unpack_from(endian + "IIQQQQ", data, at)
            else:
                name, kind, _, _, offset, size = struct.unpack_from(endian + "IIIIII", data, at)
            headers.append((name, kind, offset, size))
        names_off, names_size = headers[shstrndx][2], headers[shstrndx][3]
        names = data[names_off:names_off + names_size]
        sections = {}
        for name_at, kind, offset, size in headers:
            name = names[name_at:names.index(b"\0", name_at)].decode("ascii", "replace")
            if not DATA_SECTION_RE.match(name):
                continue
            nobits = kind == 8
            if not nobits and offset + size > len(data):
                return None
            sections[name] = (nobits, size, b"" if nobits else bytes(data[offset:offset + size]))
        return sections
    except (struct.error, ValueError, IndexError):
        return None


def data_relocations(path, objdump):
    """{section: [normalised relocation lines]} for data sections."""
    p = subprocess.run([objdump, "-r", path], capture_output=True, text=True)
    result, current = {}, None
    for line in p.stdout.splitlines():
        header = re.match(r"RELOCATION RECORDS FOR \[([^\]]+)\]", line)
        if header:
            current = header.group(1) if DATA_SECTION_RE.match(header.group(1)) else None
            if current:
                result[current] = []
        elif current and line.strip() and not line.startswith("OFFSET"):
            result[current].append(" ".join(line.split()))
    return result


def compare_data(target, candidate, objdump):
    """Differences between the data sections of two objects. Returns (list of messages, compared section names) or (None, [])."""
    a, b = read_data_sections(target), read_data_sections(candidate)
    if a is None or b is None:
        return None, []
    ra, rb = data_relocations(target, objdump), data_relocations(candidate, objdump)
    names = sorted(set(a) | set(b))
    problems = []
    for name in names:
        if name not in a or name not in b:
            side, other = ("the target", a) if name in a else ("the candidate", b)
            size = (a if name in a else b)[name][1]
            if size:
                problems.append(f"{name}: only in {side} ({size} bytes)")
            continue
        (nobits_a, size_a, bytes_a), (nobits_b, size_b, bytes_b) = a[name], b[name]
        if size_a != size_b:
            problems.append(f"{name}: size differs (target {size_a} bytes, candidate {size_b} bytes)")
        elif bytes_a != bytes_b:
            at = next(i for i in range(size_a) if bytes_a[i] != bytes_b[i])
            problems.append(f"{name}: contents differ, first at offset 0x{at:x} (target {bytes_a[at:at + 8].hex()}, candidate {bytes_b[at:at + 8].hex()})")
        if ra.get(name, []) != rb.get(name, []):
            problems.append(f"{name}: relocations differ (target {ra.get(name, [])[:2]}, candidate {rb.get(name, [])[:2]})")
    return problems, names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--candidate")
    ap.add_argument("--candidate-obj")
    ap.add_argument("--cc", default="gcc -O2 -c")
    ap.add_argument("--objdump", default="objdump")
    ap.add_argument("--func")
    ap.add_argument("--data", choices=["auto", "on", "off"], default="auto",
                    help="compare data sections: auto = yes for a whole object, no with --func")
    ap.add_argument("--full", action="store_true", help="print the whole diff instead of the first %d lines" % MAX_DIFF_LINES)
    args = ap.parse_args()

    if bool(args.candidate) == bool(args.candidate_obj):
        fail("RESULT: BUILD_FAILED\nGive exactly one of --candidate (C source) or --candidate-obj (object file).")
    for path in (args.target, args.candidate or args.candidate_obj):
        if not os.path.isfile(path):
            fail(f"RESULT: BUILD_FAILED\nfile not found: {path}")

    cand_obj = args.candidate_obj
    workdir = None
    if args.candidate:
        found = find_inline_asm(args.candidate, args.cc)
        if found:
            print("RESULT: REJECTED")
            print(f"The candidate contains inline assembly or raw data directives (found: {found[:60]!r}). Embedding the")
            print("target's instructions is not a decompilation and would satisfy this check trivially. Rewrite it in plain C.")
            sys.exit(2)
        workdir = tempfile.mkdtemp(prefix="verify-match-")
        cand_obj = os.path.join(workdir, "candidate.o")
        p = subprocess.run(split_command(args.cc) + [args.candidate, "-o", cand_obj], capture_output=True, text=True)
        if p.returncode != 0:
            shutil.rmtree(workdir, ignore_errors=True)
            print("RESULT: BUILD_FAILED")
            print("The candidate does not compile. Treat this as a failed attempt. First errors:")
            print("\n".join(p.stderr.strip().splitlines()[:15]))
            sys.exit(2)

    data_mode = args.data == "on" or (args.data == "auto" and not args.func)
    try:
        target = disassemble(args.target, args.objdump, args.func)
        cand = disassemble(cand_obj, args.objdump, args.func)
        data_problems, data_names = compare_data(args.target, cand_obj, args.objdump) if data_mode else (None, [])
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)       # gone before anything is printed, so a closed pipe cannot leak it
    if not target:
        fail("RESULT: BUILD_FAILED\nNo instructions found in the target. Check --func spelling (symbol names must match).")

    if target == cand:
        if data_problems:
            print("RESULT: NOT_MATCH score=99.0% (the instructions match but the data differs; treat as a failure)")
            for problem in data_problems[:5]:
                print(f"DATA {problem}")
            print("HINT: constants, string literals and tables live in data sections, outside the instruction diff. "
                  "Check literal values, their types (0.2f is not 0.2) and their order.")
            sys.exit(1)
        if not data_mode:
            scope = "instructions only: data sections not compared" + (" with --func; use --data on" if args.func else " (--data off)")
        elif data_problems is None:
            scope = "instructions only: data sections not compared (not an ELF object)"
        elif data_names:
            scope = "data sections identical: " + ", ".join(data_names[:6]) + (", ..." if len(data_names) > 6 else "")
        else:
            scope = "no data sections"
        print(f"RESULT: MATCH (100%, {len(target)} lines compared; {scope})")
        sys.exit(0)

    t_name = re.match(r"<([^>]+)>:", target[0]) if target else None
    c_name = re.match(r"<([^>]+)>:", cand[0]) if cand else None
    if t_name and c_name and t_name.group(1) != c_name.group(1):
        renamed = [line.replace("<" + c_name.group(1), "<" + t_name.group(1)) for line in cand]
        if renamed == target:
            print("RESULT: NOT_MATCH score=99.0% (treat as a failure)")
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

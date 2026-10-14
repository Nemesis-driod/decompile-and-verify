#!/usr/bin/env python3
"""Emulated differential oracle: run ONE function from the original binary under emulation and compare it with your rewrite.

Usage:
  verify_emulated.py --binary app --address 0x1250 --args "ptr,i32" --ret u32 --candidate-lib cand.so --symbol name
  verify_emulated.py --binary app.exe --address 0x00406400 --args i32 --ret i32 --candidate-py recovered.py:screen_pan

The original function is executed by the Unicorn CPU emulator on the machine code in the file, so no whole-program run
and no dlopen of the executable are needed. Candidates: a C shared library (--candidate-lib, called through ctypes) or
a Python function (--candidate-py module.py:function; pointer arguments arrive as bytearray).

Argument types: i8 u8 i16 u16 i32 u32 i64 u64 f64 ptr   (ptr = a buffer; its final bytes are compared too)
Return types:   void i32 u32 i64 u64 f64 (also i8 u8 i16 u16)
Cases: boundary values for every argument, plus --random N seeded random cases, plus any --cases file (JSON lines,
one array of arguments per line; ptr values are hex strings).

ABIs (default by file): sysv (x86-64 ELF), win64 (x86-64 PE), cdecl (32-bit); also stdcall and fastcall (32-bit).
Addresses: the address your tool shows. For a PIE ELF that Ghidra imported, pass --image-base 0x100000.
Limits: leaf and pure-ish functions. A call into an import or libc leaves the loaded image and ends the run with
EMULATION_ERROR. 32-bit floating-point arguments and returns (x87) are not supported.

Exit codes: 0 EQUIVALENT_ON, 1 DIFFERS, 2 SETUP_ERROR or EMULATION_ERROR. Needs: pip install unicorn
"""
import argparse
import ctypes
import importlib.util
import json
import math
import os
import random
import signal
import struct
import sys

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAGE = 0x1000
STACK, STACK_SIZE = 0x70000000, 0x100000
RET_PAGE = 0x6F000000
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x100000
TLS, TLS_SIZE = 0x6E000000, 0x2000
ELF_DYN_BASE = 0x10000000

INT_TYPES = {"i8": (8, True), "u8": (8, False), "i16": (16, True), "u16": (16, False),
             "i32": (32, True), "u32": (32, False), "i64": (64, True), "u64": (64, False)}
CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16, "u16": ctypes.c_uint16,
          "i32": ctypes.c_int32, "u32": ctypes.c_uint32, "i64": ctypes.c_int64, "u64": ctypes.c_uint64,
          "f64": ctypes.c_double, "ptr": ctypes.c_void_p}


def fail(message, code=2):
    print(message)
    sys.exit(code)


# ---------------------------------------------------------------- image loading
class Image:
    def __init__(self, fmt, bits, delta, dynamic):
        self.fmt, self.bits, self.delta, self.dynamic = fmt, bits, delta, dynamic
        self.pages = {}                    # page address -> 4 KB of bytes
        self.image_base = delta            # PE image base, or the ELF load delta

    def write(self, address, blob):
        pos = 0
        while pos < len(blob):
            page = (address + pos) & ~(PAGE - 1)
            inner = (address + pos) - page
            take = min(PAGE - inner, len(blob) - pos)
            data = bytearray(self.pages.get(page, b"\0" * PAGE))
            data[inner:inner + take] = blob[pos:pos + take]
            self.pages[page] = bytes(data)
            pos += take

    def touch(self, address, size):
        for page in range(address & ~(PAGE - 1), address + size, PAGE):
            self.pages.setdefault(page, b"\0" * PAGE)


def load_elf(data):
    if data[5] != 1:
        fail("RESULT: SETUP_ERROR\nOnly little-endian ELF files are supported.")
    is64 = data[4] == 2
    machine, = struct.unpack_from("<H", data, 18)
    if machine not in (0x3E, 0x03):
        fail(f"RESULT: SETUP_ERROR\nUnsupported ELF architecture 0x{machine:x}. This oracle emulates x86 and x86-64 only.")
    e_type, = struct.unpack_from("<H", data, 16)
    dynamic = e_type == 3
    img = Image("elf", 64 if is64 else 32, ELF_DYN_BASE if dynamic else 0, dynamic)
    if is64:
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    else:
        phoff, = struct.unpack_from("<I", data, 0x1C)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    for i in range(phnum):
        at = phoff + i * phentsize
        if is64:
            ptype, _, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, at)
        else:
            ptype, offset, vaddr, _, filesz, memsz, _, _ = struct.unpack_from("<IIIIIIII", data, at)
        if ptype != 1:
            continue
        img.touch(img.delta + vaddr, memsz)
        img.write(img.delta + vaddr, data[offset:offset + filesz])
    return img


def load_pe(data):
    lfanew, = struct.unpack_from("<I", data, 0x3C)
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        fail("RESULT: SETUP_ERROR\nNot a valid PE file.")
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
    if machine not in (0x14C, 0x8664):
        fail(f"RESULT: SETUP_ERROR\nUnsupported PE architecture 0x{machine:x}. This oracle emulates x86 and x86-64 only.")
    opt = lfanew + 24
    magic, = struct.unpack_from("<H", data, opt)
    is64 = magic == 0x20B
    image_base, = struct.unpack_from("<Q", data, opt + 24) if is64 else struct.unpack_from("<I", data, opt + 28)
    size_of_headers, = struct.unpack_from("<I", data, opt + 60)
    img = Image("pe", 64 if is64 else 32, 0, False)
    img.image_base = image_base
    img.touch(image_base, size_of_headers)
    img.write(image_base, data[:size_of_headers])
    for i in range(nsec):
        at = opt + opt_size + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, at + 8)
        img.touch(image_base + vaddr, max(vsize, rawsize))
        img.write(image_base + vaddr, data[rawptr:rawptr + rawsize])
    return img


def load_image(path):
    try:
        data = open(path, "rb").read()
    except OSError as e:
        fail(f"RESULT: SETUP_ERROR\ncannot read {path}: {e}")
    if data[:4] == b"\x7fELF":
        return load_elf(data)
    if data[:2] == b"MZ":
        return load_pe(data)
    fail("RESULT: SETUP_ERROR\nUnsupported file format. Supported: ELF and PE (x86, x86-64).")


# ---------------------------------------------------------------- cases
def int_bounds(kind):
    width, signed = INT_TYPES[kind]
    lo, hi = (-(1 << (width - 1)), (1 << (width - 1)) - 1) if signed else (0, (1 << width) - 1)
    values = {0, 1, 2, lo, hi, lo + 1, hi - 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}
    if signed:
        values |= {-1, -2, -0x80, -0x8000}
    return sorted(v for v in values if lo <= v <= hi)


def wrap(kind, value):
    width, signed = INT_TYPES[kind]
    value &= (1 << width) - 1
    return value - (1 << width) if signed and value >= 1 << (width - 1) else value


def base_value(kind, ptr_len):
    return bytes(ptr_len) if kind == "ptr" else (0.0 if kind == "f64" else 0)


def boundary_cases(kinds, ptr_len):
    base = [base_value(k, ptr_len) for k in kinds]
    cases = [list(base)]
    for i, kind in enumerate(kinds):
        if kind == "ptr":
            variants = [b"\xff" * ptr_len, bytes(range(ptr_len)), bytes((0x80 + j) & 0xFF for j in range(ptr_len)), b"\x01" * ptr_len]
        elif kind == "f64":
            variants = [0.0, -0.0, 1.0, -1.0, 0.5, 2.5, 1e-300, 1e300, math.pi, 100.0, 255.0]
        else:
            variants = int_bounds(kind)
        for v in variants:
            case = list(base)
            case[i] = v
            cases.append(case)
    for pick in (0, -1):                              # all arguments at their lowest / highest boundary at once
        case = []
        for kind in kinds:
            if kind == "ptr":
                case.append(b"\xff" * ptr_len if pick else bytes(ptr_len))
            elif kind == "f64":
                case.append(1e300 if pick else 0.0)
            else:
                case.append(int_bounds(kind)[pick])
        cases.append(case)
    return cases


def random_cases(kinds, ptr_len, count, seed):
    rnd = random.Random(seed)
    cases = []
    for _ in range(count):
        case = []
        for kind in kinds:
            if kind == "ptr":
                case.append(bytes(rnd.getrandbits(8) for _ in range(ptr_len)))
            elif kind == "f64":
                case.append(rnd.choice([rnd.uniform(-1000, 1000), rnd.uniform(-1, 1), float(rnd.randint(-5000, 5000))]))
            else:
                width, signed = INT_TYPES[kind]
                case.append(wrap(kind, rnd.getrandbits(width)) if rnd.random() < 0.7 else rnd.choice(int_bounds(kind)))
        cases.append(case)
    return cases


def file_cases(path, kinds):
    cases = []
    try:
        with open(path, encoding="utf-8") as f:
            for number, line in enumerate(f, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if len(row) != len(kinds):
                    fail(f"RESULT: SETUP_ERROR\n{path} line {number} has {len(row)} values but --args has {len(kinds)}.")
                cases.append([bytes.fromhex(v) if k == "ptr" else v for k, v in zip(kinds, row)])
    except (OSError, ValueError) as e:
        fail(f"RESULT: SETUP_ERROR\ncannot read cases from {path}: {e}")
    return cases


# ---------------------------------------------------------------- emulation
def run_original(unicorn, img, entry, abi, kinds, ret, case, max_insns):
    """Run the function once on a fresh CPU. Returns (return_value, [buffer bytes]) or raises RuntimeError(reason)."""
    uc_mod, x86 = unicorn
    uc = uc_mod.Uc(uc_mod.UC_ARCH_X86, uc_mod.UC_MODE_64 if img.bits == 64 else uc_mod.UC_MODE_32)

    def lazy_map(uc, access, address, size, value, user):
        page = address & ~(PAGE - 1)
        if page in img.pages:
            uc.mem_map(page, PAGE)
            uc.mem_write(page, img.pages[page])
            return True
        return False

    uc.hook_add(uc_mod.UC_HOOK_MEM_UNMAPPED, lazy_map)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(SCRATCH, SCRATCH_SIZE)
    uc.mem_map(RET_PAGE, PAGE)
    if img.bits == 64:
        uc.mem_map(TLS, TLS_SIZE)
        uc.mem_write(TLS + 0x828, b"\x5a\xa5\x5a\xa5\x5a\xa5\x5a\xa5")      # stack-protector canary at fs:0x28
        uc.reg_write(x86.UC_X86_REG_FS_BASE, TLS + 0x800)

    # place pointer arguments in scratch memory
    cursor, values, buffers = SCRATCH, [], []
    for kind, value in zip(kinds, case):
        if kind == "ptr":
            uc.mem_write(cursor, value)
            buffers.append((cursor, len(value)))
            values.append(cursor)
            cursor += (len(value) + 31) & ~15
        else:
            values.append(value)

    word = 8 if img.bits == 64 else 4
    sp = STACK + STACK_SIZE - 0x1000
    if abi in ("sysv", "win64"):
        int_regs = ([x86.UC_X86_REG_RDI, x86.UC_X86_REG_RSI, x86.UC_X86_REG_RDX, x86.UC_X86_REG_RCX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9]
                    if abi == "sysv" else [x86.UC_X86_REG_RCX, x86.UC_X86_REG_RDX, x86.UC_X86_REG_R8, x86.UC_X86_REG_R9])
        xmm_regs = [getattr(x86, f"UC_X86_REG_XMM{i}") for i in range(8)]
        ints = floats = 0
        for position, (kind, value) in enumerate(zip(kinds, values)):
            if kind == "f64":
                slot = floats if abi == "sysv" else position
                if slot >= (8 if abi == "sysv" else 4):
                    raise RuntimeError("too many floating-point arguments for registers")
                uc.reg_write(xmm_regs[slot], struct.unpack("<Q", struct.pack("<d", value))[0])
                floats += 1
            else:
                slot = ints if abi == "sysv" else position
                if slot >= len(int_regs):
                    raise RuntimeError("more integer arguments than registers (stack arguments are not supported)")
                uc.reg_write(int_regs[slot], (value & 0xFFFFFFFFFFFFFFFF) if kind != "ptr" else value)
                ints += 1
        if abi == "win64":
            sp -= 0x20                                  # shadow space
        sp -= word
        uc.mem_write(sp, struct.pack("<Q", RET_PAGE))
        uc.reg_write(x86.UC_X86_REG_RSP, sp)
    else:                                               # 32-bit conventions
        stack_args = list(values)
        if abi == "fastcall":
            for reg in (x86.UC_X86_REG_ECX, x86.UC_X86_REG_EDX):
                if stack_args:
                    uc.reg_write(reg, stack_args.pop(0) & 0xFFFFFFFF)
        for kind, value in reversed(list(zip(kinds[len(kinds) - len(stack_args):], stack_args))):
            if kind in ("f64", "i64", "u64"):
                raise RuntimeError("64-bit and floating-point arguments are not supported in 32-bit mode")
            sp -= 4
            uc.mem_write(sp, struct.pack("<I", value & 0xFFFFFFFF))
        sp -= 4
        uc.mem_write(sp, struct.pack("<I", RET_PAGE))
        uc.reg_write(x86.UC_X86_REG_ESP, sp)

    try:
        uc.emu_start(entry, RET_PAGE, count=max_insns)
    except uc_mod.UcError as e:
        pc = uc.reg_read(x86.UC_X86_REG_RIP if img.bits == 64 else x86.UC_X86_REG_EIP)
        raise RuntimeError(f"{e} at 0x{pc:x}")
    pc = uc.reg_read(x86.UC_X86_REG_RIP if img.bits == 64 else x86.UC_X86_REG_EIP)
    if pc != RET_PAGE:
        raise RuntimeError(f"did not return within {max_insns} instructions (stopped at 0x{pc:x})")

    if ret == "void":
        value = None
    elif ret == "f64":
        if img.bits != 64:
            raise RuntimeError("floating-point returns are not supported in 32-bit mode (x87)")
        value = struct.unpack("<d", struct.pack("<Q", uc.reg_read(x86.UC_X86_REG_XMM0) & 0xFFFFFFFFFFFFFFFF))[0]
    else:
        width, _ = INT_TYPES[ret]
        if img.bits == 32 and width == 64:
            raise RuntimeError("64-bit returns are not supported in 32-bit mode")
        raw = uc.reg_read(x86.UC_X86_REG_RAX if img.bits == 64 else x86.UC_X86_REG_EAX)
        value = wrap(ret, raw)
    return value, [bytes(uc.mem_read(a, n)) for a, n in buffers]


def hint_for(reason, entry, img):
    if "FETCH_UNMAPPED" in reason:
        return ("The function jumped outside the loaded image: it probably calls an import or a library function (PLT or IAT). "
                "Pick a leaf function, or verify the whole program with verify_run.py instead.")
    if "READ_UNMAPPED" in reason or "WRITE_UNMAPPED" in reason:
        return ("The function touched memory that is not part of the image: a global set up by the loader (relocations, TLS, heap), "
                "or a pointer argument you did not declare as ptr.")
    if "INSN_INVALID" in reason:
        return "The emulator hit an instruction it does not support (for example a newer vector extension)."
    return "Check --abi, --args and --address; see the usage text."


# ---------------------------------------------------------------- candidates
def make_candidate(args, kinds):
    if args.candidate_lib:
        try:
            lib = ctypes.CDLL(os.path.abspath(args.candidate_lib))
            fn = getattr(lib, args.symbol)
        except (OSError, AttributeError) as e:
            fail(f"RESULT: SETUP_ERROR\ncannot load {args.symbol} from {args.candidate_lib}: {e}")
        fn.argtypes = [CTYPES[k] for k in kinds]
        fn.restype = None if args.ret == "void" else CTYPES[args.ret]

        def call(case):
            buffers, values = [], []
            for kind, value in zip(kinds, case):
                if kind == "ptr":
                    buf = (ctypes.c_ubyte * max(len(value), 1))(*value)
                    buffers.append((buf, len(value)))
                    values.append(ctypes.addressof(buf))
                else:
                    values.append(value)
            result = fn(*values)
            return result, [bytes(buf)[:n] for buf, n in buffers]
        return call
    if args.candidate_py:
        path, _, name = args.candidate_py.partition(":")
        try:
            spec = importlib.util.spec_from_file_location("candidate_module", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            fn = getattr(module, name)
        except (OSError, AttributeError, SyntaxError, ImportError) as e:
            fail(f"RESULT: SETUP_ERROR\ncannot load {name} from {path}: {e}")

        def call(case):
            buffers, values = [], []
            for kind, value in zip(kinds, case):
                if kind == "ptr":
                    buf = bytearray(value)
                    buffers.append(buf)
                    values.append(buf)
                else:
                    values.append(value)
            return fn(*values), [bytes(b) for b in buffers]
        return call
    fail("RESULT: SETUP_ERROR\nGive a candidate: --candidate-lib LIB --symbol NAME, or --candidate-py module.py:function")


def same(a, b, ret, tol):
    if ret == "void":
        return True
    if ret == "f64":
        return a == b or (math.isnan(a) and math.isnan(b)) or (tol > 0 and math.isclose(a, b, rel_tol=tol, abs_tol=tol))
    return wrap(ret, int(a)) == wrap(ret, int(b))


def show(kinds, case):
    parts = []
    for kind, value in zip(kinds, case):
        parts.append(value.hex()[:48] + ("..." if len(value) > 24 else "") if kind == "ptr" else repr(value))
    return "(" + ", ".join(parts) + ")"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--address", required=True)
    ap.add_argument("--image-base", default="0", help="subtract this from --address (Ghidra shows 0x100000 for PIE ELF files)")
    ap.add_argument("--abi", choices=["sysv", "win64", "cdecl", "stdcall", "fastcall"])
    ap.add_argument("--args", default="", help="comma-separated argument types, for example ptr,i32")
    ap.add_argument("--ret", default="i32", help="return type (void, i32, u32, i64, u64, f64, ...)")
    ap.add_argument("--candidate-lib")
    ap.add_argument("--symbol")
    ap.add_argument("--candidate-py")
    ap.add_argument("--cases", help="JSON-lines file of argument arrays")
    ap.add_argument("--random", type=int, default=200, help="number of random cases (default 200)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--ptr-len", type=int, default=16, help="size of every ptr buffer in bytes (default 16)")
    ap.add_argument("--no-boundary", action="store_true")
    ap.add_argument("--max-insns", type=int, default=5_000_000)
    ap.add_argument("--float-tol", type=float, default=0.0)
    ap.add_argument("--show", type=int, default=3, help="how many mismatches to print")
    args = ap.parse_args()

    try:
        import unicorn
        from unicorn import x86_const
    except ImportError:
        fail("RESULT: SETUP_ERROR\nThe Unicorn emulator is missing. Install it with: pip install unicorn")

    kinds = [k.strip() for k in args.args.split(",") if k.strip()]
    for k in kinds:
        if k not in CTYPES:
            fail(f"RESULT: SETUP_ERROR\nunknown argument type '{k}'. Use: {', '.join(CTYPES)}")
    if args.ret != "void" and args.ret not in CTYPES:
        fail(f"RESULT: SETUP_ERROR\nunknown return type '{args.ret}'.")
    if args.candidate_lib and not args.symbol:
        fail("RESULT: SETUP_ERROR\n--candidate-lib needs --symbol NAME")

    img = load_image(args.binary)
    abi = args.abi or ("sysv" if (img.fmt == "elf" and img.bits == 64) else "win64" if img.bits == 64 else "cdecl")
    if abi in ("sysv", "win64") and img.bits != 64 or abi in ("cdecl", "stdcall", "fastcall") and img.bits != 32:
        fail(f"RESULT: SETUP_ERROR\n--abi {abi} does not match a {img.bits}-bit image.")
    try:
        address = int(args.address, 16) if args.address.lower().startswith("0x") else int(args.address, 0)
        base = int(args.image_base, 0)
    except ValueError:
        fail("RESULT: SETUP_ERROR\n--address and --image-base must be numbers like 0x1250")
    entry = address - base + img.delta if img.fmt == "elf" else (address if address >= img.image_base else address + img.image_base)
    if (entry & ~(PAGE - 1)) not in img.pages:
        fail(f"RESULT: SETUP_ERROR\nAddress 0x{address:x} is not inside the loaded image (entry would be 0x{entry:x}). "
             f"For a PIE ELF imported into Ghidra add --image-base 0x100000.")

    candidate = make_candidate(args, kinds)
    cases = [] if args.no_boundary else boundary_cases(kinds, args.ptr_len)
    n_boundary = len(cases)
    cases += random_cases(kinds, args.ptr_len, args.random, args.seed)
    if args.cases:
        cases += file_cases(args.cases, kinds)
    if not cases:
        fail("RESULT: SETUP_ERROR\nNo cases to run.")

    bad = []
    for number, case in enumerate(cases):
        try:
            original = run_original((unicorn, x86_const), img, entry, abi, kinds, args.ret, case, args.max_insns)
        except RuntimeError as e:
            print("RESULT: EMULATION_ERROR")
            print(f"case {number}: args={show(kinds, case)}: {e}")
            print(f"HINT: {hint_for(str(e), entry, img)}")
            sys.exit(2)
        result, buffers = candidate(case)
        if not same(original[0], result, args.ret, args.float_tol) or original[1] != buffers:
            bad.append((number, case, original, (result, buffers)))

    if bad:
        print(f"RESULT: DIFFERS on {len(bad)} of {len(cases)} cases (treat as a failure)")
        for number, case, (ov, ob), (cv, cb) in bad[:args.show]:
            print(f"  case {number}: args={show(kinds, case)}")
            if not same(ov, cv, args.ret, args.float_tol):
                print(f"    return: original={ov!r} candidate={cv!r}")
            for i, (x, y) in enumerate(zip(ob, cb)):
                if x != y:
                    print(f"    buffer {i}: original={x.hex()[:48]} candidate={y.hex()[:48]}")
        if len(bad) > args.show:
            print(f"  ... {len(bad) - args.show} more differing cases")
        sys.exit(1)
    print(f"RESULT: EQUIVALENT_ON {len(cases)} cases (emulated original vs candidate; {n_boundary} boundary, "
          f"{len(cases) - n_boundary} random or from file; a sample, not a proof)")
    if len(cases) < 20:
        print(f"WARNING: only {len(cases)} cases. Add boundary and random cases before trusting this.")
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Emulated differential oracle: run ONE function from the original binary under emulation and compare it with your rewrite.

Usage:
  verify_emulated.py --binary app --address 0x1250 --args "ptr,i32" --ret u32 --candidate-lib cand.so --symbol name
  verify_emulated.py --binary app.exe --address 0x00406400 --args i32 --ret i32 --candidate-py recovered.py:screen_pan

The original function is executed by the Unicorn CPU emulator on the machine code in the file, so no whole-program run
and no dlopen of the executable are needed. Candidates: a C shared library (--candidate-lib, called through ctypes) or
a Python function (--candidate-py module.py:function; pointer arguments arrive as bytearray). The candidate runs in a
separate process, so a crash or an endless loop in it ends the run with CANDIDATE_CRASH or CANDIDATE_TIMEOUT instead
of taking the verifier down.

Argument types: i8 u8 i16 u16 i32 u32 i64 u64 f64 ptr   (ptr = a buffer; its final bytes are compared too)
Return types:   void i32 u32 i64 u64 f64 (also i8 u8 i16 u16). A pointer return is not supported: the emulated and the
                native address spaces differ, so compare the pointed-to data or an offset instead.
Cases: boundary values for every argument, pairwise combinations of the boundary values of the first three arguments,
plus --random N seeded random cases, plus any --cases file (JSON lines, one array of arguments per line; ptr values are
hex strings). Boundaries and random values do not find bugs that need one specific constant (x == 7 and y == 13):
add such inputs with --cases.

ABIs (default by file): sysv (x86-64 ELF), win64 (x86-64 PE), cdecl (32-bit); also stdcall and fastcall (32-bit).
Addresses: the address your tool shows. For a PIE ELF that Ghidra imported, pass --image-base 0x100000.
Limits: leaf and pure-ish functions. A call into an import or libc leaves the loaded image and ends the run with
EMULATION_ERROR. 32-bit floating-point arguments and returns (x87) are not supported.

Exit codes: 0 EQUIVALENT_ON; 1 DIFFERS, CANDIDATE_CRASH or CANDIDATE_TIMEOUT; 2 SETUP_ERROR or EMULATION_ERROR.
Needs: pip install unicorn
"""
import argparse
import ctypes
import importlib.util
import itertools
import json
import math
import multiprocessing
import os
import random
import signal
import struct
import sys

# SIGPIPE keeps Python's default (ignored, raised as BrokenPipeError): this script talks to a candidate process through a
# pipe and must survive that process dying. A closed stdout (piping into head) is handled at the bottom of the file.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PAGE = 0x1000
STACK, STACK_SIZE = 0x70000000, 0x100000
RET_PAGE = 0x6F000000
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x100000
TLS, TLS_SIZE = 0x6E000000, 0x2000
ELF_DYN_BASE = 0x10000000
MAX_HEADERS = 256
MAX_SECONDS = 86400            # one day: larger values only hide a hang
MAX_INSNS = 1 << 40

INT_TYPES = {"i8": (8, True), "u8": (8, False), "i16": (16, True), "u16": (16, False),
             "i32": (32, True), "u32": (32, False), "i64": (64, True), "u64": (64, False)}
CTYPES = {"i8": ctypes.c_int8, "u8": ctypes.c_uint8, "i16": ctypes.c_int16, "u16": ctypes.c_uint16,
          "i32": ctypes.c_int32, "u32": ctypes.c_uint32, "i64": ctypes.c_int64, "u64": ctypes.c_uint64,
          "f64": ctypes.c_double, "ptr": ctypes.c_void_p}


class SetupError(Exception):
    pass


def fail(message, code=2):
    print(message)
    sys.exit(code)


# ---------------------------------------------------------------- image loading
class Image:
    """Segments of the file, composed into 4 KB pages only when the emulated code touches them."""

    def __init__(self, fmt, bits, delta, dynamic):
        self.fmt, self.bits, self.delta, self.dynamic = fmt, bits, delta, dynamic
        self.segments = []                 # (start address, size in memory, bytes stored in the file)
        self.image_base = delta

    def add(self, start, memsize, blob):
        if start < 0 or start + memsize >= 1 << 64:
            raise ValueError("segment address out of range")
        self.segments.append((start, memsize, blob))

    def page(self, page_addr):
        """The 4 KB page at page_addr, or None when no segment covers it."""
        buf = None
        for start, memsize, blob in self.segments:
            lo, hi = max(page_addr, start), min(page_addr + PAGE, start + memsize)
            if lo >= hi:
                continue
            if buf is None:
                buf = bytearray(PAGE)
            src_lo, src_hi = lo - start, min(hi - start, len(blob))
            if src_lo < src_hi:
                buf[lo - page_addr:lo - page_addr + (src_hi - src_lo)] = blob[src_lo:src_hi]
        return bytes(buf) if buf is not None else None


def load_elf(data):
    if data[5] != 1:
        raise SetupError("Only little-endian ELF files are supported.")
    is64 = data[4] == 2
    machine, = struct.unpack_from("<H", data, 18)
    if machine not in (0x3E, 0x03):
        raise SetupError(f"Unsupported ELF architecture 0x{machine:x}. This oracle emulates x86 and x86-64 only.")
    e_type, = struct.unpack_from("<H", data, 16)
    dynamic = e_type == 3
    img = Image("elf", 64 if is64 else 32, ELF_DYN_BASE if dynamic else 0, dynamic)
    if is64:
        phoff, = struct.unpack_from("<Q", data, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
        minimum = 56
    else:
        phoff, = struct.unpack_from("<I", data, 0x1C)
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
        minimum = 32
    if phnum > MAX_HEADERS or phentsize < minimum or phoff + phnum * phentsize > len(data):
        raise ValueError("program header table is outside the file or implausibly large")
    view = memoryview(data)
    for i in range(phnum):
        at = phoff + i * phentsize
        if is64:
            ptype, _, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", data, at)
        else:
            ptype, offset, vaddr, _, filesz, memsz, _, _ = struct.unpack_from("<IIIIIIII", data, at)
        if ptype == 1:
            if filesz > memsz or offset + filesz > len(data):
                raise ValueError(f"segment {i} claims file bytes 0x{offset:x}-0x{offset + filesz:x}, but the file has only "
                                 f"0x{len(data):x} bytes (it is truncated or corrupt)")
            img.add(img.delta + vaddr, memsz, view[offset:offset + filesz])
    return img


def load_pe(data):
    lfanew, = struct.unpack_from("<I", data, 0x3C)
    if data[lfanew:lfanew + 4] != b"PE\0\0":
        raise SetupError("Not a valid PE file.")
    machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, lfanew + 4)
    if machine not in (0x14C, 0x8664):
        raise SetupError(f"Unsupported PE architecture 0x{machine:x}. This oracle emulates x86 and x86-64 only.")
    opt = lfanew + 24
    magic, = struct.unpack_from("<H", data, opt)
    is64 = magic == 0x20B
    image_base, = struct.unpack_from("<Q", data, opt + 24) if is64 else struct.unpack_from("<I", data, opt + 28)
    size_of_headers, = struct.unpack_from("<I", data, opt + 60)
    if nsec > MAX_HEADERS or opt + opt_size + nsec * 40 > len(data):
        raise ValueError("section table is outside the file or implausibly large")
    img = Image("pe", 64 if is64 else 32, 0, False)
    img.image_base = image_base
    view = memoryview(data)
    if size_of_headers > len(data):
        raise ValueError(f"the headers claim 0x{size_of_headers:x} bytes, but the file has only 0x{len(data):x} (it is truncated or corrupt)")
    img.add(image_base, size_of_headers, view[:size_of_headers])
    for i in range(nsec):
        at = opt + opt_size + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, at + 8)
        if rawsize and rawptr + rawsize > len(data):
            raise ValueError(f"section {i} claims raw data 0x{rawptr:x}-0x{rawptr + rawsize:x}, but the file has only "
                             f"0x{len(data):x} bytes (it is truncated or corrupt)")
        img.add(image_base + vaddr, max(vsize, rawsize), view[rawptr:rawptr + rawsize] if rawsize else view[0:0])
    return img


def load_image(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        fail(f"RESULT: SETUP_ERROR\ncannot read {path}: {e}")
    try:
        if data[:4] == b"\x7fELF":
            return load_elf(data)
        if data[:2] == b"MZ":
            return load_pe(data)
    except SetupError as e:
        fail(f"RESULT: SETUP_ERROR\n{e}")
    except (struct.error, IndexError, ValueError, OverflowError) as e:
        kind = "ELF" if data[:4] == b"\x7fELF" else "PE"
        fail(f"RESULT: SETUP_ERROR\nThe file looks like {kind} but is malformed or truncated ({e}).")
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


def ramp(n):
    """0, 1, 2 ... 255, 0, 1 ... (bytes(range(n)) raises for n > 256)."""
    return bytes(i & 0xFF for i in range(n))


def base_value(kind, ptr_len):
    return bytes(ptr_len) if kind == "ptr" else (0.0 if kind == "f64" else 0)


def small_values(kind, ptr_len):
    if kind == "ptr":
        return [bytes(ptr_len), b"\xff" * ptr_len, ramp(ptr_len)]
    if kind == "f64":
        return [0.0, 1.0, -1.0, 0.5, 1e300]
    width, signed = INT_TYPES[kind]
    lo, hi = (-(1 << (width - 1)), (1 << (width - 1)) - 1) if signed else (0, (1 << width) - 1)
    return sorted({0, 1, lo, hi} | ({-1} if signed else set()))


def boundary_cases(kinds, ptr_len):
    base = [base_value(k, ptr_len) for k in kinds]
    cases = [list(base)]
    for i, kind in enumerate(kinds):
        if kind == "ptr":
            variants = [b"\xff" * ptr_len, ramp(ptr_len), bytes((0x80 + j) & 0xFF for j in range(ptr_len)), b"\x01" * ptr_len]
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
    if len(kinds) >= 2:                               # combinations: bugs that need two arguments at their edges together
        head = min(len(kinds), 3)
        for combo in itertools.product(*[small_values(k, ptr_len) for k in kinds[:head]]):
            cases.append(list(combo) + base[head:])
    unique, seen = [], set()
    for case in cases:
        key = repr(case)
        if key not in seen:
            seen.add(key)
            unique.append(case)
    return unique


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


def case_value(kind, value, where):
    """Check one value from a --cases file against its declared type. Raises ValueError with a precise message."""
    if kind == "ptr":
        if not isinstance(value, str):
            raise ValueError(f"{where}: expected a hex string, got {value!r}")
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise ValueError(f"{where}: {value[:20]!r} is not a valid hex string")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where}: expected a number, got {value!r}")
    if kind == "f64":
        try:
            return float(value)
        except OverflowError:
            raise ValueError(f"{where}: {value!r} does not fit a double")
    if not isinstance(value, int):
        raise ValueError(f"{where}: expected a whole number, got {value!r}")
    width, _ = INT_TYPES[kind]
    low, high = -(1 << (width - 1)), (1 << width) - 1
    if not low <= value <= high:
        raise ValueError(f"{where}: {value} does not fit {kind} (allowed {low} to {high})")
    return wrap(kind, value)


def file_cases(path, kinds):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except (OSError, ValueError) as e:
        fail(f"RESULT: SETUP_ERROR\ncannot read cases from {path}: {e}")
    cases = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as e:
            fail(f"RESULT: SETUP_ERROR\n{path} line {number} is not valid JSON ({e})")
        if not isinstance(row, list) or len(row) != len(kinds):
            fail(f"RESULT: SETUP_ERROR\n{path} line {number} must be an array of {len(kinds)} values (--args has {len(kinds)}).")
        try:
            cases.append([case_value(k, v, f"{path} line {number}, argument {i} ({k})") for i, (k, v) in enumerate(zip(kinds, row), 1)])
        except ValueError as e:
            fail(f"RESULT: SETUP_ERROR\n{e}")
    return cases


# ---------------------------------------------------------------- emulation
def run_original(unicorn, img, entry, abi, kinds, ret, case, max_insns):
    """Run the function once on a fresh CPU. Returns (return_value, [buffer bytes]) or raises RuntimeError(reason)."""
    uc_mod, x86 = unicorn
    uc = uc_mod.Uc(uc_mod.UC_ARCH_X86, uc_mod.UC_MODE_64 if img.bits == 64 else uc_mod.UC_MODE_32)

    def lazy_map(uc, access, address, size, value, user):
        page = address & ~(PAGE - 1)
        blob = img.page(page)
        if blob is None:
            return False
        uc.mem_map(page, PAGE)
        uc.mem_write(page, blob)
        return True

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
            if cursor + len(value) > SCRATCH + SCRATCH_SIZE:
                raise RuntimeError("pointer buffers do not fit in the scratch area; use a smaller --ptr-len")
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

    pc_reg = x86.UC_X86_REG_RIP if img.bits == 64 else x86.UC_X86_REG_EIP
    try:
        uc.emu_start(entry, RET_PAGE, count=max_insns)
    except uc_mod.UcError as e:
        raise RuntimeError(f"{e} at 0x{uc.reg_read(pc_reg):x}")
    pc = uc.reg_read(pc_reg)
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


def hint_for(reason):
    if "FETCH_UNMAPPED" in reason:
        return ("The function jumped outside the loaded image: it probably calls an import or a library function (PLT or IAT). "
                "Pick a leaf function, or verify the whole program with verify_run.py instead.")
    if "READ_UNMAPPED" in reason or "WRITE_UNMAPPED" in reason:
        return ("The function touched memory that is not part of the image: a global set up by the loader (relocations, TLS, heap), "
                "or a pointer argument you did not declare as ptr.")
    if "INSN_INVALID" in reason:
        return "The emulator hit an instruction it does not support (for example a newer vector extension)."
    return "Check --abi, --args and --address; see the usage text."


# ---------------------------------------------------------------- candidates (run in their own process)
def split_candidate_spec(text):
    """'path/to/mod.py:func' -> (path, func). Splits at the LAST colon so Windows drive letters (C:\\x\\mod.py:func) survive."""
    path, sep, name = text.rpartition(":")
    if not sep or len(path) < 2 or not name.isidentifier():
        raise ValueError("--candidate-py must look like path/to/module.py:function_name")
    return path, name


def make_candidate(spec):
    kinds, ret = spec["kinds"], spec["ret"]
    if spec.get("lib"):
        try:
            lib = ctypes.CDLL(spec["lib"])
            fn = getattr(lib, spec["symbol"])
        except (OSError, AttributeError) as e:
            raise SetupError(f"cannot load {spec['symbol']} from {spec['lib']}: {e}")
        fn.argtypes = [CTYPES[k] for k in kinds]
        fn.restype = None if ret == "void" else CTYPES[ret]

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
    path, name = spec["py"]
    try:
        module_spec = importlib.util.spec_from_file_location("candidate_module", path)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        fn = getattr(module, name)
    except Exception as e:                                # a candidate file can fail in any way while loading
        raise SetupError(f"cannot load {name} from {path}: {type(e).__name__}: {e}")

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


def candidate_worker(conn, spec):
    """Runs in a separate process: a crash or an endless loop here cannot take the verifier down."""
    try:
        call = make_candidate(spec)
    except SetupError as e:
        conn.send(("setup_error", str(e)))
        return
    conn.send(("ready", None))
    while True:
        try:
            case = conn.recv()
        except EOFError:
            return
        if case is None:
            return
        try:
            conn.send(("ok", call(case)))
        except Exception as e:                            # the candidate raised: report it, keep serving
            conn.send(("error", f"{type(e).__name__}: {e}"))


class Candidate:
    def __init__(self, spec, timeout):
        ctx = multiprocessing.get_context("spawn")
        self.conn, child = ctx.Pipe()
        self.proc = ctx.Process(target=candidate_worker, args=(child, spec), daemon=True)
        self.proc.start()
        child.close()
        self.timeout = timeout
        if not self.conn.poll(max(timeout, 30)):
            self.kill()
            fail("RESULT: SETUP_ERROR\nThe candidate process did not start in time.")
        try:
            kind, payload = self.conn.recv()
        except (EOFError, OSError):
            fail(f"RESULT: SETUP_ERROR\nThe candidate process died while loading ({self.exit_reason()}).")
        if kind == "setup_error":
            self.close()
            fail(f"RESULT: SETUP_ERROR\n{payload}")

    def call(self, case):
        """Returns ("ok", (value, buffers)), ("error", text), ("crash", reason) or ("timeout", None)."""
        try:
            self.conn.send(case)
        except (BrokenPipeError, OSError):
            return "crash", self.exit_reason()
        if not self.conn.poll(self.timeout):
            self.kill()
            return "timeout", None
        try:
            return self.conn.recv()
        except (EOFError, OSError):
            return "crash", self.exit_reason()

    def exit_reason(self):
        self.proc.join(2)
        code = self.proc.exitcode
        if code is None:
            return "the candidate process stopped responding"
        if code < 0:
            try:
                name = signal.Signals(-code).name
            except ValueError:
                name = f"signal {-code}"
            return f"the candidate process was killed by {name}"
        return f"the candidate process exited with status {code}"

    def kill(self):
        if self.proc.is_alive():
            self.proc.kill()
        self.proc.join(2)

    def close(self):
        try:
            self.conn.send(None)
        except (BrokenPipeError, OSError):
            pass
        self.proc.join(2)
        if self.proc.is_alive():
            self.proc.kill()
            self.proc.join(2)


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
    ap.add_argument("--candidate-py", help="path/to/module.py:function")
    ap.add_argument("--candidate-timeout", type=float, default=10, help="seconds the candidate may take per case (default 10)")
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
    if args.ret == "ptr":
        fail("RESULT: SETUP_ERROR\nA pointer return cannot be compared: the emulated and the native address spaces differ. "
             "Return the pointed-to value or an offset into one of the buffers (u64) from a small wrapper instead.")
    if args.ret != "void" and args.ret not in CTYPES:
        fail(f"RESULT: SETUP_ERROR\nunknown return type '{args.ret}'. Use void, f64 or an integer type (i8 u8 i16 u16 i32 u32 i64 u64).")
    if not (math.isfinite(args.float_tol) and args.float_tol >= 0):
        fail("RESULT: SETUP_ERROR\n--float-tol must be a finite number that is not negative.")
    if not (math.isfinite(args.candidate_timeout) and 0 < args.candidate_timeout <= MAX_SECONDS):
        fail(f"RESULT: SETUP_ERROR\n--candidate-timeout must be a number of seconds greater than 0 and at most {MAX_SECONDS}.")
    if not 1 <= args.max_insns <= MAX_INSNS:
        fail(f"RESULT: SETUP_ERROR\n--max-insns must be between 1 and {MAX_INSNS}.")
    if args.ptr_len < 0 or args.random < 0 or args.show < 0:
        fail("RESULT: SETUP_ERROR\n--ptr-len, --random and --show cannot be negative.")
    pointer_args = sum(1 for k in kinds if k == "ptr")
    if pointer_args and ((args.ptr_len + 31) & ~15) * pointer_args > SCRATCH_SIZE:
        fail(f"RESULT: SETUP_ERROR\n--ptr-len {args.ptr_len} is too large for {pointer_args} pointer argument(s): the emulator reserves "
             f"{SCRATCH_SIZE // 1024} KiB for pointer buffers (about {SCRATCH_SIZE // pointer_args - 32} bytes each at most).")
    if bool(args.candidate_lib) == bool(args.candidate_py):
        fail("RESULT: SETUP_ERROR\nGive a candidate: --candidate-lib LIB --symbol NAME, or --candidate-py module.py:function")
    if args.candidate_lib and not args.symbol:
        fail("RESULT: SETUP_ERROR\n--candidate-lib needs --symbol NAME")

    img = load_image(args.binary)
    abi = args.abi or ("sysv" if (img.fmt == "elf" and img.bits == 64) else "win64" if img.bits == 64 else "cdecl")
    if abi in ("sysv", "win64") and img.bits != 64 or abi in ("cdecl", "stdcall", "fastcall") and img.bits != 32:
        fail(f"RESULT: SETUP_ERROR\n--abi {abi} does not match a {img.bits}-bit image.")
    try:
        address = int(args.address, 0)
        base = int(args.image_base, 0)
    except ValueError:
        fail("RESULT: SETUP_ERROR\n--address and --image-base must be numbers like 0x1250")
    entry = address - base + img.delta if img.fmt == "elf" else (address if address >= img.image_base else address + img.image_base)
    if entry < 0 or img.page(entry & ~(PAGE - 1)) is None:
        fail(f"RESULT: SETUP_ERROR\nAddress 0x{address:x} is not inside the loaded image (entry would be 0x{entry:x}). "
             f"For a PIE ELF imported into Ghidra add --image-base 0x100000.")

    spec = {"kinds": kinds, "ret": args.ret, "lib": None, "symbol": args.symbol, "py": None}
    if args.candidate_lib:
        spec["lib"] = os.path.abspath(args.candidate_lib)
    else:
        try:
            path, name = split_candidate_spec(args.candidate_py)
        except ValueError as e:
            fail(f"RESULT: SETUP_ERROR\n{e}")
        spec["py"] = (os.path.abspath(path), name)

    cases = [] if args.no_boundary else boundary_cases(kinds, args.ptr_len)
    n_boundary = len(cases)
    cases += random_cases(kinds, args.ptr_len, args.random, args.seed)
    if args.cases:
        cases += file_cases(args.cases, kinds)
    if not cases:
        fail("RESULT: SETUP_ERROR\nNo cases to run.")

    candidate = Candidate(spec, args.candidate_timeout)
    bad = []
    try:
        for number, case in enumerate(cases):
            try:
                original = run_original((unicorn, x86_const), img, entry, abi, kinds, args.ret, case, args.max_insns)
            except RuntimeError as e:
                print("RESULT: EMULATION_ERROR")
                print(f"case {number}: args={show(kinds, case)}: {e}")
                print(f"HINT: {hint_for(str(e))}")
                sys.exit(2)
            kind, payload = candidate.call(case)
            if kind == "crash":
                print(f"RESULT: CANDIDATE_CRASH at case {number}: args={show(kinds, case)}: {payload} (treat as a failure)")
                print("HINT: an out-of-bounds read or write is the usual cause; ptr buffers are exactly --ptr-len bytes.")
                sys.exit(1)
            if kind == "timeout":
                print(f"RESULT: CANDIDATE_TIMEOUT at case {number}: args={show(kinds, case)}: no answer within {args.candidate_timeout:g} s "
                      "(treat as a failure)")
                sys.exit(1)
            if kind == "error":
                bad.append((number, case, original, ("raised", payload)))
                continue
            result, buffers = payload
            if not same(original[0], result, args.ret, args.float_tol) or original[1] != buffers:
                bad.append((number, case, original, (result, buffers)))
    finally:
        candidate.close()

    if bad:
        print(f"RESULT: DIFFERS on {len(bad)} of {len(cases)} cases (treat as a failure)")
        for number, case, (ov, ob), (cv, cb) in bad[:args.show]:
            print(f"  case {number}: args={show(kinds, case)}")
            if cv == "raised":
                print(f"    candidate raised {cb}")
                continue
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
    try:
        main()
    except BrokenPipeError:                                # the reader of our output went away (for example `| head`)
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(1)

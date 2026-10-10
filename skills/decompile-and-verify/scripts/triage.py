#!/usr/bin/env python3
"""Static triage of a binary: identity, format, protection hints, notable strings, suggested route.

Usage: triage.py <file> [--json OUT.json]
Stdlib only. Never executes the file. Secret-like values are redacted in all output.
"""
import argparse
import hashlib
import json
import math
import os
import re
import struct
import signal
import sys
import zipfile

SCAN_LIMIT = 32 * 1024 * 1024  # bytes used for strings and entropy
ELF_MACHINES = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS", 0xF3: "RISC-V",
                0x14: "PowerPC", 0x15: "PowerPC64"}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "AArch64"}

PACKER_MARKERS = [  # (needle, name, kind)
    (b"UPX!", "UPX", "packer"), (b"UPX0", "UPX", "packer"),
    (b".vmp0", "VMProtect", "protector"), (b".themida", "Themida", "protector"),
    (b"Themida", "Themida", "protector"), (b".aspack", "ASPack", "packer"),
    (b".MPRESS1", "MPRESS", "packer"), (b"Enigma Protector", "Enigma", "protector"),
    (b"PyInstaller", "PyInstaller", "bundler"), (b"pyi-runtime", "PyInstaller", "bundler"),
]
RUNTIME_PATTERNS = [
    (r"GCC: \([^)]*\) [\d.]+", "GCC"), (r"clang version [\d.]+", "clang"), (r"rustc version [\d.]+|/rustc/[0-9a-f]{40}", "Rust"),
    (r"Go build ID|go1\.\d+(\.\d+)?", "Go"), (r"Microsoft \(R\) Optimizing|VCRUNTIME\d+|MSVCP\d+", "MSVC runtime"),
    (r"il2cpp|IL2CPP", "Unity IL2CPP"), (r"UnityPlayer", "Unity"), (r"python3\d+\.dll|libpython3\.\d+", "CPython embedded"),
]
SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("pem-private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("credential-assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\s*[=:]\s*\S{6,}")),
]
URL_RE = re.compile(r"https?://[^\s\"'<>\\]{6,}")
URL_USERINFO_RE = re.compile(r"^(https?://)[^/\s:@]+:[^/\s@]+@", re.I)
URL_SECRET_PARAM_RE = re.compile(r"(?i)([?&][\w.-]*(?:token|key|secret|passw(?:or)?d|sig(?:nature)?|auth|session)[\w.-]*=)[^&\s#]+")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
BUILD_PATH_RE = re.compile(r"(?:/home/[^/\s]+/[^\s]{3,}|/Users/[^/\s]+/[^\s]{3,}|[A-Za-z]:\\Users\\[^\\\s]+\\[^\s]{3,}|[A-Za-z]:\\[^\s]{3,}\.pdb)")


if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet exit when piped into head
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def plausible_ip(ip):
    """Heuristic: drop OIDs (1.3.6.1, 2.5.29.31) and version numbers (1.5.3.0) that look like IPv4 addresses."""
    a, b, c, d = (int(x) for x in ip.split("."))
    if a == 0 or (a < 10 and d == 0):
        return False
    if a in (1, 2) and max(a, b, c, d) < 100:
        return False
    return True


def entropy_of(counts, total):
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def entropy_report(data):
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    overall = entropy_of(counts, len(data))
    blocks = high = 0
    for off in range(0, len(data), 4096):
        chunk = data[off:off + 4096]
        if len(chunk) < 1024:
            continue
        c = [0] * 256
        for b in chunk:
            c[b] += 1
        blocks += 1
        if entropy_of(c, len(chunk)) > 7.5:
            high += 1
    return round(overall, 2), (round(high / blocks, 3) if blocks else 0.0)


def extract_strings(data):
    out = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{6,}", data)]
    out += [m.decode("utf-16le") for m in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)]
    return out


def redact_url(url):
    """Hide credentials embedded in URLs (user:pass@host and token-like query values)."""
    return URL_SECRET_PARAM_RE.sub(r"\1***", URL_USERINFO_RE.sub(r"\1***:***@", url))


def redact(value, kind):
    if kind == "pem-private-key":
        return "PEM private key header"
    return f"{value[:6]}...({len(value)} chars)"


def parse_elf(f):
    f.seek(0)
    ident = f.read(16)
    is64 = ident[4] == 2
    endian = "<" if ident[5] == 1 else ">"
    fmt = endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    vals = struct.unpack(fmt, f.read(struct.calcsize(fmt)))
    machine, shoff, shentsize, shnum, shstrndx = vals[1], vals[5], vals[10], vals[11], vals[12]
    info = {"format": "ELF", "bits": 64 if is64 else 32, "arch": ELF_MACHINES.get(machine, f"machine 0x{machine:x}")}
    names = []
    if shoff and shnum and shentsize:
        shfmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
        sections = []
        for i in range(shnum):
            f.seek(shoff + i * shentsize)
            raw = f.read(struct.calcsize(shfmt))
            if len(raw) < struct.calcsize(shfmt):
                break
            sections.append(struct.unpack(shfmt, raw))
        if shstrndx < len(sections):
            off, size = sections[shstrndx][4], sections[shstrndx][5]
            f.seek(off)
            strtab = f.read(size)
            for s in sections:
                end = strtab.find(b"\0", s[0])
                names.append(strtab[s[0]:end].decode("latin-1") if end >= 0 else "")
    info["stripped"] = ".symtab" not in names if names else None
    info["has_debug_info"] = any(n.startswith((".debug_", ".zdebug_")) for n in names)
    info["go_binary"] = any(n in (".gopclntab", ".go.buildinfo", ".note.go.buildid") for n in names)
    info["section_names"] = names
    return info


def parse_pe(f):
    f.seek(0x3C)
    (lfanew,) = struct.unpack("<I", f.read(4))
    f.seek(lfanew)
    if f.read(4) != b"PE\0\0":
        return None
    machine, nsec, _, _, _, opt_size, _ = struct.unpack("<HHIIIHH", f.read(20))
    opt = f.read(opt_size)
    magic = struct.unpack_from("<H", opt, 0)[0]
    dd_off = 112 if magic == 0x20B else 96
    ndd = struct.unpack_from("<I", opt, dd_off - 4)[0]
    dirs = [struct.unpack_from("<II", opt, dd_off + 8 * i) for i in range(min(ndd, 16))]
    names = []
    for _ in range(nsec):
        sec = f.read(40)
        if len(sec) < 40:
            break
        names.append(sec[:8].rstrip(b"\0").decode("latin-1"))
    return {"format": "PE", "bits": 64 if magic == 0x20B else 32, "arch": PE_MACHINES.get(machine, f"machine 0x{machine:x}"),
            "managed": len(dirs) > 14 and dirs[14][0] != 0, "has_debug_directory": len(dirs) > 6 and dirs[6][0] != 0,
            "section_names": names}


def parse_zip(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
    classes = [n for n in names if n.endswith(".class")]
    info = {"format": "ZIP", "entries": len(names)}
    if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
        info["format"], info["kind"] = "APK", "android"
        info["native_libs"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
    elif classes or "META-INF/MANIFEST.MF" in names:
        info["format"], info["kind"] = "JAR", "java"
        short = [n for n in classes if all(len(seg) <= 2 for seg in n[:-6].split("/"))]
        info["short_class_names_ratio"] = round(len(short) / len(classes), 3) if classes else 0.0
        info["class_count"] = len(classes)
    return info


def detect(path):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(16)
        info = {"format": "unknown", "kind": "unknown"}
        if head[:4] == b"\x7fELF":
            info = parse_elf(f)
            info["kind"] = "native"
        elif head[:2] == b"MZ":
            pe = parse_pe(f)
            if pe:
                info = pe
                info["kind"] = "dotnet" if pe["managed"] else "native"
        elif head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
            info = {"format": "Mach-O", "kind": "native"}
        elif head[:4] == b"\xca\xfe\xba\xbe":
            (n,) = struct.unpack(">I", head[4:8])
            info = {"format": "Mach-O universal", "kind": "native"} if n < 30 else {"format": "Java class", "kind": "java"}
        elif head[:4] == b"PK\x03\x04" and zipfile.is_zipfile(path):
            info = parse_zip(path)
        elif head[:4] == b"\xaf\x1b\xb1\xfa":
            info = {"format": "IL2CPP metadata (global-metadata.dat)", "kind": "unity-il2cpp-metadata"}
        elif head[:4] == b"dex\n":
            info = {"format": "DEX", "kind": "android"}
        elif head[:4] == b"\0asm":
            info = {"format": "WebAssembly", "kind": "wasm"}
        elif head[:4] == b"\x04\x00\x00\x00" and b'{"files":' in head + f.read(240):
            info = {"format": "Electron asar archive", "kind": "electron"}
        elif head[2:4] == b"\r\n" and size > 16:
            info = {"format": "Python bytecode (.pyc)", "kind": "python"}
    return size, info


ROUTES = {
    "native": "native -> python3 scripts/ghidra_export.py <file> <outdir>   (references/routes.md: Native)",
    "python-bundle": "PyInstaller bundle -> pyinstxtractor <file>, then pycdc on the .pyc files   (references/routes.md: Python)",
    "electron": "Electron -> npx @electron/asar extract <file> <outdir>   (references/routes.md: Electron)",
    "unity-il2cpp-metadata": "Unity IL2CPP metadata -> Il2CppDumper <GameAssembly> <this file> <outdir>   (references/routes.md: Unity)",
    "dotnet": ".NET -> ilspycmd -p -o <outdir> <file>   (references/routes.md: .NET)",
    "java": "Java -> CFR / Vineflower   (references/routes.md: Java and Android)",
    "android": "Android -> jadx -d <outdir> <file>   (references/routes.md: Java and Android)",
    "wasm": "WebAssembly -> wasm-decompile <file>   (references/routes.md: WebAssembly)",
    "python": "Python bytecode -> pycdc <file>   (references/routes.md: Python)",
    "unknown": "unknown format -> run `file`, check for an archive/firmware container, then re-triage the extracted files",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--json", metavar="OUT", help="also write machine-readable results here")
    args = ap.parse_args()

    if os.path.isdir(args.file):
        sys.exit("ERROR: got a directory. Pass a single file (for an APK/JAR/installer pass the archive itself).")
    if not os.path.isfile(args.file):
        sys.exit(f"ERROR: file not found: {args.file}")

    size, info = detect(args.file)
    with open(args.file, "rb") as f:
        data = f.read(SCAN_LIMIT)
    sha = hashlib.sha256()
    with open(args.file, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)

    strings = extract_strings(data)
    blob = "\n".join(strings)
    runtime = sorted({label for pat, label in RUNTIME_PATTERNS if re.search(pat, blob)})
    compiler = re.search(r"GCC: \([^)]*\) [\d.]+|clang version [\d.]+|rustc version [\d.]+", blob)
    protections = {f"{name} ({kind})" for needle, name, kind in PACKER_MARKERS
                   if needle in data or needle.decode() in info.get("section_names", [])}
    with open(args.file, "rb") as f:                        # the PyInstaller cookie sits at the very end of the file
        f.seek(max(0, size - 4096))
        if b"MEI\x0c\x0b\x0a\x0b\x0e" in f.read():
            protections.add("PyInstaller (bundler)")
            if info.get("kind") == "native":
                info["kind"] = "python-bundle"
    protections = sorted(protections)
    overall, high_ratio = entropy_report(data)
    if "Unity IL2CPP" in runtime and info.get("kind") == "native":
        info["kind"] = "native"
        info["note"] = "Unity IL2CPP: also needs global-metadata.dat (references/routes.md: Unity)"

    findings = {"urls": sorted({redact_url(u) for u in URL_RE.findall(blob)})[:20], "ips": sorted(ip for ip in set(IPV4_RE.findall(blob)) if plausible_ip(ip))[:20],
                "build_paths": sorted(set(BUILD_PATH_RE.findall(blob)))[:10], "secret_like": []}
    seen = set()
    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(blob):
            key = (kind, m.group(0))
            if key not in seen:
                seen.add(key)
                findings["secret_like"].append({"type": kind, "redacted": redact(m.group(0), kind)})

    result = {"file": os.path.basename(args.file), "sha256": sha.hexdigest(), "size_bytes": size, **info,
              "runtime_hints": runtime, "compiler_banner": compiler.group(0) if compiler else None,
              "protection_hints": protections, "entropy_overall": overall, "high_entropy_block_ratio": high_ratio,
              "route": ROUTES.get(info.get("kind", "unknown"), ROUTES["unknown"]), "findings": findings}
    result.pop("section_names", None)

    sym = ""
    if result.get("stripped") is not None:
        sym = f"{'stripped (no .symtab)' if result['stripped'] else 'symbols present'}; debug info: {'yes' if result.get('has_debug_info') else 'no'}"
    print(f"== triage: {result['file']} ==")
    print(f"sha256     : {result['sha256']}")
    print(f"size       : {size:,} bytes")
    print(f"format     : {result['format']} {result.get('bits', '')}{'-bit' if result.get('bits') else ''} {result.get('arch', '')}".rstrip())
    if sym:
        print(f"symbols    : {sym}")
    if result.get("managed") is not None:
        print(f"managed    : {'yes (.NET metadata present, expect near-source output)' if result['managed'] else 'no'}")
    if "short_class_names_ratio" in result:
        print(f"jar        : {result['class_count']} classes, {result['short_class_names_ratio']:.0%} with 1-2 char names (high = already obfuscated)")
    print(f"runtime    : {', '.join(runtime) or 'none detected'}{'; ' + result['compiler_banner'] if result['compiler_banner'] else ''}")
    print(f"protection : {', '.join(protections) or 'no known packer/protector markers'}")
    if result["format"] in ("JAR", "APK", "ZIP"):
        print("entropy    : n/a (compressed archive; high entropy is expected)")
    else:
        print(f"entropy    : {overall}/8 overall, {high_ratio:.0%} of 4 KB blocks above 7.5 (high suggests packed or encrypted data)")
    print(f"route      : {result['route']}")
    if result.get("note"):
        print(f"note       : {result['note']}")
    shown = False
    for label, items in (("url", findings["urls"][:5]), ("ip", findings["ips"][:3]), ("build-path", findings["build_paths"][:3])):
        for item in items:
            if not shown:
                print("notable strings:")
                shown = True
            print(f"  {label:<10} {item}")
    for s in findings["secret_like"][:8]:
        if not shown:
            print("notable strings:")
            shown = True
        print(f"  {'secret':<10} {s['redacted']}  [{s['type']}]")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2)
        print(f"json       : {args.json}")


if __name__ == "__main__":
    main()

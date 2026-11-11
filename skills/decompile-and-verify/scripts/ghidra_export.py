#!/usr/bin/env python3
"""Export a function inventory and decompiled C for every function, using Ghidra headless (Windows, macOS, Linux).

Usage: ghidra_export.py <binary> <outdir> [--max N] [--no-decompile] [--timeout SECONDS] [--decompile-timeout SECONDS]
Output: <outdir>/functions.csv, summary.txt (written last: the completion marker), decompiled/<addr>_<name>.c, ghidra.log
A previous export in <outdir> is deleted first, so old files can never be mistaken for this run's output.

Ghidra: set GHIDRA_HOME to the folder that contains support/analyzeHeadless (or put analyzeHeadless on PATH).
Ghidra needs a full JDK (21 or newer, with javac). A JRE alone makes it print a misleading
"unsupported java version" error.
"""
import argparse
import glob
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

IS_WINDOWS = os.name == "nt"
HEADLESS = "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
SEARCH_PATTERNS = [
    "/opt/ghidra*", "/usr/local/ghidra*", "~/ghidra*", "~/tools/ghidra*", "~/Downloads/ghidra*",   # Linux
    "/Applications/ghidra*", "/opt/homebrew/Caskroom/ghidra/*", "/usr/local/Caskroom/ghidra/*",    # macOS
    "C:/ghidra*", "C:/Program Files/ghidra*", "C:/tools/ghidra*",                                  # Windows
]


def fail(message, code=2):
    print(message)
    sys.exit(code)


def headless_in(folder):
    """Return support/analyzeHeadless inside folder, or one level down (zip files unpack into a ghidra_x.y folder)."""
    for candidate in [Path(folder)] + sorted(Path(folder).glob("ghidra_*")):
        script = candidate / "support" / HEADLESS
        if script.is_file():
            return script
    return None


def find_headless():
    home = os.environ.get("GHIDRA_HOME")
    if home:
        found = headless_in(home)
        if found:
            return found
    on_path = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
    if on_path:
        return Path(on_path)
    for pattern in SEARCH_PATTERNS:
        for match in sorted(glob.glob(os.path.expanduser(pattern))):
            found = headless_in(match)
            if found:
                return found
    return None


def has_javac():
    java_home = os.environ.get("JAVA_HOME")
    names = ["javac.exe"] if IS_WINDOWS else ["javac"]
    if java_home and any((Path(java_home) / "bin" / n).is_file() for n in names):
        return True
    return shutil.which("javac") is not None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("outdir")
    ap.add_argument("--max", type=int, default=0, help="stop after N functions (0 = all)")
    ap.add_argument("--no-decompile", action="store_true", help="inventory only, skip the decompiler")
    ap.add_argument("--timeout", type=int, default=600, help="Ghidra analysis timeout in seconds (default 600)")
    ap.add_argument("--decompile-timeout", type=int, default=30,
                    help="seconds Ghidra may spend decompiling ONE function (default 30); functions that exceed it get decompile_status=timeout")
    args = ap.parse_args()

    if args.timeout <= 0 or args.max < 0 or not 1 <= args.decompile_timeout <= 3600:
        fail("RESULT: SETUP_ERROR\n--timeout must be greater than 0, --max cannot be negative, and --decompile-timeout must be 1 to 3600 seconds.")
    binary = Path(args.binary)
    if not binary.is_file():
        fail(f"RESULT: SETUP_ERROR\nbinary not found: {binary}")
    headless = find_headless()
    if headless is None:
        fail("RESULT: SETUP_ERROR\nGhidra not found. Download it from https://github.com/NationalSecurityAgency/ghidra/releases, "
             "unzip it, and set GHIDRA_HOME to the folder that contains support/analyzeHeadless. "
             "Ask the user before installing anything.")
    if not has_javac():
        print("WARNING: no javac found. Ghidra needs a full JDK 21+ (not a JRE). If it fails with 'unsupported java version', "
              "install a JDK (for example Temurin 21) and set JAVA_HOME.")

    out = Path(args.outdir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    project = Path(tempfile.mkdtemp(prefix="ghidra-proj-"))
    log_path = out / "ghidra.log"
    for name in ("functions.csv", "summary.txt", "ghidra.log"):      # an old export must not pass for this run's output
        (out / name).unlink(missing_ok=True)
    shutil.rmtree(out / "decompiled", ignore_errors=True)
    print(f"ghidra_export: analyzing {binary.name} (large files take a while; log: {log_path})")
    command = [str(headless), str(project), "export", "-import", str(binary.resolve()), "-overwrite",
               "-analysisTimeoutPerFile", str(args.timeout), "-scriptPath", str(scripts),
               "-postScript", "ExportFunctions.java", str(out), str(args.max), "0" if args.no_decompile else "1", str(args.decompile_timeout)]
    try:
        with open(log_path, "wb") as log:
            code = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
    except OSError as e:
        fail(f"RESULT: SETUP_ERROR\ncould not start Ghidra ({e}).")
    finally:
        shutil.rmtree(project, ignore_errors=True)

    csv_path, summary_path = out / "functions.csv", out / "summary.txt"
    has_csv = csv_path.is_file() and csv_path.stat().st_size > 0
    finished = summary_path.is_file()                      # ExportFunctions.java writes summary.txt last
    if not (has_csv and finished):
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if has_csv:
            with open(csv_path, encoding="utf-8", errors="replace") as f:
                rows = max(sum(1 for _ in f) - 1, 0)
            print(f"RESULT: PARTIAL (Ghidra exited {code}; functions.csv has {rows} rows but the export did not finish, "
                  "so the inventory is incomplete). Last log lines:")
        else:
            print(f"RESULT: FAILED (Ghidra exited {code} and produced no functions.csv). Last log lines:")
        print("\n".join(log_text.splitlines()[-25:]))
        if "FileSystemException" in log_text or "No space left" in log_text:
            print("HINT: the file system refused a file: a full disk, missing permissions, or a path that is too long. The log names the file.")
        elif "unsupported java version" in log_text or "JDK path" in log_text or "JAVA_HOME" in log_text:
            print("HINT: Ghidra needs a full JDK 21+ with javac. Install one and set JAVA_HOME.")
        else:
            print("HINT: unsupported format or architecture, a script compile error, a timeout, or too little memory. "
                  "Try --no-decompile first.")
        sys.exit(1)

    print("RESULT: OK")
    if code != 0:
        print(f"WARNING: Ghidra exited with status {code} after the export finished.")
    print(summary_path.read_text(encoding="utf-8").rstrip())


if __name__ == "__main__":
    main()

# Routes by target type

## Contents
- Status of each route
- Picking the route
- Native
- .NET
- Java and Android
- Python
- Unity
- Electron
- WebAssembly
- Retro ROMs
- Firmware and containers

## Status of each route

"Verified" means the commands below were run on a real file and did what is described. "Not run" means standard usage from the tool's documentation that this repository has not run. Say which one you are relying on when you report results to the user. Route reports are welcome; see CONTRIBUTING.md.

| Route | Status | What was run |
|---|---|---|
| Native ELF, x86-64 | verified | Ghidra 12.1.4 headless through `ghidra_export.py`, JDK 21 |
| Native PE, 32-bit x86 | verified | same, on a Win32 C++ exercise program (296 functions, all decompiled) |
| Mach-O, ARM, MIPS and others | not run | Ghidra supports them; `triage.py` recognises Mach-O headers only |
| Java JAR | verified | jadx 1.5.6, CFR 0.152, Vineflower 1.12.0 on a 63 KB JAR (17 classes) |
| Android APK | partly | the jadx JAR and DEX path is verified; an APK and apktool were not run |
| .NET | not run | `ilspycmd` installs from NuGet, which was blocked in the test environment |
| Python bundle | verified, with a warning | triage, pyinstxtractor, and pycdc commit b428976 on 3.12 bytecode; the decompiled output was wrong (see Python) |
| Electron | verified | @electron/asar pack and extract; triage detects asar |
| WebAssembly | verified, with caveats | wasm2c, wasm2wat and wasm-objdump from wabt 1.0.42 (see WebAssembly) |
| Unity IL2CPP | not run | metadata detection tested on synthetic bytes only |
| Retro ROMs | not run | commands taken from public write-ups |
| rizin | verified | 0.9.1 static build: `aaa; afl` and `pdf @ main` |

## Picking the route

Run `python3 scripts/triage.py <file>`; its `route:` line names the section below. Run each tool's `--help` first, because flags change between versions. Check what is installed (`command -v ghidra analyzeHeadless java javac python3 jadx rizin objdump`; on Windows use `where`) and tell the user what you would install, and from where, before installing it.

Managed code (.NET, Java, Android) usually decompiles to near-source because names and types survive compilation. Native code loses them, so expect more inference and more verification work.

## Native

- Batch export: `python3 scripts/ghidra_export.py <bin> work/export` (Windows: `python`). Needs Ghidra and a JDK 21+ with `javac`; set `GHIDRA_HOME` to the folder that contains `support/analyzeHeadless`. A 14 KB ELF took about 40 seconds and a 296-function Win32 program about 47 on one CPU. Use `--max N` or `--no-decompile` to scope big files.
- Ranking: `python3 scripts/rank_functions.py work/export/functions.csv`. When Ghidra recognised library code (the Win32 sample came back with 223 of 296 functions already named, mostly runtime library), add `--unnamed-only` so the worklist is the code nobody has identified yet.
- Interactive work: a Ghidra MCP server lets the agent rename, retype and follow cross references live (GhidraMCP, pyghidra-mcp, ReVa; IDA has ida-pro-mcp and an official MCP). Not run here. Bind any MCP or debugger server to 127.0.0.1, since some default to 0.0.0.0. Keep using the batch export for ranking.
- rizin: `rizin -e scr.color=0 -qc 'aaa; afl' file` lists functions and `rizin -e scr.color=0 -qc 'aaa; pdf @ main' file` disassembles one. Without `-e scr.color=0` it prints ANSI colour codes even when piped. It named `main` correctly in a stripped build. Not in the Ubuntu 24.04 archive; the static release from GitHub works.
- `objdump -d -M intel --no-show-raw-insn file` disassembles everything.
- Function-level testing: `ctypes` and `dlopen` cannot load a position-independent executable ("cannot dynamically load position-independent executable"). Use a shared library, a whole-program test, or emulation.
- Strings first, then cross references, then the function. Rename what you understand; renames accumulate into a readable program.
- Confirm dynamic claims before building on them. Agents can confidently misidentify things.
- Go: GoReSym recovers names from `.gopclntab`, even when stripped. Rust: `rustfilt` demangles. Unreal Engine: dump the reflection data first (UE4SS or Dumper-7 style tools). None of these were run here.
- Ghidra's Python scripting differs by version (Jython versus PyGhidra). `ExportFunctions.java` is plain Java for that reason.

## .NET

Not run here. `dotnet tool install -g ilspycmd`, then `ilspycmd -p -o work/out <file>.dll` writes a C# project you can grep. dnSpyEx is the debugger. Obfuscated assemblies (renamed members, control-flow flattening) need a deobfuscation pass first; record which tool you used and what it recovered.

## Java and Android

Verified on a JAR:

- jadx: `jadx -d work/out file.jar` (17 classes in about 4 seconds)
- CFR: `java -jar cfr.jar file.jar --outputdir work/out`
- Vineflower: `java -jar vineflower.jar file.jar work/out/` (writes a source tree)

For an APK, `jadx -d work/out app.apk` uses the same engine, but an APK was not run here. `apktool d app.apk -o work/smali` gives resources and smali (not run). A ProGuard or R8 `mapping.txt` restores original names when you have the owner's build. Native libraries inside an APK (`lib/<abi>/*.so`) go through the Native route. Recaf is the interactive option for JARs.

## Python

- PyInstaller executables: `triage.py` reports `PyInstaller (bundler)`. `python3 pyinstxtractor.py <exe>` extracts `<exe>_extracted/` with the program's own `.pyc` and prints the Python version (verified).
- pycdc: build it from source (`cmake`, about 12 seconds), then `pycdc file.pyc`. **Do not trust its output.** On a 15-line Python 3.12 program it produced code that did not run (a `return` at module level) and, after a minimal fix, differed from the original on 15 of 25 inputs: `tier == 2` came out as `None == 2`, a final `return` vanished, and an `and` turned into a no-op. One small program and one pycdc commit; the point is that nothing flagged it. Check every function with `examples/python-bundle/diff_funcs.py`-style comparisons or `verify_run.py`.
- Ground truth is the bytecode: `pycdas file.pyc` (built with pycdc), or when your Python matches the bytecode version, `python3 -c "import dis, marshal; f = open('x.pyc', 'rb'); f.read(16); dis.dis(marshal.load(f))"` (nested functions live in `co_consts`).

## Unity

Not run here.

- Mono (`Assembly-CSharp.dll`): treat as .NET.
- IL2CPP (`GameAssembly.dll` plus `global-metadata.dat`): Il2CppDumper or Cpp2IL recovers type, field and method names and signatures. Load `GameAssembly.dll` in Ghidra and apply the generated script. `triage.py` recognises `global-metadata.dat` by its header bytes (tested on synthetic bytes only).

## Electron

Verified: `npx @electron/asar extract app.asar work/out`, then a formatter such as prettier. `triage.py` detects `.asar` files by their header. Look for shipped source maps.

## WebAssembly

Verified with wabt 1.0.42 on a 250 KB module:

- `wasm-objdump -x -j Export file.wasm` lists exports (use `-j Import` for imports)
- `wasm2wat file.wasm -o work/out.wat` for the text form
- `wasm2c file.wasm -o work/out.c` for compilable C (about 119,000 lines for that module)

`wasm-decompile file.wasm -o work/out.dcmp` gives readable pseudo-code on a small module (wabt 1.0.34 from the Ubuntu archive), but it aborted with an assertion failure on the 250 KB module, and the Linux release tarball of wabt 1.0.42 does not include it. Use `wasm-decompile` for small functions only.

## Retro ROMs

Not run here. Search "<game> decomp" and "<game> recomp" first: many classics already have matching decompilations or ports, and the right move is to build on them. Otherwise:

- Split the ROM into assembly and data (splat; decomp-toolkit for GameCube and Wii), identify the compiler and flags (decomp.me lists the supported compilers; the console's era and sibling games narrow it), get a first-draft C from m2c, compare with asm-differ or objdiff, and share scratches on decomp.me.
- Public write-ups of agent loops converge on: one function at a time; a build-and-verify script that reports how close an attempt is; one file per attempt; about ten attempts then move on; commit every match; a shared LEARNINGS file; cheapest functions first; several worktrees in parallel; a second model for the hard ones.
- decomp-permuter helps only on nearly matched functions. At low scores it finds shapes no developer would write.
- Some decomp communities restrict AI-generated contributions. Read a project's rules and disclose AI use.

## Firmware and containers

`binwalk -e image.bin` unpacks; re-triage each extracted file. Not run here.

"""Tests for the decompile-and-verify scripts. Run: python3 -m unittest discover -s tests -v"""
import csv
import glob
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "skills" / "decompile-and-verify" / "scripts"
ASSESS = ROOT / "skills" / "decompile-assess" / "scripts"
SAMPLE = ROOT / "examples" / "sample" / "artifacts"
HAVE_GCC = bool(shutil.which("gcc") and shutil.which("objdump"))
IS_LINUX = sys.platform.startswith("linux")      # the tests that build binaries assume ELF and GNU tools
IS_POSIX = os.name != "nt"
HAVE_UNICORN = importlib.util.find_spec("unicorn") is not None
SUM_TO = "int sum_to(int n){int s=0;for(int i=1;i<=n;i++)s+=i;return s;}\n"
# Built at runtime so no key-shaped literal is ever committed (secret scanners would flag it).
FAKE_AWS_KEY = "AKIA" + "Q" * 16


def py(script, *args):
    return subprocess.run([sys.executable, str(script), *map(str, args)], capture_output=True, text=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)


@unittest.skipUnless(HAVE_GCC and IS_LINUX, "needs gcc and GNU objdump on Linux")
class VerifyMatchTests(TempDirCase):
    def setUp(self):
        super().setUp()
        (self.tmp / "target.c").write_text(SUM_TO)
        subprocess.run(["gcc", "-O2", "-c", str(self.tmp / "target.c"), "-o", str(self.tmp / "target.o")], check=True)

    def verdict(self, source):
        cand = self.tmp / "cand.c"
        cand.write_text(source)
        return py(SCRIPTS / "verify_match.py", "--target", self.tmp / "target.o", "--candidate", cand)

    def test_identical_source_matches(self):
        r = self.verdict(SUM_TO)
        self.assertIn("RESULT: MATCH", r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_while_loop_compiles_to_the_same_instructions(self):
        r = self.verdict("int sum_to(int n){int s=0;int i=1;while(i<=n){s+=i;i++;}return s;}\n")
        self.assertIn("RESULT: MATCH", r.stdout)

    def test_off_by_one_does_not_match(self):
        r = self.verdict("int sum_to(int n){int s=0;for(int i=1;i<n;i++)s+=i;return s;}\n")
        self.assertIn("RESULT: NOT_MATCH", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_wrong_function_name_gets_a_rename_hint(self):
        r = self.verdict(SUM_TO.replace("sum_to", "sum_upto"))
        self.assertIn("RESULT: NOT_MATCH", r.stdout)
        self.assertIn("Rename 'sum_upto' to 'sum_to'", r.stdout)

    def test_inline_assembly_is_rejected(self):
        r = self.verdict('int sum_to(int n){__asm__ volatile("nop");return 0;}\n')
        self.assertIn("RESULT: REJECTED", r.stdout)
        self.assertEqual(r.returncode, 2)

    def test_build_failure_is_reported(self):
        r = self.verdict("int sum_to(int n){return n +;}\n")
        self.assertIn("RESULT: BUILD_FAILED", r.stdout)
        self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAVE_GCC and IS_POSIX, "needs gcc and a POSIX system")
class VerifyRunTests(TempDirCase):
    PROGRAM = '#include <stdio.h>\nint f(int n){int s=0;for(int i=1;i<=n;i++)s+=i;return s;}\n' \
              'int main(void){int n;while(scanf("%d",&n)==1)printf("%d\\n",f(n));return 0;}\n'

    def build(self, name, source):
        (self.tmp / f"{name}.c").write_text(source)
        subprocess.run(["gcc", "-O2", "-o", str(self.tmp / name), str(self.tmp / f"{name}.c")], check=True)
        return self.tmp / name

    def inputs(self, values):
        d = self.tmp / "in"
        d.mkdir(exist_ok=True)
        for i, v in enumerate(values):
            (d / f"c{i:03d}.txt").write_text(f"{v}\n")
        return d

    def test_equivalent_rewrite_passes_and_warns_on_small_samples(self):
        orig = self.build("orig", self.PROGRAM)
        new = self.build("new", self.PROGRAM.replace("for(int i=1;i<=n;i++)s+=i;", "int i=1;while(i<=n){s+=i;i++;}"))
        r = py(SCRIPTS / "verify_run.py", "--original", orig, "--rewrite", new, "--inputs", self.inputs([0, 1, 5]))
        self.assertIn("RESULT: EQUIVALENT_ON 3 inputs", r.stdout)
        self.assertIn("WARNING: only 3 inputs", r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_boundary_inputs_catch_what_easy_inputs_miss(self):
        orig = self.build("orig", self.PROGRAM)
        bad = self.build("bad", self.PROGRAM.replace("i<=n", "i<n"))
        easy = py(SCRIPTS / "verify_run.py", "--original", orig, "--rewrite", bad, "--inputs", self.inputs([0, -3]))
        self.assertIn("RESULT: EQUIVALENT_ON", easy.stdout)  # the trap: easy inputs call a bug equivalent
        full = py(SCRIPTS / "verify_run.py", "--original", orig, "--rewrite", bad, "--inputs", self.inputs([0, -3, 1, 2, 10]))
        self.assertIn("RESULT: DIFFERS on 3 of 5 inputs", full.stdout)
        self.assertEqual(full.returncode, 1)

    def test_setup_error_exits_2(self):
        orig = self.build("orig", self.PROGRAM)
        r = py(SCRIPTS / "verify_run.py", "--original", orig, "--rewrite", self.tmp / "missing", "--inputs", self.inputs([1]))
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


class WindowsPathTests(unittest.TestCase):
    def test_backslash_paths_survive_command_splitting_on_windows(self):
        module = load_module(SCRIPTS / "verify_run.py", "verify_run_nt")
        real_os = module.os
        module.os = types.SimpleNamespace(name="nt", path=real_os.path)
        try:
            self.assertEqual(module.split_command(r'C:\tools\mingw\bin\gcc.exe -O2 -c'), [r"C:\tools\mingw\bin\gcc.exe", "-O2", "-c"])
            self.assertEqual(module.split_command('"C:\\Program Files\\gcc.exe" -O2'), [r"C:\Program Files\gcc.exe", "-O2"])
        finally:
            module.os = real_os


class RankFunctionsTests(TempDirCase):
    HEADER = "address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,decompile_status,c_lines,gotos,autovars,c_file\n"

    def write_csv(self):
        rows = [
            '00100010,"FUN_00100010",false,90,40,4,3,0,false,ok,30,0,5,decompiled/a.c',      # score 40+12+6 = 58
            '00100100,"FUN_00100100",false,30,10,1,0,0,false,ok,10,0,2,decompiled/b.c',      # score 13
            '00100150,"known_lib_fn",true,40,12,1,0,0,false,ok,10,0,2,decompiled/f.c',       # named: dropped by --unnamed-only
            '00100200,"_DT_INIT",true,20,8,0,1,0,false,ok,6,0,0,decompiled/c.c',             # loader stub: skipped
            '00100300,"printf",true,6,1,0,0,1,true,ok,2,0,0,decompiled/d.c',                 # thunk: skipped
            '00100400,"FUN_00100400",false,8,2,0,0,0,false,ok,4,0,0,decompiled/e.c',         # too small: skipped
        ]
        path = self.tmp / "functions.csv"
        path.write_text(self.HEADER + "\n".join(rows) + "\n")
        return path

    def test_cheapest_first_and_noise_filtered(self):
        r = py(SCRIPTS / "rank_functions.py", self.write_csv(), "--out", self.tmp / "w.csv")
        self.assertTrue(r.stdout.startswith("NEXT: 00100100 FUN_00100100"))
        self.assertIn("3 candidates", r.stdout)

    def test_unnamed_only_skips_recognised_code(self):
        r = py(SCRIPTS / "rank_functions.py", self.write_csv(), "--unnamed-only", "--out", self.tmp / "w.csv")
        self.assertIn("2 candidates", r.stdout)
        self.assertNotIn("known_lib_fn", r.stdout)

    def test_ledger_removes_finished_functions(self):
        ledger = self.tmp / "ledger.csv"
        ledger.write_text("address,name,status,oracle,attempts,notes\n0x100100,FUN_00100100,matched,matching,2,\n")
        r = py(SCRIPTS / "rank_functions.py", self.write_csv(), "--ledger", ledger, "--unnamed-only", "--out", self.tmp / "w.csv")
        self.assertTrue(r.stdout.startswith("NEXT: 00100010 FUN_00100010"))

    def test_everything_done_says_so(self):
        ledger = self.tmp / "ledger.csv"
        ledger.write_text("address,name,status,oracle,attempts,notes\n0x100010,a,matched,m,1,\n0x100100,b,skipped,m,10,\n0x100150,c,matched,m,1,\n")
        r = py(SCRIPTS / "rank_functions.py", self.write_csv(), "--ledger", ledger, "--out", self.tmp / "w.csv")
        self.assertIn("RESULT: NOTHING_LEFT", r.stdout)


class LedgerTests(TempDirCase):
    def add(self, *extra):
        return py(SCRIPTS / "ledger.py", "add", self.tmp / "l.csv", *extra)

    def test_add_validates_and_quotes(self):
        r = self.add("--address", "101280", "--name", "f", "--status", "matched", "--notes", "has, a comma")
        self.assertIn("RESULT: LEDGER_OK 0x101280", r.stdout)
        with open(self.tmp / "l.csv", newline="", encoding="utf-8") as f:
            self.assertEqual(list(csv.DictReader(f))[0]["notes"], "has, a comma")

    def test_cost_accumulates_when_a_function_is_updated(self):
        self.add("--address", "0x10", "--name", "f", "--status", "skipped", "--attempts", "10", "--seconds", "600")
        self.add("--address", "0x10", "--name", "f", "--status", "equivalent-tested", "--attempts", "3", "--seconds", "420")
        with open(self.tmp / "l.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["status"], rows[0]["attempts"], rows[0]["seconds"]), ("equivalent-tested", "13", "1020"))

    def test_bad_inputs_are_rejected(self):
        self.assertEqual(self.add("--address", "xyz", "--name", "f", "--status", "matched").returncode, 2)
        self.assertNotEqual(self.add("--address", "0x1", "--name", "f", "--status", "maybe").returncode, 0)

    def test_summary_counts(self):
        self.add("--address", "0x1", "--name", "a", "--status", "matched", "--oracle", "m", "--attempts", "2")
        self.add("--address", "0x2", "--name", "b", "--status", "skipped", "--attempts", "10")
        r = py(SCRIPTS / "ledger.py", "summary", self.tmp / "l.csv")
        self.assertIn("2 functions", r.stdout)
        self.assertIn("attempts: 12 total (12.0 per recovered function)", r.stdout)


@unittest.skipUnless(HAVE_GCC and IS_LINUX and shutil.which("strip"), "needs gcc and strip on Linux (ELF)")
class TriageTests(TempDirCase):
    SOURCE = ('#include <stdio.h>\nint main(void){puts("https://api.example.test/v1");puts("%s");'
              'puts("https://deploy:hunter2@host.example.test/x?token=abc123&page=2");return 0;}\n') % FAKE_AWS_KEY

    def build(self, strip):
        (self.tmp / "t.c").write_text(self.SOURCE)
        out = self.tmp / "t"
        subprocess.run(["gcc", "-O2", "-o", str(out), str(self.tmp / "t.c")], check=True)
        if strip:
            subprocess.run(["strip", str(out)], check=True)
        return out

    def test_symbols_and_secret_redaction(self):
        for strip, label in ((False, "symbols present"), (True, "stripped")):
            r = py(SCRIPTS / "triage.py", self.build(strip), "--json", self.tmp / "t.json")
            self.assertIn(label, r.stdout)
            self.assertIn("https://api.example.test/v1", r.stdout)
            self.assertNotIn(FAKE_AWS_KEY, r.stdout)                  # secret values are never printed in full
            data = json.loads((self.tmp / "t.json").read_text())
            self.assertIn("aws-access-key-id", [s["type"] for s in data["findings"]["secret_like"]])
            self.assertNotIn(FAKE_AWS_KEY, json.dumps(data))

    def test_url_credentials_and_tokens_are_redacted(self):
        r = py(SCRIPTS / "triage.py", self.build(False), "--json", self.tmp / "t.json")
        self.assertNotIn("hunter2", r.stdout)
        self.assertNotIn("abc123", r.stdout)
        self.assertIn("https://***:***@host.example.test/x?token=***&page=2", r.stdout)

    def test_errors(self):
        self.assertIn("file not found", py(SCRIPTS / "triage.py", self.tmp / "nope").stderr)
        self.assertIn("got a directory", py(SCRIPTS / "triage.py", self.tmp).stderr)

    def test_oid_like_strings_are_not_reported_as_ips(self):
        blob = self.tmp / "blob.bin"
        blob.write_bytes(b"\x7fELF" + b"\0" * 60 + b"oid 1.3.6.1 and 2.5.29.31 and version 1.5.3.0 and host 10.20.30.40 end" + b"\0" * 20)
        py(SCRIPTS / "triage.py", blob, "--json", self.tmp / "b.json")
        self.assertEqual(json.loads((self.tmp / "b.json").read_text())["findings"]["ips"], ["10.20.30.40"])


class FormatDetectionTests(TempDirCase):
    def kind(self, name, data):
        path = self.tmp / name
        path.write_bytes(data)
        py(SCRIPTS / "triage.py", path, "--json", self.tmp / "o.json")
        return json.loads((self.tmp / "o.json").read_text())

    def test_electron_asar(self):
        header = b"\x04\x00\x00\x00" + b"\x20\x00\x00\x00\x1c\x00\x00\x00\x18\x00\x00\x00" + b'{"files":{"a.js":{"size":1,"offset":"0"}}}'
        self.assertEqual(self.kind("x.asar", header + b"\0" * 100)["kind"], "electron")

    def test_il2cpp_metadata(self):
        self.assertEqual(self.kind("global-metadata.dat", b"\xaf\x1b\xb1\xfa" + b"\0" * 200)["kind"], "unity-il2cpp-metadata")

    def test_pyinstaller_cookie_routes_to_the_python_bundle_path(self):
        data = b"\x7fELF" + b"\0" * 60 + b"\0" * 5000 + b"MEI\x0c\x0b\x0a\x0b\x0e" + b"\0" * 80
        result = self.kind("app", data)
        self.assertEqual(result["kind"], "python-bundle")
        self.assertIn("PyInstaller (bundler)", result["protection_hints"])

    def test_wasm_and_dex_headers(self):
        self.assertEqual(self.kind("m.wasm", b"\0asm\x01\0\0\0" + b"\0" * 40)["kind"], "wasm")
        self.assertEqual(self.kind("c.dex", b"dex\n035\0" + b"\0" * 40)["kind"], "android")


class ScoreExposureTests(TempDirCase):
    HEADER = "address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,decompile_status,c_lines,gotos,autovars,c_file\n"

    def files(self, named):
        flag = "true" if named else "false"
        rows = "".join(f'0010{i}00,"f{i}",{flag},50,20,2,1,0,false,ok,12,0,3,x.c\n' for i in range(4))
        (self.tmp / "functions.csv").write_text(self.HEADER + rows)
        (self.tmp / "triage.json").write_text(json.dumps({"file": "t", "kind": "native", "findings": {"secret_like": [], "urls": [], "ips": [], "build_paths": []}}))
        return self.tmp / "functions.csv", self.tmp / "triage.json"

    def score(self, named, ledger=None):
        fn, tr = self.files(named)
        args = ["--functions", fn, "--triage", tr] + (["--ledger", ledger] if ledger else [])
        return py(ASSESS / "score_exposure.py", *args)

    def test_symbols_raise_the_index(self):
        def ri(out):
            return int(out.split("RI (v0, uncalibrated): ")[1].split("/")[0])
        self.assertGreater(ri(self.score(True).stdout), ri(self.score(False).stdout))

    def test_measured_recovery_is_reported_with_cost(self):
        ledger = self.tmp / "ledger.csv"
        ledger.write_text("address,name,status,oracle,attempts,seconds,notes\n0x1000,f0,matched,m,2,30,\n0x1100,f1,skipped,m,10,600,\n")
        r = self.score(False, ledger)
        self.assertIn("1 of 2 attempted functions recovered in 12 attempts", r.stdout)
        self.assertIn("cost-to-recover", r.stdout)

    def test_bad_ledger_is_an_error_not_a_silent_fallback(self):
        bad = self.tmp / "bad.csv"
        bad.write_text("foo,bar\n1,2\n")
        self.assertIn("missing column", self.score(False, bad).stderr)

    def test_packer_marks_the_surface_inconclusive(self):
        fn, tr = self.files(True)
        data = json.loads(tr.read_text())
        data["protection_hints"] = ["VMProtect (protector)"]
        tr.write_text(json.dumps(data))
        self.assertIn("inconclusive", py(ASSESS / "score_exposure.py", "--functions", fn, "--triage", tr).stdout)

    def test_managed_build_without_a_function_inventory(self):
        tr = self.tmp / "managed.json"
        tr.write_text(json.dumps({"file": "App.dll", "kind": "dotnet", "findings": {"secret_like": [], "urls": [], "ips": [], "build_paths": []}}))
        r = py(ASSESS / "score_exposure.py", "--triage", tr)
        self.assertIn("L legibility       : not measured", r.stdout)
        self.assertIn("RI (v0", r.stdout)


class RenderReportTests(TempDirCase):
    def render(self, ledger=True, **extra):
        out = self.tmp / "report.md"
        exposure = self.tmp / "exposure.json"
        score_args = ["--functions", SAMPLE / "functions.csv", "--triage", SAMPLE / "triage.json", "--json", exposure]
        if ledger:
            score_args += ["--ledger", extra.get("ledger_path", SAMPLE / "ledger.csv")]
        py(ASSESS / "score_exposure.py", *score_args)
        args = ["--triage", SAMPLE / "triage.json", "--exposure", exposure, "--out", out]
        if ledger:
            args += ["--ledger", extra.get("ledger_path", SAMPLE / "ledger.csv")]
        r = py(ASSESS / "render_report.py", *args)
        return r, (out.read_text(encoding="utf-8") if out.exists() else "")

    def test_report_is_built_from_measured_data(self):
        r, text = self.render()
        self.assertIn("RESULT: REPORT_WRITTEN", r.stdout)
        self.assertIn("Recoverability Index: **76/100 (HIGH)**", text)
        self.assertIn("4 attempts for 4 recovered function(s)", text)
        self.assertIn("MASVS-RESILIENCE", text)
        self.assertIn("Rotate now", text)                     # the secret-like string drives the first recommendation

    def test_secret_values_never_appear(self):
        _, text = self.render()
        self.assertNotIn("NOT-A-REAL-KEY-0123456789", text)

    def test_ledger_notes_are_scrubbed(self):
        ledger = self.tmp / "ledger.csv"
        ledger.write_text("address,name,status,oracle,attempts,seconds,notes\n0x10,f,matched,m,1,,key was %s here\n" % FAKE_AWS_KEY)
        _, text = self.render(ledger_path=ledger)
        self.assertNotIn(FAKE_AWS_KEY, text)
        self.assertIn("[redacted]", text)

    def test_report_without_a_recovery_pass_says_so(self):
        _, text = self.render(ledger=False)
        self.assertIn("not measured (no recovery pass was run)", text)
        self.assertIn("not assessed (no recovery pass)", text)

    def test_missing_inputs_are_a_clear_error(self):
        r = py(ASSESS / "render_report.py", "--triage", self.tmp / "nope.json", "--exposure", self.tmp / "nope2.json")
        self.assertIn("RESULT: REPORT_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


def make_pe(code, bits):
    """Build a minimal PE (one .text section) so the emulator's PE loader can be tested on any platform."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    opt_size = 224 if bits == 32 else 240
    coff = struct.pack("<HHIIIHH", 0x14C if bits == 32 else 0x8664, 1, 0, 0, 0, opt_size, 0x0102)
    base = 0x400000 if bits == 32 else 0x140000000
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B if bits == 32 else 0x20B)
    if bits == 32:
        struct.pack_into("<I", opt, 28, base)
    else:
        struct.pack_into("<Q", opt, 24, base)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, 0x200)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIII", sec, 8, len(code), 0x1000, 0x200, 0x200)
    head = (bytes(dos) + b"PE\0\0" + coff + bytes(opt) + bytes(sec)).ljust(0x200, b"\0")
    return head + code.ljust(0x200, b"\0")



def make_elf(code, offset=0x100, filesz=0x1000, memsz=0x1000, file_len=0x200):
    """A minimal ELF64 with one PT_LOAD whose file range is [offset, offset + filesz); file_len lets a test truncate it."""
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, 0x3E)
    struct.pack_into("<Q", header, 0x20, 64)
    struct.pack_into("<HH", header, 0x36, 56, 1)
    body = (bytes(header) + struct.pack("<IIQQQQQQ", 1, 5, offset, 0x400000, 0, filesz, memsz, 0x1000)).ljust(offset, b"\0") + code
    return body.ljust(file_len, b"\0")[:file_len]


@unittest.skipUnless(HAVE_UNICORN, "needs: pip install unicorn")
class VerifyEmulatedPortableTests(TempDirCase):
    def run_oracle(self, binary, *extra):
        return py(SCRIPTS / "verify_emulated.py", "--binary", binary, *extra)

    def setUp(self):
        super().setUp()
        (self.tmp / "add32.exe").write_bytes(make_pe(bytes.fromhex("8B442404" "03442408" "C3"), 32))   # cdecl: a + b
        (self.tmp / "add64.exe").write_bytes(make_pe(bytes.fromhex("8D0411" "C3"), 64))                # win64: lea eax,[rcx+rdx]
        (self.tmp / "fast32.exe").write_bytes(make_pe(bytes.fromhex("8D0411" "C3"), 32))               # fastcall: lea eax,[ecx+edx]
        (self.tmp / "cand.py").write_text("def add(a, b):\n    return a + b\n\ndef wrong(a, b):\n    return a - b\n")

    def test_pe32_cdecl_with_va_and_rva_addresses(self):
        for address in ("0x401000", "0x1000"):
            r = self.run_oracle(self.tmp / "add32.exe", "--address", address, "--args", "i32,i32", "--ret", "i32",
                                "--candidate-py", f"{self.tmp / 'cand.py'}:add")
            self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)
            self.assertEqual(r.returncode, 0)

    def test_pe64_win64_convention(self):
        r = self.run_oracle(self.tmp / "add64.exe", "--address", "0x140001000", "--args", "i32,i32", "--ret", "i32",
                            "--candidate-py", f"{self.tmp / 'cand.py'}:add")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)

    def test_fastcall_convention(self):
        r = self.run_oracle(self.tmp / "fast32.exe", "--address", "0x401000", "--abi", "fastcall", "--args", "i32,i32", "--ret", "i32",
                            "--candidate-py", f"{self.tmp / 'cand.py'}:add")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)

    def test_a_wrong_candidate_is_caught(self):
        r = self.run_oracle(self.tmp / "add32.exe", "--address", "0x401000", "--args", "i32,i32", "--ret", "i32",
                            "--candidate-py", f"{self.tmp / 'cand.py'}:wrong")
        self.assertIn("RESULT: DIFFERS", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_cases_file_is_used(self):
        (self.tmp / "cases.jsonl").write_text("[2147483647, 1]\n[-2147483648, -1]\n")
        r = self.run_oracle(self.tmp / "add32.exe", "--address", "0x401000", "--args", "i32,i32", "--ret", "i32", "--no-boundary",
                            "--random", "0", "--cases", self.tmp / "cases.jsonl", "--candidate-py", f"{self.tmp / 'cand.py'}:add")
        self.assertIn("RESULT: EQUIVALENT_ON 2 cases", r.stdout, r.stdout)
        self.assertIn("WARNING: only 2 cases", r.stdout)

    def test_setup_errors_exit_2(self):
        r = self.run_oracle(self.tmp / "add32.exe", "--address", "0x9999999", "--args", "i32", "--ret", "i32",
                            "--candidate-py", f"{self.tmp / 'cand.py'}:add")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)
        r = self.run_oracle(self.tmp / "add32.exe", "--address", "0x401000", "--args", "i32", "--ret", "i32")
        self.assertIn("Give a candidate", r.stdout)

    def test_missing_unicorn_has_an_install_hint(self):
        code = ("import sys, runpy; sys.modules['unicorn'] = None; "
                f"sys.argv = ['v', '--binary', {str(self.tmp / 'add32.exe')!r}, '--address', '0x401000', '--args', 'i32,i32', '--candidate-py', {str(self.tmp / 'cand.py') + ':add'!r}]; "
                f"runpy.run_path({str(SCRIPTS / 'verify_emulated.py')!r}, run_name='__main__')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertIn("pip install unicorn", r.stdout)
        self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAVE_UNICORN and HAVE_GCC and IS_LINUX and shutil.which("strip") and shutil.which("nm"), "needs unicorn, gcc, strip and nm on Linux")
class VerifyEmulatedElfTests(TempDirCase):
    SOURCE = """
#include <stdio.h>
__attribute__((noinline)) unsigned int fnv16(const unsigned char *p){ unsigned int h=2166136261u; for(int i=0;i<16;i++){h^=p[i];h*=16777619u;} return h&0x7fffffff; }
__attribute__((noinline)) void fill(unsigned char *p){ for(int i=0;i<16;i++) p[i]=(unsigned char)(i*3+1); }
__attribute__((noinline)) double scale(double x, int n){ return x*n + 0.5; }
__attribute__((noinline)) int calls_puts(int x){ puts("hi"); return x + 1; }
int main(int c,char**v){ unsigned char b[16]={0}; b[0]=(unsigned char)c; printf("%u %f %d\\n", fnv16(b), scale(c*1.5,c), calls_puts(c)); fill(b); return b[1]; }
"""
    CANDIDATE = """
unsigned int fnv16(const unsigned char *p){ unsigned int h=2166136261u; for(int i=0;i<16;i++){h^=p[i];h*=16777619u;} return h&0x7fffffff; }
void fill(unsigned char *p){ for(int i=0;i<16;i++) p[i]=(unsigned char)(i*3+1); }
double scale(double x, int n){ return x*n + 0.5; }
int calls_puts(int x){ return x + 1; }
"""

    def setUp(self):
        super().setUp()
        (self.tmp / "t.c").write_text(self.SOURCE)
        subprocess.run(["gcc", "-O2", "-fno-ipa-cp", "-fno-ipa-sra", "-fno-stack-protector", "-o", str(self.tmp / "t"), str(self.tmp / "t.c")], check=True)
        nm = subprocess.run(["nm", str(self.tmp / "t")], capture_output=True, text=True).stdout
        self.addr = {parts[2]: "0x" + parts[0] for parts in (line.split() for line in nm.splitlines()) if len(parts) == 3 and parts[1] in "tT"}
        subprocess.run(["strip", str(self.tmp / "t")], check=True)             # the oracle must work on a stripped binary
        for name, text in (("good", self.CANDIDATE), ("bad", self.CANDIDATE.replace("16777619u", "16777620u"))):
            (self.tmp / f"{name}.c").write_text(text)
            subprocess.run(["gcc", "-O2", "-shared", "-fPIC", "-o", str(self.tmp / f"{name}.so"), str(self.tmp / f"{name}.c")], check=True)

    def oracle(self, func, args, ret, lib="good"):
        return py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / "t", "--address", self.addr[func], "--args", args, "--ret", ret,
                  "--candidate-lib", self.tmp / f"{lib}.so", "--symbol", func)

    def test_pointer_in_integer_return(self):
        self.assertIn("RESULT: EQUIVALENT_ON", self.oracle("fnv16", "ptr", "u32").stdout)

    def test_pointer_out_buffer_is_compared(self):
        self.assertIn("RESULT: EQUIVALENT_ON", self.oracle("fill", "ptr", "void").stdout)

    def test_double_arguments_and_return(self):
        self.assertIn("RESULT: EQUIVALENT_ON", self.oracle("scale", "f64,i32", "f64").stdout)

    def test_sabotaged_candidate_is_caught_on_the_stripped_binary(self):
        r = self.oracle("fnv16", "ptr", "u32", lib="bad")
        self.assertIn("RESULT: DIFFERS", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_call_into_libc_is_a_clear_emulation_error(self):
        r = self.oracle("calls_puts", "i32", "i32")
        self.assertIn("RESULT: EMULATION_ERROR", r.stdout)
        self.assertIn("calls an import or a library function", r.stdout)
        self.assertEqual(r.returncode, 2)


class VerifyTraceTests(TempDirCase):
    def write(self, name, rows):
        path = self.tmp / name
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return path

    def trace(self, drift=0.0, late_from=None):
        return [{"t": t, "x": float(t) + (drift if t >= 3 else 0.0), "hp": 100 - t // 7} for t in range(40)]

    def compare(self, a, b, *extra):
        return py(SCRIPTS / "verify_trace.py", "--original", self.write("a.jsonl", a), "--rewrite", self.write("b.jsonl", b), *extra)

    def test_identical_traces_match(self):
        r = self.compare(self.trace(), self.trace())
        self.assertIn("RESULT: TRACE_MATCH 40 ticks", r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_first_divergence_is_reported_with_its_tick(self):
        r = self.compare(self.trace(), self.trace(drift=0.5))
        self.assertIn("RESULT: TRACE_DIVERGES at tick 3", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_tolerance_accepts_float32_sized_drift(self):
        self.assertIn("TRACE_DIVERGES", self.compare(self.trace(), self.trace(drift=2e-5)).stdout)
        self.assertIn("RESULT: TRACE_MATCH", self.compare(self.trace(), self.trace(drift=2e-5), "--tolerance", "1e-4").stdout)

    def test_per_key_tolerance_and_ignore(self):
        a, b = self.trace(), self.trace()
        b[5]["hp"] += 1
        self.assertIn("TRACE_DIVERGES", self.compare(a, b).stdout)
        self.assertIn("TRACE_MATCH", self.compare(a, b, "--ignore", "hp").stdout)
        self.assertIn("TRACE_MATCH", self.compare(a, b, "--key-tolerance", "hp=1").stdout)

    def test_dropped_tick_is_a_misalignment_not_a_value_difference(self):
        b = self.trace()
        del b[10]
        r = self.compare(self.trace(), b)
        self.assertIn("RESULT: TRACE_MISALIGNED at line 11", r.stdout)

    def test_different_lengths_are_reported(self):
        self.assertIn("different lengths", self.compare(self.trace(), self.trace() + [{"t": 40, "x": 40.0, "hp": 94}]).stdout)

    def test_missing_file_is_a_setup_error(self):
        r = py(SCRIPTS / "verify_trace.py", "--original", self.tmp / "no.jsonl", "--rewrite", self.tmp / "no2.jsonl")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


def command_for(script_path):
    """A command string for verify_run.py that runs a Python script, quoted for any platform."""
    return f'"{sys.executable}" "{script_path}"'


class VerifyRunSafetyTests(TempDirCase):
    """Findings from the public review of verify_run.py: timeouts and vacuous results must not read as equivalence."""

    def setUp(self):
        super().setUp()
        (self.tmp / "hang.py").write_text("import time\ntime.sleep(30)\n")
        (self.tmp / "ok.py").write_text("print(1)\n")
        (self.tmp / "die.py").write_text("import sys\nsys.exit(3)\n")
        self.inputs = self.tmp / "in"
        self.inputs.mkdir()
        (self.inputs / "a.txt").write_text("1\n")

    def verdict(self, original, rewrite, *extra):
        return py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / original), "--rewrite", command_for(self.tmp / rewrite),
                  "--inputs", self.inputs, "--min-inputs", "1", *extra)

    def test_two_timeouts_are_inconclusive_not_equivalent(self):
        r = self.verdict("hang.py", "hang.py", "--timeout", "1")
        self.assertIn("RESULT: INCONCLUSIVE", r.stdout)
        self.assertNotIn("EQUIVALENT_ON", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_a_timeout_on_one_side_only_is_a_difference(self):
        r = self.verdict("ok.py", "hang.py", "--timeout", "1")
        self.assertIn("RESULT: DIFFERS on 1 of 1 inputs", r.stdout)
        self.assertIn("rewrite=timeout", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_identical_failures_on_every_input_are_flagged(self):
        r = self.verdict("die.py", "die.py")
        self.assertIn("WARNING: both programs exited with an error on every input", r.stdout)
        strict = self.verdict("die.py", "die.py", "--strict")
        self.assertIn("RESULT: INCONCLUSIVE", strict.stdout)
        self.assertEqual(strict.returncode, 1)

    def test_strict_turns_the_minimum_into_a_requirement(self):
        loose = py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / "ok.py"), "--rewrite", command_for(self.tmp / "ok.py"),
                   "--inputs", self.inputs, "--min-inputs", "50")
        self.assertEqual(loose.returncode, 0)
        self.assertIn("WARNING: only 1 inputs", loose.stdout)
        strict = py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / "ok.py"), "--rewrite", command_for(self.tmp / "ok.py"),
                    "--inputs", self.inputs, "--min-inputs", "50", "--strict")
        self.assertIn("RESULT: TOO_FEW_INPUTS", strict.stdout)
        self.assertEqual(strict.returncode, 1)

    def test_nonsense_timeout_is_a_setup_error(self):
        r = self.verdict("ok.py", "ok.py", "--timeout", "0")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAVE_UNICORN, "needs: pip install unicorn")
class VerifyEmulatedSafetyTests(TempDirCase):
    """Findings from the public review of verify_emulated.py, plus the Windows path bug found by CI."""

    def setUp(self):
        super().setUp()
        (self.tmp / "add32.exe").write_bytes(make_pe(bytes.fromhex("8B442404" "03442408" "C3"), 32))
        (self.tmp / "good.py").write_text("def add(a, b):\n    return a + b\n")
        (self.tmp / "raises.py").write_text("def add(a, b):\n    return [][5]\n")
        (self.tmp / "loops.py").write_text("def add(a, b):\n    while True:\n        pass\n")
        (self.tmp / "dies.py").write_text("import os\n\ndef add(a, b):\n    os._exit(3)\n")
        (self.tmp / "edge.py").write_text("def add(a, b):\n    if a == -2147483648 and b == 2147483647:\n        return 0\n    return a + b\n")

    def oracle(self, candidate, *extra, binary="add32.exe", ret="i32", args="i32,i32"):
        return py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / binary, "--address", "0x401000", "--args", args, "--ret", ret,
                  "--candidate-py", f"{self.tmp / candidate}:add", "--random", "3", *extra)

    def test_candidate_spec_splits_at_the_last_colon_so_windows_drive_letters_work(self):
        module = load_module(SCRIPTS / "verify_emulated.py", "verify_emulated_spec")
        self.assertEqual(module.split_candidate_spec(r"C:\Users\x\cand.py:add"), (r"C:\Users\x\cand.py", "add"))
        self.assertEqual(module.split_candidate_spec("/tmp/a:b/cand.py:add"), ("/tmp/a:b/cand.py", "add"))
        for bad in ("cand.py", r"C:\Users\x\cand.py", "cand.py:", "cand.py:not an identifier", "C:add"):
            with self.assertRaises(ValueError, msg=bad):
                module.split_candidate_spec(bad)

    @unittest.skipIf(os.name == "nt", "Windows folder names cannot contain colons; drive-letter parsing is covered by the spec test above")
    def test_a_path_with_a_colon_in_a_folder_name_works(self):
        folder = self.tmp / "dir:with:colons"
        folder.mkdir()
        (folder / "cand.py").write_text("def add(a, b):\n    return a + b\n")
        r = self.oracle("dir:with:colons/cand.py")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)

    def test_pointer_return_is_rejected_cleanly_not_with_a_traceback(self):
        r = self.oracle("good.py", ret="ptr")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertIn("pointer return cannot be compared", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_truncated_and_malformed_files_are_setup_errors(self):
        (self.tmp / "t.elf").write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00")
        (self.tmp / "t.exe").write_bytes(b"MZ\x90\x00\x03\x00")
        for name in ("t.elf", "t.exe"):
            r = self.oracle("good.py", binary=name)
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, name)
            self.assertIn("malformed or truncated", r.stdout, name)
            self.assertNotIn("Traceback", r.stderr, name)
            self.assertEqual(r.returncode, 2)

    def test_a_tiny_file_declaring_a_gigantic_segment_cannot_exhaust_memory(self):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4], header[5] = 2, 1
        struct.pack_into("<H", header, 16, 2)
        struct.pack_into("<H", header, 18, 0x3E)
        struct.pack_into("<Q", header, 0x20, 64)
        struct.pack_into("<HH", header, 0x36, 56, 1)
        (self.tmp / "huge.elf").write_bytes(bytes(header) + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, 0, 8 << 30, 0x1000))
        r = py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / "huge.elf", "--address", "0x400000", "--args", "i32", "--ret", "i32",
               "--candidate-py", f"{self.tmp / 'good.py'}:add", "--random", "1")
        self.assertIn("RESULT:", r.stdout)                       # a verdict, not an out-of-memory kill
        self.assertIn(r.returncode, (1, 2))

    def test_a_python_candidate_that_raises_is_reported_as_a_difference(self):
        r = self.oracle("raises.py")
        self.assertIn("RESULT: DIFFERS", r.stdout)
        self.assertIn("candidate raised IndexError", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_an_endless_loop_in_the_candidate_times_out_instead_of_hanging(self):
        r = self.oracle("loops.py", "--candidate-timeout", "2")
        self.assertIn("RESULT: CANDIDATE_TIMEOUT", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_a_candidate_process_that_dies_is_a_verdict_not_a_dead_verifier(self):
        r = self.oracle("dies.py")
        self.assertIn("RESULT: CANDIDATE_CRASH", r.stdout)
        self.assertIn("exited with status 3", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_bugs_that_need_two_arguments_at_their_edges_are_found(self):
        r = self.oracle("edge.py", "--random", "0")
        self.assertIn("RESULT: DIFFERS", r.stdout, r.stdout)

    def test_nonsense_numeric_options_are_rejected(self):
        for flag, value in (("--float-tol", "-1"), ("--float-tol", "nan"), ("--candidate-timeout", "0")):
            r = self.oracle("good.py", flag, value)
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, (flag, value))
            self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAVE_UNICORN and HAVE_GCC and IS_LINUX, "needs unicorn and gcc on Linux")
class VerifyEmulatedNativeCandidateTests(TempDirCase):
    def test_a_segfaulting_native_candidate_is_reported_and_does_not_kill_the_verifier(self):
        (self.tmp / "c.c").write_text("unsigned int f(unsigned int a, unsigned int b){ return *(volatile unsigned int*)0; }\n")
        subprocess.run(["gcc", "-shared", "-fPIC", "-o", str(self.tmp / "c.so"), str(self.tmp / "c.c")], check=True)
        (self.tmp / "o.exe").write_bytes(make_pe(bytes.fromhex("8B442404" "03442408" "C3"), 32))
        r = py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / "o.exe", "--address", "0x401000", "--args", "u32,u32", "--ret", "u32",
               "--candidate-lib", self.tmp / "c.so", "--symbol", "f", "--random", "2")
        self.assertIn("RESULT: CANDIDATE_CRASH", r.stdout, r.stdout + r.stderr)
        self.assertIn("SIGSEGV", r.stdout)
        self.assertEqual(r.returncode, 1)


class LedgerEvidenceTests(TempDirCase):
    def add(self, *extra, name="f", address="0x10"):
        return py(SCRIPTS / "ledger.py", "add", self.tmp / "l.csv", "--address", address, "--name", name, "--status", "equivalent-tested", *extra)

    def setUp(self):
        super().setUp()
        (self.tmp / "app").write_bytes(b"binary-A")
        (self.tmp / "other").write_bytes(b"binary-B")
        (self.tmp / "cand.c").write_text("int f(void){return 1;}\n")
        (self.tmp / "inputs").mkdir()
        (self.tmp / "inputs" / "a").write_text("1")

    def pinned_row(self):
        self.add("--build", self.tmp / "app", "--candidate", self.tmp / "cand.c", "--corpus", self.tmp / "inputs")

    def check(self, *extra):
        return py(SCRIPTS / "ledger.py", "check", self.tmp / "l.csv", "--root", "/", *extra)

    def test_rows_record_the_hashes_of_their_evidence(self):
        self.pinned_row()
        with open(self.tmp / "l.csv", newline="", encoding="utf-8") as f:
            row = list(csv.DictReader(f))[0]
        self.assertEqual(len(row["build_sha256"]), 64)
        self.assertEqual(len(row["candidate_sha256"]), 64)
        self.assertEqual(len(row["corpus_sha256"]), 64)

    def test_check_passes_when_nothing_changed(self):
        self.pinned_row()
        r = self.check("--build", self.tmp / "app")
        self.assertIn("RESULT: LEDGER_CURRENT", r.stdout, r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_check_catches_a_candidate_edited_after_verification(self):
        self.pinned_row()
        (self.tmp / "cand.c").write_text("int f(void){return 2;}\n")
        r = self.check("--build", self.tmp / "app")
        self.assertIn("RESULT: LEDGER_STALE", r.stdout)
        self.assertIn("STALE: candidate", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_check_catches_changed_or_missing_inputs(self):
        self.pinned_row()
        (self.tmp / "inputs" / "b").write_text("2")
        self.assertIn("STALE: corpus", self.check("--build", self.tmp / "app").stdout)
        for child in (self.tmp / "inputs").iterdir():
            child.unlink()
        (self.tmp / "inputs").rmdir()
        self.assertIn("MISSING: corpus", self.check("--build", self.tmp / "app").stdout)

    def test_check_catches_a_row_verified_against_a_different_build(self):
        self.pinned_row()
        r = self.check("--build", self.tmp / "other")
        self.assertIn("BUILD_MISMATCH", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_unpinned_rows_are_called_out(self):
        self.add()
        r = self.check()
        self.assertIn("UNPINNED", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_a_hand_edited_bad_value_is_a_clean_error_not_a_traceback(self):
        self.add()
        text = (self.tmp / "l.csv").read_text().replace(",equivalent-tested,,1,", ",equivalent-tested,,ten,")
        (self.tmp / "l.csv").write_text(text)
        r = py(SCRIPTS / "ledger.py", "summary", self.tmp / "l.csv")
        self.assertIn("RESULT: LEDGER_ERROR", r.stdout)
        self.assertIn("line 2: attempts 'ten' must be a whole number", r.stdout)
        self.assertNotIn("Traceback", r.stderr)
        self.assertEqual(r.returncode, 2)

    def test_the_write_is_atomic_and_leaves_no_temporary_files(self):
        self.pinned_row()
        self.add(address="0x20", name="g")
        self.assertEqual([p.name for p in self.tmp.iterdir() if p.name.startswith(".ledger-")], [])

    def test_old_seven_column_ledgers_still_load(self):
        (self.tmp / "l.csv").write_text("address,name,status,oracle,attempts,seconds,notes\n0x10,f,matched,m,2,,\n")
        r = py(SCRIPTS / "ledger.py", "summary", self.tmp / "l.csv")
        self.assertIn("RESULT: LEDGER_OK 1 functions", r.stdout)


class BuildAwareConsumersTests(TempDirCase):
    HEADER = "address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,decompile_status,c_lines,gotos,autovars,c_file\n"
    SHA_A, SHA_B = "a" * 64, "b" * 64

    def write_inputs(self):
        (self.tmp / "functions.csv").write_text(self.HEADER + '00100100,"FUN_00100100",false,30,10,1,0,0,false,ok,10,0,2,x.c\n'
                                                '00100200,"FUN_00100200",false,30,12,1,0,0,false,ok,10,0,2,y.c\n')
        (self.tmp / "summary.txt").write_text(f"program=app\nsha256={self.SHA_A}\nfunctions=2\n")
        (self.tmp / "triage.json").write_text(json.dumps({"file": "app", "sha256": self.SHA_A, "kind": "native",
                                                          "findings": {"secret_like": [], "urls": [], "ips": [], "build_paths": []}}))

    def ledger(self, rows):
        text = "address,name,status,oracle,attempts,seconds,notes,build_sha256\n" + "".join(rows)
        (self.tmp / "ledger.csv").write_text(text)

    def test_rank_ignores_rows_verified_against_another_build(self):
        self.write_inputs()
        self.ledger([f"0x100100,FUN_00100100,matched,m,1,,,{self.SHA_B}\n"])
        r = py(SCRIPTS / "rank_functions.py", self.tmp / "functions.csv", "--ledger", self.tmp / "ledger.csv", "--out", self.tmp / "w.csv")
        self.assertTrue(r.stdout.startswith("NEXT: 00100100"), r.stdout)          # not skipped: that row proves nothing here
        self.assertIn("ignored 1 ledger row", r.stderr)

    def test_rank_still_honours_rows_for_this_build(self):
        self.write_inputs()
        self.ledger([f"0x100100,FUN_00100100,matched,m,1,,,{self.SHA_A}\n"])
        r = py(SCRIPTS / "rank_functions.py", self.tmp / "functions.csv", "--ledger", self.tmp / "ledger.csv", "--out", self.tmp / "w.csv")
        self.assertTrue(r.stdout.startswith("NEXT: 00100200"), r.stdout)

    def test_scorer_does_not_count_rows_from_another_build(self):
        self.write_inputs()
        self.ledger([f"0x100100,FUN_00100100,matched,m,1,,,{self.SHA_B}\n", f"0x100200,FUN_00100200,skipped,m,10,,,{self.SHA_A}\n"])
        r = py(ASSESS / "score_exposure.py", "--functions", self.tmp / "functions.csv", "--triage", self.tmp / "triage.json",
               "--ledger", self.tmp / "ledger.csv")
        self.assertIn("0 of 1 attempted functions recovered", r.stdout, r.stdout)
        self.assertIn("1 excluded (verified against a different build)", r.stdout)

    def test_scorer_rejects_non_numeric_ledger_values_cleanly(self):
        self.write_inputs()
        self.ledger([f"0x100100,FUN_00100100,matched,m,ten,,,{self.SHA_A}\n"])
        r = py(ASSESS / "score_exposure.py", "--functions", self.tmp / "functions.csv", "--triage", self.tmp / "triage.json",
               "--ledger", self.tmp / "ledger.csv")
        self.assertIn("is not a number", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_report_states_how_well_the_evidence_is_pinned(self):
        out = self.tmp / "report.md"
        exposure = self.tmp / "exposure.json"
        py(ASSESS / "score_exposure.py", "--functions", SAMPLE / "functions.csv", "--triage", SAMPLE / "triage.json",
           "--ledger", SAMPLE / "ledger.csv", "--json", exposure)
        py(ASSESS / "render_report.py", "--triage", SAMPLE / "triage.json", "--exposure", exposure, "--ledger", SAMPLE / "ledger.csv", "--out", out)
        text = out.read_text(encoding="utf-8")
        self.assertIn("Evidence: 4 of 4 ledger rows are pinned to this build", text)
        self.assertIn("build, candidate, corpus", text)


class TriageRobustnessTests(TempDirCase):
    def triage(self, name, data, *extra):
        path = self.tmp / name
        path.write_bytes(data)
        r = py(SCRIPTS / "triage.py", path, "--json", self.tmp / "o.json", *extra)
        return r, (json.loads((self.tmp / "o.json").read_text()) if (self.tmp / "o.json").exists() else None)

    def test_truncated_headers_give_a_result_not_a_traceback(self):
        for name, data in (("t.elf", b"\x7fELF\x02\x01\x01\x00\x00\x00"), ("t.exe", b"MZ\x90\x00\x03\x00"),
                           ("t.zip", b"PK\x03\x04not-a-real-zip"), ("t.class", b"\xca\xfe\xba\xbe")):
            r, result = self.triage(name, data)
            self.assertEqual(r.returncode, 0, (name, r.stderr))
            self.assertNotIn("Traceback", r.stderr, name)
            self.assertEqual(result["kind"], "unknown", name) if name != "t.zip" else None

    def test_a_malformed_header_is_stated_in_the_output(self):
        r, result = self.triage("t.elf", b"\x7fELF\x02\x01\x01\x00\x00\x00")
        self.assertIn("malformed or truncated", r.stdout)
        self.assertTrue(result["malformed"])

    def test_a_partial_scan_is_visible_and_the_limit_is_adjustable(self):
        data = b"\0" * (2 << 20) + b"api_key=SUPERSECRETVALUE1234567890\n"
        r, result = self.triage("big.bin", data, "--scan-mib", "1")
        self.assertIn("only the first 1 MiB", r.stdout)
        self.assertTrue(result["scan_truncated"])
        self.assertEqual(result["findings"]["secret_like"], [])
        r, result = self.triage("big.bin", data, "--scan-mib", "4")
        self.assertFalse(result["scan_truncated"])
        self.assertEqual(len(result["findings"]["secret_like"]), 1)


class GhidraExportCompletionTests(TempDirCase):
    """The wrapper must not call a partial or stale export a success. Uses a fake analyzeHeadless, so it needs no Ghidra."""

    HEADER = "address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,decompile_status,c_lines,gotos,autovars,c_file"

    def fake_ghidra(self, body, exit_code):
        support = self.tmp / "fake" / "support"
        support.mkdir(parents=True, exist_ok=True)
        script = support / "analyzeHeadless"
        script.write_text("#!/bin/sh\ndir=$(echo \"$@\" | sed 's/.*ExportFunctions.java \\([^ ]*\\).*/\\1/')\nmkdir -p \"$dir\"\n"
                          f"{body}\nexit {exit_code}\n")
        script.chmod(0o755)
        (self.tmp / "dummy.bin").write_bytes(b"x")

    def export(self, outdir="out"):
        env = dict(os.environ, GHIDRA_HOME=str(self.tmp / "fake"))
        return subprocess.run([sys.executable, str(SCRIPTS / "ghidra_export.py"), str(self.tmp / "dummy.bin"), str(self.tmp / outdir)],
                              capture_output=True, text=True, env=env)

    row = '00100000,"FUN_00100000",false,10,3,0,0,0,false,ok,3,0,0,x.c'

    @unittest.skipIf(os.name == "nt", "the fake Ghidra is a shell script")
    def test_a_run_that_dies_halfway_is_partial_not_ok(self):
        self.fake_ghidra(f"printf '%s\\n%s\\n' '{self.HEADER}' '{self.row}' > \"$dir/functions.csv\"", 1)
        r = self.export()
        self.assertIn("RESULT: PARTIAL", r.stdout)
        self.assertNotIn("RESULT: OK", r.stdout)
        self.assertEqual(r.returncode, 1)

    @unittest.skipIf(os.name == "nt", "the fake Ghidra is a shell script")
    def test_stale_files_from_an_earlier_run_are_not_mistaken_for_output(self):
        (self.tmp / "out").mkdir()
        (self.tmp / "out" / "functions.csv").write_text(self.HEADER + "\n" + self.row + "\n")
        (self.tmp / "out" / "summary.txt").write_text("program=old\n")
        self.fake_ghidra(":", 0)
        r = self.export()
        self.assertIn("RESULT: FAILED", r.stdout)
        self.assertEqual(r.returncode, 1)

    @unittest.skipIf(os.name == "nt", "the fake Ghidra is a shell script")
    def test_a_finished_export_is_ok(self):
        self.fake_ghidra(f"printf '%s\\n%s\\n' '{self.HEADER}' '{self.row}' > \"$dir/functions.csv\"; printf 'program=dummy\\nfunctions=1\\n' > \"$dir/summary.txt\"", 0)
        r = self.export()
        self.assertIn("RESULT: OK", r.stdout, r.stdout)
        self.assertEqual(r.returncode, 0)


@unittest.skipUnless(HAVE_GCC and IS_LINUX, "needs gcc and GNU objdump on Linux")
class VerifyMatchHygieneTests(TempDirCase):
    def test_no_temporary_folders_are_left_behind(self):
        (self.tmp / "t.c").write_text(SUM_TO)
        subprocess.run(["gcc", "-O2", "-c", str(self.tmp / "t.c"), "-o", str(self.tmp / "t.o")], check=True)
        for body in (SUM_TO, SUM_TO.replace("<=", "<"), "int sum_to(int n){return n +;}\n"):
            (self.tmp / "c.c").write_text(body)
            subprocess.run([sys.executable, str(SCRIPTS / "verify_match.py"), "--target", str(self.tmp / "t.o"), "--candidate", str(self.tmp / "c.c")],
                           capture_output=True, text=True)
        before = set(glob.glob(os.path.join(tempfile.gettempdir(), "verify-match-*")))
        (self.tmp / "c.c").write_text(SUM_TO.replace("<=", "<"))
        subprocess.run([sys.executable, str(SCRIPTS / "verify_match.py"), "--target", str(self.tmp / "t.o"), "--candidate", str(self.tmp / "c.c")],
                       capture_output=True, text=True)
        after = set(glob.glob(os.path.join(tempfile.gettempdir(), "verify-match-*")))
        self.assertEqual(after - before, set())


class VerifyTraceToleranceTests(TempDirCase):
    def test_negative_and_non_finite_tolerances_are_rejected(self):
        for rows in ("a.jsonl", "b.jsonl"):
            (self.tmp / rows).write_text('{"t": 0, "x": 1.0}\n')
        for value in ("-1", "nan", "inf"):
            r = py(SCRIPTS / "verify_trace.py", "--original", self.tmp / "a.jsonl", "--rewrite", self.tmp / "b.jsonl", "--tolerance", value)
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, value)
            self.assertEqual(r.returncode, 2)
        r = py(SCRIPTS / "verify_trace.py", "--original", self.tmp / "a.jsonl", "--rewrite", self.tmp / "b.jsonl", "--key-tolerance", "x=-2")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)


@unittest.skipUnless(HAVE_UNICORN, "needs: pip install unicorn")
class VerifyEmulatedInputValidationTests(TempDirCase):
    """Second public review: file-backed bytes must really be in the file, pointer buffers of any size, finite numbers."""

    SEVEN = bytes.fromhex("B807000000C3")                      # mov eax, 7 ; ret

    def setUp(self):
        super().setUp()
        (self.tmp / "seven.py").write_text("def f():\n    return 7\n")
        (self.tmp / "first.py").write_text("def f(*bufs):\n    return bufs[0][0]\n")
        self.first_byte = make_pe(bytes.fromhex("8B442404" "0FB600" "C3"), 32)          # movzx eax, byte [ptr]

    def oracle(self, binary, address, candidate, *extra, args="", ret="i32"):
        return py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / binary, "--address", address, "--args", args, "--ret", ret,
                  "--candidate-py", f"{self.tmp / candidate}:f", "--random", "2", *extra)

    def test_an_elf_segment_extending_past_the_end_of_the_file_is_rejected(self):
        (self.tmp / "t.elf").write_bytes(make_elf(self.SEVEN, offset=0x100, filesz=0x1000, memsz=0x1000, file_len=0x200))
        r = self.oracle("t.elf", "0x400000", "seven.py")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout, r.stdout)
        self.assertIn("truncated or corrupt", r.stdout)
        self.assertEqual(r.returncode, 2)

    def test_a_segment_ending_exactly_at_the_end_of_the_file_is_accepted(self):
        (self.tmp / "ok.elf").write_bytes(make_elf(self.SEVEN, offset=0x100, filesz=0x10, memsz=0x1000, file_len=0x110))
        r = self.oracle("ok.elf", "0x400000", "seven.py")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)

    def test_a_segment_whose_file_size_exceeds_its_memory_size_is_rejected(self):
        (self.tmp / "bad.elf").write_bytes(make_elf(self.SEVEN, offset=0x100, filesz=0x20, memsz=0x10, file_len=0x200))
        self.assertIn("RESULT: SETUP_ERROR", self.oracle("bad.elf", "0x400000", "seven.py").stdout)

    def test_a_pe_section_extending_past_the_end_of_the_file_is_rejected(self):
        (self.tmp / "t.exe").write_bytes(make_pe(self.SEVEN, 32)[:0x300])                 # the section declares 0x200 bytes at 0x200
        r = self.oracle("t.exe", "0x401000", "seven.py")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout, r.stdout)
        self.assertIn("truncated or corrupt", r.stdout)

    def test_a_complete_pe_is_still_accepted(self):
        (self.tmp / "t.exe").write_bytes(make_pe(self.SEVEN, 32))
        self.assertIn("RESULT: EQUIVALENT_ON", self.oracle("t.exe", "0x401000", "seven.py").stdout)

    def test_pointer_buffers_larger_than_256_bytes_work(self):
        (self.tmp / "p.exe").write_bytes(self.first_byte)
        for size in ("255", "256", "257", "4000"):
            r = self.oracle("p.exe", "0x401000", "first.py", "--ptr-len", size, args="ptr", ret="u32")
            self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, (size, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr, size)

    def test_cases_file_values_are_checked_against_their_declared_types(self):
        (self.tmp / "t.exe").write_bytes(make_pe(bytes.fromhex("8B442404" "03442408" "C3"), 32))
        (self.tmp / "add.py").write_text("def f(a, b):\n    return a + b\n")
        cases = {'["abc", 1]': "expected a number", "[3.5, 1]": "expected a whole number", "[true, 1]": "expected a number",
                 "[null, 1]": "expected a number", "[99999999999999999999999, 1]": "does not fit i32", "not json": "not valid JSON",
                 '["12"]': "must be an array of 2 values"}
        for line, expected in cases.items():
            (self.tmp / "c.jsonl").write_text(line + "\n")
            r = self.oracle("t.exe", "0x401000", "add.py", "--no-boundary", "--random", "0", "--cases", self.tmp / "c.jsonl", args="i32,i32")
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, (line, r.stdout, r.stderr))
            self.assertIn(expected, r.stdout, line)
            self.assertIn("c.jsonl line 1", r.stdout, line) if line != "not json" else None
            self.assertNotIn("Traceback", r.stderr, line)
        (self.tmp / "c.jsonl").write_text("[4294967295, 1]\n[-2147483648, 2147483647]\n")                  # both signed and unsigned forms are fine
        ok = self.oracle("t.exe", "0x401000", "add.py", "--no-boundary", "--random", "0", "--cases", self.tmp / "c.jsonl", args="i32,i32")
        self.assertIn("RESULT: EQUIVALENT_ON 2 cases", ok.stdout, ok.stdout)

    def test_pointer_values_in_a_cases_file_must_be_hex_strings(self):
        (self.tmp / "p.exe").write_bytes(self.first_byte)
        for line, expected in (('["xyz"]', "not a valid hex string"), ("[5]", "expected a hex string")):
            (self.tmp / "c.jsonl").write_text(line + "\n")
            r = self.oracle("p.exe", "0x401000", "first.py", "--no-boundary", "--random", "0", "--cases", self.tmp / "c.jsonl", args="ptr", ret="u32")
            self.assertIn(expected, r.stdout, line)

    def test_buffers_that_cannot_fit_are_a_setup_error(self):
        (self.tmp / "p.exe").write_bytes(self.first_byte)
        r = self.oracle("p.exe", "0x401000", "first.py", "--ptr-len", "600000", args="ptr,ptr", ret="u32")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertIn("too large for 2 pointer argument(s)", r.stdout)

    def test_non_finite_and_absurd_numeric_options_are_rejected_cleanly(self):
        (self.tmp / "t.exe").write_bytes(make_pe(self.SEVEN, 32))
        for flag, value in (("--candidate-timeout", "nan"), ("--candidate-timeout", "inf"), ("--candidate-timeout", "1e999"),
                            ("--candidate-timeout", "1e30"), ("--max-insns", "0"), ("--max-insns", "99999999999999999999"),
                            ("--ptr-len", "-1"), ("--show", "-1")):
            r = self.oracle("t.exe", "0x401000", "seven.py", flag, value)
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, (flag, value, r.stdout, r.stderr))
            self.assertNotIn("Traceback", r.stderr, (flag, value))
            self.assertEqual(r.returncode, 2)


class UnreadableFileTests(TempDirCase):
    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), "needs a non-root POSIX user")
    def test_triage_reports_a_file_it_cannot_read(self):
        path = self.tmp / "locked.bin"
        path.write_bytes(b"x")
        path.chmod(0)
        try:
            r = py(SCRIPTS / "triage.py", path)
        finally:
            path.chmod(0o600)
        self.assertIn("ERROR: cannot read", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


class NumericOptionValidationTests(TempDirCase):
    """nan, infinity and absurd values must be rejected up front by every script, never reach an API call or the ledger."""

    BAD = ("nan", "inf", "1e999", "-1", "0", "1e30")

    def test_triage_scan_limit(self):
        (self.tmp / "f.bin").write_bytes(b"\0" * 64)
        for value in self.BAD:
            r = py(SCRIPTS / "triage.py", self.tmp / "f.bin", "--scan-mib", value)
            self.assertIn("--scan-mib must be a number greater than 0", r.stderr, value)
            self.assertNotIn("Traceback", r.stderr, value)

    def test_verify_run_timeout(self):
        (self.tmp / "ok.py").write_text("print(1)\n")
        (self.tmp / "in").mkdir()
        (self.tmp / "in" / "a").write_text("1")
        for value in self.BAD:
            r = py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / "ok.py"), "--rewrite", command_for(self.tmp / "ok.py"),
                   "--inputs", self.tmp / "in", "--timeout", value)
            self.assertIn("RESULT: SETUP_ERROR", r.stdout, value)
            self.assertNotIn("Traceback", r.stderr, value)

    def test_the_ledger_never_stores_non_finite_seconds(self):
        for value in ("nan", "inf", "-1"):
            r = py(SCRIPTS / "ledger.py", "add", self.tmp / "l.csv", "--address", "0x1", "--name", "f", "--status", "matched", "--seconds", value)
            self.assertEqual(r.returncode, 2, value)
            self.assertFalse((self.tmp / "l.csv").exists(), value)
        (self.tmp / "bad.csv").write_text("address,name,status,oracle,attempts,seconds,notes\n0x1,f,matched,m,1,nan,\n")
        r = py(SCRIPTS / "ledger.py", "summary", self.tmp / "bad.csv")
        self.assertIn("RESULT: LEDGER_ERROR", r.stdout)
        self.assertIn("must be a finite number", r.stdout)

    def test_the_scorer_rejects_non_finite_ledger_values(self):
        (self.tmp / "t.json").write_text(json.dumps({"file": "x", "kind": "native", "sha256": "0" * 64,
                                                      "findings": {"secret_like": [], "urls": [], "ips": [], "build_paths": []}}))
        (self.tmp / "bad.csv").write_text("address,name,status,oracle,attempts,seconds,notes\n0x1,f,matched,m,1,inf,\n")
        r = py(ASSESS / "score_exposure.py", "--triage", self.tmp / "t.json", "--ledger", self.tmp / "bad.csv")
        self.assertIn("is not a number", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_ghidra_wrapper_rejects_nonsense_options(self):
        (self.tmp / "b.bin").write_bytes(b"x")
        r = py(SCRIPTS / "ghidra_export.py", self.tmp / "b.bin", self.tmp / "out", "--timeout", "0")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


@unittest.skipUnless(HAVE_GCC and IS_LINUX, "needs gcc and GNU objdump on Linux")
class VerifyMatchDataAndAsmTests(TempDirCase):
    """Third review: constants and strings live outside the instruction stream; the asm guard must know every spelling."""

    def build_target(self, source):
        (self.tmp / "t.c").write_text(source)
        subprocess.run(["gcc", "-O2", "-c", str(self.tmp / "t.c"), "-o", str(self.tmp / "t.o")], check=True)

    def match(self, source, *extra):
        (self.tmp / "c.c").write_text(source)
        return py(SCRIPTS / "verify_match.py", "--target", self.tmp / "t.o", "--candidate", self.tmp / "c.c", *extra)

    def test_a_different_float_constant_is_not_a_match(self):
        self.build_target("float f(float x) { return x * 0.2f; }\n")
        r = self.match("float f(float x) { return x * 0.3f; }\n")
        self.assertIn("RESULT: NOT_MATCH", r.stdout, r.stdout)
        self.assertIn("the instructions match but the data differs", r.stdout)
        self.assertIn("DATA .rodata", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_a_different_string_literal_is_not_a_match(self):
        self.build_target('#include <stdio.h>\nint f(void) { return puts("hello"); }\n')
        r = self.match('#include <stdio.h>\nint f(void) { return puts("WORLD"); }\n')
        self.assertIn("RESULT: NOT_MATCH", r.stdout, r.stdout)
        self.assertIn("DATA .rodata", r.stdout)

    def test_identical_constants_still_match_and_the_line_says_what_was_compared(self):
        self.build_target("float f(float x) { return x * 0.2f; }\n")
        r = self.match("float f(float x) { return x * 0.2f; }\n")
        self.assertIn("RESULT: MATCH (100%", r.stdout, r.stdout)
        self.assertIn("data sections identical", r.stdout)

    def test_func_mode_says_data_was_not_compared_and_data_on_compares_it(self):
        self.build_target("float f(float x) { return x * 0.2f; }\n")
        r = self.match("float f(float x) { return x * 0.3f; }\n", "--func", "f")
        self.assertIn("instructions only: data sections not compared with --func", r.stdout)
        r = self.match("float f(float x) { return x * 0.3f; }\n", "--func", "f", "--data", "on")
        self.assertIn("RESULT: NOT_MATCH", r.stdout)

    def test_every_inline_asm_spelling_is_rejected(self):
        self.build_target("int f(int x){ return x + 1; }\n")
        body = '("lea 1(%q1), %0":"=r"(r):"r"(x))'
        for spelling in (f"asm{body}", f"asm volatile{body}", f"__asm__ volatile{body}", f"__asm__ __volatile__{body}",
                         f"asm __volatile__{body}", f"asm inline{body}", f"asm volatile goto{body}", f'__asm mov eax, 1'):
            r = self.match(f"int f(int x){{ int r; {spelling}; return r; }}\n")
            self.assertIn("RESULT: REJECTED", r.stdout, (spelling, r.stdout))
            self.assertEqual(r.returncode, 2, spelling)

    def test_asm_hidden_behind_a_macro_is_rejected(self):
        self.build_target("int f(int x){ return x + 1; }\n")
        r = self.match('#define A __asm__\nint f(int x){ int r; A("lea 1(%q1), %0":"=r"(r):"r"(x)); return r; }\n')
        self.assertIn("RESULT: REJECTED", r.stdout, r.stdout)

    def test_words_that_only_look_like_asm_are_not_rejected(self):
        self.build_target("int asm_helper(int a){return a;}\nint f(int x){ return x + 1; }\n")
        r = self.match('/* we avoid asm (for now) */\nint asm_helper(int a){return a;}\n'
                       'int f(int x){ const char *s = "asm (volatile)"; (void)s; return x + 1; }\n')
        self.assertNotIn("REJECTED", r.stdout, r.stdout)

    def test_system_headers_that_use_asm_internally_are_not_rejected(self):
        self.build_target('#include <stdio.h>\nint f(void) { return puts("hello"); }\n')
        r = self.match('#include <stdio.h>\nint f(void) { return puts("hello"); }\n')
        self.assertIn("RESULT: MATCH", r.stdout, r.stdout)


class TriageSecretsAndHostileInputTests(TempDirCase):
    """Third review: webhook secrets live in the URL path, JSON quotes the credential name, headers can lie about sizes."""

    def run_triage(self, data, *extra):
        (self.tmp / "f.bin").write_bytes(data)
        r = py(SCRIPTS / "triage.py", self.tmp / "f.bin", "--json", self.tmp / "o.json", *extra)
        return r, (json.loads((self.tmp / "o.json").read_text()) if (self.tmp / "o.json").exists() else None)

    def test_webhook_urls_are_redacted_everywhere(self):
        secrets = ["T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "123456789012345678/abcDEFghiJKLmnoPQRstuVWXyz0123456789",
                   "123456789:AAEhBP0av28QKSPLEtgHJ4xyzABCDEFGHIJ", "ABCdef123456abcdef123456abcdef12"]
        data = (b"\0" * 32 + b"https://hooks.slack.com/services/" + secrets[0].encode() + b"\0"
                + b"https://discord.com/api/webhooks/" + secrets[1].encode() + b"\0"
                + b"https://api.telegram.org/bot" + secrets[2].encode() + b"/sendMessage\0"
                + b"https://contoso.webhook.office.com/webhookb2/" + secrets[3].encode() + b"\0"
                + b"https://example.com/docs/page\0")
        r, result = self.run_triage(data)
        everything = r.stdout + json.dumps(result)
        for secret in secrets:
            self.assertNotIn(secret.split("/")[-1], everything, secret)
        self.assertIn("https://api.telegram.org/bot***/sendMessage", result["findings"]["urls"])
        self.assertIn("https://example.com/docs/page", result["findings"]["urls"])             # ordinary URLs are untouched

    def test_json_style_credentials_are_flagged_and_never_printed(self):
        data = b'\0{"password":"hunter2hunter2"}\0{"api_key": "sk-live-abcdefghijklmnop"}\0password=hunter2hunter3\0'
        r, result = self.run_triage(data)
        kinds = [f["type"] for f in result["findings"]["secret_like"]]
        self.assertEqual(kinds.count("credential-assignment"), 3, result["findings"]["secret_like"])
        for value in ("hunter2hunter2", "hunter2hunter3", "sk-live-abcdefghijklmnop"):
            self.assertNotIn(value, r.stdout + json.dumps(result))

    def test_ordinary_text_with_the_word_password_is_not_flagged(self):
        r, result = self.run_triage(b"\0Enter your password to continue\0the token list is empty\0")
        self.assertEqual(result["findings"]["secret_like"], [])

    def test_a_hostile_elf_header_cannot_exhaust_memory(self):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4], header[5] = 2, 1
        struct.pack_into("<H", header, 16, 2)
        struct.pack_into("<H", header, 18, 0x3E)
        struct.pack_into("<Q", header, 0x28, 64)
        struct.pack_into("<HHH", header, 0x3A, 64, 2, 1)
        shstr = bytearray(64)
        struct.pack_into("<II", shstr, 0, 1, 3)
        struct.pack_into("<QQQ", shstr, 0x10, 0, 0, 70 * 10 ** 12)                  # a 70 TB section-name table in a 192-byte file
        r, result = self.run_triage(bytes(header) + bytes(64) + bytes(shstr))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)
        self.assertTrue(result["malformed"])

    def test_text_with_crlf_at_bytes_2_and_3_is_not_python_bytecode(self):
        r, result = self.run_triage(b"OK\r\nthis is just a text file\r\nwith several lines in it\r\n")
        self.assertNotIn("bytecode", r.stdout)

    def test_a_real_pyc_is_still_recognised(self):
        import py_compile
        (self.tmp / "m.py").write_text("def f(x):\n    return x + 1\n")
        py_compile.compile(str(self.tmp / "m.py"), cfile=str(self.tmp / "m.pyc"), doraise=True)
        r = py(SCRIPTS / "triage.py", self.tmp / "m.pyc")
        self.assertIn("Python bytecode", r.stdout, r.stdout)

    def test_the_wasm_route_names_tools_that_every_wabt_release_ships(self):
        r, result = self.run_triage(b"\0asm\x01\0\0\0")
        self.assertIn("wasm2wat", r.stdout)
        self.assertIn("only if your wabt build has it", r.stdout)


class RankUndecompiledTests(TempDirCase):
    HEADER = "address,name,named,size_bytes,instructions,branches,calls,jumps,is_thunk,decompile_status,c_lines,gotos,autovars,c_file\n"

    def rank(self, rows, *extra):
        (self.tmp / "f.csv").write_text(self.HEADER + rows)
        return py(SCRIPTS / "rank_functions.py", self.tmp / "f.csv", "--out", self.tmp / "w.csv", *extra)

    FAILED = ('00100100,"FUN_00100100",false,300,90,9,2,0,false,timeout,0,0,0,\n'
              '00100200,"FUN_00100200",false,300,80,8,2,0,false,failed,0,0,0,\n')
    OK = '00100300,"FUN_00100300",false,30,10,1,0,0,false,ok,10,0,2,x.c\n'

    def test_only_undecompiled_functions_left_is_not_reported_as_finished(self):
        r = self.rank(self.FAILED)
        self.assertIn("RESULT: UNDECOMPILED_LEFT", r.stdout)
        self.assertIn("failed=1, timeout=1", r.stdout)
        self.assertIn("--decompile-timeout", r.stdout)
        self.assertNotIn("NOTHING_LEFT", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_include_undecompiled_ranks_them_for_work_from_the_disassembly(self):
        r = self.rank(self.FAILED, "--include-undecompiled")
        self.assertTrue(r.stdout.startswith("NEXT: 00100200"), r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_missing_functions_are_mentioned_next_to_the_ranked_ones(self):
        r = self.rank(self.FAILED + self.OK)
        self.assertTrue(r.stdout.startswith("NEXT: 00100300"), r.stdout)
        self.assertIn("NOTE: 2 more function(s) have no decompiled C", r.stdout)

    def test_a_finished_list_is_still_nothing_left(self):
        r = self.rank("")
        self.assertIn("RESULT: NOTHING_LEFT", r.stdout)
        self.assertEqual(r.returncode, 0)


@unittest.skipUnless(HAVE_UNICORN, "needs: pip install unicorn")
class VerifyEmulatedBufferLengthTests(TempDirCase):
    """Third review: a buffer plus its length must be generated together, or a correct candidate looks broken."""

    # x86-32 cdecl: unsigned sum_bytes(const unsigned char *p, int n) { unsigned s = 0; for (; n > 0; n--) s += *p++; return s; }
    SUM_BYTES = bytes.fromhex("8B542404" "8B4C2408" "31C0" "85C9" "7E09" "0FB61A" "01D8" "42" "49" "75F7" "C3")

    def setUp(self):
        super().setUp()
        (self.tmp / "s.exe").write_bytes(make_pe(self.SUM_BYTES, 32))
        (self.tmp / "good.py").write_text("def f(buf, n):\n    return sum(buf[:n])\n")
        (self.tmp / "bad.py").write_text("def f(buf, n):\n    return sum(buf[:max(n - 1, 0)])\n")

    def oracle(self, candidate, *extra, args="ptr,len32"):
        return py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / "s.exe", "--address", "0x401000", "--args", args, "--ret", "u32",
                  "--candidate-py", f"{self.tmp / candidate}:f", *extra)

    def test_a_correct_buffer_plus_length_candidate_passes_with_len32(self):
        r = self.oracle("good.py")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout + r.stderr)

    def test_a_wrong_candidate_is_still_caught(self):
        r = self.oracle("bad.py")
        self.assertIn("RESULT: DIFFERS", r.stdout, r.stdout)

    def test_without_len32_the_failure_names_the_real_cause(self):
        r = self.oracle("good.py", args="ptr,i32")
        self.assertIn("RESULT: EMULATION_ERROR", r.stdout, r.stdout)
        self.assertIn("len32", r.stdout)
        self.assertNotIn("Check --abi", r.stdout)

    def test_zero_length_and_full_length_buffers_are_among_the_cases_and_always_consistent(self):
        log = self.tmp / "seen.txt"
        (self.tmp / "log.py").write_text(f"def f(buf, n):\n    open({str(log)!r}, 'a').write(f'{{len(buf)}} {{n}}\\n')\n    return sum(buf[:n])\n")
        r = self.oracle("log.py", "--random", "0", "--ptr-len", "8")
        self.assertIn("RESULT: EQUIVALENT_ON", r.stdout, r.stdout)
        seen = {tuple(map(int, line.split())) for line in log.read_text().splitlines()}
        self.assertIn((0, 0), seen)                                   # an empty buffer
        self.assertIn((8, 8), seen)                                   # a full buffer
        self.assertTrue(all(length == n for length, n in seen), seen)  # the length argument always equals the buffer size

    def test_len_types_must_follow_a_pointer(self):
        for args in ("len32", "i32,len32", "ptr,len32,len32", "len64,ptr"):
            r = self.oracle("good.py", args=args)
            self.assertIn("must come right after the ptr argument", r.stdout, args)
            self.assertEqual(r.returncode, 2)

    def test_a_len_type_is_not_a_return_type(self):
        r = py(SCRIPTS / "verify_emulated.py", "--binary", self.tmp / "s.exe", "--address", "0x401000", "--args", "ptr,len32", "--ret", "len32",
               "--candidate-py", f"{self.tmp / 'good.py'}:f")
        self.assertIn("unknown return type", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    def test_cases_files_give_the_length_as_a_plain_integer(self):
        (self.tmp / "c.jsonl").write_text('["0102030405", 5]\n["0102030405", 2]\n["", 0]\n')
        r = self.oracle("good.py", "--no-boundary", "--random", "0", "--cases", self.tmp / "c.jsonl")
        self.assertIn("RESULT: EQUIVALENT_ON 3 cases", r.stdout, r.stdout)


class TraceKeyHandlingTests(TempDirCase):
    def compare(self, a, b, *extra):
        for name, rows in (("a.jsonl", a), ("b.jsonl", b)):
            (self.tmp / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return py(SCRIPTS / "verify_trace.py", "--original", self.tmp / "a.jsonl", "--rewrite", self.tmp / "b.jsonl", *extra)

    OPTIONAL = [{"t": 0, "x": 1}, {"t": 1, "x": 2, "event": "hit"}, {"t": 2, "x": 3}]

    def test_an_optional_key_missing_from_both_traces_on_a_tick_is_not_a_difference(self):
        r = self.compare(self.OPTIONAL, self.OPTIONAL)
        self.assertIn("RESULT: TRACE_MATCH 3 ticks, 2 keys", r.stdout, r.stdout)
        self.assertEqual(r.returncode, 0)

    def test_a_real_difference_in_an_optional_key_is_still_caught(self):
        other = [dict(row) for row in self.OPTIONAL]
        other[1]["event"] = "miss"
        r = self.compare(self.OPTIONAL, other)
        self.assertIn("RESULT: TRACE_DIVERGES at tick 1 (event:", r.stdout)

    def test_a_key_logged_on_a_tick_by_one_side_only_is_a_difference(self):
        other = [dict(row) for row in self.OPTIONAL]
        del other[1]["event"]
        r = self.compare(self.OPTIONAL, other, "--keys", "x,event")
        self.assertIn("RESULT: TRACE_DIVERGES", r.stdout)

    def test_a_key_that_only_one_trace_ever_logs_is_reported_not_silently_skipped(self):
        a = [{"t": 0, "x": 1, "hp": 50}, {"t": 1, "x": 2, "hp": 49}]
        b = [{"t": 0, "x": 1}, {"t": 1, "x": 2}]
        r = self.compare(a, b)
        self.assertIn("RESULT: TRACE_MATCH", r.stdout)
        self.assertIn("WARNING: not compared", r.stdout)
        self.assertIn("only in the original: hp", r.stdout)

    def test_strict_fails_when_the_traces_log_different_keys(self):
        a = [{"t": 0, "x": 1, "hp": 50}]
        b = [{"t": 0, "x": 1}]
        r = self.compare(a, b, "--strict")
        self.assertIn("RESULT: TRACE_KEYS_DIFFER", r.stdout)
        self.assertEqual(r.returncode, 1)

    def test_naming_the_key_with_keys_makes_it_a_requirement(self):
        a = [{"t": 0, "x": 1, "hp": 50}]
        b = [{"t": 0, "x": 1}]
        self.assertIn("TRACE_DIVERGES", self.compare(a, b, "--keys", "x,hp").stdout)


class VerifyRunHiddenFilesTests(TempDirCase):
    def test_hidden_files_are_not_test_cases(self):
        (self.tmp / "ok.py").write_text("print(1)\n")
        (self.tmp / "in").mkdir()
        (self.tmp / "in" / "real").write_text("1")
        (self.tmp / "in" / ".gitkeep").write_text("")
        (self.tmp / "in" / ".DS_Store").write_text("")
        r = py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / "ok.py"), "--rewrite", command_for(self.tmp / "ok.py"),
               "--inputs", self.tmp / "in", "--min-inputs", "3", "--strict")
        self.assertIn("RESULT: TOO_FEW_INPUTS 1", r.stdout, r.stdout)
        self.assertIn("ignored 2 hidden file(s)", r.stderr)

    def test_a_folder_with_only_hidden_files_is_a_setup_error(self):
        (self.tmp / "ok.py").write_text("print(1)\n")
        (self.tmp / "in").mkdir()
        (self.tmp / "in" / ".gitkeep").write_text("")
        r = py(SCRIPTS / "verify_run.py", "--original", command_for(self.tmp / "ok.py"), "--rewrite", command_for(self.tmp / "ok.py"),
               "--inputs", self.tmp / "in")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


class RepoHygieneTests(unittest.TestCase):
    TEXT = {".py", ".md", ".json", ".yml", ".yaml", ".c", ".java", ".csv", ".txt", ".toml", ""}
    KEY_SHAPES = [re.compile(p) for p in (r"AKIA[0-9A-Z]{16}", r"ghp_[0-9A-Za-z]{36}", r"sk_live_[0-9a-zA-Z]{20}", r"xox[baprs]-[0-9A-Za-z-]{10,}",
                                          r"-----BEGIN [A-Z ]*PRIVATE KEY-----")]

    def files(self):
        for path in ROOT.rglob("*"):
            if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts and path.suffix in self.TEXT:
                yield path

    def test_no_key_shaped_strings_are_committed(self):
        for path in self.files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for rx in self.KEY_SHAPES:
                self.assertIsNone(rx.search(text), f"{path.relative_to(ROOT)} contains a key-shaped string")

    def test_every_skill_md_is_short_and_has_matching_name(self):
        for skill in (ROOT / "skills").iterdir():
            text = (skill / "SKILL.md").read_text(encoding="utf-8")
            self.assertLess(text.count("\n"), 500)
            self.assertIn(f"name: {skill.name}\n", text)

    def test_eval_suite_follows_the_floor_rules(self):
        cases = [p for p in (ROOT / "evals").iterdir() if p.is_dir()]
        self.assertGreaterEqual(len(cases), 3)
        should_not_fire = 0
        for case in cases:
            self.assertTrue((case / "prompt.md").is_file(), case.name)
            graders = list((case / "graders").glob("*.md"))
            self.assertTrue(any("type: llm" in g.read_text(encoding="utf-8") for g in graders), f"{case.name} needs an outcome grader")
            should_not_fire += any("max: 0" in g.read_text(encoding="utf-8") for g in graders)
        self.assertGreaterEqual(should_not_fire, 1)


GHIDRA_READY = bool(os.environ.get("GHIDRA_HOME") and shutil.which("javac") and HAVE_GCC)


@unittest.skipUnless(GHIDRA_READY, "set GHIDRA_HOME and install a JDK with javac to run the Ghidra test")
class GhidraExportTests(TempDirCase):
    def test_export_produces_inventory_and_decompiled_c(self):
        (self.tmp / "p.c").write_text("#include <stdio.h>\n__attribute__((noinline)) int twice(int x){return x*2+1;}\n"
                                      "int main(int c,char**v){printf(\"%d\\n\",twice(c));return 0;}\n")
        subprocess.run(["gcc", "-O1", "-o", str(self.tmp / "p"), str(self.tmp / "p.c")], check=True)
        r = py(SCRIPTS / "ghidra_export.py", self.tmp / "p", self.tmp / "out")
        self.assertIn("RESULT: OK", r.stdout, r.stdout)
        with open(self.tmp / "out" / "functions.csv", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertTrue(any(row["name"] == "twice" and row["decompile_status"] == "ok" for row in rows))
        recorded = dict(line.split("=", 1) for line in (self.tmp / "out" / "summary.txt").read_text().splitlines() if "=" in line)
        self.assertEqual(recorded["sha256"], hashlib.sha256((self.tmp / "p").read_bytes()).hexdigest())

    def test_a_very_long_function_name_does_not_abort_the_export(self):
        name = "very_long_function_name_" + "x" * 300
        (self.tmp / "p.c").write_text(f"#include <stdio.h>\nint {name}(int a){{return a*3+1;}}\nint helper(int a){{return a-1;}}\n"
                                      f"int main(int c,char**v){{printf(\"%d\\n\",{name}(c)+helper(c));return 0;}}\n")
        subprocess.run(["gcc", "-O0", "-o", str(self.tmp / "p"), str(self.tmp / "p.c")], check=True)
        r = py(SCRIPTS / "ghidra_export.py", self.tmp / "p", self.tmp / "out")
        self.assertIn("RESULT: OK", r.stdout, r.stdout)
        files = [p.name for p in (self.tmp / "out" / "decompiled").iterdir()]
        self.assertTrue(any("very_long_function_name_" in f for f in files))
        self.assertLessEqual(max(len(f) for f in files), 255)
        with open(self.tmp / "out" / "functions.csv", newline="", encoding="utf-8") as f:
            rows = {row["name"]: row for row in csv.DictReader(f)}
        self.assertEqual(rows[name]["decompile_status"], "ok")
        self.assertIn("helper", rows)                               # the functions after the long one were exported too

    def test_the_decompile_limit_reaches_ghidra(self):
        (self.tmp / "p.c").write_text("int twice(int x){return x*2+1;}\nint main(int c,char**v){return twice(c);}\n")
        subprocess.run(["gcc", "-O1", "-o", str(self.tmp / "p"), str(self.tmp / "p.c")], check=True)
        for given, expected in ((None, "30"), ("7", "7")):
            extra = ["--decompile-timeout", given] if given else []
            r = py(SCRIPTS / "ghidra_export.py", self.tmp / "p", self.tmp / "out", *extra)
            self.assertIn("RESULT: OK", r.stdout, r.stdout)
            self.assertIn(f"decompile_timeout_seconds={expected}", (self.tmp / "out" / "summary.txt").read_text())

    def test_missing_binary_is_a_setup_error(self):
        r = py(SCRIPTS / "ghidra_export.py", self.tmp / "nope", self.tmp / "out")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

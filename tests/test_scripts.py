"""Tests for the decompile-and-verify scripts. Run: python3 -m unittest discover -s tests -v"""
import csv
import importlib.util
import json
import os
import re
import shutil
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

    def test_missing_binary_is_a_setup_error(self):
        r = py(SCRIPTS / "ghidra_export.py", self.tmp / "nope", self.tmp / "out")
        self.assertIn("RESULT: SETUP_ERROR", r.stdout)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

# Security policy

## Reporting a vulnerability

If you find a security problem in the scripts in this repository, for example a crafted binary, archive or ledger file that makes a script execute code, write outside its output folder, or print a secret it should have redacted, please report it privately with the "Report a vulnerability" button on this repository's Security tab. Please do not open a public issue for it.

Include the version (see `CHANGELOG.md`), the command you ran, and a minimal sample file if you can. I aim to acknowledge reports within about a week.

## What the scripts execute

- `triage.py` only reads files. It never executes them.
- `ghidra_export.py` runs Ghidra headless with the bundled `ExportFunctions.java`. Analysis is static; the analysed binary is not run.
- `verify_run.py` **runs the programs you point it at** (`--original` and `--rewrite`). If the original is untrusted, run it inside a disposable VM or container with no network.
- `verify_match.py` runs the compiler you give it (`--cc`) on a candidate source file.
- `ledger.py`, `rank_functions.py`, `score_exposure.py` and `render_report.py` read and write CSV and JSON files only.

## Secrets in output

`triage.py` redacts secret-like values and URL credentials in everything it prints and writes, and `render_report.py` scrubs ledger notes again before writing a report. Redaction is pattern-based, so treat any report as sensitive and review it before sharing.

# Sample: a toy licence check

`sample.c` is a four-function licence check with an activation endpoint and a demo credential string (not a real key). It is built twice, with and without symbols. The walkthrough recovers it from the stripped build and scores both.

## Try the scoring and the report without installing anything

The measured artifacts from the author's run are in `artifacts/` (triage output, Ghidra's function inventory, the recovery ledger, the engagement sheet). Score them and render the report yourself:

```bash
mkdir -p work
python3 ../../skills/decompile-assess/scripts/score_exposure.py \
  --functions artifacts/functions.csv --triage artifacts/triage.json --ledger artifacts/ledger.csv --json work/exposure.json

python3 ../../skills/decompile-assess/scripts/render_report.py \
  --triage artifacts/triage.json --exposure work/exposure.json --ledger artifacts/ledger.csv \
  --engagement artifacts/engagement.md --client "Example Corp (toy sample)" --out work/report.md
```

`artifacts/report.md` is the result of that run. File hashes in `triage.json` come from the author's build and will differ if you rebuild.

## Run the whole pipeline

Needs gcc, Python 3.9+, [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a full JDK 21+ with `javac` (Windows: use WSL for gcc).

```bash
mkdir -p work
bash build.sh
S=../../skills/decompile-and-verify/scripts
python3 $S/triage.py sample_stripped --json work/triage.json
python3 $S/ghidra_export.py sample_stripped work/export     # set GHIDRA_HOME first
python3 $S/rank_functions.py work/export/functions.csv      # prints NEXT:
ls work/export/decompiled/                                  # read the cheapest functions first

# rewrite.c is the reconstruction written from that decompiled output. Verify it:
gcc -O2 -o rewrite rewrite.c
python3 make_inputs.py inputs                               # boundary lengths, valid keys, random keys
python3 $S/verify_run.py --original ./sample_stripped --rewrite ./rewrite --inputs inputs --mode arg-text
```

### Check one function against the original machine code

`candidate_checksum.c` is the checksum function as recovered. `verify_emulated.py` runs the original function (at Ghidra address 0x101250 in the stripped build) under emulation and compares:

```bash
pip install unicorn
gcc -O2 -shared -fPIC -o cand_checksum.so candidate_checksum.c
python3 $S/verify_emulated.py --binary sample_stripped --address 0x101250 --image-base 0x100000 \
  --args ptr --ret u32 --candidate-lib cand_checksum.so --symbol fnv1a_16
```

Function addresses and counts depend on your compiler version; `artifacts/ledger.csv` holds the author's addresses.

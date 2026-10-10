#!/usr/bin/env python3
"""Generate differential-test inputs for the sample: boundary lengths plus valid and random license keys."""
import os, random, sys

def fnv_ok(key):
    h = 2166136261
    for b in key.encode():
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return (h & 0x7FFFFFFF) % 97 == 42

out = sys.argv[1] if len(sys.argv) > 1 else "inputs"
os.makedirs(out, exist_ok=True)
rnd = random.Random(7)
alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
cases = ["", "a", "A" * 15, "A" * 16, "A" * 17, "0" * 16, "~" * 16]
valid = []
while len(valid) < 8:                                   # keys that pass the check, so the "ok" path is exercised
    k = "".join(rnd.choice(alphabet) for _ in range(16))
    if fnv_ok(k):
        valid.append(k)
cases += valid + ["".join(rnd.choice(alphabet) for _ in range(16)) for _ in range(25)]
for i, text in enumerate(cases):
    with open(os.path.join(out, f"case_{i:03d}.txt"), "w") as f:
        f.write(text)
print(f"{len(cases)} inputs in {out} ({len(valid)} valid keys, boundary lengths 0/1/15/16/17)")

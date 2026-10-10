"""Compare two Python modules function by function across boundary inputs.

Usage: python3 diff_funcs.py demo.py demo_pycdc.py
Prints a verdict per function in the same vocabulary as the other oracles (EQUIVALENT_ON / DIFFERS).
"""
import importlib.util
import itertools
import sys


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def keys():
    base = "ABCDEFGHJKLMNPQR"                         # 16 characters
    out = ["", "a", base, base[:15], base + "S"]
    for length in (15, 16, 17):                       # strings of each length whose ord-sum % 97 == 42
        for n in range(1, 400):
            candidate = ("A" * (length - 1)) + chr(32 + (n % 90))
            if sum(map(ord, candidate)) % 97 == 42:
                out.append(candidate)
                break
    return out


def report(name, cases, original, rewrite, show):
    bad = [(c, original(*c), rewrite(*c)) for c in cases if original(*c) != rewrite(*c)]
    print(f"{name}: DIFFERS on {len(bad)} of {len(cases)} inputs" if bad else f"{name}: EQUIVALENT_ON {len(cases)} inputs")
    for case, a, b in bad[:3]:
        print(f"   {name}{case}: original={a!r} rewrite={b!r}")
    return bool(bad)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    orig, cand = load(sys.argv[1], "orig"), load(sys.argv[2], "cand")
    prices, tiers = [0.0, 1.0, 99.99, 100.0, 250.5], [0, 1, 2, 3, 4]
    failed = report("apply_discount", list(itertools.product(prices, tiers)), orig.apply_discount, cand.apply_discount, True)
    failed |= report("validate", [(k,) for k in keys()], orig.validate, cand.validate, True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

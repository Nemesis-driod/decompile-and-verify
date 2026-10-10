# Names, types and libraries

## Contents
- Evidence ladder for names
- Constants that identify algorithms
- Types and structs
- Libraries

## Evidence ladder for names

Keep `FUN_<addr>` or `sub_<addr>` until you reach a rung, strongest first:

1. A symbol source: symbols, PDB or DWARF, a ProGuard mapping, source maps, an unstripped sibling build.
2. A string the function prints or compares (error text, format strings, file names).
3. An imported API it wraps, or a known library signature.
4. A well-known constant or structure (table below).
5. Consistent use across callers: what they pass in and what they do with the result.

Mark inferred names, for example `/* inferred: wraps CreateFileW */`. A confident wrong name misleads every later reader, human or agent.

## Constants that identify algorithms

| Constant | Means |
|---|---|
| 0x811C9DC5 and 0x01000193 | FNV-1a 32-bit (offset basis, prime) |
| 0xCBF29CE484222325 and 0x100000001B3 | FNV-1a 64-bit |
| 0xEDB88320 | CRC-32 (reflected polynomial) |
| 65521 (0xFFF1) | Adler-32 modulus |
| 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 | MD5 initial state; SHA-1 adds 0xC3D2E1F0 |
| 0x6A09E667 / 0x428A2F98 | SHA-256 initial value / first round constant |
| 0x63, 0x7C, 0x77, 0x7B | start of the AES S-box |
| the string `expand 32-byte k` | ChaCha20 / Salsa20 |
| 0x9E3779B9 | TEA, XTEA, Fibonacci hashing |
| 0xCC9E2D51 and 0x1B873593 | MurmurHash3 |
| 0x5BD1E995 | MurmurHash2 |
| 0x6C078965 and 0x9908B0DF | Mersenne Twister (MT19937) |
| 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1 | xxHash32 primes |
| `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` | Base64 alphabet |
| bytes 0x78 0x9C (also 0x78 0x01, 0x78 0xDA) | zlib stream header |

The sample build in `examples/sample` shows the first row at work: stripped of every name, the checksum function still announces FNV-1a through two constants.

## Types and structs

- Infer layouts from offsets across at least three call sites, not one. Note padding and alignment for the original ABI.
- Prove a layout by compiling it: `_Static_assert(offsetof(struct S, f) == 0x18, "f");` and `_Static_assert(sizeof(struct S) == 0x40, "size");`. Never trust mental arithmetic for offsets.
- Apply the struct in Ghidra and re-decompile; correct types clarify several functions at once.
- Recover enums from switch tables and comparison chains, and flag sets from `& 0x...` masks.

## Libraries

Statically linked libraries (zlib, libpng, SDL, libc, OpenSSL, SQLite) should be identified and replaced with the upstream source at the right version, not decompiled.

- Version strings: `inflate 1.`, `libpng version`, `OpenSSL 3.`, `SQLite format 3`, `libcurl/`, `Lua 5.`.
- Ghidra Function ID databases, or FLIRT signatures in IDA.

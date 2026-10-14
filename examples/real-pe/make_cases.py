"""Write header_cases.jsonl: 128-byte buffers that exercise each branch of the header check."""
import json
import struct


def header(mz=b"MZ", e_lfanew=0x40, sig=b"PE\0\0", magic=0x10B, size=128):
    b = bytearray(size)
    b[0:2] = mz
    struct.pack_into("<i", b, 0x3C, e_lfanew)
    b[e_lfanew:e_lfanew + 4] = sig
    struct.pack_into("<H", b, e_lfanew + 0x18, magic)
    return b.hex()


rows = [header(), header(magic=0x20B), header(magic=0x10A), header(sig=b"PX\0\0"), header(mz=b"ZM"),
        header(e_lfanew=0x20), header(e_lfanew=0x30), header(e_lfanew=0x60), header(magic=0x110B)]
with open("header_cases.jsonl", "w") as f:
    f.write("\n".join(json.dumps([r]) for r in rows) + "\n")
print(f"wrote {len(rows)} cases to header_cases.jsonl")

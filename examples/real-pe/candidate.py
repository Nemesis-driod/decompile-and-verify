"""Candidate for __ValidateImageBase, written from Ghidra's decompiled C of the real function."""


def validate_image_base(buf):
    if buf[0:2] != b"MZ":
        return 0
    e = int.from_bytes(buf[0x3C:0x40], "little", signed=True)
    if buf[e:e + 4] != b"PE\0\0":
        return 0
    return 1 if int.from_bytes(buf[e + 0x18:e + 0x1A], "little") == 0x10B else 0


def wrong_magic(buf):
    """Negative control: checks for PE32+ instead of PE32. The oracle must reject it."""
    if buf[0:2] != b"MZ":
        return 0
    e = int.from_bytes(buf[0x3C:0x40], "little", signed=True)
    if buf[e:e + 4] != b"PE\0\0":
        return 0
    return 1 if int.from_bytes(buf[e + 0x18:e + 0x1A], "little") == 0x20B else 0

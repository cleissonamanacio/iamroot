#!/usr/bin/env python3
from __future__ import annotations

import os
import sys

def info(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr, flush=True)

def good(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr, flush=True)

def warn(msg: str) -> None:
    print(f"[-] {msg}", file=sys.stderr, flush=True)

def die(msg: str, code: int = 1) -> None:
    warn(msg)
    sys.exit(code)

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

def linux_only() -> None:
    if not sys.platform.startswith("linux"):
        die("this helper only runs on Linux x86-64")

def work_dir() -> str:
    return os.environ.get("IAMROOT_WORK_DIR") or os.getcwd()

SYS_write = 1
SYS_open = 2
SYS_close = 3
SYS_splice = 275
SYS_vmsplice = 278
SYS_fcntl = 72
SYS_memfd_create = 319

F_GETPIPE_SZ = 1032
O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
PIPE_BUF = 4096

SPLICE_F_MOVE = 1
SPLICE_F_MORE = 4
SPLICE_F_GIFT = 8

def load_libc():
    try:
        import ctypes

        return ctypes.CDLL("libc.so.6", use_errno=True)
    except OSError:
        try:
            import ctypes

            return ctypes.CDLL("libc.dylib", use_errno=True)
        except OSError:
            return None

def parse_int(s: str, default: int = 0) -> int:
    try:
        return int(s, 0)
    except (TypeError, ValueError):
        return default

if __name__ == "__main__":

    if "--selftest" in sys.argv:
        info("common.py selftest OK")
        info(f"platform={sys.platform} root={is_root()} work_dir={work_dir()}")
        libc = load_libc()
        good(f"libc loaded: {libc is not None}")
        sys.exit(0)
    die("import this module from other pylib scripts, or run with --selftest")

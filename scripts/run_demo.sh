#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PATH="$HOME/.local/bin:$PATH"

mkdir -p data/audit data/reports

# Load .env if present
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export SANDBOX_URL="${SANDBOX_URL:-http://127.0.0.1:3001}"
export ALLOWLIST="${ALLOWLIST:-localhost,127.0.0.1,juice-shop.local,*.modal.run,*.trycloudflare.com}"

echo "▶ Starting lab sandbox on :3001"
python3 demo/sandbox_app.py &
SANDBOX_PID=$!

cleanup() {
  kill "$SANDBOX_PID" 2>/dev/null || true
  kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

echo "▶ Starting Prism API on :8787"
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8787 &
API_PID=$!

sleep 1
echo "▶ Health: $(curl -s http://127.0.0.1:8787/api/health)"
echo ""
echo "Dashboard: cd dashboard && npm run dev  → http://localhost:3000"
echo "Or start a scan: curl -X POST http://127.0.0.1:8787/api/scans -H 'content-type: application/json' -d '{\"target\":\"http://127.0.0.1:3001\"}'"
echo ""
wait
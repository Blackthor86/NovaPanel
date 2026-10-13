#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT_DIR"

python -m pip install -r requirements.txt

# App-host mode needs a private Xray process. The binary is pinned and hash-verified.
if [ "${NOVAPANEL_DEPLOYMENT_MODE:-auto}" = "paas_ws" ] || {
  [ "${NOVAPANEL_DEPLOYMENT_MODE:-auto}" != "direct" ] &&
  { [ -n "${PORT:-}" ] || [ -n "${SERVER_PORT:-}" ] || [ -n "${RAILWAY_PUBLIC_DOMAIN:-}" ] || [ -n "${RENDER_EXTERNAL_HOSTNAME:-}" ] || [ -n "${KOYEB_PUBLIC_DOMAIN:-}" ]; }
}; then
  if ! command -v xray >/dev/null 2>&1 && [ ! -x "$ROOT_DIR/bin/xray" ]; then
    if ! python tools/bootstrap_xray.py; then
      echo "[NovaPanel] Xray bootstrap failed; dashboard will start, but the VPN engine will remain unavailable."
    fi
  fi
fi

npm --prefix frontend install
npm --prefix frontend run build

exec python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-${SERVER_PORT:-8000}}"

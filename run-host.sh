#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$ROOT_DIR"

python -m pip install -r requirements.txt
npm --prefix frontend install
npm --prefix frontend run build

exec python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"

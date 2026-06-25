#!/usr/bin/env bash
# Start all services locally on one origin (Fuse console :8000). Connectors are
# connected MANUALLY from the dashboard (or "Quick-connect demo"). The token
# monitoring grant inventory is served NATIVELY by Fuse (/api/grants) from a
# seeded local store — no separate service.
set -e
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)"
PY="$(pwd)/.venv/bin/python"; [ -x "$PY" ] || PY="python3"

export FUSE_URL="http://localhost:8000"
export COMPANY_API_URL="http://localhost:8010"
export VENDOR_URL="http://localhost:8020"
# grant-inventory store (seeded automatically by Fuse on startup)
export DATABASE_URL="sqlite:///$(pwd)/fuse_monitor.db"
export SECRET_ENCRYPTION_KEY="${SECRET_ENCRYPTION_KEY:-$("$PY" -c 'import base64;print(base64.urlsafe_b64encode(b"fuse-merged-demo-key-0123456789A").decode())')}"

echo "Company Data API  : http://localhost:8010"
"$PY" -m uvicorn company_api.main:app --host 0.0.0.0 --port 8010 &
echo "Vendor            : http://localhost:8020"
"$PY" -m uvicorn vendor.main:app --host 0.0.0.0 --port 8020 &
echo "Fuse console      : http://localhost:8000  (UI + grant inventory)"
"$PY" -m uvicorn fuse.main:app --host 0.0.0.0 --port 8000 &

echo ""; echo "Open http://localhost:8000 and click 'Quick-connect demo'. Ctrl-C to stop."
trap "kill 0" EXIT
wait

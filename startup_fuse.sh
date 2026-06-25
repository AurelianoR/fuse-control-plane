#!/usr/bin/env bash
# Azure App Service startup command for the FUSE app (dashboard + control plane).
#
# Single worker on purpose. All state (connections, revocations, the signing
# key, the seen-proof cache, SSE subscribers) lives in memory, so more than one
# worker or instance would not share it. Keep this app at one worker and do not
# scale out. `python -m uvicorn` makes sure the app root is on the import path.
python -m uvicorn fuse.main:app --host 0.0.0.0 --port 8000

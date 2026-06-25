#!/usr/bin/env bash
# Azure App Service startup command for the COMPANY DATA API app (resource server).
#
# Single worker on purpose: the seen-proof replay cache is in memory, so a second
# worker would let a replayed proof through on the worker that has not seen it.
# Keep this app at one worker and do not scale out.
python -m uvicorn company_api.main:app --host 0.0.0.0 --port 8000

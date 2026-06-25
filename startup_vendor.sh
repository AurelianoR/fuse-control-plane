#!/usr/bin/env bash
# Azure App Service startup command for the VENDOR app.
#
# The vendor's private key is generated in this process and never leaves it.
# Single worker is fine; the vendor holds keys in memory and registers its
# PUBLIC key with Fuse on startup (FUSE_URL), then signs its own DPoP proofs.
python -m uvicorn vendor.main:app --host 0.0.0.0 --port 8000

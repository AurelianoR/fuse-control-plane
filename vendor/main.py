"""
Vendor service: real third-party vendors, each holding its own private key.

Keys are generated here at startup and NEVER leave this process. Fuse pulls
only the PUBLIC keys via /identity when the user connects the vendor connector.

To get a token, the vendor authenticates to Fuse's token endpoint with
private_key_jwt (a client_assertion signed by its own key) - real asymmetric
client auth - then signs a DPoP proof and calls the company directly.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from common import crypto

FUSE = os.environ.get("FUSE_URL", "http://localhost:8000")
COMPANY = os.environ.get("COMPANY_API_URL", "http://localhost:8010")
TOKEN_AUD = FUSE + "/api/token"

DEFAULT_PROFILES = [
    {"vendor": "PipelineCRM", "platform": "Salesforce", "scope": "contacts:read opportunities:read", "lifetime": 3600},
    {"vendor": "DataDrift", "platform": "Salesforce", "scope": "contacts:read full:export", "lifetime": 86400},
]
try:
    PROFILES = json.loads(os.environ["VENDOR_PROFILES"]) if os.environ.get("VENDOR_PROFILES") else DEFAULT_PROFILES
except Exception:
    PROFILES = DEFAULT_PROFILES

app = FastAPI(title="Vendor")

# Private keys live HERE only, keyed by vendor name.
KEYS = {p["vendor"]: crypto.generate_keypair() for p in PROFILES}


@app.get("/")
def root():
    return {"service": "Vendor", "represents": [p["vendor"] for p in PROFILES],
            "note": "private keys live here and never leave this process"}


@app.get("/identity")
def identity():
    """Fuse pulls public keys here when the vendor connector is connected."""
    return {"vendors": [
        {"vendor": p["vendor"], "platform": p["platform"], "scope": p["scope"],
         "lifetime": p["lifetime"], "public_jwk": crypto.public_jwk_dict(KEYS[p["vendor"]])}
        for p in PROFILES
    ]}


@app.post("/call/{vendor}")
async def call(vendor: str, request: Request):
    key = KEYS.get(vendor)
    if key is None:
        return JSONResponse({"error": f"no key for {vendor}"}, status_code=404)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    company = body.get("company_url") or COMPANY

    # 1. authenticate to Fuse with private_key_jwt and get a token.
    assertion = crypto.make_client_assertion(key, client_id=vendor, audience=TOKEN_AUD)
    async with httpx.AsyncClient(timeout=8.0) as c:
        tr = await c.post(f"{FUSE}/api/token",
                          json={"client_id": vendor, "client_assertion": assertion})
        tdata = tr.json()
    token = tdata.get("token")
    if not token:
        return JSONResponse({"error": "no token", "detail": tdata}, status_code=400)

    # 2. sign a DPoP proof with our OWN key, 3. call the company directly.
    htu = f"{company}/contacts/protected"
    proof = crypto.create_dpop_proof(key, "GET", htu, access_token=token)
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.get(f"{company}/contacts/protected",
                        headers={"Authorization": f"DPoP {token}", "DPoP": proof})
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}

    return {"status": r.status_code, "allowed": bool(data.get("allowed")),
            "count": data.get("count"), "reason": data.get("reason"),
            "checks": data.get("checks"), "token": token, "proof": proof}


@app.post("/gateway-call/{vendor}")
async def gateway_call(vendor: str, request: Request):
    """Inline gateway PoC: instead of calling the company directly, the vendor
    sends its DPoP-bound request THROUGH the Fuse gateway, which verifies the
    proof and forwards. Demonstrates the inline shape end to end."""
    key = KEYS.get(vendor)
    if key is None:
        return JSONResponse({"error": f"no key for {vendor}"}, status_code=404)
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    gateway = body.get("gateway_url") or (FUSE + "/gateway/contacts")

    assertion = crypto.make_client_assertion(key, client_id=vendor, audience=TOKEN_AUD)
    async with httpx.AsyncClient(timeout=8.0) as c:
        tr = await c.post(f"{FUSE}/api/token", json={"client_id": vendor, "client_assertion": assertion})
        token = tr.json().get("token")
    if not token:
        return JSONResponse({"error": "no token"}, status_code=400)
    proof = crypto.create_dpop_proof(key, "GET", gateway, access_token=token)
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.get(gateway, headers={"Authorization": f"DPoP {token}", "DPoP": proof})
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
    return {"status": r.status_code, "allowed": bool(data.get("allowed")),
            "count": data.get("count"), "reason": data.get("reason"),
            "stage": data.get("stage"), "checks": data.get("checks"),
            "reached_company": data.get("reached_company"),
            "binding_enforced": data.get("binding_enforced"),
            "token": token, "proof": proof, "via": "fuse-gateway"}

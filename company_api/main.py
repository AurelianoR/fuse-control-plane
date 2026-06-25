"""
Company Data API: the resource server that holds the sensitive data.

Stands in for Salesforce / Microsoft 365. Two endpoints:

  GET /contacts/legacy      - accepts a plain bearer token, no proof, no scope
                              check. This is the world today: hold the token, win.

  GET /contacts/protected   - demands a Fuse-issued token PLUS a valid DPoP proof,
                              checks revocation, AND enforces scope. A stolen
                              token without the matching private key fails here;
                              a token whose scope was minimized below what the
                              endpoint needs also fails.

This version adds real SCOPE ENFORCEMENT, so Fuse's Tier-2 "scope minimization"
lever is demonstrable, not just asserted.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from common import crypto

FUSE = os.environ.get("FUSE_URL", "http://localhost:8000")
SELF_URL = os.environ.get("COMPANY_API_URL", "http://localhost:8010")
PLATFORM_NAME = os.environ.get("PLATFORM_NAME", "Acme Data Platform")

# What scope a caller must hold to read contacts.
REQUIRED_SCOPE = "contacts:read"

# The vendor tokens this platform sees. Fuse pulls these via /discover when the
# user manually connects the company connector in the dashboard.
DISCOVERED = [
    {"vendor": "InsightSurvey", "platform": "Azure", "scope": "mail:read contacts:export",
     "age_days": 220, "lifetime": 600, "grant_type": "application",
     "client_app_id": "7c9f2a10-4b8e-4f2a-9d1c-3a1b22e0f001", "publisher_tenant": "9188040d-6c67-4c5b-b112-36a304b66dad",
     "verified_publisher": False, "account_enabled": True,
     "consent_type": "Principal", "consented_by": "j.harper@acme.example",
     "last_used_days": 134, "last_used_by": "app-only (client credentials)", "token_id": "az-insightsurvey"},
    {"vendor": "MarketBlast", "platform": "Azure", "scope": "contacts:export files:read",
     "age_days": 95, "lifetime": 86400, "grant_type": "application",
     "client_app_id": "1f3d8b22-9a4c-4e7b-8c2d-5e6f70a1b002", "publisher_tenant": "c0a80101-1111-2222-3333-444455556666",
     "verified_publisher": True, "account_enabled": True,
     "consent_type": "AllPrincipals", "consented_by": "admin (tenant-wide)",
     "last_used_days": 2, "last_used_by": "app-only (client credentials)", "token_id": "az-marketblast"},
    {"vendor": "CalendarSync", "platform": "Azure", "scope": "calendar:read",
     "age_days": 8, "lifetime": 1800, "grant_type": "delegated",
     "client_app_id": "55ab10cd-2e3f-4a5b-9c8d-7e6f50a1b003", "publisher_tenant": "c0a80101-1111-2222-3333-444455556666",
     "verified_publisher": True, "account_enabled": True,
     "consent_type": "Principal", "consented_by": "m.lee@acme.example",
     "last_used_days": 0.2, "last_used_by": "m.lee@acme.example (delegated)", "token_id": "az-calendarsync"},
]

app = FastAPI(title="Company Data API")


@app.get("/discover")
def discover():
    """Fuse calls this when the company connector is connected. Real data over
    the wire: the vendor tokens this platform currently has."""
    return {"platform": PLATFORM_NAME, "vendors": DISCOVERED}

CONTACTS = [
    {"name": "Dana Okafor", "email": "dana@acme.example", "phone": "+1-202-555-0142"},
    {"name": "Liam Rossi", "email": "liam@acme.example", "phone": "+1-202-555-0188"},
    {"name": "Mei Tanaka", "email": "mei@acme.example", "phone": "+1-202-555-0119"},
    {"name": "Sven Larsen", "email": "sven@acme.example", "phone": "+1-202-555-0173"},
]

_jwks_cache: dict = {"pem": None, "fetched": 0}
_seen_proof_jti: set[str] = set()


async def _fuse_public_pem() -> bytes:
    if _jwks_cache["pem"] and time.time() - _jwks_cache["fetched"] < 300:
        return _jwks_cache["pem"]
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.get(f"{FUSE}/api/jwks")
        keys = r.json()["keys"]
    from jwcrypto import jwk
    k = jwk.JWK(**{kk: vv for kk, vv in keys[0].items() if kk in ("kty", "crv", "x", "y")})
    pem = k.export_to_pem(private_key=False, password=None)
    _jwks_cache.update(pem=pem, fetched=time.time())
    return pem


async def _is_active(token: str) -> tuple[bool, str]:
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(f"{FUSE}/api/introspect", json={"token": token})
        data = r.json()
    return data.get("active", False), data.get("reason", "")


def _scope_ok(token_scope: str, required: str) -> bool:
    held = set((token_scope or "").split())
    return required in held


def _deny(reason: str, checks: list | None = None, code: int = 401):
    return JSONResponse({"allowed": False, "reason": reason, "checks": checks or []},
                        status_code=code)


@app.get("/contacts/legacy")
async def contacts_legacy(request: Request):
    """Today's world: a bearer token is enough. Anyone holding it gets in."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return _deny("missing bearer token")
    token = auth.split(" ", 1)[1]
    try:
        crypto.verify_access_token(await _fuse_public_pem(), token)
    except Exception:
        return _deny("token signature invalid or expired")
    # No proof, no binding, no revocation, no scope check - the weak path.
    return {"allowed": True, "count": len(CONTACTS), "contacts": CONTACTS,
            "checks": [{"name": "bearer token", "ok": True,
                        "detail": "valid token - no proof of possession required"}]}


@app.get("/contacts/protected")
async def contacts_protected(request: Request):
    """Token + DPoP proof + revocation + scope."""
    checks: list = []
    auth = request.headers.get("authorization", "")
    proof = request.headers.get("dpop")

    if not auth.lower().startswith("dpop "):
        return _deny("DPoP-bound token required (got bearer or nothing)")
    token = auth.split(" ", 1)[1]

    # Check 1: token is real and unexpired.
    try:
        claims = crypto.verify_access_token(await _fuse_public_pem(), token)
        checks.append({"name": "token valid", "ok": True, "detail": "signed by Fuse, unexpired"})
    except Exception:
        return _deny("token signature invalid or expired",
                     [{"name": "token valid", "ok": False, "detail": "bad or expired token"}])

    # Revocation (live check with Fuse).
    active, reason = await _is_active(token)
    if not active:
        checks.append({"name": "not revoked", "ok": False, "detail": reason})
        return _deny(f"token {reason}", checks)
    checks.append({"name": "not revoked", "ok": True, "detail": "connection is live"})

    # Scope enforcement (Tier 2). A token minimized below what the endpoint
    # needs is rejected here - this is scope-min actually doing something.
    token_scope = claims.get("scope", "")
    if not _scope_ok(token_scope, REQUIRED_SCOPE):
        checks.append({"name": "scope", "ok": False,
                       "detail": f"token scope '{token_scope}' lacks '{REQUIRED_SCOPE}'"})
        return _deny(f"insufficient scope (need {REQUIRED_SCOPE})", checks, code=403)
    checks.append({"name": "scope", "ok": True, "detail": f"'{REQUIRED_SCOPE}' present"})

    expected_jkt = (claims.get("cnf") or {}).get("jkt")
    if not expected_jkt:
        return _deny("token is not sender-bound", checks)

    if not proof:
        checks.append({"name": "proof present", "ok": False, "detail": "no DPoP proof sent"})
        return _deny("DPoP proof required - stolen token alone is useless here", checks)

    # Checks 2-4: the binding proof.
    fwd_proto = request.headers.get("x-forwarded-proto")
    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if fwd_proto and fwd_host:
        htu = f"{fwd_proto}://{fwd_host}{request.url.path}"
    else:
        htu = str(request.url).split("?")[0]
    ok, summary, proof_checks = crypto.verify_dpop_proof(
        proof, htm="GET", htu=htu, expected_jkt=expected_jkt,
        seen_jti=_seen_proof_jti, access_token=token, max_age_seconds=120,
    )
    checks.extend(proof_checks)
    if not ok:
        return _deny(summary, checks)

    return {"allowed": True, "count": len(CONTACTS), "contacts": CONTACTS, "checks": checks}


@app.get("/contacts/via-gateway")
async def contacts_via_gateway(request: Request):
    """Inline mode: Fuse already verified the DPoP proof and forwards the
    request with a signed gateway assertion. The company trusts Fuse's
    signature (it has Fuse's JWKS) and returns data."""
    assertion = request.headers.get("x-fuse-gateway")
    if not assertion:
        return _deny("missing gateway assertion", code=401)
    try:
        import jwt as _jwt
        claims = _jwt.decode(assertion, await _fuse_public_pem(), algorithms=["ES256"],
                             audience=SELF_URL, options={"verify_aud": False})
    except Exception:
        return _deny("gateway assertion invalid", code=401)
    if claims.get("iss") != "fuse" or claims.get("purpose") != "gateway":
        return _deny("not a Fuse gateway assertion", code=401)
    return {"allowed": True, "count": len(CONTACTS), "contacts": CONTACTS,
            "checks": [{"name": "gateway assertion", "ok": True,
                        "detail": "Fuse verified the proof inline and forwarded"}]}


@app.get("/")
def root():
    return {"service": "Company Data API", "endpoints": ["/contacts/legacy", "/contacts/protected"],
            "required_scope_for_contacts": REQUIRED_SCOPE}

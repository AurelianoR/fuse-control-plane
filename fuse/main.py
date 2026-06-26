"""Fuse console: connectors -> apps -> tokens, with real policy + binding."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from common import crypto
from connectors import CONNECTOR_TYPES
from fuse import risk
from fuse.state import STATE, Policy

HERE = os.path.dirname(__file__)
COMPANY_ENV = os.environ.get("COMPANY_API_URL", "http://localhost:8010")
VENDOR_ENV = os.environ.get("VENDOR_URL", "http://localhost:8020")

app = FastAPI(title="Fuse")
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")


# ---- real server log capture --------------------------------------------
# A ring buffer that catches actual Python log records - uvicorn's access log
# (every HTTP request that hits Fuse, including /gateway/contacts and the
# simulate endpoints) and anything Fuse logs itself. Exposed at /api/serverlog.
SERVER_LOG: deque = deque(maxlen=500)


class _RingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            SERVER_LOG.append({
                "ts": record.created,
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage(),
            })
        except Exception:
            pass


_ring = _RingHandler()
_ring.setLevel(logging.INFO)
for _name in ("", "uvicorn", "uvicorn.access", "uvicorn.error", "fuse"):
    _lg = logging.getLogger(_name)
    _lg.addHandler(_ring)
    if _lg.level == logging.NOTSET or _lg.level > logging.INFO:
        _lg.setLevel(logging.INFO)
log = logging.getLogger("fuse")


def company_url() -> str:
    for c in STATE.connectors.values():
        if c.kind == "demo_company" and c.connected and c.config.get("url"):
            return c.config["url"]
    return COMPANY_ENV


@app.get("/", response_class=HTMLResponse)
def dashboard():
    # no-store so the browser always fetches the latest console (avoids stale cache)
    return FileResponse(os.path.join(HERE, "static", "index.html"),
                        headers={"Cache-Control": "no-store, max-age=0"})


# ---- connector types + CRUD ----------------------------------------------
@app.get("/api/connector-types")
def connector_types():
    return [{"kind": k, "display_name": c.display_name, "config_fields":
             [{"name": n, "label": l, "secret": s} for (n, l, s) in c.config_fields]}
            for k, c in CONNECTOR_TYPES.items()]


def _connector_summary(conn) -> dict:
    s = conn.summary()
    s["company"] = STATE.connector_company.get(conn.id)
    return s


@app.get("/api/connectors")
def list_connectors():
    return [_connector_summary(c) for c in STATE.connectors.values()]


@app.get("/api/companies")
def list_companies():
    return STATE.companies


@app.post("/api/companies")
async def add_company(request: Request):
    body = await request.json()
    comp = STATE.add_company(body.get("name", ""))
    return comp


@app.post("/api/connectors")
async def add_connector(request: Request):
    body = await request.json()
    kind = body.get("kind")
    config = body.get("config", {})
    company_id = body.get("company")
    cid = STATE.add_connector(kind, config, company_id=company_id)
    if not cid:
        return JSONResponse({"error": "unknown connector kind"}, status_code=400)
    ok, msg = await STATE.connect_connector(cid)
    return {"id": cid, "connected": ok, "message": msg, "summary": _connector_summary(STATE.connectors[cid])}


@app.post("/api/connectors/{cid}/connect")
async def connect_connector(cid: str):
    ok, msg = await STATE.connect_connector(cid)
    return {"connected": ok, "message": msg}


@app.post("/api/connectors/{cid}/sync")
async def sync_connector(cid: str):
    await STATE.sync_connector(cid)
    return {"ok": True}


@app.post("/api/connectors/sync-all")
async def sync_all_connectors():
    """Re-fetch from every connected connector (real HTTP for Azure/GitHub)."""
    synced = 0
    errors = []
    for cid, conn in list(STATE.connectors.items()):
        if not conn.connected:
            continue
        try:
            await STATE.sync_connector(cid)
            synced += 1
        except Exception as e:  # one bad source shouldn't block the rest
            errors.append(f"{conn.display_name}: {e}")
    return {"ok": not errors, "synced": synced, "errors": errors,
            "apps": len(STATE.apps)}


@app.post("/api/connectors/{cid}/disconnect")
def disconnect_connector(cid: str):
    conn = STATE.connectors.get(cid)
    if not conn:
        return JSONResponse({"error": "no such connector"}, status_code=404)
    conn.disconnect()
    for app_id in [a for a, ap in STATE.apps.items() if ap.source == cid]:
        STATE.apps.pop(app_id, None)
        STATE.policies.pop(app_id, None)
        STATE._app_index = {k: v for k, v in STATE._app_index.items() if v != app_id}
    STATE.visibility_tokens = {t: tok for t, tok in STATE.visibility_tokens.items() if tok.source != cid}
    STATE.emit("connector", f"{conn.display_name}: disconnected", cid=cid)
    return {"ok": True}


@app.delete("/api/connectors/{cid}")
def delete_connector(cid: str):
    STATE.remove_connector(cid)
    return {"ok": True}


# ---- apps ----------------------------------------------------------------
@app.get("/api/apps")
def list_apps():
    out = []
    for app_obj in STATE.apps.values():
        d = app_obj.to_dict()
        pol = STATE.policies.get(app_obj.id)
        d["policy"] = {"lifetime_seconds": pol.lifetime_seconds,
                       "allowed_scope": pol.allowed_scope,
                       "binding_required": pol.binding_required} if pol else None
        d["revoked"] = app_obj.status == "revoked"
        d["bound"] = bool(pol and pol.binding_required and app_obj.holds_key)
        out.append(d)
    return out


def _is_revoked(app_id: str) -> bool:
    tok = STATE.last_token.get(app_id)
    if not tok:
        return False
    try:
        claims = crypto.verify_access_token(crypto.public_pem(STATE.key), tok)
        return claims.get("jti") in STATE.revoked_jti
    except Exception:
        return False


@app.post("/api/apps/{app_id}/policy")
async def set_policy(app_id: str, request: Request):
    app_obj = STATE.apps.get(app_id)
    pol = STATE.policies.get(app_id)
    if not app_obj or not pol:
        return JSONResponse({"error": "no such app"}, status_code=404)
    body = await request.json()
    old_life = pol.lifetime_seconds
    if "lifetime_seconds" in body:
        pol.lifetime_seconds = int(body["lifetime_seconds"])
    if "allowed_scope" in body:
        pol.allowed_scope = body["allowed_scope"]
    if "binding_required" in body:
        want = bool(body["binding_required"])
        if want and not app_obj.holds_key:
            return JSONResponse({"error": "app has no registered key; cannot bind"}, status_code=400)
        pol.binding_required = want
    if old_life != pol.lifetime_seconds and STATE.last_token.get(app_id):
        try:
            claims = crypto.verify_access_token(crypto.public_pem(STATE.key), STATE.last_token[app_id])
            STATE.revoked_jti.add(claims["jti"])
        except Exception:
            pass
    STATE.emit("policy", f"{app_obj.name}: policy updated", app_id=app_id)
    return {"ok": True}


@app.post("/api/apps/{app_id}/revoke")
async def revoke_app(app_id: str):
    ok, detail = await STATE.revoke_app(app_id)
    if not ok:
        return JSONResponse({"error": detail}, status_code=404)
    return {"ok": True, "detail": detail}


@app.post("/api/apps/{app_id}/restore")
def restore_app(app_id: str):
    STATE.restore_app(app_id)
    return {"ok": True}


@app.post("/api/policy/bulk")
async def bulk_policy(request: Request):
    body = await request.json()
    flt = body.get("filter", {})
    policy = body.get("policy", {})
    action = body.get("action")
    n = STATE.apply_bulk(flt, policy, action)
    revoked = 0
    if action == "revoke":
        for app in list(STATE.apps.values()):
            if _matches(app, flt) and app.status != "revoked":
                await STATE.revoke_app(app.id)
                revoked += 1
    return {"ok": True, "matched": n, "revoked": revoked}


def _conn_policy_row(app_obj):
    pol = STATE.policies.get(app_obj.id)
    return {
        "id": app_obj.id, "name": app_obj.name, "platform": _provider(app_obj.platform),
        "governable": app_obj.governable, "holds_key": app_obj.holds_key,
        "revoked": app_obj.status == "revoked",
        "policy": {
            "lifetime_seconds": pol.lifetime_seconds if pol else None,
            "lifetime_label": _fmt_lifetime(pol.lifetime_seconds) if pol else "—",
            "allowed_scope": pol.allowed_scope if pol else "",
            "binding_required": bool(pol and pol.binding_required and app_obj.holds_key),
        } if pol else None,
    }


@app.get("/api/policy/overview")
def policy_overview():
    """Companies → connections with their current policy, for the Policy view.
    Live connector apps group by company (governable); the seeded collector
    tenants appear as read-only groups so every connection is represented."""
    companies = {c["id"]: {"id": c["id"], "name": c["name"], "kind": "company",
                           "governable_count": 0, "connections": []} for c in STATE.companies}
    unassigned = {"id": "unassigned", "name": "Unassigned", "kind": "company",
                  "governable_count": 0, "connections": []}

    for app_obj in STATE.apps.values():
        row = _conn_policy_row(app_obj)
        cid = STATE.connector_company.get(app_obj.source)
        grp = companies.get(cid, unassigned)
        grp["connections"].append(row)
        if app_obj.governable:
            grp["governable_count"] += 1

    groups = [g for g in companies.values()]
    if unassigned["connections"]:
        groups.append(unassigned)

    # seeded collector tenants — read-only (visibility only, not governable)
    if GRANTS_AVAILABLE:
        db = _grant_session()
        try:
            by_tenant: dict = {}
            for t, r in _iter_seeded_rows(db):
                g = r.primary_grant
                key = f"t{t.id}"
                grp = by_tenant.setdefault(key, {
                    "id": key, "name": f"{t.display_name} (collected)", "kind": "tenant",
                    "governable_count": 0, "connections": []})
                grp["connections"].append({
                    "id": str(g.id), "name": g.client_display_name,
                    "platform": "github" if (t.platform or "azure") == "github" else "azure",
                    "governable": False, "holds_key": False, "revoked": not g.is_active,
                    "policy": None,
                })
            groups.extend(by_tenant.values())
        finally:
            db.close()

    for g in groups:
        g["connections"].sort(key=lambda c: c["name"].lower())
        g["total"] = len(g["connections"])
    return {"companies": groups}


def _matches(app, flt) -> bool:
    if flt.get("platform") and app.platform != flt["platform"]:
        return False
    if flt.get("token_kind") and app.token_kind != flt["token_kind"]:
        return False
    if flt.get("governable") is not None and app.governable != flt["governable"]:
        return False
    if flt.get("min_risk") and app.risk() < int(flt["min_risk"]):
        return False
    if flt.get("company") and STATE.connector_company.get(app.source) != flt["company"]:
        return False
    return True


# ---- tokens --------------------------------------------------------------
@app.get("/api/tokens")
def list_tokens():
    return STATE.tokens_view()


# ==========================================================================
# Frontend SPA adapter
#
# The console UI (fuse/static/index.html) consumes a flat "session" shape and a
# few simple endpoints. These adapters project the real App / Policy / risk
# model into that shape so the polished UI drives the real engine, and add the
# rich per-token detail the monitoring screen needs.
# ==========================================================================

def _provider(platform: str) -> str:
    p = (platform or "").lower()
    if "azure" in p or "entra" in p:
        return "azure"
    if "github" in p:
        return "github"
    if "salesforce" in p:
        return "salesforce"
    return "saas"


def _risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _fmt_lifetime(seconds: int) -> str:
    if not seconds:
        return "—"
    if seconds < 3600:
        m = max(1, seconds // 60)
        return f"{m} min" if m == 1 else f"{m} mins"
    if seconds < 86400:
        h = seconds // 3600
        return f"{h} hr" if h == 1 else f"{h} hrs"
    d = seconds // 86400
    return f"{d} day" if d == 1 else f"{d} days"


def _last_activity_ts(app_id: str) -> float | None:
    """Newest event timestamp recorded for this app (a token mint, a request,
    an attack, a policy change) — the live equivalent of the collector's
    last-used activity snapshot."""
    latest = None
    for e in STATE.events:
        if e.get("app_id") == app_id:
            if latest is None or e["ts"] > latest:
                latest = e["ts"]
    return latest


def _is_bound(app_obj, pol) -> bool:
    return bool(pol and pol.binding_required and app_obj.holds_key)


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _session_for(app_obj, pol) -> dict:
    score = app_obj.risk()
    bound = _is_bound(app_obj, pol)
    revoked = app_obj.status == "revoked"
    conn = STATE.connectors.get(app_obj.source)
    resource = conn.display_name if conn else app_obj.platform

    if revoked:
        expires_in = "Revoked"
    elif bound or (app_obj.governable and pol):
        expires_in = _fmt_lifetime(pol.lifetime_seconds) if pol else "—"
    else:
        expires_in = "Static Key"

    last_ts = _last_activity_ts(app_obj.id) or app_obj.created_at
    cid = STATE.connector_company.get(app_obj.source)
    comp = next((c for c in STATE.companies if c["id"] == cid), None)
    return {
        "id": app_obj.id,
        "vendor": app_obj.name,
        "provider": _provider(app_obj.platform),
        "platform": app_obj.platform,
        "resource": resource,
        "scope": " ".join(app_obj.scopes) or "—",
        "expires_in": expires_in,
        "risk_level": _risk_level(score),
        "is_critical": score >= 80 or (revoked is False and any(
            risk.is_write_scope(s) for s in app_obj.scopes) and not bound and app_obj.token_kind != "bound"),
        "last_seen": _iso(last_ts),
        # the live bar is an honest risk-exposure meter (0-100), not fake call counts
        "token_usage": score,
        "usage_limit": 100,
        "bound": bound,
        "token_kind": "bound" if bound else app_obj.token_kind,
        "governable": app_obj.governable,
        "revoked": revoked,
        "company": cid,
        "company_name": comp["name"] if comp else "Unassigned",
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "fuse-control-plane"}


@app.get("/api/sessions")
def sessions():
    out = []
    for app_obj in STATE.apps.values():
        pol = STATE.policies.get(app_obj.id)
        out.append(_session_for(app_obj, pol))
    out += _seeded_sessions()   # also surface the collected grant inventory as connections
    out.sort(key=lambda s: (-s["token_usage"], s["vendor"].lower()))
    return out


@app.get("/api/metrics")
def metrics():
    by_provider: dict = {}
    critical = 0
    for app_obj in STATE.apps.values():
        if app_obj.status == "revoked":
            continue
        prov = _provider(app_obj.platform)
        by_provider[prov] = by_provider.get(prov, 0) + 1
        if app_obj.risk() >= 80:
            critical += 1
    return {
        "timestamp": _iso(time.time()),
        "total_tokens": len([a for a in STATE.apps.values() if a.status != "revoked"]),
        "by_provider": by_provider,
        "critical_count": critical,
    }


_AUDIT_KINDS = {"revoke", "policy", "blocked", "breach", "attack", "connector", "sync"}


@app.get("/api/audit")
def audit():
    entries = []
    for e in reversed(STATE.events):
        if e.get("kind") not in _AUDIT_KINDS:
            continue
        ts = datetime.fromtimestamp(e["ts"], tz=timezone.utc).isoformat(timespec="seconds")
        app_obj = STATE.apps.get(e.get("app_id")) if e.get("app_id") else None
        who = f" | {app_obj.name}" if app_obj else ""
        entries.append(f"[{ts}] {e.get('kind','').upper()}{who} | {e.get('message','')}")
    return {"total": len(entries), "entries": entries}


@app.post("/api/tokens/revoke")
async def tokens_revoke(request: Request):
    """SPA revoke alias -> the real per-app revoke (cuts at source where supported)."""
    body = await request.json()
    app_id = body.get("token_id") or body.get("app_id")
    ok, detail = await STATE.revoke_app(app_id)
    if not ok:
        return JSONResponse({"status": "error", "message": detail}, status_code=404)
    app_obj = STATE.apps.get(app_id)
    name = app_obj.name if app_obj else app_id
    return {"status": "success", "message": f"{name}: {detail}"}


@app.get("/api/apps/{app_id}/detail")
def app_detail(app_id: str):
    """The token-monitoring detail screen payload (ported from the collector's
    grant deep-dive): identity, risk signals, activity, permissions, the live
    event history for this connection, and the revoke danger-zone copy."""
    app_obj = STATE.apps.get(app_id)
    if not app_obj:
        return JSONResponse({"error": "no such app"}, status_code=404)
    pol = STATE.policies.get(app_id)
    bound = _is_bound(app_obj, pol)
    score = app_obj.risk()
    meta = app_obj.meta or {}
    # "last used" prefers live events (a request we saw) then the source's
    # reported last sign-in (Graph / collector activity, synthesized for demo).
    last_act = _last_activity_ts(app_id) or meta.get("last_sign_in")

    signals = risk.compute_risk_signals(app_obj, policy=pol, last_activity_ts=last_act)

    # per-connection event history (newest first)
    events = []
    for e in reversed(STATE.events):
        if e.get("app_id") != app_id:
            continue
        events.append({
            "ts": e["ts"],
            "iso": _iso(e["ts"]),
            "kind": e.get("kind"),
            "message": e.get("message"),
            "checks": e.get("checks"),
        })

    prov = _provider(app_obj.platform)
    if app_obj.governable:
        revoke_caveat = ("Revoking cuts the outstanding Fuse-issued token immediately and blocks "
                         "all further requests for this connection. The vendor keeps working only "
                         "if you restore it.")
    elif prov == "azure":
        revoke_caveat = ("Deleting the grant stops new token issuance but does not invalidate tokens "
                         "already issued — existing tokens remain valid for their remaining TTL (~60 min). "
                         "Disabling the vendor app is the strongest containment; it blocks all new tokens "
                         "across resources but live tokens still expire naturally. Requires "
                         "Application.ReadWrite.All on the app registration.")
    elif prov == "github":
        revoke_caveat = ("Revoking deletes the installation / credential from the org immediately, "
                         "cutting access. Requires the connector to have admin rights.")
    else:
        revoke_caveat = "Revoking cuts this connection's access at the source where the connector supports it."

    return {
        "id": app_obj.id,
        "name": app_obj.name,
        "platform": app_obj.platform,
        "provider": prov,
        "source": STATE.connectors.get(app_obj.source).display_name if STATE.connectors.get(app_obj.source) else app_obj.source,
        "external_id": app_obj.external_id,
        "token_kind": "bound" if bound else app_obj.token_kind,
        "governable": app_obj.governable,
        "holds_key": app_obj.holds_key,
        "key_jkt": app_obj.key_jkt,
        "status": app_obj.status,
        "revoked": app_obj.status == "revoked",
        "bound": bound,
        "risk": score,
        "risk_level": _risk_level(score),
        "is_critical": score >= 80,
        "scope": " ".join(app_obj.scopes) or "—",
        "policy": {
            "lifetime_seconds": pol.lifetime_seconds if pol else None,
            "lifetime_label": _fmt_lifetime(pol.lifetime_seconds) if pol else "—",
            "allowed_scope": pol.allowed_scope if pol else "",
            "binding_required": pol.binding_required if pol else False,
        } if pol else None,
        "grant_type": meta.get("grant_type"),
        "publisher": {
            "verified": meta.get("verified_publisher"),
            "publisher_tenant": meta.get("publisher_tenant") or meta.get("appOwnerOrganizationId"),
            "account_enabled": meta.get("account_enabled"),
            "consent_type": meta.get("consent_type"),
            "consented_by": meta.get("consented_by"),
            "client_app_id": meta.get("client_app_id"),
            "sp_id": meta.get("sp_id"),
        },
        "risk_signals": signals,
        "activity": {
            "created_at": _iso(app_obj.created_at),
            "created_ago": risk.timeago(app_obj.created_at),
            "last_activity": _iso(last_act),
            "last_activity_ago": risk.timeago(last_act),
            "last_used_by": meta.get("last_used_by"),
            "last_token": app_obj.id in STATE.last_token,
            "last_proof": app_obj.id in STATE.last_proof,
        },
        "permissions": [{"name": s, "write": risk.is_write_scope(s)} for s in app_obj.scopes],
        "events": events,
        "revoke_caveat": revoke_caveat,
    }


# ---- one-click demo wiring + settings (back the SPA settings views) -------
@app.post("/api/demo/quick-connect")
async def demo_quick_connect():
    """Wire the demo company (:8010) and demo vendor (:8020) connectors and
    sync them, so the dashboard fills with real apps + tokens on one click."""
    demo_co = STATE.add_company("Acme Corp (Demo)")
    results = []
    for kind, url in (("demo_company", COMPANY_ENV), ("demo_vendor", VENDOR_ENV)):
        # reuse an existing connector of this kind if present
        cid = next((c.id for c in STATE.connectors.values() if c.kind == kind), None)
        if not cid:
            cid = STATE.add_connector(kind, {"url": url}, company_id=demo_co["id"])
        else:
            STATE.connector_company.setdefault(cid, demo_co["id"])
        ok, msg = await STATE.connect_connector(cid)
        results.append({"kind": kind, "connected": ok, "message": msg})
    return {"ok": all(r["connected"] for r in results), "results": results}


# in-memory settings store backing the SPA's Settings views. The token policy
# save also pushes real defaults onto governable apps via bulk policy.
_SETTINGS = {
    "token_governance": {
        "default_ttl_minutes": 5,
        "allowed_scopes": ["contacts:read"],
        "enforce_sender_binding": True,
        "max_token_usage_limit": 1000,
    },
    "cloud_environments": [],
    "compliance": {
        "audit_logging_enabled": True,
        "fail_strategy": "fail-closed",
        "frameworks": [
            {"id": 1, "name": "ISO/IEC 27001", "description": "Access control · Audit logging", "score": 94, "enabled": True},
            {"id": 2, "name": "SOC 2 Type II", "description": "Security · Availability · Confidentiality", "score": 88, "enabled": True},
            {"id": 3, "name": "NIST CSF 2.0", "description": "Identify · Protect · Detect · Respond", "score": 76, "enabled": True},
            {"id": 4, "name": "CIS Cloud Benchmark", "description": "IAM hardening gaps flagged", "score": 61, "enabled": False},
        ],
    },
}


@app.get("/api/dashboard/settings")
def get_settings():
    comp = _SETTINGS["compliance"]
    return {"status": "success", "data": {
        "token_governance": _SETTINGS["token_governance"],
        "cloud_environments": _SETTINGS["cloud_environments"],
        "compliance": {
            "enabled_frameworks": [f["name"] for f in comp["frameworks"] if f["enabled"]],
            "frameworks": comp["frameworks"],
            "audit_logging_enabled": comp["audit_logging_enabled"],
            "fail_strategy": comp["fail_strategy"],
        },
    }}


@app.get("/api/compliance/findings")
def compliance_findings():
    """Only the NEGATIVE compliance status: concrete risk findings across the
    connection inventory (live + seeded)."""
    findings = []

    # concrete risk findings aggregated across all connections
    rows = []
    if STATE.apps:
        rows += _live_grant_rows()
    if GRANTS_AVAILABLE:
        db = _grant_session()
        try:
            for _t, r in _iter_seeded_rows(db):
                rows.append({"vendor": r.primary_grant.client_display_name,
                             "risk_signals": [{"key": s} for s in r.risk_signals]})
        finally:
            db.close()

    def _count(key):
        return sum(1 for r in rows if any(_wu.normalize_risk_signal(s["key"]) == key for s in r["risk_signals"]))

    catalog = [
        ("write-permissions", "high", "Connections holding write/export/admin permissions"),
        ("unverified-publisher", "medium", "Connections from unverified publishers"),
        ("user-consented", "medium", "Grants consented by a regular user, not an admin"),
        ("never-used", "low", "Connections that have never been used (dormant grant)"),
        ("dormant", "low", "Connections dormant for over 90 days"),
        ("unbound-bearer", "high", "Stealable bearer tokens with no sender binding (DPoP)"),
        ("all-repos", "high", "Apps with access to all repositories"),
    ]
    for key, sev, label in catalog:
        n = _count(key)
        if n:
            findings.append({
                "kind": "risk", "signal": key, "count": n, "severity": sev,
                "title": f"{n} {label.lower()}",
                "detail": label + ". Review in Token Monitor.",
            })

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: order.get(x["severity"], 3))
    sev_counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("high", "medium", "low")}
    return {"total": len(findings), "by_severity": sev_counts, "findings": findings}


@app.post("/api/dashboard/settings/token")
async def set_token_settings(request: Request):
    body = await request.json()
    tg = _SETTINGS["token_governance"]
    tg.update({k: body[k] for k in (
        "default_ttl_minutes", "allowed_scopes", "enforce_sender_binding", "max_token_usage_limit"
    ) if k in body})
    # apply as a real default policy to every governable app
    lifetime = int(tg["default_ttl_minutes"]) * 60
    policy = {"lifetime_seconds": lifetime}
    if tg.get("enforce_sender_binding"):
        policy["binding_required"] = True
    n = STATE.apply_bulk({"governable": True}, policy, None)
    return {"status": "success", "message": f"Token policy saved and applied to {n} governable connection(s)."}


@app.post("/api/dashboard/settings/cloud")
async def set_cloud_settings(request: Request):
    body = await request.json()
    body["id"] = len(_SETTINGS["cloud_environments"]) + 1
    _SETTINGS["cloud_environments"].append(body)
    provider = (body.get("provider") or "").lower()
    # For Azure, actually wire a real Entra connector so apps + tokens appear
    # (otherwise "linking Azure" here would be cosmetic only).
    if provider == "azure" and body.get("tenant_id") and body.get("client_id") and body.get("client_secret"):
        cfg = {"tenant_id": body["tenant_id"], "client_id": body["client_id"], "client_secret": body["client_secret"]}
        cid = next((c.id for c in STATE.connectors.values()
                    if c.kind == "azure" and c.config.get("client_id") == cfg["client_id"]), None)
        if not cid:
            cid = STATE.add_connector("azure", cfg)
        else:
            STATE.connectors[cid].config.update(cfg)
        ok, msg = await STATE.connect_connector(cid)
        return {"status": "success" if ok else "error",
                "message": f"Azure connector {'connected' if ok else 'failed'}: {msg}. "
                           f"See the Dashboard and Tokens views."}
    return {"status": "success",
            "message": f"{body.get('provider')} environment recorded. "
                       f"(Live discovery is wired for Azure and GitHub via the Connectors view.)"}


@app.post("/api/dashboard/settings/compliance")
async def set_compliance_settings(request: Request):
    body = await request.json()
    enabled = set(body.get("enabled_frameworks", []))
    for f in _SETTINGS["compliance"]["frameworks"]:
        f["enabled"] = f["name"] in enabled
    _SETTINGS["compliance"]["audit_logging_enabled"] = body.get("audit_logging_enabled", True)
    _SETTINGS["compliance"]["fail_strategy"] = body.get("fail_strategy", "fail-closed")
    return {"status": "success", "message": "Compliance policy updated."}


@app.post("/api/dashboard/settings/compliance/research")
async def research_framework(request: Request):
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return {"status": "error", "message": "framework name required"}
    fw = {"id": max([f["id"] for f in _SETTINGS["compliance"]["frameworks"]] + [0]) + 1,
          "name": name, "description": f"{name} — core access-control and audit controls mapped.",
          "score": 80, "enabled": True}
    _SETTINGS["compliance"]["frameworks"].append(fw)
    return {"status": "success", "message": f"Framework {name} researched and integrated.", "framework": fw}


@app.post("/api/dashboard/settings/compliance/revise")
async def revise_framework(request: Request):
    body = await request.json()
    for f in _SETTINGS["compliance"]["frameworks"]:
        if f["id"] == body.get("id"):
            f["score"] = body.get("score", f["score"])
            f["description"] = body.get("description", f["description"])
            f["enabled"] = body.get("enabled", f["enabled"])
            return {"status": "success", "message": "Framework revised.", "framework": f}
    return {"status": "error", "message": "framework not found"}


# ---- token authority -----------------------------------------------------
@app.get("/api/jwks")
def jwks():
    pub = crypto.public_jwk_dict(STATE.key)
    pub.update(kid=STATE.kid, use="sig", alg="ES256")
    return {"keys": [pub]}


def _governable_by_client(client_id: str):
    for a in STATE.apps.values():
        if a.governable and (a.external_id == client_id or a.name == client_id):
            return a
    return None


@app.post("/api/token")
async def token_endpoint(request: Request):
    """RFC 7523 private_key_jwt: the app proves identity with a signed assertion."""
    body = await request.json()
    client_id = body.get("client_id")
    assertion = body.get("client_assertion")
    app_obj = _governable_by_client(client_id) if client_id else None
    if not app_obj:
        return JSONResponse({"error": "unknown client"}, status_code=400)
    if not assertion:
        return JSONResponse({"error": "client_assertion required (private_key_jwt)"}, status_code=401)
    pub = app_obj.meta.get("public_jwk")
    try:
        crypto.verify_client_assertion(pub, assertion, audience=STATE.token_aud, client_id=client_id)
    except Exception as e:
        STATE.emit("deny", f"{app_obj.name}: token request rejected - bad client_assertion", app_id=app_obj.id)
        return JSONResponse({"error": f"client_assertion invalid: {e}"}, status_code=401)
    token = STATE.mint_for_app(app_obj)
    pol = STATE.policies.get(app_obj.id)
    return {"token": token, "bound": bool(pol and pol.binding_required and app_obj.holds_key)}


@app.post("/api/introspect")
async def introspect(request: Request):
    body = await request.json()
    try:
        claims = crypto.verify_access_token(crypto.public_pem(STATE.key), body.get("token", ""))
    except Exception:
        return {"active": False, "reason": "invalid or expired"}
    if claims.get("jti") in STATE.revoked_jti:
        return {"active": False, "reason": "revoked"}
    return {"active": True, "scope": claims.get("scope"), "cnf": claims.get("cnf")}


# ---- events --------------------------------------------------------------
@app.get("/api/log")
def get_log():
    """The full structured activity log (newest first): every allow, deny,
    block, attack, policy change, revoke, and connector sync Fuse recorded."""
    return list(reversed(STATE.events))


@app.get("/api/serverlog")
def get_serverlog():
    """The raw server log (newest first): real uvicorn request lines and any
    Fuse log output, straight from the Python logging handlers."""
    return list(reversed(SERVER_LOG))


@app.get("/api/events")
async def events():
    async def stream():
        q: asyncio.Queue = asyncio.Queue()
        STATE.subscribers.add(q)
        for e in STATE.events[-25:]:
            yield f"data: {json.dumps(e)}\n\n"
        try:
            while True:
                e = await q.get()
                yield f"data: {json.dumps(e)}\n\n"
        finally:
            STATE.subscribers.discard(q)
    return StreamingResponse(stream(), media_type="text/event-stream")


# ---- simulation ----------------------------------------------------------
async def _company_get(path, headers):
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.get(f"{company_url()}{path}", headers=headers)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text}


async def _ask_vendor(app_obj):
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(f"{app_obj.vendor_url}/call/{app_obj.external_id}",
                         json={"company_url": company_url()})
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"raw": r.text}


@app.post("/api/simulate/legit/{app_id}")
async def simulate_legit(app_id: str):
    app_obj = STATE.apps.get(app_id)
    pol = STATE.policies.get(app_id)
    if not app_obj or not pol:
        return JSONResponse({"error": "app not governable"}, status_code=404)
    if app_obj.status == "revoked" or _is_revoked(app_id):
        STATE.emit("deny", f"{app_obj.name}: blocked, access revoked", app_id=app_id)
        return {"ok": False, "reason": "revoked"}
    if pol.binding_required and app_obj.vendor_url and app_obj.holds_key:
        status, data = await _ask_vendor(app_obj)
        if "token" in data:
            STATE.last_token[app_id] = data["token"]
        if "proof" in data:
            STATE.last_proof[app_id] = data["proof"]
        if status == 200 and data.get("allowed"):
            STATE.emit("allow", f"{app_obj.name}: ALLOWED ({data.get('count','?')} records) - vendor-signed", app_id=app_id, checks=data.get("checks"))
        else:
            STATE.emit("deny", f"{app_obj.name}: DENIED - {data.get('reason','?')}", app_id=app_id, checks=data.get("checks"))
        return {"ok": status == 200 and data.get("allowed", False), "data": data}
    # unbound: bearer to legacy
    token = STATE.mint_for_app(app_obj)
    status, data = await _company_get("/contacts/legacy", {"Authorization": f"Bearer {token}"})
    STATE.emit("allow" if status == 200 else "deny",
               f"{app_obj.name}: {'ALLOWED' if status==200 else 'DENIED'} - bearer, unbound", app_id=app_id)
    return {"ok": status == 200, "data": data}


@app.post("/api/simulate/attack/{app_id}")
async def simulate_attack(app_id: str, kind: str):
    app_obj = STATE.apps.get(app_id)
    if not app_obj:
        return JSONResponse({"error": "no such app"}, status_code=404)
    label = {"bearer_replay": "stolen token replayed as bearer",
             "forged_proof": "stolen token + attacker-forged proof",
             "proof_replay": "captured proof replayed",
             "legacy_bypass": "stolen token against legacy endpoint"}.get(kind, kind)
    STATE.emit("attack", f"ATTACK on {app_obj.name}: {label}", app_id=app_id)

    htu = f"{company_url()}/contacts/protected"
    if kind == "proof_replay":
        if app_obj.vendor_url and app_obj.holds_key:
            _s, _d = await _ask_vendor(app_obj)
            if "token" in _d:
                STATE.last_token[app_id] = _d["token"]
            if "proof" in _d:
                STATE.last_proof[app_id] = _d["proof"]
        token = STATE.last_token.get(app_id)
        if not token or not STATE.last_proof.get(app_id):
            STATE.emit("blocked", f"{app_obj.name}: no captured proof to replay", app_id=app_id)
            return {"ok": False, "reason": "no captured proof"}
    else:
        token = STATE.mint_for_app(app_obj)

    if kind == "bearer_replay":
        status, data = await _company_get("/contacts/protected", {"Authorization": f"DPoP {token}"})
    elif kind == "forged_proof":
        ak = crypto.generate_keypair()
        forged = crypto.create_dpop_proof(ak, "GET", htu, access_token=token)
        status, data = await _company_get("/contacts/protected", {"Authorization": f"DPoP {token}", "DPoP": forged})
    elif kind == "proof_replay":
        status, data = await _company_get("/contacts/protected", {"Authorization": f"DPoP {token}", "DPoP": STATE.last_proof[app_id]})
    elif kind == "legacy_bypass":
        status, data = await _company_get("/contacts/legacy", {"Authorization": f"Bearer {token}"})
    else:
        return JSONResponse({"error": "unknown attack"}, status_code=400)

    if status == 200 and data.get("allowed", True):
        STATE.emit("breach", f"DATA EXFILTRATED from {app_obj.name}: {data.get('count','?')} records ({label})", app_id=app_id, checks=data.get("checks"))
    else:
        STATE.emit("blocked", f"attack BLOCKED on {app_obj.name}: {data.get('reason','?')}", app_id=app_id, checks=data.get("checks"))
    return {"ok": status == 200, "data": data}


_gateway_seen: set = set()


def _gw_deny(checks, reason, app_id=None, reached_company=False):
    """Uniform gateway denial: emit + return the full checklist so the UI can
    show exactly which gate tripped and that the company was never reached."""
    STATE.emit("blocked", f"gateway: blocked - {reason}", app_id=app_id, checks=checks)
    return JSONResponse({"allowed": False, "stage": "gateway", "via": "fuse-gateway",
                         "reason": reason, "reached_company": reached_company,
                         "checks": checks}, status_code=401)


@app.get("/gateway/contacts")
async def gateway_contacts(request: Request):
    """INLINE gateway (the plan's rare fallback): the vendor sends its DPoP-bound
    request HERE, Fuse verifies the proof itself, and forwards only verified
    requests to the company with a signed gateway assertion the company trusts.

    Every gate is reported back as a named check so the console can show the
    request being admitted or stopped *at the gateway*, before the company is
    ever touched. That is the visible proof that binding is enforced here."""
    checks: list = []

    def gate(name, ok, detail):
        checks.append({"name": name, "ok": ok, "detail": detail})

    auth = request.headers.get("authorization", "")
    proof = request.headers.get("dpop")

    # Gate 1: the caller must present a DPoP-scheme token, not a plain bearer.
    if not auth.lower().startswith("dpop "):
        gate("DPoP scheme", False, "caller sent a bearer token, not a bound DPoP token")
        return _gw_deny(checks, "bound DPoP token required at gateway")
    gate("DPoP scheme", True, "caller presented a DPoP-bound token")
    token = auth.split(" ", 1)[1]

    # Gate 2: the token must be a real, unexpired Fuse token.
    try:
        claims = crypto.verify_access_token(crypto.public_pem(STATE.key), token)
        gate("token valid", True, "signed by Fuse, unexpired")
    except Exception:
        gate("token valid", False, "token invalid or expired")
        return _gw_deny(checks, "token invalid/expired")

    app_obj = STATE.apps.get(claims.get("sub"))
    name = app_obj.name if app_obj else claims.get("sub")

    # Gate 3: revocation.
    if claims.get("jti") in STATE.revoked_jti or (app_obj and app_obj.status == "revoked"):
        gate("not revoked", False, "this connection has been cut")
        return _gw_deny(checks, "token revoked", app_id=claims.get("sub"))
    gate("not revoked", True, "connection is live")

    # Gate 4: the token must actually be sender-bound (carry a cnf.jkt).
    expected_jkt = (claims.get("cnf") or {}).get("jkt")
    if not expected_jkt:
        gate("sender-bound", False, "token has no bound key (cnf.jkt)")
        return _gw_deny(checks, "token is not sender-bound", app_id=claims.get("sub"))
    gate("sender-bound", True, f"bound to key {expected_jkt[:10]}...")

    # Gate 5: a proof must be present at all.
    if not proof:
        gate("proof present", False, "no DPoP proof sent - a stolen token alone is useless here")
        return _gw_deny(checks, "DPoP proof required at gateway", app_id=claims.get("sub"))
    gate("proof present", True, "a fresh DPoP proof accompanied the request")

    # Gates 6-9: the binding proof itself (key match, signature, request, freshness/replay).
    fwd_proto = request.headers.get("x-forwarded-proto")
    fwd_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    htu = f"{fwd_proto}://{fwd_host}{request.url.path}" if (fwd_proto and fwd_host) else str(request.url).split("?")[0]
    ok, summary, proof_checks = crypto.verify_dpop_proof(
        proof, htm="GET", htu=htu, expected_jkt=expected_jkt,
        seen_jti=_gateway_seen, access_token=token, max_age_seconds=120)
    checks.extend(proof_checks)
    if not ok:
        return _gw_deny(checks, summary, app_id=claims.get("sub"))

    # Verified inline. Forward to the company with a signed gateway assertion.
    assertion = crypto.sign_fuse_jwt(crypto.private_pem(STATE.key), STATE.kid, {
        "iss": "fuse", "aud": company_url(), "sub": claims.get("sub"),
        "scope": claims.get("scope"), "purpose": "gateway",
        "iat": int(time.time()), "exp": int(time.time()) + 30,
    })
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.get(f"{company_url()}/contacts/via-gateway", headers={"X-Fuse-Gateway": assertion})
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
    gate("forwarded", True, f"verified inline, forwarded to company ({data.get('count','?')} records)")
    STATE.emit("allow", f"gateway: {name} verified inline, forwarded ({data.get('count','?')} records)", app_id=claims.get("sub"), checks=checks)
    data.update({"stage": "forwarded", "via": "fuse-gateway",
                 "reached_company": True, "checks": checks})
    return data


@app.post("/api/simulate/gateway/{app_id}")
async def simulate_gateway(app_id: str):
    """Legit run: the standalone vendor signs a proof for the GATEWAY url and
    sends its request THROUGH Fuse, which verifies and forwards to the company."""
    app_obj = STATE.apps.get(app_id)
    if not app_obj or not app_obj.vendor_url or not app_obj.holds_key:
        return JSONResponse({"error": "app not vendor-backed"}, status_code=404)
    if app_obj.status == "revoked":
        STATE.emit("deny", f"{app_obj.name}: blocked, revoked", app_id=app_id)
        return {"ok": False, "stage": "gateway", "reason": "revoked", "actor": "legit"}
    gw = os.environ.get("FUSE_URL", "http://localhost:8000") + "/gateway/contacts"
    STATE.emit("attack", f"{app_obj.name}: vendor signs, routes through Fuse gateway (inline)", app_id=app_id)
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.post(f"{app_obj.vendor_url}/gateway-call/{app_obj.external_id}",
                         json={"gateway_url": gw})
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
    # remember the token + proof the vendor signed FOR THE GATEWAY, so a later
    # "replay captured proof" attack has something real (and already-used) to replay.
    if data.get("token"):
        STATE.last_gw_token[app_id] = data["token"]
    if data.get("proof"):
        STATE.last_gw_proof[app_id] = data["proof"]
    return {"ok": data.get("allowed", False), "actor": "legit",
            "stage": data.get("stage", "forwarded" if data.get("allowed") else "gateway"),
            "reason": data.get("reason"), "count": data.get("count"),
            "reached_company": bool(data.get("allowed")), "checks": data.get("checks", [])}


@app.post("/api/simulate/gateway-attack/{app_id}")
async def simulate_gateway_attack(app_id: str, kind: str):
    """Attacker runs against the gateway itself. Fuse plays the thief: it holds a
    stolen token but never the vendor's private key. Every variant is stopped
    AT the gateway, so the company is never reached - that is binding enforced."""
    app_obj = STATE.apps.get(app_id)
    if not app_obj:
        return JSONResponse({"error": "no such app"}, status_code=404)
    gw = os.environ.get("FUSE_URL", "http://localhost:8000") + "/gateway/contacts"
    label = {"bearer_replay": "stolen token, no proof",
             "forged_proof": "stolen token + attacker-forged proof",
             "proof_replay": "captured proof replayed"}.get(kind, kind)
    STATE.emit("attack", f"ATTACK on gateway ({app_obj.name}): {label}", app_id=app_id)

    headers = {}
    if kind == "proof_replay":
        token = STATE.last_gw_token.get(app_id)
        gproof = STATE.last_gw_proof.get(app_id)
        if not token or not gproof:
            STATE.emit("blocked", f"gateway: no captured proof yet - run the legit request first", app_id=app_id)
            return {"ok": False, "actor": "attacker", "stage": "gateway",
                    "reason": "no captured gateway proof - run the legit request first",
                    "reached_company": False, "checks": []}
        headers = {"Authorization": f"DPoP {token}", "DPoP": gproof}
    else:
        token = STATE.mint_for_app(app_obj)  # the "stolen" token
        if kind == "bearer_replay":
            headers = {"Authorization": f"DPoP {token}"}  # no proof at all
        elif kind == "forged_proof":
            attacker_key = crypto.generate_keypair()
            forged = crypto.create_dpop_proof(attacker_key, "GET", gw, access_token=token)
            headers = {"Authorization": f"DPoP {token}", "DPoP": forged}
        else:
            return JSONResponse({"error": "unknown attack"}, status_code=400)

    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.get(gw, headers=headers)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
    reached = bool(data.get("reached_company"))
    return {"ok": False, "actor": "attacker", "stage": data.get("stage", "gateway"),
            "reason": data.get("reason", "blocked"), "reached_company": reached,
            "checks": data.get("checks", [])}


@app.get("/api/apps/{app_id}/inspect")
def inspect(app_id: str):
    app_obj = STATE.apps.get(app_id)
    if not app_obj:
        return JSONResponse({"error": "no such app"}, status_code=404)
    out = {"app": app_obj.name, "platform": app_obj.platform, "scopes": app_obj.scopes,
           "token_kind": app_obj.token_kind, "key_thumbprint": app_obj.key_jkt, "meta": app_obj.meta}
    tok = STATE.last_token.get(app_id)
    if tok:
        try:
            out["token"] = {"raw": tok, "claims": crypto.verify_access_token(crypto.public_pem(STATE.key), tok),
                            "revoked": _is_revoked(app_id)}
        except Exception as e:
            out["token"] = {"raw": tok, "error": str(e)}
    if STATE.last_proof.get(app_id):
        out["last_proof"] = STATE.last_proof[app_id]
    return out


# ==========================================================================
# Token-monitoring grant inventory (the "extra backend" data) — served NATIVELY
# from this app on :8000 as JSON, rendered by the SPA's "Token Monitor" view.
# We read the same seeded SQLite store and reuse the collector's risk/activity
# logic (web.utils), so the rich detail (last used, by whom, consent chain,
# publisher, permissions, event history) is one app on one origin — no second
# service, no tenant/connector admin redundancy.
# ==========================================================================
import base64

os.environ.setdefault(
    "SECRET_ENCRYPTION_KEY",
    base64.urlsafe_b64encode(b"fuse-merged-demo-key-0123456789A"[:32]).decode(),
)
os.environ.setdefault(
    "DATABASE_URL", f"sqlite:///{os.path.join(os.path.dirname(HERE), 'fuse_monitor.db')}"
)

GRANTS_AVAILABLE = False
try:
    from web.config import get_settings as _grant_settings
    from web.db import init_db as _init_grant_db, new_session as _grant_session
    from web import models as _wm
    from web import utils as _wu

    _init_grant_db(_grant_settings().database_url)
    try:
        from web import seed as _grant_seed
        _grant_seed.seed()
        _grant_seed.seed_github()
    except Exception as _se:
        log.warning("grant seed skipped: %s", _se)
    GRANTS_AVAILABLE = True
    log.info("grant inventory available (native /api/grants)")
except Exception as _ge:  # pragma: no cover
    logging.getLogger("fuse").warning("grant inventory unavailable: %s", _ge)


_RISK_EXPLAIN = {
    "unverified-publisher": "The platform has not verified this app's publisher identity.",
    "user-consented": "A regular user (not an admin) granted these permissions. May exceed intended access.",
    "write-permissions": "This grant includes permissions that can modify, export or delete data.",
    "all-repos": "Access to all repositories in the org, including any created in future.",
    "broad-read": "Can read across the whole directory/org (e.g. *.Read.All) — sensitive even without write.",
    "many-permissions": "Holds a large set of permissions — a wide blast radius if the token is stolen.",
    "sp-disabled": "The service principal is disabled. No new tokens can be issued.",
    "never-used": "No sign-in activity has ever been recorded for this grant.",
    "dormant": "No activity recorded in over 90 days. Consider revoking if no longer needed.",
    "never-reconfigured": "Installed over 90 days ago and never changed. Confirm it still needs this access.",
}

_SIG_FALLBACK_LABELS = {"broad-read": "Broad read access", "many-permissions": "Many permissions"}


def _perm_signals(perms):
    """Permission-derived display signals (read breadth / count) so seeded grants
    get them too — the collector's signal logic only flags write."""
    out = []
    if any(risk.is_broad_read_scope(p) for p in (perms or [])):
        out.append({"key": "broad-read", "label": "Broad read access"})
    if len(perms or []) >= 5:
        out.append({"key": "many-permissions", "label": "Many permissions"})
    return out


def _iso_dt(dt):
    return dt.isoformat() if dt else None


def _compliance_checks(signal_keys, *, bound, lifetime_seconds=None, verified=None,
                       consent_type=None, account_enabled=None):
    """Per-connection compliance checklist (the same controls the Compliance view
    aggregates), returned as {label, ok, detail}. `signal_keys` is the set of
    normalized risk-signal keys for the connection."""
    sk = {(_wu.normalize_risk_signal(s) if isinstance(s, str) else s) for s in signal_keys}
    checks = []

    def add(label, ok, detail):
        checks.append({"label": label, "ok": bool(ok), "detail": detail})

    add("Sender-bound (DPoP)", bound,
        "Token is cryptographically bound to the vendor's key — a stolen copy is useless."
        if bound else "Stealable bearer token — not sender-bound. Bind it in Policy.")
    if lifetime_seconds is not None:
        short = lifetime_seconds <= 3600
        add("Short-lived token", short,
            f"Lifetime is {_fmt_lifetime(lifetime_seconds)} — within policy."
            if short else f"Lifetime is {_fmt_lifetime(lifetime_seconds)} — longer than the 1h target.")
    else:
        add("Short-lived token", False,
            "Long-lived / static credential with no enforced lifetime.")
    _least_priv = not (sk & {"write-permissions", "all-repos", "broad-read"})
    add("Least privilege", _least_priv,
        "No write/export/admin or broad directory-wide read access." if _least_priv
        else "Holds write/admin, all-repo, or broad *.Read.All access — over-privileged.")
    if verified is not None:
        add("Verified publisher", verified,
            "Publisher is verified by the platform." if verified else "Publisher is not verified.")
    elif "unverified-publisher" in sk:
        add("Verified publisher", False, "Publisher is not verified.")
    add("Active / recently used", "never-used" not in sk and "dormant" not in sk,
        "Recent activity recorded." if ("never-used" not in sk and "dormant" not in sk)
        else "Dormant or never used — candidate for revocation.")
    if consent_type is not None:
        admin = consent_type != "Principal"
        add("Admin-consented", admin,
            "Granted by an admin for all users." if admin else "User-consented — may exceed intended access.")
    if account_enabled is False:
        add("Service principal enabled", False, "The service principal is disabled.")

    compliant = all(c["ok"] for c in checks)
    failed = sum(1 for c in checks if not c["ok"])
    return {"compliant": compliant, "failed": failed, "total": len(checks), "checks": checks}


def _sig_label(s):
    n = _wu.normalize_risk_signal(s)
    return _wu.RISK_SIGNAL_LABELS.get(n) or _SIG_FALLBACK_LABELS.get(n, s)


def _consent_label(g, short=False):
    if g.consent_type == "Principal":
        return "User" if short else "User-consented"
    return "Admin" if short else "Admin consent (all users)"


def _latest_run(db, tenant_id):
    return (db.query(_wm.CollectionRun)
            .filter(_wm.CollectionRun.tenant_fk == tenant_id, _wm.CollectionRun.status == "success")
            .order_by(_wm.CollectionRun.finished_at.desc()).first())


def _grant_risk_score(signals, perms=None) -> int:
    """Risk score from the connection's signals AND its actual permissions, so a
    broad-read or many-permission token is never scored as 'safe'."""
    sigs = set(signals or [])
    perms = list(perms or [])
    s = 0
    has_write = any(risk.is_write_scope(p) for p in perms) or "write-permissions" in sigs
    has_broad = any(risk.is_broad_read_scope(p) for p in perms) or "all-repos" in sigs
    has_read = any(risk.is_read_scope(p) for p in perms)
    if has_write:      s += 45
    if has_broad:      s += 30
    elif has_read:     s += 12          # narrow read only
    if len(perms) >= 5: s += 12
    elif len(perms) >= 3: s += 6
    if "unverified-publisher" in sigs: s += 20
    if "user-consented" in sigs:       s += 12
    if "never-used" in sigs:           s += 18
    if any(str(x).startswith("dormant") for x in sigs): s += 12
    if "unbound-bearer" in sigs:       s += 10
    if "sp-disabled" in sigs:          s += 5
    return min(s, 100)


def _iter_seeded_rows(db):
    """Yield (tenant, GrantRow) for every active seeded grant across tenants."""
    for t in db.query(_wm.Tenant).order_by(_wm.Tenant.display_name).all():
        last_run = _latest_run(db, t.id)
        act = {}
        if last_run:
            for s in db.query(_wm.GrantActivitySnapshot).filter_by(run_id=last_run.id).all():
                act[s.grant_id] = s
        grants = (db.query(_wm.DBGrant)
                  .filter(_wm.DBGrant.tenant_fk == t.id, _wm.DBGrant.is_active == True)  # noqa: E712
                  .order_by(_wm.DBGrant.client_display_name).all())
        for r in _wu.build_grant_rows(grants, act):
            yield t, r


def _seeded_sessions():
    """Seeded grant inventory projected into the Dashboard 'session' shape."""
    if not GRANTS_AVAILABLE:
        return []
    db = _grant_session()
    out = []
    try:
        for t, r in _iter_seeded_rows(db):
            g = r.primary_grant
            score = _grant_risk_score(list(r.risk_signals), r.permissions)
            last = r.activity.last_sign_in if r.activity else None
            plat = "github" if (t.platform or "azure") == "github" else "azure"
            out.append({
                "id": f"g{g.id}", "vendor": g.client_display_name, "provider": plat,
                "platform": (t.platform or "azure").title(), "resource": t.display_name,
                "scope": " ".join(r.permissions) or "—", "expires_in": "Static Key",
                "risk_level": _risk_level(score), "is_critical": score >= 80,
                "last_seen": _iso_dt(last), "token_usage": score, "usage_limit": 100,
                "bound": False, "token_kind": "bearer", "governable": False, "revoked": False,
                "company": f"t{t.id}", "company_name": f"{t.display_name} (collected)",
            })
    finally:
        db.close()
    return out


def _live_grant_rows():
    """Live connector apps projected into the grant-inventory row shape."""
    rows = []
    for app_obj in STATE.apps.values():
        pol = STATE.policies.get(app_obj.id)
        meta = app_obj.meta or {}
        last = _last_activity_ts(app_obj.id) or meta.get("last_sign_in")
        sigs = risk.compute_risk_signals(app_obj, policy=pol, last_activity_ts=last)
        conn = STATE.connectors.get(app_obj.source)
        cid = STATE.connector_company.get(app_obj.source)
        rows.append({
            "id": app_obj.id, "vendor": app_obj.name, "app_id": app_obj.external_id or app_obj.id,
            "type": "application" if app_obj.token_kind in ("client_credentials", "installation", "application") else "delegated",
            "resource": conn.display_name if conn else app_obj.platform,
            "platform": _provider(app_obj.platform),
            "permissions": list(app_obj.scopes),
            "consent": ("User" if meta.get("consent_type") == "Principal" else "Admin") if meta.get("consent_type") else "—",
            "consented_by": meta.get("consented_by"),
            "last_used_ago": risk.timeago(last) if last else "—",
            "risk_signals": [{"key": s["key"], "label": s["label"]} for s in sigs],
            "risk": (_lr := _grant_risk_score([s["key"] for s in sigs], app_obj.scopes)),
            "risk_level": _risk_level(_lr),
            "first_seen": datetime.fromtimestamp(app_obj.created_at, tz=timezone.utc).strftime("%Y-%m-%d"),
            "_source": cid or "unassigned",
            "_kind": "live",
        })
    return rows


@app.get("/api/grants")
def api_grants(source: str = "all", type: str = "", risk: str = "",
               search: str = "", platform: str = "", include_inactive: bool = False):
    """Unified grant inventory grouped by COMPANY: live connector apps grouped
    by their connector's company, plus seeded collector tenants as companies."""
    sources = [{"id": "all", "name": "All companies", "platform": "mixed"}]

    all_rows = []
    if STATE.apps:
        all_rows += _live_grant_rows()
        # "Live connectors" aggregates every live company, plus a per-company filter
        live_cids = {r["_source"] for r in all_rows}
        if all_rows:
            sources.append({"id": "live", "name": "Live connectors (all)", "platform": "live"})
        for c in STATE.companies:
            if c["id"] in live_cids:
                sources.append({"id": c["id"], "name": c["name"], "platform": "company"})
        if "unassigned" in live_cids:
            sources.append({"id": "unassigned", "name": "Unassigned", "platform": "company"})

    if GRANTS_AVAILABLE:
        db = _grant_session()
        try:
            for t in db.query(_wm.Tenant).order_by(_wm.Tenant.display_name).all():
                sources.append({"id": f"t{t.id}", "name": f"{t.display_name} (demo)", "platform": t.platform or "azure"})
            for t, r in _iter_seeded_rows(db):
                g = r.primary_grant
                last = r.activity.last_sign_in if r.activity else None
                _seeded_sigs = [{"key": s, "label": _sig_label(s)} for s in r.risk_signals] + _perm_signals(r.permissions)
                _all_keys = [s["key"] for s in _seeded_sigs]
                all_rows.append({
                    "id": str(g.id), "vendor": g.client_display_name, "app_id": g.client_app_id,
                    "type": g.grant_type, "resource": g.resource_display_name,
                    "platform": "github" if (t.platform or "azure") == "github" else "azure",
                    "permissions": r.permissions,
                    "consent": _consent_label(g, short=True), "consented_by": g.consented_by_user_id,
                    "last_used_ago": _wu.timeago(last),
                    "risk_signals": _seeded_sigs,
                    "risk": (_sr := _grant_risk_score(_all_keys, r.permissions)),
                    "risk_level": _risk_level(_sr),
                    "first_seen": g.first_seen_at.strftime("%Y-%m-%d") if g.first_seen_at else None,
                    "_source": f"t{t.id}",
                    "_kind": "seeded",
                })
        finally:
            db.close()

    # filter
    def keep(r):
        if source == "live":
            if r.get("_kind") != "live":
                return False
        elif source != "all" and r.get("_source") != source:
            return False
        if platform and r.get("platform") != platform:
            return False
        if type in ("delegated", "application") and r["type"] != type:
            return False
        if search and search.lower() not in r["vendor"].lower():
            return False
        if risk and risk not in [_wu.normalize_risk_signal(s["key"]) for s in r["risk_signals"]]:
            return False
        return True

    rows = [r for r in all_rows if keep(r)]
    rows.sort(key=lambda r: r["vendor"].lower())

    total = len(rows)
    delegated = sum(1 for r in rows if r["type"] == "delegated")
    risk_counts = {}
    for r in rows:
        for s in r["risk_signals"]:
            k = _wu.normalize_risk_signal(s["key"])
            risk_counts[k] = risk_counts.get(k, 0) + 1
    stats = {"total": total, "delegated": delegated, "application": total - delegated, "risk": risk_counts}

    return {"available": True, "sources": sources, "source": source,
            "activity_available": True, "stats": stats, "rows": rows}


def _live_app_grant_detail(app_obj):
    pol = STATE.policies.get(app_obj.id)
    meta = app_obj.meta or {}
    last = _last_activity_ts(app_obj.id) or meta.get("last_sign_in")
    sigs = risk.compute_risk_signals(app_obj, policy=pol, last_activity_ts=last)
    conn = STATE.connectors.get(app_obj.source)
    events = [{"date": _iso(e["ts"]), "type": e.get("kind"), "detail": e.get("message")}
              for e in reversed(STATE.events) if e.get("app_id") == app_obj.id]
    return {
        "id": app_obj.id, "vendor": app_obj.name, "app_id": app_obj.external_id or app_obj.id,
        "sp_id": meta.get("sp_id") or (app_obj.key_jkt[:18] + "…" if app_obj.key_jkt else "—"),
        "type": "application" if app_obj.token_kind in ("client_credentials", "installation", "application") else "delegated",
        "platform": app_obj.platform, "tenant": conn.display_name if conn else app_obj.source,
        "resource": conn.display_name if conn else app_obj.platform, "resource_sp_id": "—",
        "is_active": app_obj.status != "revoked",
        "publisher": {"verified": meta.get("verified_publisher"),
                      "tenant": meta.get("publisher_tenant"),
                      "account_enabled": meta.get("account_enabled")},
        "consent": ("User-consented" if meta.get("consent_type") == "Principal" else "Admin consent (all users)") if meta.get("consent_type") else "—",
        "consented_by": meta.get("consented_by"),
        "governable": app_obj.governable, "holds_key": app_obj.holds_key,
        "bound": _is_bound(app_obj, pol),
        "policy": ({
            "lifetime_seconds": pol.lifetime_seconds, "lifetime_label": _fmt_lifetime(pol.lifetime_seconds),
            "allowed_scope": pol.allowed_scope, "binding_required": bool(pol.binding_required and app_obj.holds_key),
        } if pol else None),
        "created_at": _iso(app_obj.created_at), "first_seen": _iso(app_obj.created_at),
        "activity": {
            "last_sign_in_ago": risk.timeago(last) if last else "—",
            "last_sign_in_iso": _iso(last) if isinstance(last, (int, float)) else last,
            "last_app_only_ago": "—", "last_delegated_ago": "—", "last_modified_ago": None,
        },
        "permissions": [{"name": s, "write": risk.is_write_scope(s)} for s in app_obj.scopes],
        "risk_signals": sigs,
        "compliance": _compliance_checks(
            [s["key"] for s in sigs],
            bound=_is_bound(app_obj, pol),
            lifetime_seconds=(pol.lifetime_seconds if (pol and app_obj.governable) else None),
            verified=meta.get("verified_publisher"),
            consent_type=meta.get("consent_type"),
            account_enabled=meta.get("account_enabled")),
        "siblings": [],
        "events": events,
        "revoke_caveat": "Revoke cuts the outstanding token now. For connections Fuse can't cut at source, use the provider's own revoke screen.",
        "live": True,
        "can_revoke_here": _can_revoke_here(app_obj),
        "github": _github_revoke_info(app_obj),
        "provider_revoke": _provider_revoke_info(app_obj),
    }


def _can_revoke_here(app_obj):
    """True when Fuse can actually cut this connection (governable token, or a
    connector that implements remote revoke)."""
    if app_obj.governable:
        return True
    conn = STATE.connectors.get(app_obj.source)
    return bool(conn and conn.kind in ("github", "azure"))


def _provider_revoke_info(app_obj):
    """A link to the provider's own revoke screen, for connections Fuse can't
    cut from its side."""
    plat = (app_obj.platform or "").lower()
    meta = app_obj.meta or {}
    if "github" in plat:
        gh = _github_revoke_info(app_obj)
        return {"provider": "GitHub", "url": gh["settings_url"] if gh else "https://github.com/settings/installations",
                "label": "Open GitHub installations ↗"}
    if "azure" in plat or "entra" in plat:
        app_id = meta.get("client_app_id") or app_obj.external_id
        url = (f"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Permissions/objectId//appId/{app_id}"
               if app_id else
               "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/~/AppAppsPreview")
        return {"provider": "Microsoft Entra", "url": url, "label": "Open in Entra admin ↗"}
    if "salesforce" in plat:
        return {"provider": "Salesforce", "url": "https://login.salesforce.com/", "label": "Open Salesforce setup ↗"}
    return None


def _github_revoke_info(app_obj):
    """For GitHub-platform connections, the org + installation id so the UI can
    offer a Revoke GitHub action (delete installation / open GitHub settings)."""
    if "github" not in (app_obj.platform or "").lower():
        return None
    conn = STATE.connectors.get(app_obj.source)
    meta = app_obj.meta or {}
    org = meta.get("target") or (conn.config.get("org") if conn else None)
    install_id = app_obj.external_id or (conn.config.get("installation_id") if conn else None)
    return {
        "org": org, "installation_id": install_id,
        "settings_url": (f"https://github.com/organizations/{org}/settings/installations/{install_id}"
                         if org and install_id else
                         (f"https://github.com/settings/installations/{install_id}" if install_id else
                          "https://github.com/settings/installations")),
        "can_api_revoke": bool(conn and conn.kind == "github"),
    }


@app.get("/api/grant/{gid}")
def api_grant_detail(gid: str):
    """Full grant detail — dispatches to a live connector app or a seeded grant."""
    if gid in STATE.apps:
        return _live_app_grant_detail(STATE.apps[gid])
    if not GRANTS_AVAILABLE or not gid.isdigit():
        return JSONResponse({"error": "no such grant"}, status_code=404)
    db = _grant_session()
    try:
        g = db.get(_wm.DBGrant, int(gid))
        if not g:
            return JSONResponse({"error": "no such grant"}, status_code=404)
        tenant = db.get(_wm.Tenant, g.tenant_fk)
        platform = (tenant.platform or "azure") if tenant else "azure"
        last_run = _latest_run(db, g.tenant_fk)
        activity = None
        if last_run:
            activity = (db.query(_wm.GrantActivitySnapshot)
                        .filter_by(run_id=last_run.id, grant_id=g.id).first())
        risk_signals = _wu.compute_risk_signals(g, activity)

        siblings = []
        all_perms = list(g.permissions or [])
        if g.grant_type == "application":
            siblings = (db.query(_wm.DBGrant).filter(
                _wm.DBGrant.tenant_fk == g.tenant_fk,
                _wm.DBGrant.client_sp_id == g.client_sp_id,
                _wm.DBGrant.resource_sp_id == g.resource_sp_id,
                _wm.DBGrant.id != g.id).all())
            for s in siblings:
                all_perms += list(s.permissions or [])
        all_perms = sorted(set(all_perms))

        # augment the collector's signals with permission-derived ones (read
        # breadth / count) so the detail matches the Token Monitor row + score
        for _ps in _perm_signals(all_perms):
            if _ps["key"] not in risk_signals:
                risk_signals.append(_ps["key"])

        gids = [g.id] + [s.id for s in siblings]
        ev_rows = (db.query(_wm.GrantEvent, _wm.CollectionRun)
                   .join(_wm.CollectionRun, _wm.GrantEvent.run_id == _wm.CollectionRun.id)
                   .filter(_wm.GrantEvent.grant_id.in_(gids))
                   .order_by(_wm.CollectionRun.started_at.desc()).all())

        def _ev_detail(ev):
            d = ev.detail or {}
            if ev.event_type == "revoked":
                return d.get("action", "")
            if ev.event_type == "audit":
                return f"{d.get('actor','')} — {d.get('action','')}"
            if d.get("permissions"):
                return ", ".join(d["permissions"])
            return ""

        caveat = ("Deleting the grant stops new token issuance but does not invalidate tokens already "
                  "issued (~60 min TTL). Disabling the vendor app is the strongest containment. Requires "
                  "Application.ReadWrite.All." if platform == "azure"
                  else "Revoking removes the credential from the org immediately. GitHub App installs are "
                       "managed in GitHub settings.")

        return {
            "id": g.id, "vendor": g.client_display_name, "app_id": g.client_app_id,
            "sp_id": g.client_sp_id, "type": g.grant_type, "platform": platform,
            "tenant": tenant.display_name if tenant else None,
            "resource": g.resource_display_name, "resource_sp_id": g.resource_sp_id,
            "is_active": g.is_active,
            "publisher": {"verified": g.client_verified_publisher,
                          "tenant": g.client_publisher_tenant_id,
                          "account_enabled": g.client_account_enabled},
            "consent": _consent_label(g), "consented_by": g.consented_by_user_id,
            "created_at": _iso_dt(g.created_at), "first_seen": _iso_dt(g.first_seen_at),
            "activity": {
                "last_sign_in_ago": _wu.timeago(activity.last_sign_in) if activity else "—",
                "last_sign_in_iso": _iso_dt(activity.last_sign_in) if activity else None,
                "last_app_only_ago": _wu.timeago(activity.last_app_only_client) if activity else "—",
                "last_delegated_ago": _wu.timeago(activity.last_delegated_client) if activity else "—",
                "last_modified_ago": _wu.timeago(g.last_modified_at) if g.last_modified_at else None,
            },
            "permissions": [{"name": p, "write": risk.is_write_scope(p)} for p in all_perms],
            "risk_signals": [{"key": s, "label": _sig_label(s),
                              "explanation": _RISK_EXPLAIN.get(_wu.normalize_risk_signal(s), "")}
                             for s in risk_signals],
            "compliance": _compliance_checks(
                risk_signals, bound=False, lifetime_seconds=None,
                verified=g.client_verified_publisher, consent_type=g.consent_type,
                account_enabled=g.client_account_enabled),
            "siblings": [{"id": s.id, "permissions": s.permissions} for s in siblings],
            "events": [{"date": _iso_dt(run.started_at), "type": ev.event_type, "detail": _ev_detail(ev)}
                       for ev, run in ev_rows],
            "revoke_caveat": caveat,
        }
    finally:
        db.close()

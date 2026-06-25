"""
Fuse control-plane state for the reimagined console.

Holds connectors (manually connected), the apps and tokens they surface, the
policies Fuse enforces on the apps it can govern, the tokens Fuse has issued,
and the live event feed. Fuse's signing key is real; vendor private keys never
reach Fuse (only their registered public keys, via the demo-vendor connector).
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional

from common import crypto
from connectors import CONNECTOR_TYPES, App, Token


@dataclass
class Policy:
    lifetime_seconds: int = 300
    allowed_scope: str = ""
    binding_required: bool = False


class FuseState:
    def __init__(self) -> None:
        self.key = crypto.generate_keypair()
        self.kid = "fuse-key-1"
        self.token_aud = os.environ.get("FUSE_URL", "http://localhost:8000") + "/api/token"

        self.connectors: dict = {}            # cid -> Connector
        self.companies: list = []             # [{id, name}] logical grouping of connectors
        self.connector_company: dict = {}     # cid -> company_id
        self.apps: dict = {}                  # app_id -> App
        self._app_index: dict = {}            # (source, external_id) -> app_id
        self.policies: dict = {}              # app_id -> Policy
        self.visibility_tokens: dict = {}     # token_id -> Token (from connectors)
        self.issued: list = []                # Fuse-issued access tokens (dicts)
        self.revoked_jti: set = set()
        self.last_proof: dict = {}            # app_id -> last captured proof
        self.last_token: dict = {}            # app_id -> last issued token string
        self.last_gw_proof: dict = {}         # app_id -> last proof signed for the GATEWAY url
        self.last_gw_token: dict = {}         # app_id -> last token used at the GATEWAY

        self.events: list = []
        self.subscribers: set = set()

    # ---- events -----------------------------------------------------------
    def emit(self, kind: str, message: str, **extra) -> None:
        e = {"ts": time.time(), "kind": kind, "message": message, **extra}
        self.events.append(e)
        self.events = self.events[-200:]
        for q in list(self.subscribers):
            try:
                q.put_nowait(e)
            except Exception:
                self.subscribers.discard(q)

    # ---- companies (lightweight logical grouping of connectors) -----------
    def add_company(self, name: str) -> dict:
        name = (name or "").strip() or "Untitled company"
        existing = next((c for c in self.companies if c["name"].lower() == name.lower()), None)
        if existing:
            return existing
        comp = {"id": f"co-{uuid.uuid4().hex[:6]}", "name": name}
        self.companies.append(comp)
        return comp

    # ---- connectors -------------------------------------------------------
    def add_connector(self, kind: str, config: dict, company_id: Optional[str] = None) -> Optional[str]:
        cls = CONNECTOR_TYPES.get(kind)
        if not cls:
            return None
        cid = f"conn-{kind}-{uuid.uuid4().hex[:6]}"
        self.connectors[cid] = cls(cid, config)
        if company_id and any(c["id"] == company_id for c in self.companies):
            self.connector_company[cid] = company_id
        return cid

    def remove_connector(self, cid: str) -> None:
        conn = self.connectors.pop(cid, None)
        self.connector_company.pop(cid, None)
        if not conn:
            return
        # drop this source's apps + visibility tokens
        for app_id in [a for a, app in self.apps.items() if app.source == cid]:
            self.apps.pop(app_id, None)
            self.policies.pop(app_id, None)
            self._app_index = {k: v for k, v in self._app_index.items() if v != app_id}
        self.visibility_tokens = {t: tok for t, tok in self.visibility_tokens.items() if tok.source != cid}

    async def connect_connector(self, cid: str) -> tuple[bool, str]:
        conn = self.connectors.get(cid)
        if not conn:
            return False, "no such connector"
        ok, msg = await conn.connect()
        self.emit("connector", f"{conn.display_name}: {msg}", cid=cid, ok=ok)
        if ok:
            await self.sync_connector(cid)
        return ok, msg

    async def sync_connector(self, cid: str) -> None:
        conn = self.connectors.get(cid)
        if not conn or not conn.connected:
            return
        apps, tokens = await conn.sync()
        for app in apps:
            self._upsert_app(app)
        # replace this source's visibility tokens
        self.visibility_tokens = {t: tok for t, tok in self.visibility_tokens.items() if tok.source != cid}
        for tok in tokens:
            self.visibility_tokens[tok.id] = tok
        self.emit("sync", f"{conn.display_name}: synced {len(apps)} apps, {len(tokens)} tokens", cid=cid)

    def _upsert_app(self, app: App) -> None:
        key = (app.source, app.external_id or app.name)
        existing_id = self._app_index.get(key)
        if existing_id and existing_id in self.apps:
            # keep id + policy; refresh fields
            old = self.apps[existing_id]
            app.id = old.id
            app.created_at = old.created_at
            self.apps[old.id] = app
        else:
            self.apps[app.id] = app
            self._app_index[key] = app.id
            lifetime = int(app.meta.get("lifetime", 3600))
            self.policies[app.id] = Policy(
                lifetime_seconds=lifetime,
                allowed_scope=" ".join(app.scopes),
                binding_required=False,
            )

    # ---- policy -----------------------------------------------------------
    def policy_for(self, app_id: str) -> Optional[Policy]:
        return self.policies.get(app_id)

    async def revoke_app(self, app_id: str) -> tuple[bool, str]:
        app = self.apps.get(app_id)
        if not app:
            return False, "no such app"
        app.status = "revoked"
        # kill any outstanding Fuse token for this app
        tok = self.last_token.get(app_id)
        if tok:
            try:
                claims = crypto.verify_access_token(crypto.public_pem(self.key), tok)
                self.revoked_jti.add(claims["jti"])
            except Exception:
                pass
        # if it came from a connector that can revoke at the source, do it for real
        detail = "access cut (local)"
        conn = self.connectors.get(app.source)
        if conn:
            ok, msg = await conn.revoke_app(app)
            if ok:
                detail = f"cut at source - {msg}"
            elif "does not support" not in msg:
                detail = f"local revoke; source action failed: {msg}"
        self.emit("revoke", f"{app.name}: {detail}", app_id=app_id)
        return True, detail

    def restore_app(self, app_id: str) -> None:
        app = self.apps.get(app_id)
        if app:
            app.status = "active"
            self.emit("policy", f"{app.name}: restored", app_id=app_id)

    def apply_bulk(self, flt: dict, policy: dict, action: Optional[str]) -> int:
        """Apply a policy (and/or revoke) to every app matching the filter:
        platform, token_kind, governable, min_risk."""
        n = 0
        for app in list(self.apps.values()):
            if flt.get("platform") and app.platform != flt["platform"]:
                continue
            if flt.get("token_kind") and app.token_kind != flt["token_kind"]:
                continue
            if flt.get("governable") is not None and app.governable != flt["governable"]:
                continue
            if flt.get("min_risk") and app.risk() < int(flt["min_risk"]):
                continue
            pol = self.policies.get(app.id)
            if pol:
                if "lifetime_seconds" in policy:
                    pol.lifetime_seconds = int(policy["lifetime_seconds"])
                if "allowed_scope" in policy:
                    pol.allowed_scope = policy["allowed_scope"]
                if "binding_required" in policy and app.holds_key:
                    pol.binding_required = bool(policy["binding_required"])
            n += 1
        if policy or action:
            label = []
            if flt:
                label.append("where " + ", ".join(f"{k}={v}" for k, v in flt.items()))
            self.emit("policy", f"bulk policy applied to {n} app(s) " + " ".join(label))
        return n

    # ---- token issuance ---------------------------------------------------
    def mint_for_app(self, app: App) -> str:
        pol = self.policies.get(app.id) or Policy()
        bound = app.key_jkt if (pol.binding_required and app.holds_key) else None
        token, claims = crypto.issue_access_token(
            crypto.private_pem(self.key), self.kid,
            connection_id=app.id, vendor=app.name,
            scope=pol.allowed_scope or " ".join(app.scopes),
            bound_jkt=bound, lifetime_seconds=pol.lifetime_seconds,
        )
        self.last_token[app.id] = token
        self.issued.insert(0, {
            "id": claims["jti"][:8], "app_id": app.id, "app": app.name,
            "scope": claims["scope"], "iat": claims["iat"], "exp": claims["exp"],
            "jti": claims["jti"], "bound_jkt": bound, "kind": "bound" if bound else "bearer",
        })
        self.issued = self.issued[:50]
        return token

    def issued_view(self) -> list:
        now = time.time()
        out = []
        for t in self.issued:
            status = "active"
            if t["jti"] in self.revoked_jti:
                status = "revoked"
            elif now > t["exp"]:
                status = "expired"
            out.append({**t, "status": status,
                        "sender_bound": bool(t["bound_jkt"]),
                        "ttl_seconds": int(t["exp"] - now)})
        return out

    def tokens_view(self) -> list:
        """All tokens for the Tokens view: Fuse-issued + connector visibility."""
        rows = self.issued_view()
        for tok in self.visibility_tokens.values():
            d = tok.to_dict()
            app = self.apps.get(d["app_id"])
            rows.append({
                "id": d["id"][:8], "app_id": d["app_id"],
                "app": app.name if app else d["app_id"],
                "scope": d["scope"], "exp": d["expires_at"], "iat": d["issued_at"],
                "jti": d.get("jti"), "bound_jkt": d["bound_jkt"], "kind": d["kind"],
                "status": d["status"], "sender_bound": d["sender_bound"],
                "ttl_seconds": d["ttl_seconds"], "note": d["note"],
            })
        return rows


STATE = FuseState()

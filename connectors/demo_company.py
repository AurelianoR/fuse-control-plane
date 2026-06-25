"""Demo company connector: pulls the vendor tokens the company platform sees."""
from __future__ import annotations

import time
import httpx

from .base import App, Token, Connector, new_id


class DemoCompanyConnector(Connector):
    kind = "demo_company"
    display_name = "Demo Company Platform"
    config_fields = [("url", "Company API URL", False)]

    async def connect(self) -> tuple[bool, str]:
        url = self.config.get("url")
        if not url:
            return False, "company URL required"
        try:
            async with httpx.AsyncClient(timeout=6.0) as c:
                r = await c.get(f"{url}/discover")
            if r.status_code != 200:
                return False, f"discover failed ({r.status_code})"
        except Exception as e:
            return False, f"cannot reach company: {e}"
        self.connected = True
        self.connected_at = time.time()
        self.status_detail = "connected - platform granted read access"
        return True, "connected"

    async def sync(self) -> tuple[list, list]:
        url = self.config.get("url")
        apps, tokens = [], []
        try:
            async with httpx.AsyncClient(timeout=6.0) as c:
                r = await c.get(f"{url}/discover")
            data = r.json()
        except Exception:
            self.status_detail = "sync failed"
            return [], []
        now = time.time()
        for d in data.get("vendors", []):
            last_used = d.get("last_used_days")
            last_sign_in = None if last_used is None else now - float(last_used) * 86400
            meta = {
                "lifetime": d.get("lifetime", 3600),
                "grant_type": d.get("grant_type", "application"),
                "client_app_id": d.get("client_app_id"),
                "publisher_tenant": d.get("publisher_tenant"),
                "verified_publisher": d.get("verified_publisher"),
                "account_enabled": d.get("account_enabled", True),
                "consent_type": d.get("consent_type"),
                "consented_by": d.get("consented_by"),
                "last_sign_in": last_sign_in,
                "last_used_by": d.get("last_used_by"),
            }
            app = App(
                id=new_id("app"), name=d["vendor"], source=self.id,
                platform=d.get("platform", "SaaS"), scopes=d.get("scope", "").split(),
                token_kind="bearer", governable=False, holds_key=False,
                external_id=d["vendor"], meta=meta,
            )
            if d.get("age_days"):
                app.created_at = now - float(d["age_days"]) * 86400
            apps.append(app)
            # surface the real bearer token this platform holds for the vendor
            lifetime = d.get("lifetime")
            tokens.append(Token(
                id=d.get("token_id") or new_id("tok"), app_id=app.id, source=self.id,
                kind="bearer", scope=d.get("scope", ""),
                issued_at=app.created_at,
                expires_at=None if not lifetime else now + float(lifetime),
                note="bearer token the platform issued to this vendor (stealable)",
            ))
        self.last_sync = time.time()
        self.status_detail = f"connected - {len(apps)} apps discovered"
        return apps, tokens

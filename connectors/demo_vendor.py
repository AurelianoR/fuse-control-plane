"""Demo vendor connector: the vendor presents its public key and is governable."""
from __future__ import annotations

import time
import httpx
from jwcrypto import jwk

from .base import App, Token, Connector, new_id


class DemoVendorConnector(Connector):
    kind = "demo_vendor"
    display_name = "Demo Vendor"
    config_fields = [("url", "Vendor service URL", False)]

    async def connect(self) -> tuple[bool, str]:
        url = self.config.get("url")
        if not url:
            return False, "vendor URL required"
        try:
            async with httpx.AsyncClient(timeout=6.0) as c:
                r = await c.get(f"{url}/identity")
            if r.status_code != 200:
                return False, f"identity failed ({r.status_code})"
        except Exception as e:
            return False, f"cannot reach vendor: {e}"
        self.connected = True
        self.connected_at = time.time()
        self.status_detail = "connected - vendor registered a key"
        return True, "connected"

    async def sync(self) -> tuple[list, list]:
        url = self.config.get("url")
        apps = []
        try:
            async with httpx.AsyncClient(timeout=6.0) as c:
                r = await c.get(f"{url}/identity")
            data = r.json()
        except Exception:
            self.status_detail = "sync failed"
            return [], []
        for v in data.get("vendors", []):
            pub = v["public_jwk"]
            jkt = jwk.JWK(**pub).thumbprint()
            apps.append(App(
                id=new_id("app"), name=v["vendor"], source=self.id,
                platform=v.get("platform", "Salesforce"),
                scopes=v.get("scope", "").split(),
                token_kind="bound", governable=True, holds_key=True,
                key_jkt=jkt, vendor_url=url, external_id=v["vendor"],
                meta={"public_jwk": pub, "lifetime": v.get("lifetime", 3600),
                      "grant_type": "delegated", "verified_publisher": True,
                      "account_enabled": True, "consent_type": "AllPrincipals",
                      "consented_by": "admin (tenant-wide)",
                      "last_used_by": "vendor service (private_key_jwt + DPoP)"},
            ))
        self.last_sync = time.time()
        self.status_detail = f"connected - {len(apps)} governable app(s)"
        return apps, []

"""
Azure / Entra connector - authenticates with an app registration using client
credentials (the realistic way an always-on governance tool reads tenant-wide
third-party access). Flow:

  1. POST client_id + client_secret to the tenant token endpoint, scope
     https://graph.microsoft.com/.default -> a real Graph access token Fuse holds.
  2. List servicePrincipals (enterprise apps / third-party apps in the tenant).
  3. List oauth2PermissionGrants (which app was granted which delegated scopes).

Needs an app registration with application permissions (e.g. Application.Read.All,
Directory.Read.All) and admin consent. Secrets are entered in the dashboard at
runtime, never here. Cannot be reached from the build sandbox; test in your tenant.
"""
from __future__ import annotations

import time
import httpx

from .base import App, Token, Connector, new_id

GRAPH = "https://graph.microsoft.com/v1.0"


class AzureConnector(Connector):
    kind = "azure"
    display_name = "Azure / Entra ID"
    config_fields = [
        ("tenant_id", "Tenant ID", False),
        ("client_id", "Client (app) ID", False),
        ("client_secret", "Client secret", True),
    ]

    def __init__(self, conn_id: str, config: dict):
        super().__init__(conn_id, config)
        self._token = None
        self._token_expires = None

    async def _get_token(self) -> tuple[bool, str]:
        t = self.config.get("tenant_id")
        cid = self.config.get("client_id")
        sec = self.config.get("client_secret")
        if not (t and cid and sec):
            return False, "tenant_id, client_id and client_secret required"
        url = f"https://login.microsoftonline.com/{t}/oauth2/v2.0/token"
        data = {"client_id": cid, "client_secret": sec,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.post(url, data=data)
        except Exception as e:
            return False, f"token endpoint unreachable: {e}"
        if r.status_code != 200:
            return False, f"token failed ({r.status_code}): {r.text[:160]}"
        body = r.json()
        self._token = body["access_token"]
        self._token_expires = time.time() + int(body.get("expires_in", 3600))
        return True, "graph token acquired"

    async def connect(self) -> tuple[bool, str]:
        ok, msg = await self._get_token()
        if not ok:
            self.status_detail = msg
            return False, msg
        self.connected = True
        self.connected_at = time.time()
        self.status_detail = "connected - Graph token active"
        return True, "connected"

    async def revoke_app(self, app) -> tuple[bool, str]:
        """Actually cut this enterprise app's access: delete its delegated
        permission grants and disable its service principal. Needs write
        permissions (e.g. Directory.ReadWrite.All); reports cleanly if missing."""
        if not self._token:
            ok, msg = await self._get_token()
            if not ok:
                return False, msg
        sp_id = app.meta.get("sp_id")
        if not sp_id:
            return False, "no service principal id"
        h = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        deleted, disabled, errs = 0, False, []
        try:
            async with httpx.AsyncClient(timeout=12.0) as c:
                g = await c.get(f"{GRAPH}/servicePrincipals/{sp_id}/oauth2PermissionGrants", headers=h)
                if g.status_code == 200:
                    for grant in g.json().get("value", []):
                        d = await c.delete(f"{GRAPH}/oauth2PermissionGrants/{grant['id']}", headers=h)
                        if d.status_code in (204, 200):
                            deleted += 1
                        else:
                            errs.append(f"grant {d.status_code}")
                p = await c.patch(f"{GRAPH}/servicePrincipals/{sp_id}",
                                  headers=h, json={"accountEnabled": False})
                if p.status_code in (204, 200):
                    disabled = True
                elif p.status_code not in (403,):
                    errs.append(f"disable {p.status_code}")
                if p.status_code == 403 or (g.status_code == 403):
                    return False, "Graph denied write (app needs Directory.ReadWrite.All + admin consent)"
        except Exception as e:
            return False, f"graph error: {e}"
        msg = f"revoked: deleted {deleted} grant(s)" + (", disabled service principal" if disabled else "")
        if errs:
            msg += f" (partial: {', '.join(errs)})"
        return True, msg

    async def sync(self) -> tuple[list, list]:
        if not self._token or (self._token_expires and self._token_expires < time.time() + 60):
            ok, msg = await self._get_token()
            if not ok:
                self.status_detail = msg
                return [], []
        h = {"Authorization": f"Bearer {self._token}"}
        apps, tokens = [], []
        grants_by_client: dict = {}
        try:
            async with httpx.AsyncClient(timeout=12.0) as c:
                g = await c.get(f"{GRAPH}/oauth2PermissionGrants?$top=200", headers=h)
                if g.status_code == 200:
                    for grant in g.json().get("value", []):
                        grants_by_client.setdefault(grant.get("clientId"), []).extend(
                            (grant.get("scope") or "").split())
                sp = await c.get(
                    f"{GRAPH}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,tags&$top=100",
                    headers=h)
            if sp.status_code != 200:
                self.status_detail = f"servicePrincipals failed ({sp.status_code})"
                return [], []
            for s in sp.json().get("value", []):
                tags = s.get("tags") or []
                # Third-party enterprise apps the tenant has consented to.
                if s.get("servicePrincipalType") != "Application":
                    continue
                scopes = sorted(set(grants_by_client.get(s.get("id"), [])))
                apps.append(App(
                    id=new_id("az"), name=s.get("displayName", "app"), source=self.id,
                    platform="Azure", scopes=scopes or ["(no delegated grants)"],
                    token_kind="oauth", governable=False, holds_key=False,
                    external_id=s.get("appId"),
                    meta={"sp_id": s.get("id"), "tags": tags},
                ))
        except Exception as e:
            self.status_detail = f"connected, sync error: {e}"
            return apps, tokens

        tokens.append(Token(
            id=new_id("tok"), app_id="azure-graph", source=self.id,
            kind="client_credentials",
            scope="https://graph.microsoft.com/.default",
            expires_at=self._token_expires, bound_jkt=None,
            note="real Graph client-credentials token - bearer, not sender-bound",
        ))
        self.last_sync = time.time()
        self.status_detail = f"connected - {len(apps)} enterprise app(s), 1 live token"
        return apps, tokens

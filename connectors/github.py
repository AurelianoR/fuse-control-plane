"""
GitHub connector - authenticates as a GitHub App (the realistic way a security
product integrates). Flow:

  1. Sign a short-lived App JWT (RS256) with the app's private key.
  2. Exchange it for an installation access token (a real, ~1h token Fuse holds).
  3. Use that token to enumerate what it can reach, and - if the app has org
     admin permission - the org's other installed GitHub Apps.

Nothing here is mocked. Supply a real App ID + private key (.pem) + installation
or org at runtime in the dashboard. Secrets are entered in the app, never here.
"""
from __future__ import annotations

import time
import httpx

from common import crypto
from .base import App, Token, Connector, new_id

API = "https://api.github.com"


class GitHubConnector(Connector):
    kind = "github"
    display_name = "GitHub (GitHub App)"
    config_fields = [
        ("app_id", "GitHub App ID", False),
        ("private_key_pem", "App private key (PEM contents)", True),
        ("installation_id", "Installation ID (optional)", False),
        ("org", "Org login (optional, for app inventory)", False),
    ]

    def __init__(self, conn_id: str, config: dict):
        super().__init__(conn_id, config)
        self._inst_token = None
        self._inst_expires = None
        self._permissions = {}

    async def _installation_token(self) -> tuple[bool, str]:
        app_id = self.config.get("app_id")
        pem = self.config.get("private_key_pem")
        if not app_id or not pem:
            return False, "app_id and private_key_pem required"
        try:
            app_jwt = crypto.github_app_jwt(app_id, pem)
        except Exception as e:
            return False, f"could not sign app JWT (bad private key?): {e}"
        headers = {"Authorization": f"Bearer {app_jwt}",
                   "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        inst_id = self.config.get("installation_id")
        async with httpx.AsyncClient(timeout=10.0) as c:
            if not inst_id:
                r = await c.get(f"{API}/app/installations", headers=headers)
                if r.status_code != 200:
                    return False, f"list installations failed ({r.status_code}): {r.text[:140]}"
                items = r.json()
                if not items:
                    return False, "app has no installations"
                inst_id = items[0]["id"]
                self.config["installation_id"] = str(inst_id)
            r = await c.post(f"{API}/app/installations/{inst_id}/access_tokens", headers=headers)
        if r.status_code not in (200, 201):
            return False, f"installation token failed ({r.status_code}): {r.text[:140]}"
        body = r.json()
        self._inst_token = body["token"]
        self._inst_expires = body.get("expires_at")
        self._permissions = body.get("permissions", {})
        return True, "installation token minted"

    async def connect(self) -> tuple[bool, str]:
        ok, msg = await self._installation_token()
        if not ok:
            self.status_detail = msg
            return False, msg
        self.connected = True
        self.connected_at = time.time()
        self.status_detail = "connected - installation token active"
        return True, "connected"

    async def revoke_app(self, app) -> tuple[bool, str]:
        """Cut access by deleting the app's installation (needs the app's own
        private key; only works for installations this GitHub App manages)."""
        app_id = self.config.get("app_id")
        pem = self.config.get("private_key_pem")
        inst = app.external_id or self.config.get("installation_id")
        if not (app_id and pem and inst):
            return False, "app credentials + installation id required"
        try:
            app_jwt = crypto.github_app_jwt(app_id, pem)
        except Exception as e:
            return False, f"could not sign app JWT: {e}"
        headers = {"Authorization": f"Bearer {app_jwt}",
                   "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.delete(f"{API}/app/installations/{inst}", headers=headers)
        except Exception as e:
            return False, f"github error: {e}"
        if r.status_code == 204:
            return True, "installation deleted - access cut"
        return False, f"delete failed ({r.status_code}): {r.text[:120]}"

    async def sync(self) -> tuple[list, list]:
        # Installation tokens are short-lived and cheap to mint; refresh if absent.
        if not self._inst_token:
            ok, msg = await self._installation_token()
            if not ok:
                self.status_detail = msg
                return [], []
        apps, tokens = [], []
        ith = {"Authorization": f"Bearer {self._inst_token}",
               "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}

        # The installation token itself is a real token Fuse now holds.
        exp = None
        if self._inst_expires:
            try:
                exp = time.mktime(time.strptime(self._inst_expires, "%Y-%m-%dT%H:%M:%SZ"))
            except Exception:
                exp = None
        scope_str = " ".join(f"{k}:{v}" for k, v in self._permissions.items())

        org = self.config.get("org")
        listed = 0
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                if org:
                    # Real third-party app inventory: GitHub Apps installed on the org.
                    r = await c.get(f"{API}/orgs/{org}/installations", headers=ith)
                    if r.status_code == 200:
                        for it in r.json().get("installations", []):
                            apps.append(App(
                                id=new_id("gh"), name=it.get("app_slug", "github-app"),
                                source=self.id, platform="GitHub",
                                scopes=[f"{k}:{v}" for k, v in (it.get("permissions") or {}).items()],
                                token_kind="installation", governable=False, holds_key=False,
                                external_id=str(it.get("id")),
                                meta={"app_id": it.get("app_id"), "target": it.get("account", {}).get("login")},
                            ))
                            listed += 1
                if listed == 0:
                    # Fallback: surface the repositories this token can reach.
                    r = await c.get(f"{API}/installation/repositories", headers=ith)
                    if r.status_code == 200:
                        repos = [x["full_name"] for x in r.json().get("repositories", [])]
                        apps.append(App(
                            id=new_id("gh"), name="this GitHub App installation", source=self.id,
                            platform="GitHub", scopes=list(self._permissions.keys()),
                            token_kind="installation", governable=False, holds_key=False,
                            external_id=str(self.config.get("installation_id")),
                            meta={"repositories": repos[:25], "repo_count": len(repos)},
                        ))
        except Exception as e:
            self.status_detail = f"connected, sync error: {e}"

        tokens.append(Token(
            id=new_id("tok"), app_id=apps[0].id if apps else "github",
            source=self.id, kind="installation", scope=scope_str,
            expires_at=exp, bound_jkt=None,
            note="real GitHub installation token - bearer, not sender-bound",
        ))
        self.last_sync = time.time()
        self.status_detail = f"connected - {len(apps)} app(s), 1 live token"
        return apps, tokens

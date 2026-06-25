"""
Connector framework: each connector is a source of token + app visibility.

A connector authenticates to some system (the demo company, the demo vendor, a
real GitHub org via a GitHub App, a real Azure tenant via client credentials)
and normalizes what it finds into two record types the console understands:

  App   - a third-party integration that holds access to your data.
  Token - an actual credential, with scope / lifetime / binding state.

Connecting is always MANUAL: the user supplies config and clicks Connect.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class App:
    id: str
    name: str
    source: str                       # connector id this came from
    platform: str                     # "GitHub", "Azure", "Salesforce", ...
    scopes: list = field(default_factory=list)
    token_kind: str = "bearer"        # bearer | bound | installation | oauth | client_credentials
    governable: bool = False          # can Fuse issue/bind tokens for this app?
    holds_key: bool = False           # has a registered sender-binding key?
    key_jkt: Optional[str] = None
    vendor_url: Optional[str] = None  # if Fuse can drive it
    external_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    status: str = "active"            # active | revoked
    meta: dict = field(default_factory=dict)

    def risk(self) -> int:
        s = 0
        joined = " ".join(self.scopes).lower()
        if any(w in joined for w in ("write", "export", "full", "admin", "directory.read.all", "all")):
            s += 45
        elif "read" in joined:
            s += 15
        if self.token_kind in ("bearer", "oauth", "client_credentials", "installation") and not self.holds_key:
            s += 25
        age_days = (time.time() - self.created_at) / 86400
        if age_days > 180:
            s += 15
        return min(s, 100)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk()
        return d


@dataclass
class Token:
    id: str
    app_id: str
    source: str
    kind: str                          # bound | bearer | installation | client_credentials
    scope: str = ""
    issued_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    bound_jkt: Optional[str] = None
    jti: Optional[str] = None
    status: str = "active"            # active | expired | revoked
    note: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        now = time.time()
        if self.status == "active" and self.expires_at and now > self.expires_at:
            d["status"] = "expired"
        d["sender_bound"] = self.bound_jkt is not None
        d["ttl_seconds"] = int(self.expires_at - now) if self.expires_at else None
        return d


class Connector:
    """Base connector. Subclasses implement connect() and sync()."""
    kind = "base"
    display_name = "Connector"
    # config fields the UI should prompt for: list of (name, label, secret?)
    config_fields: list = []

    def __init__(self, conn_id: str, config: dict):
        self.id = conn_id
        self.config = config or {}
        self.connected = False
        self.status_detail = "not connected"
        self.connected_at: Optional[float] = None
        self.last_sync: Optional[float] = None

    async def connect(self) -> tuple[bool, str]:
        raise NotImplementedError

    async def sync(self) -> tuple[list, list]:
        """Return (apps, tokens). Default: nothing."""
        return [], []

    async def revoke_app(self, app) -> tuple[bool, str]:
        """Actually cut an app's access at the source. Default: not supported."""
        return False, "this connector does not support remote revoke"

    def disconnect(self) -> None:
        self.connected = False
        self.status_detail = "disconnected"
        self.connected_at = None

    def summary(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "display_name": self.display_name,
            "connected": self.connected,
            "status_detail": self.status_detail,
            "connected_at": self.connected_at,
            "last_sync": self.last_sync,
            "config_fields": self.config_fields,
            # never leak secret values back to the UI
            "config_present": {k: bool(self.config.get(k)) for k, *_ in self.config_fields},
        }


# Populated in connectors/__init__.py
CONNECTOR_TYPES: dict = {}


def new_id(prefix: str = "app") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

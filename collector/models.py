from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


@dataclass
class SPActivity:
    last_sign_in: datetime | None = None
    last_app_only_client: datetime | None = None
    last_delegated_client: datetime | None = None


@dataclass
class Grant:
    id: str
    grant_type: Literal["delegated", "application"]

    client_sp_id: str
    client_app_id: str
    client_display_name: str
    client_publisher_tenant_id: str | None
    client_verified_publisher: bool
    client_account_enabled: bool

    resource_sp_id: str
    resource_display_name: str

    permissions: list[str]

    consent_type: str | None
    consented_by_user_id: str | None

    # Only available on application grants (appRoleAssignment.createdDateTime)
    created_at: datetime | None
    # Collector-assigned; preserved across runs
    first_seen_at: datetime

    activity: SPActivity | None = None

    @property
    def risk_signals(self) -> list[str]:
        signals = []
        if not self.client_verified_publisher:
            signals.append("unverified-publisher")
        if self.consent_type == "Principal":
            signals.append("user-consented")
        if any("Write" in p or "ReadWrite" in p for p in self.permissions):
            signals.append("write-permissions")
        if not self.client_account_enabled:
            signals.append("sp-disabled")
        if self.activity is not None:
            if self.activity.last_sign_in is None:
                signals.append("never-used")
            else:
                days = (datetime.now(timezone.utc) - self.activity.last_sign_in).days
                if days > 90:
                    signals.append(f"dormant-{days}d")
        return signals

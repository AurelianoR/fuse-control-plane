from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Request

from web.models import DBGrant, GrantActivitySnapshot


@dataclass
class GrantRow:
    """A display row in the grant list — one delegated grant or a group of application grants."""
    primary_grant: DBGrant
    permissions: list[str]
    grant_ids: list[int]
    activity: GrantActivitySnapshot | None
    risk_signals: list[str]


def compute_risk_signals(
    grant: DBGrant,
    activity: GrantActivitySnapshot | None,
    all_permissions: list[str] | None = None,
) -> list[str]:
    signals = []
    if not grant.client_verified_publisher:
        signals.append("unverified-publisher")
    if grant.consent_type == "Principal":
        signals.append("user-consented")
    perms = all_permissions if all_permissions is not None else (grant.permissions or [])
    # Azure: "Mail.ReadWrite"; GitHub App: "contents:write", "administration:admin"
    # GitHub OAuth: "repo", "admin:org", "delete_repo", "gist", "workflow" etc.
    _OAUTH_WRITE = frozenset({
        "repo", "public_repo", "delete_repo", "gist", "workflow",
        "write:packages", "write:org", "write:discussion",
        "admin:org", "admin:repo_hook", "admin:public_key", "admin:gpg_key",
        "admin:enterprise",
    })
    if any("Write" in p or ":write" in p or ":admin" in p or p in _OAUTH_WRITE for p in perms):
        signals.append("write-permissions")
    if "all-repositories" in perms:
        signals.append("all-repos")
    if not grant.client_account_enabled:
        signals.append("sp-disabled")
    if activity is not None:
        if activity.last_sign_in is None:
            signals.append("never-used")
        else:
            days = _days_ago(activity.last_sign_in)
            if days > 90:
                signals.append(f"dormant-{days}d")
    # GitHub App installs: flag if config has never changed since installation day.
    if grant.last_modified_at and grant.created_at:
        diff_s = abs(
            (_ensure_utc(grant.last_modified_at) - _ensure_utc(grant.created_at))
            .total_seconds()
        )
        if diff_s < 300 and _days_ago(grant.created_at) > 90:
            signals.append("never-reconfigured")
    return signals


def build_grant_rows(
    grants: list[DBGrant],
    activity_by_grant_id: dict[int, GrantActivitySnapshot],
) -> list[GrantRow]:
    """Merge application grants by (client_sp_id, resource_sp_id) into single display rows."""
    rows: list[GrantRow] = []
    # Group application grants by (client_sp_id, resource_sp_id)
    app_groups: dict[tuple, dict] = {}

    for g in grants:
        if g.grant_type == "delegated":
            act = activity_by_grant_id.get(g.id)
            rows.append(GrantRow(
                primary_grant=g,
                permissions=list(g.permissions or []),
                grant_ids=[g.id],
                activity=act,
                risk_signals=compute_risk_signals(g, act),
            ))
        else:
            key = (g.client_sp_id, g.resource_sp_id)
            if key not in app_groups:
                app_groups[key] = {
                    "primary": g,
                    "permissions": [],
                    "grant_ids": [],
                    "activity": activity_by_grant_id.get(g.id),
                }
            app_groups[key]["permissions"].extend(g.permissions or [])
            app_groups[key]["grant_ids"].append(g.id)

    for group in app_groups.values():
        perms = sorted(set(group["permissions"]))
        act = group["activity"]
        rows.append(GrantRow(
            primary_grant=group["primary"],
            permissions=perms,
            grant_ids=group["grant_ids"],
            activity=act,
            risk_signals=compute_risk_signals(group["primary"], act, all_permissions=perms),
        ))

    rows.sort(key=lambda r: r.primary_grant.client_display_name.lower())
    return rows


def timeago(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    days = _days_ago(dt)
    if days == 0:
        diff = datetime.now(timezone.utc) - _ensure_utc(dt)
        hours = int(diff.total_seconds()) // 3600
        if hours == 0:
            minutes = int(diff.total_seconds()) // 60
            return f"{minutes}m ago"
        return f"{hours}h ago"
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"


def _days_ago(dt: datetime) -> int:
    return (datetime.now(timezone.utc) - _ensure_utc(dt)).days


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_risk_signal(signal: str) -> str:
    """Collapse dormant-{N}d variants to 'dormant' for bucketing."""
    if signal.startswith("dormant-"):
        return "dormant"
    return signal


RISK_SIGNAL_LABELS = {
    "unverified-publisher": "Unverified publisher",
    "user-consented": "User-consented",
    "write-permissions": "Write permissions",
    "sp-disabled": "SP disabled",
    "never-used": "Never used",
    "dormant": "Dormant (>90d)",
    "all-repos": "All repositories",
    "never-reconfigured": "Never reconfigured",
}


def compute_grant_stats(rows: list[GrantRow]) -> dict:
    total = len(rows)
    delegated = sum(1 for r in rows if r.primary_grant.grant_type == "delegated")
    application = total - delegated
    risk_counts: dict[str, int] = {}
    for r in rows:
        for sig in r.risk_signals:
            bucket = normalize_risk_signal(sig)
            risk_counts[bucket] = risk_counts.get(bucket, 0) + 1
    return {"total": total, "delegated": delegated, "application": application, "risk": risk_counts}


def add_flash(request: Request, type: str, message: str) -> None:
    if "flash" not in request.session:
        request.session["flash"] = []
    request.session["flash"].append({"type": type, "message": message})


def pop_flash(request: Request) -> list:
    msgs = list(request.session.get("flash", []))
    request.session["flash"] = []
    return msgs

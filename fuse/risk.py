"""
Risk-signal enrichment for the token-monitoring detail screen.

Ported and adapted from backend-extra/web/utils.py (the collector's grant
detail view). The original computed signals over Microsoft Graph / GitHub
grant rows (DBGrant); here we compute the equivalent signals over the App
model the live connectors surface (connectors/base.py), so the SPA's detail
panel reads exactly like the collector's grant deep-dive.

Each signal is returned as {key, label, explanation} so the UI can render a
badge plus the human explanation in one pass.
"""
from __future__ import annotations

import time

# write/sensitive scope detection — union of the Azure ("Mail.ReadWrite"),
# GitHub App ("contents:write", "administration:admin") and GitHub OAuth
# ("repo", "admin:org", ...) markers from the original collector.
_OAUTH_WRITE = frozenset({
    "repo", "public_repo", "delete_repo", "gist", "workflow",
    "write:packages", "write:org", "write:discussion",
    "admin:org", "admin:repo_hook", "admin:public_key", "admin:gpg_key",
    "admin:enterprise",
})
_WRITE_WORDS = ("write", "export", "full", "admin", "manage", "delete", ".all")


def is_write_scope(scope: str) -> bool:
    s = scope.lower()
    if scope in _OAUTH_WRITE:
        return True
    if ":write" in s or ":admin" in s:
        return True
    return any(w in s for w in _WRITE_WORDS)


# label + explanation for every signal key we can emit. dormant-{N}d is handled
# specially (the day count is interpolated into the label/explanation).
RISK_SIGNALS = {
    "unverified-publisher": (
        "Unverified publisher",
        "The platform has not verified this app's publisher identity.",
    ),
    "user-consented": (
        "User-consented",
        "A regular user (not an admin) granted these permissions. May exceed intended access.",
    ),
    "write-permissions": (
        "Write permissions",
        "This connection holds permissions that can modify, export or delete data.",
    ),
    "all-repos": (
        "All repositories",
        "This app can reach every repository in the organization, including ones created in future.",
    ),
    "unbound-bearer": (
        "Unbound bearer token",
        "This connection uses a stealable bearer token with no sender binding (DPoP). "
        "A stolen token replays directly against the platform.",
    ),
    "sp-disabled": (
        "Source disabled",
        "The underlying service principal / installation is disabled. No new tokens can be issued.",
    ),
    "revoked": (
        "Revoked",
        "Access for this connection has been cut by Fuse.",
    ),
    "never-used": (
        "Never used",
        "No activity has ever been recorded for this connection.",
    ),
    "long-lived-token": (
        "Long-lived token",
        "The policy lifetime for this connection is long enough that a stolen token stays valid for hours.",
    ),
    "stale": (
        "Stale connection",
        "This connection was first seen over 180 days ago and has not been re-reviewed.",
    ),
}


def compute_risk_signals(app, *, policy=None, last_activity_ts: float | None = None) -> list[dict]:
    """Return the active risk signals for an App as {key,label,explanation} dicts."""
    keys: list[str] = []

    meta = app.meta or {}
    scopes = list(app.scopes or [])

    # publisher verification — only meaningful when the source reported it
    if "verified_publisher" in meta and not meta.get("verified_publisher"):
        keys.append("unverified-publisher")

    # consent type (Azure delegated grants)
    if meta.get("consent_type") == "Principal":
        keys.append("user-consented")

    if any(is_write_scope(s) for s in scopes):
        keys.append("write-permissions")

    if "all-repositories" in scopes or "all-repos" in scopes:
        keys.append("all-repos")

    # the signature risk for this domain: a stealable, unbound bearer token
    bound = bool(policy and policy.binding_required and app.holds_key)
    if app.token_kind in ("bearer", "oauth", "installation", "client_credentials") and not bound:
        keys.append("unbound-bearer")

    if meta.get("account_enabled") is False:
        keys.append("sp-disabled")

    if app.status == "revoked":
        keys.append("revoked")

    # activity / dormancy
    if last_activity_ts is None:
        # no token ever minted, no proof, no events for this app
        keys.append("never-used")
    else:
        days = int((time.time() - last_activity_ts) / 86400)
        if days > 90:
            keys.append(f"dormant-{days}d")

    # lifetime exposure (only governable apps have a meaningful policy)
    if policy and policy.lifetime_seconds and policy.lifetime_seconds > 3600 and not bound:
        keys.append("long-lived-token")

    age_days = (time.time() - app.created_at) / 86400
    if age_days > 180:
        keys.append("stale")

    out = []
    for k in keys:
        if k.startswith("dormant-"):
            days = k.split("-", 1)[1]
            out.append({
                "key": k,
                "label": f"Dormant ({days})",
                "explanation": f"No activity recorded in over 90 days ({days}). Consider revoking if no longer needed.",
            })
        else:
            label, expl = RISK_SIGNALS.get(k, (k, ""))
            out.append({"key": k, "label": label, "explanation": expl})
    return out


def timeago(ts: float | None) -> str:
    """Human 'N ago' string for a unix timestamp (matches utils.timeago)."""
    if not ts:
        return "—"
    diff = time.time() - ts
    if diff < 0:
        diff = 0
    mins = int(diff // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins}m ago"
    hours = mins // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days}d ago"
    if days < 365:
        return f"{days // 30}mo ago"
    return f"{days // 365}y ago"

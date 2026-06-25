from datetime import datetime

from .client import GitHubClient
from .models import GHActivity, GHPat


def fetch_pats(client: GitHubClient, org: str) -> list[GHPat]:
    """
    Fetch fine-grained PATs approved for the org.

    Only returns data when the org has "Require approval for fine-grained PATs"
    policy enabled. Returns empty list on 403/404 (policy off or insufficient scope).
    Requires: read:org scope (org owner).
    """
    try:
        raw = client.get_all(f"/orgs/{org}/personal-access-tokens")
    except Exception as exc:
        if _is_permissive_err(exc):
            return []
        raise

    results: list[GHPat] = []
    for pat in raw:
        pat_id = pat.get("id")
        if not pat_id:
            continue

        owner = pat.get("owner") or {}
        owner_login = owner.get("login", "unknown")
        name = pat.get("name") or f"pat-{pat_id}"

        raw_perms = pat.get("permissions") or {}
        perms = sorted(f"{k}:{v}" for k, v in _flatten(raw_perms).items())

        last_used = _parse_dt(pat.get("token_last_used_at"))

        results.append(GHPat(
            id=f"ghpat_{pat_id}",
            client_sp_id=str(pat_id),
            client_app_id=f"{owner_login}:{name}",
            client_display_name=f"{name} ({owner_login})",
            client_verified_publisher=False,
            client_account_enabled=not pat.get("token_expired", False),
            resource_sp_id=org,
            resource_display_name=f"GitHub / {org}",
            permissions=perms,
            consent_type="Principal",
            consented_by_user_id=owner_login,
            created_at=_parse_dt(pat.get("access_granted_at")),
            activity=GHActivity(last_sign_in=last_used),
        ))

    return results


def _flatten(perms: dict, prefix: str = "") -> dict:
    """Flatten nested permission dict: {"repo": {"issues": "write"}} → {"repo.issues": "write"}."""
    out = {}
    for k, v in perms.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _is_permissive_err(exc: Exception) -> bool:
    msg = str(exc)
    return "403" in msg or "404" in msg or "401" in msg

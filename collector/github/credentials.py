from datetime import datetime

from .client import GitHubClient
from .models import GHOAuthGrant

# OAuth scopes that imply broad write or admin access.
_WRITE_SCOPES = frozenset({
    "repo", "public_repo", "delete_repo", "gist", "workflow",
    "write:packages", "write:org", "write:discussion",
    "admin:org", "admin:repo_hook", "admin:public_key", "admin:gpg_key",
    "admin:enterprise", "admin:billing",
})


def fetch_oauth_grants(client: GitHubClient, org: str) -> list[GHOAuthGrant]:
    """
    Fetch OAuth App credential authorizations for org members.

    Returns one entry per active OAuth token (same app + N users = N entries).
    Returns empty list on 403/404 — requires admin:org scope.

    Does NOT return fine-grained or classic PATs (filtered out here; those
    are handled by fetch_pats or ignored).
    """
    try:
        raw = client.get_all(f"/orgs/{org}/credential-authorizations")
    except Exception as exc:
        if _is_permissive_err(exc):
            return []
        raise

    results: list[GHOAuthGrant] = []
    for cred in raw:
        if cred.get("credential_type") != "oauth":
            continue

        cred_id = cred.get("credential_id")
        app_id = cred.get("authorized_credential_id") or cred_id
        app_name = cred.get("authorized_credential_title") or f"oauth-app-{app_id}"
        scopes: list[str] = cred.get("scopes") or []

        # "repo" scope = access to all repos, present and future.
        perms = scopes[:]
        if "repo" in scopes:
            perms = ["all-repositories"] + perms

        results.append(GHOAuthGrant(
            id=f"ghoauth_{cred_id}",
            client_sp_id=str(app_id),
            client_app_id=str(app_id),
            client_display_name=app_name,
            client_verified_publisher=False,
            client_account_enabled=True,
            resource_sp_id=org,
            resource_display_name=f"GitHub / {org}",
            permissions=perms,
            consent_type="Principal",
            consented_by_user_id=cred.get("login"),
            created_at=_parse_dt(cred.get("credential_authorized_at")),
        ))

    return results


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _is_permissive_err(exc: Exception) -> bool:
    msg = str(exc)
    return "403" in msg or "404" in msg or "401" in msg

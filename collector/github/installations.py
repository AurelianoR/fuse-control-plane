from datetime import datetime

from .client import GitHubClient
from .models import GHInstallation


def fetch_installations(client: GitHubClient, org: str) -> list[GHInstallation]:
    """
    Fetch all GitHub App installations for an org.

    Requires a PAT with read:org scope (or a GitHub App token with
    the organization_administration:read permission).
    """
    raw = client.get_all(f"/orgs/{org}/installations")

    # Batch-fetch app details for each unique slug (for name + marketplace URL).
    app_cache: dict[str, dict] = {}
    for install in raw:
        slug = install.get("app_slug", "")
        if slug and slug not in app_cache:
            try:
                app_cache[slug] = client.get(f"/apps/{slug}")
            except Exception:
                app_cache[slug] = {}

    results: list[GHInstallation] = []
    for install in raw:
        slug = install.get("app_slug", "")
        app = app_cache.get(slug, {})
        app_name = app.get("name") or slug

        # Build sorted permission list: ["contents:read", "issues:write", ...]
        raw_perms: dict[str, str] = install.get("permissions", {})
        perms = sorted(f"{k}:{v}" for k, v in raw_perms.items())

        # Encode repository scope as a synthetic permission marker.
        if install.get("repository_selection") == "all":
            perms = ["all-repositories"] + perms

        # Marketplace-listed app → treat as verified publisher.
        html_url = app.get("html_url", "")
        is_marketplace = "marketplace" in html_url.lower()

        results.append(GHInstallation(
            id=f"gh_{install['id']}",
            client_sp_id=str(install["id"]),
            client_app_id=slug,
            client_display_name=app_name,
            client_verified_publisher=is_marketplace,
            client_account_enabled=install.get("suspended_at") is None,
            resource_sp_id=org,
            resource_display_name=f"GitHub / {org}",
            permissions=perms,
            created_at=_parse_dt(install.get("created_at")),
            updated_at=_parse_dt(install.get("updated_at")),
        ))

    return results


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

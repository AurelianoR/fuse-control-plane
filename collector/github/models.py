from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GHActivity:
    """Mirrors the SPActivity interface expected by web/jobs.py."""
    last_sign_in: datetime | None = None
    last_app_only_client: datetime | None = None
    last_delegated_client: datetime | None = None


@dataclass
class GHInstallation:
    """GitHub App installation — same interface as collector.models.Grant for web/jobs.py."""
    id: str                                # "gh_{installation_id}"
    grant_type: str = "application"

    client_sp_id: str = ""                 # str(installation_id)
    client_app_id: str = ""                # app_slug
    client_display_name: str = ""          # app name
    client_publisher_tenant_id: str | None = None
    client_verified_publisher: bool = False
    client_account_enabled: bool = True    # False if suspended

    resource_sp_id: str = ""              # org slug
    resource_display_name: str = ""       # "GitHub / {org}"

    # Each entry is "resource:access" e.g. "contents:read", "issues:write".
    # "all-repositories" is a synthetic marker when repository_selection == "all".
    permissions: list[str] = field(default_factory=list)

    consent_type: str | None = "AllPrincipals"
    consented_by_user_id: str | None = None

    created_at: datetime | None = None
    updated_at: datetime | None = None     # last config change; stored as last_modified_at

    # No sign-in activity for App installs. updated_at is stored separately, not here.
    activity: None = None


@dataclass
class GHPat:
    """Fine-grained PAT approved for the org — grant_type=delegated, Principal consent."""
    id: str                                # "ghpat_{pat_id}"
    grant_type: str = "delegated"

    client_sp_id: str = ""                 # str(pat_id)
    client_app_id: str = ""                # "{owner_login}:{token_name}"
    client_display_name: str = ""          # "{name} ({owner_login})"
    client_publisher_tenant_id: str | None = None
    client_verified_publisher: bool = False
    client_account_enabled: bool = True    # False if expired

    resource_sp_id: str = ""              # org slug
    resource_display_name: str = ""       # "GitHub / {org}"

    permissions: list[str] = field(default_factory=list)

    consent_type: str | None = "Principal"
    consented_by_user_id: str | None = None  # owner login

    created_at: datetime | None = None     # access_granted_at
    updated_at: datetime | None = None     # not used for PATs

    # GHActivity with last_sign_in = token_last_used_at (None if never used).
    activity: GHActivity | None = None


@dataclass
class GHOAuthGrant:
    """OAuth App credential authorization for an org member.

    Source: GET /orgs/{org}/credential-authorizations (credential_type == "oauth").
    One row per token (not per app) — the same OAuth App authorized by N users = N rows.
    Requires admin:org scope.
    """
    id: str                                # "ghoauth_{credential_id}"
    grant_type: str = "delegated"

    client_sp_id: str = ""                 # str(authorized_credential_id) — stable OAuth App ID
    client_app_id: str = ""                # str(authorized_credential_id)
    client_display_name: str = ""          # authorized_credential_title (app name)
    client_publisher_tenant_id: str | None = None
    client_verified_publisher: bool = False
    client_account_enabled: bool = True

    resource_sp_id: str = ""              # org slug
    resource_display_name: str = ""       # "GitHub / {org}"

    # Classic OAuth scopes: ["repo", "gist", "user:email", ...].
    # "all-repositories" synthetic marker added when "repo" scope is present.
    permissions: list[str] = field(default_factory=list)

    consent_type: str | None = "Principal"
    consented_by_user_id: str | None = None  # GitHub login of the authorizing user

    created_at: datetime | None = None     # credential_authorized_at
    updated_at: datetime | None = None

    # No last-used timestamp available from this endpoint.
    activity: None = None

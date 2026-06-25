from datetime import datetime, timezone

from collector.graph.client import GraphClient
from collector.graph.resolve import AppRoleResolver
from collector.models import Grant

_SELECT_SP = ",".join([
    "id",
    "appId",
    "displayName",
    "appOwnerOrganizationId",
    "accountEnabled",
    "verifiedPublisher",
    "servicePrincipalType",
])

_SELECT_DELEGATED = "id,clientId,resourceId,consentType,principalId,scope"


def fetch_grants(client: GraphClient, tenant_id: str) -> list[Grant]:
    resolver = AppRoleResolver(client)
    now = datetime.now(timezone.utc)

    # Enumerate all service principals in the tenant
    all_sps = client.get_all("/servicePrincipals", params={"$select": _SELECT_SP})
    sp_by_id: dict[str, dict] = {sp["id"]: sp for sp in all_sps}

    # Third-party SPs: Application type, registered in a different tenant
    third_party_ids = {
        sp["id"]
        for sp in all_sps
        if sp.get("servicePrincipalType") == "Application"
        and sp.get("appOwnerOrganizationId") != tenant_id
    }

    grants: list[Grant] = []

    # Delegated grants (oauth2PermissionGrants)
    delegated = client.get_all(
        "/oauth2PermissionGrants", params={"$select": _SELECT_DELEGATED}
    )
    for g in delegated:
        if g["clientId"] not in third_party_ids:
            continue
        sp = sp_by_id.get(g["clientId"], {})
        resource_sp = sp_by_id.get(g["resourceId"], {})
        grants.append(Grant(
            id=g["id"],
            grant_type="delegated",
            client_sp_id=g["clientId"],
            client_app_id=sp.get("appId", ""),
            client_display_name=sp.get("displayName") or g["clientId"],
            client_publisher_tenant_id=sp.get("appOwnerOrganizationId"),
            client_verified_publisher=bool(sp.get("verifiedPublisher")),
            client_account_enabled=sp.get("accountEnabled", True),
            resource_sp_id=g["resourceId"],
            resource_display_name=resource_sp.get("displayName") or g["resourceId"],
            permissions=g.get("scope", "").split() if g.get("scope") else [],
            consent_type=g.get("consentType"),
            consented_by_user_id=g.get("principalId"),
            created_at=None,  # not available on oauth2PermissionGrant — see audit log
            first_seen_at=now,
        ))

    # Application grants (appRoleAssignments per third-party SP)
    for sp_id in third_party_ids:
        sp = sp_by_id[sp_id]
        assignments = client.get_all(f"/servicePrincipals/{sp_id}/appRoleAssignments")
        for a in assignments:
            resource_sp = sp_by_id.get(a["resourceId"], {})
            permission = resolver.resolve(a["resourceId"], a["appRoleId"])

            created_at: datetime | None = None
            if dt_str := a.get("createdDateTime"):
                created_at = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))

            grants.append(Grant(
                id=a["id"],
                grant_type="application",
                client_sp_id=sp_id,
                client_app_id=sp.get("appId", ""),
                client_display_name=sp.get("displayName") or sp_id,
                client_publisher_tenant_id=sp.get("appOwnerOrganizationId"),
                client_verified_publisher=bool(sp.get("verifiedPublisher")),
                client_account_enabled=sp.get("accountEnabled", True),
                resource_sp_id=a["resourceId"],
                resource_display_name=resource_sp.get("displayName") or a["resourceId"],
                permissions=[permission],
                consent_type="AllPrincipals",  # app grants are always admin-consented
                consented_by_user_id=None,
                created_at=created_at,
                first_seen_at=now,
            ))

    return grants

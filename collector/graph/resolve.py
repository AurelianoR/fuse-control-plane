from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collector.graph.client import GraphClient

# Zero GUID is used when an SP is assigned to a resource with no specific role (default access).
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"


class AppRoleResolver:
    """Resolves appRoleId GUIDs to human-readable permission names.

    appRoleAssignment.appRoleId is an opaque GUID. This class fetches the
    resource SP's appRoles[] collection and caches it to avoid redundant calls.
    """

    def __init__(self, client: GraphClient):
        self._client = client
        # resource_sp_id -> {role_id -> role_value}
        self._cache: dict[str, dict[str, str]] = {}

    def resolve(self, resource_sp_id: str, role_id: str) -> str:
        if role_id == _ZERO_GUID:
            return "DefaultAccess"
        if resource_sp_id not in self._cache:
            self._cache[resource_sp_id] = self._fetch_roles(resource_sp_id)
        name = self._cache[resource_sp_id].get(role_id)
        if name is None:
            return f"unknown:{role_id[:8]}"
        return name

    def _fetch_roles(self, resource_sp_id: str) -> dict[str, str]:
        try:
            sp = self._client.get(
                f"/servicePrincipals/{resource_sp_id}",
                params={"$select": "appRoles"},
            )
            return {role["id"]: role["value"] for role in sp.get("appRoles", [])}
        except Exception:
            return {}

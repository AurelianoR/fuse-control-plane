from .client import GraphClient


def revoke_delegated_grant(client: GraphClient, grant_id: str) -> None:
    client.delete(f"/oauth2PermissionGrants/{grant_id}")


def revoke_app_assignment(client: GraphClient, client_sp_id: str, assignment_id: str) -> None:
    client.delete(f"/servicePrincipals/{client_sp_id}/appRoleAssignments/{assignment_id}")


def disable_service_principal(client: GraphClient, sp_id: str) -> None:
    client.patch(f"/servicePrincipals/{sp_id}", {"accountEnabled": False})

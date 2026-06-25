from .client import GitHubClient


def revoke_oauth_credential(client: GitHubClient, org: str, credential_id: str) -> None:
    client.delete(f"/orgs/{org}/credential-authorizations/{credential_id}")

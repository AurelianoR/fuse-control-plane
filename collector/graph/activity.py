from datetime import datetime

from collector.graph.client import GraphClient
from collector.models import SPActivity


def fetch_activity(client: GraphClient) -> dict[str, SPActivity]:
    """Fetch last-used timestamps for all service principals.

    Returns a dict keyed by appId (not SP object ID). The caller must reconcile
    against grant.client_app_id.

    Requires Entra ID P1/P2. Returns an empty dict on 403 (unlicensed tenant)
    rather than raising, so the caller can degrade gracefully.
    """
    try:
        records = client.get_all(
            "/reports/servicePrincipalSignInActivities", version="beta"
        )
    except Exception as exc:
        if _is_auth_error(exc):
            return {}
        raise

    result: dict[str, SPActivity] = {}
    for record in records:
        app_id = record.get("appId")
        if not app_id:
            continue
        result[app_id] = SPActivity(
            last_sign_in=_parse_activity(record.get("lastSignInActivity")),
            last_app_only_client=_parse_activity(
                record.get("applicationAuthenticationClientSignInActivity")
            ),
            last_delegated_client=_parse_activity(
                record.get("delegatedClientSignInActivity")
            ),
        )
    return result


def _parse_activity(obj: dict | None) -> datetime | None:
    if not obj:
        return None
    dt_str = obj.get("lastSignInDateTime")
    if not dt_str:
        return None
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def _is_auth_error(exc: Exception) -> bool:
    msg = str(exc)
    return "403" in msg or "401" in msg or "Forbidden" in msg or "Unauthorized" in msg

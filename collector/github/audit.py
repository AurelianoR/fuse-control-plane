from datetime import datetime, timezone

from .client import GitHubClient

_INSTALL_ACTIONS = frozenset({
    "integration_installation.create",
    "integration_installation.destroy",
    "integration_installation.repositories_added",
    "integration_installation.repositories_removed",
    "integration_installation.suspend",
    "integration_installation.unsuspend",
})


def fetch_audit_events(client: GitHubClient, org: str) -> list[dict]:
    """
    Fetch GitHub App installation events from the org audit log (last 90 days).

    Returns empty list on 403/404 — requires read:audit_log or admin:org scope.
    Events have keys: action, actor, @timestamp (ms), installation_id (may be absent).
    """
    try:
        raw = client.get_all(
            f"/orgs/{org}/audit-log",
            params={"phrase": "action:integration_installation", "per_page": 100},
        )
    except Exception as exc:
        if _is_permissive_err(exc):
            return []
        raise

    cutoff_ms = _ninety_days_ago_ms()
    events = []
    for e in raw:
        ts = e.get("@timestamp") or e.get("created_at_ms")
        if ts and ts < cutoff_ms:
            continue
        if e.get("action") in _INSTALL_ACTIONS:
            events.append(e)
    return events


def parse_event_dt(event: dict) -> datetime | None:
    ts_ms = event.get("@timestamp") or event.get("created_at_ms")
    if ts_ms:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    return None


def parse_installation_id(event: dict) -> str | None:
    """Return the 'gh_{id}' key matching a GHInstallation.id, or None."""
    install_id = (
        event.get("installation_id")
        or (event.get("installation") or {}).get("id")
    )
    if install_id:
        return f"gh_{install_id}"
    return None


def _ninety_days_ago_ms() -> int:
    import time
    return int((time.time() - 90 * 86400) * 1000)


def _is_permissive_err(exc: Exception) -> bool:
    msg = str(exc)
    return "403" in msg or "404" in msg or "401" in msg

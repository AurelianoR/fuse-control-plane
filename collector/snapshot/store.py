import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from collector.models import Grant, SPActivity


class SnapshotStore:
    def __init__(self, snapshot_dir: str):
        self._dir = Path(snapshot_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, grants: list[Grant]) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self._dir / f"snapshot_{ts}.json"
        path.write_text(json.dumps([_to_dict(g) for g in grants], indent=2, default=str))
        return path

    def load_latest(self) -> list[Grant] | None:
        snapshots = sorted(self._dir.glob("snapshot_*.json"))
        if not snapshots:
            return None
        return _load_file(snapshots[-1])

    def merge_first_seen(self, previous: list[Grant], current: list[Grant]) -> list[Grant]:
        """Preserve firstSeenAt timestamps from the previous snapshot for known grants."""
        prev_by_id = {g.id: g for g in previous}
        for g in current:
            if g.id in prev_by_id:
                g.first_seen_at = prev_by_id[g.id].first_seen_at
        return current

    def diff(self, previous: list[Grant], current: list[Grant]) -> dict:
        prev_by_id = {g.id: g for g in previous}
        curr_by_id = {g.id: g for g in current}

        new_grants = [curr_by_id[i] for i in set(curr_by_id) - set(prev_by_id)]
        removed_grants = [prev_by_id[i] for i in set(prev_by_id) - set(curr_by_id)]

        changed = []
        for gid in set(prev_by_id) & set(curr_by_id):
            prev_perms = set(prev_by_id[gid].permissions)
            curr_perms = set(curr_by_id[gid].permissions)
            if prev_perms != curr_perms:
                changed.append({
                    "grant_id": gid,
                    "display_name": curr_by_id[gid].client_display_name,
                    "added_permissions": sorted(curr_perms - prev_perms),
                    "removed_permissions": sorted(prev_perms - curr_perms),
                })

        return {"new": new_grants, "removed": removed_grants, "changed": changed}


def _to_dict(g: Grant) -> dict:
    d = asdict(g)
    for key in ("created_at", "first_seen_at"):
        if d[key] is not None:
            d[key] = d[key].isoformat()
    if d["activity"]:
        for key in ("last_sign_in", "last_app_only_client", "last_delegated_client"):
            if d["activity"][key] is not None:
                d["activity"][key] = d["activity"][key].isoformat()
    return d


def _load_file(path: Path) -> list[Grant]:
    data = json.loads(path.read_text())
    return [_from_dict(d) for d in data]


def _from_dict(d: dict) -> Grant:
    activity = None
    if d.get("activity"):
        a = d["activity"]
        activity = SPActivity(
            last_sign_in=_parse_dt(a.get("last_sign_in")),
            last_app_only_client=_parse_dt(a.get("last_app_only_client")),
            last_delegated_client=_parse_dt(a.get("last_delegated_client")),
        )
    return Grant(
        id=d["id"],
        grant_type=d["grant_type"],
        client_sp_id=d["client_sp_id"],
        client_app_id=d["client_app_id"],
        client_display_name=d["client_display_name"],
        client_publisher_tenant_id=d["client_publisher_tenant_id"],
        client_verified_publisher=d["client_verified_publisher"],
        client_account_enabled=d["client_account_enabled"],
        resource_sp_id=d["resource_sp_id"],
        resource_display_name=d["resource_display_name"],
        permissions=d["permissions"],
        consent_type=d["consent_type"],
        consented_by_user_id=d["consented_by_user_id"],
        created_at=_parse_dt(d.get("created_at")),
        first_seen_at=_parse_dt(d["first_seen_at"]),
        activity=activity,
    )


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s)

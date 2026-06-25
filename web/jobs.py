import threading
from datetime import datetime, timezone

from web.db import new_session
from web.models import CollectionRun, DBGrant, GrantActivitySnapshot, GrantEvent, Tenant


def trigger(tenant_db_id: int, run_id: int) -> threading.Thread:
    t = threading.Thread(
        target=_run,
        args=(tenant_db_id, run_id),
        daemon=True,
        name=f"collect-{run_id}",
    )
    t.start()
    return t


def _run(tenant_db_id: int, run_id: int) -> None:
    db = new_session()
    try:
        from web.config import get_settings
        settings = get_settings()

        # Mark as running immediately so the status poller sees progress
        run = db.get(CollectionRun, run_id)
        tenant = db.get(Tenant, tenant_db_id)
        run.status = "running"
        db.commit()

        # All HTTP calls happen outside any transaction
        secret = tenant.get_secret(settings.secret_encryption_key)
        platform = tenant.platform or "azure"

        if platform == "github":
            from collector.github.audit import fetch_audit_events
            from collector.github.client import GitHubClient
            from collector.github.credentials import fetch_oauth_grants
            from collector.github.installations import fetch_installations
            gh_client = GitHubClient(secret)
            installations = fetch_installations(gh_client, tenant.tenant_id)
            oauth_grants = fetch_oauth_grants(gh_client, tenant.tenant_id)
            audit_events = fetch_audit_events(gh_client, tenant.tenant_id)
            raw_grants = installations + oauth_grants
            activity_available = True
        else:
            from collector.graph.activity import fetch_activity
            from collector.graph.client import GraphClient
            from collector.graph.grants import fetch_grants
            az_client = GraphClient(tenant.tenant_id, tenant.client_id, secret)
            raw_grants = fetch_grants(az_client, tenant.tenant_id)
            activity_map = fetch_activity(az_client)
            activity_available = bool(activity_map)
            audit_events = []
            for g in raw_grants:
                g.activity = activity_map.get(g.client_app_id)

        # Load existing grants for this tenant
        existing: dict[str, DBGrant] = {
            g.graph_id: g
            for g in db.query(DBGrant).filter(DBGrant.tenant_fk == tenant_db_id).all()
        }

        current_graph_ids: set[str] = set()
        new_grants_list: list[tuple[DBGrant, object]] = []   # (db_grant, raw_grant)
        updated_grants_list: list[tuple[DBGrant, object, set, set]] = []  # (db_grant, raw, old_perms, new_perms)

        # Pass 1: upsert DBGrant rows
        for g in raw_grants:
            current_graph_ids.add(g.id)
            if g.id not in existing:
                db_grant = DBGrant(
                    tenant_fk=tenant_db_id,
                    graph_id=g.id,
                    grant_type=g.grant_type,
                    client_sp_id=g.client_sp_id,
                    client_app_id=g.client_app_id,
                    client_display_name=g.client_display_name,
                    client_publisher_tenant_id=g.client_publisher_tenant_id,
                    client_verified_publisher=g.client_verified_publisher,
                    client_account_enabled=g.client_account_enabled,
                    resource_sp_id=g.resource_sp_id,
                    resource_display_name=g.resource_display_name,
                    permissions=g.permissions,
                    consent_type=g.consent_type,
                    consented_by_user_id=g.consented_by_user_id,
                    created_at=g.created_at,
                    last_modified_at=getattr(g, "updated_at", None),
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_run_id=run_id,
                    is_active=True,
                )
                db.add(db_grant)
                new_grants_list.append((db_grant, g))
            else:
                db_grant = existing[g.id]
                old_perms = set(db_grant.permissions or [])
                new_perms = set(g.permissions or [])
                db_grant.client_display_name = g.client_display_name
                db_grant.client_verified_publisher = g.client_verified_publisher
                db_grant.client_account_enabled = g.client_account_enabled
                db_grant.permissions = g.permissions
                db_grant.last_seen_run_id = run_id
                db_grant.is_active = True
                if getattr(g, "updated_at", None):
                    db_grant.last_modified_at = g.updated_at
                updated_grants_list.append((db_grant, g, old_perms, new_perms))

        # Flush so new DBGrant rows get IDs
        db.flush()

        new_count = removed_count = changed_count = 0

        # Pass 2: events + activity snapshots for new grants
        for db_grant, g in new_grants_list:
            db.add(GrantEvent(run_id=run_id, grant_id=db_grant.id, event_type="new"))
            new_count += 1
            if activity_available and g.activity:
                db.add(GrantActivitySnapshot(
                    run_id=run_id, grant_id=db_grant.id,
                    last_sign_in=g.activity.last_sign_in,
                    last_app_only_client=g.activity.last_app_only_client,
                    last_delegated_client=g.activity.last_delegated_client,
                ))

        # Pass 3: events + activity snapshots for updated grants
        for db_grant, g, old_perms, new_perms in updated_grants_list:
            if old_perms != new_perms:
                added = sorted(new_perms - old_perms)
                removed_perms = sorted(old_perms - new_perms)
                if added:
                    db.add(GrantEvent(
                        run_id=run_id, grant_id=db_grant.id,
                        event_type="permission_added",
                        detail={"permissions": added},
                    ))
                if removed_perms:
                    db.add(GrantEvent(
                        run_id=run_id, grant_id=db_grant.id,
                        event_type="permission_removed",
                        detail={"permissions": removed_perms},
                    ))
                changed_count += 1
            if activity_available and g.activity:
                db.add(GrantActivitySnapshot(
                    run_id=run_id, grant_id=db_grant.id,
                    last_sign_in=g.activity.last_sign_in,
                    last_app_only_client=g.activity.last_app_only_client,
                    last_delegated_client=g.activity.last_delegated_client,
                ))

        # Backfill audit events for newly-discovered GitHub App installs.
        # Only for new grants (first seen this run) so we don't duplicate on re-runs.
        if audit_events and new_grants_list:
            from collector.github.audit import parse_event_dt, parse_installation_id
            new_gh_ids = {g.id: db_grant.id for db_grant, g in new_grants_list}
            for event in audit_events:
                gh_id = parse_installation_id(event)
                if gh_id is None or gh_id not in new_gh_ids:
                    continue
                event_dt = parse_event_dt(event)
                db.add(GrantEvent(
                    run_id=run_id,
                    grant_id=new_gh_ids[gh_id],
                    event_type="audit",
                    detail={
                        "action": event.get("action", ""),
                        "actor": event.get("actor", ""),
                        "at": event_dt.isoformat() if event_dt else None,
                    },
                ))

        # Mark grants absent from this run as inactive
        for graph_id, db_grant in existing.items():
            if graph_id not in current_graph_ids and db_grant.is_active:
                db_grant.is_active = False
                db.add(GrantEvent(run_id=run_id, grant_id=db_grant.id, event_type="removed"))
                removed_count += 1

        # Finalize run — single commit for the entire diff
        run.status = "success"
        run.finished_at = datetime.now(timezone.utc)
        run.activity_available = activity_available
        run.total_grants = len(raw_grants)
        run.new_grants = new_count
        run.removed_grants = removed_count
        run.changed_grants = changed_count
        db.commit()

    except Exception as exc:
        try:
            run = db.get(CollectionRun, run_id)
            if run:
                run.status = "failed"
                run.finished_at = datetime.now(timezone.utc)
                run.error_message = str(exc)[:2000]
                db.commit()
        except Exception:
            pass
        raise
    finally:
        db.close()

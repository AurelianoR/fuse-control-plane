from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from web.db import get_db
from web.models import CollectionRun, DBGrant, GrantActivitySnapshot, GrantEvent, Tenant
from web.templating import templates
from web.utils import (
    GrantRow,
    add_flash,
    build_grant_rows,
    compute_risk_signals,
    normalize_risk_signal,
    pop_flash,
)

router = APIRouter(prefix="/tenants/{id}/grants", tags=["grants"])

PER_PAGE = 50

RISK_SIGNAL_LABELS = {
    "unverified-publisher": "Unverified publisher",
    "user-consented": "User-consented",
    "write-permissions": "Write permissions",
    "sp-disabled": "SP disabled",
    "never-used": "Never used",
    "dormant": "Dormant (>90d)",
    "all-repos": "All repositories",
    "never-reconfigured": "Never reconfigured",
}


def _get_tenant(id: int, db: Session) -> Tenant:
    tenant = db.get(Tenant, id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


def _base_ctx(request: Request, db: Session, tenant: Tenant, **kwargs) -> dict:
    return {
        "request": request,
        "tenant": tenant,
        "tenants": db.query(Tenant).order_by(Tenant.display_name).all(),
        "flash": pop_flash(request),
        **kwargs,
    }


def _latest_successful_run(tenant_id: int, db: Session) -> CollectionRun | None:
    return (
        db.query(CollectionRun)
        .filter(CollectionRun.tenant_fk == tenant_id, CollectionRun.status == "success")
        .order_by(CollectionRun.finished_at.desc())
        .first()
    )


def _activity_by_grant_id(run_id: int, db: Session) -> dict[int, GrantActivitySnapshot]:
    if run_id is None:
        return {}
    snapshots = db.query(GrantActivitySnapshot).filter_by(run_id=run_id).all()
    return {s.grant_id: s for s in snapshots}


@router.get("", response_class=HTMLResponse, name="grants_list")
def grants_list(
    request: Request,
    id: int,
    type: str = "",
    risk: str = "",
    resource: str = "",
    include_inactive: bool = False,
    search: str = "",
    page: int = 1,
    db: Session = Depends(get_db),
):
    tenant = _get_tenant(id, db)
    last_run = _latest_successful_run(id, db)
    activity_by_id = _activity_by_grant_id(last_run.id if last_run else None, db)

    # Base query
    query = db.query(DBGrant).filter(DBGrant.tenant_fk == id)
    if not include_inactive:
        query = query.filter(DBGrant.is_active == True)
    if type in ("delegated", "application"):
        query = query.filter(DBGrant.grant_type == type)
    if resource:
        query = query.filter(DBGrant.resource_sp_id == resource)
    if search:
        query = query.filter(DBGrant.client_display_name.ilike(f"%{search}%"))

    all_grants = query.order_by(DBGrant.client_display_name).all()

    # Build display rows (groups application grants)
    rows = build_grant_rows(all_grants, activity_by_id)

    # Risk filter (applied after grouping since it requires activity data)
    if risk:
        rows = [r for r in rows if risk in [normalize_risk_signal(s) for s in r.risk_signals]]

    # Stats (computed before pagination)
    stats = _compute_stats(rows)

    # Pagination
    total = len(rows)
    offset = (page - 1) * PER_PAGE
    page_rows = rows[offset: offset + PER_PAGE]
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    # Filter options
    resources = (
        db.query(DBGrant.resource_sp_id, DBGrant.resource_display_name)
        .filter(DBGrant.tenant_fk == id)
        .distinct()
        .order_by(DBGrant.resource_display_name)
        .all()
    )

    return templates.TemplateResponse(
        request, "grants/list.html",
        _base_ctx(
            request, db, tenant,
            rows=page_rows,
            stats=stats,
            last_run=last_run,
            activity_available=last_run.activity_available if last_run else False,
            tenant_platform=tenant.platform or "azure",
            resources=resources,
            risk_signal_labels=RISK_SIGNAL_LABELS,
            # active filters
            filter_type=type,
            filter_risk=risk,
            filter_resource=resource,
            filter_include_inactive=include_inactive,
            filter_search=search,
            # pagination
            page=page,
            total_pages=total_pages,
            total=total,
        ),
    )


@router.get("/{gid}", response_class=HTMLResponse, name="grants_detail")
def grants_detail(
    request: Request, id: int, gid: int, db: Session = Depends(get_db)
):
    tenant = _get_tenant(id, db)
    grant = db.get(DBGrant, gid)
    if not grant or grant.tenant_fk != id:
        raise HTTPException(status_code=404)

    last_run = _latest_successful_run(id, db)
    activity_by_id = _activity_by_grant_id(last_run.id if last_run else None, db)
    activity = activity_by_id.get(grant.id)
    risk_signals = compute_risk_signals(grant, activity)

    # For application grants, fetch siblings (same vendor + resource)
    siblings: list[DBGrant] = []
    if grant.grant_type == "application":
        siblings = (
            db.query(DBGrant)
            .filter(
                DBGrant.tenant_fk == id,
                DBGrant.client_sp_id == grant.client_sp_id,
                DBGrant.resource_sp_id == grant.resource_sp_id,
                DBGrant.id != grant.id,
            )
            .all()
        )
        all_permissions = list(grant.permissions or []) + [
            p for s in siblings for p in (s.permissions or [])
        ]
    else:
        all_permissions = list(grant.permissions or [])

    # Event history for this grant (and siblings for application grants)
    grant_ids = [grant.id] + [s.id for s in siblings]
    events = (
        db.query(GrantEvent, CollectionRun)
        .join(CollectionRun, GrantEvent.run_id == CollectionRun.id)
        .filter(GrantEvent.grant_id.in_(grant_ids))
        .order_by(CollectionRun.started_at.desc())
        .all()
    )

    return templates.TemplateResponse(
        request, "grants/detail.html",
        _base_ctx(
            request, db, tenant,
            grant=grant,
            siblings=siblings,
            all_permissions=sorted(set(all_permissions)),
            activity=activity,
            risk_signals=risk_signals,
            activity_available=last_run.activity_available if last_run else False,
            tenant_platform=tenant.platform or "azure",
            events=events,
            risk_signal_labels=RISK_SIGNAL_LABELS,
        ),
    )


@router.post("/{gid}/revoke", name="grants_revoke")
def grants_revoke(
    request: Request,
    id: int,
    gid: int,
    action: str = Form(...),
    db: Session = Depends(get_db),
):
    tenant = _get_tenant(id, db)
    grant = db.get(DBGrant, gid)
    if not grant or grant.tenant_fk != id or not grant.is_active:
        raise HTTPException(status_code=404)

    from web.config import get_settings
    settings = get_settings()
    secret = tenant.get_secret(settings.secret_encryption_key)
    platform = tenant.platform or "azure"
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        if platform == "azure":
            from collector.graph.client import GraphClient
            from collector.graph.revoke import (
                disable_service_principal,
                revoke_app_assignment,
                revoke_delegated_grant,
            )
            az_client = GraphClient(tenant.tenant_id, tenant.client_id, secret)

            if action == "disable_sp":
                disable_service_principal(az_client, grant.client_sp_id)
                # Immediately reflect disabled state for all grants of this SP
                db.query(DBGrant).filter(
                    DBGrant.tenant_fk == id,
                    DBGrant.client_sp_id == grant.client_sp_id,
                    DBGrant.is_active == True,
                ).update({"client_account_enabled": False})
                db.add(GrantEvent(
                    run_id=grant.last_seen_run_id,
                    grant_id=grant.id,
                    event_type="revoked",
                    detail={"action": "disable_sp", "at": now_iso},
                ))
            elif grant.grant_type == "delegated":
                revoke_delegated_grant(az_client, grant.graph_id)
                grant.is_active = False
                db.add(GrantEvent(
                    run_id=grant.last_seen_run_id,
                    grant_id=grant.id,
                    event_type="revoked",
                    detail={"action": action, "at": now_iso},
                ))
            else:
                # Application grant: revoke all active assignments for this vendor+resource
                all_app_grants = (
                    db.query(DBGrant)
                    .filter(
                        DBGrant.tenant_fk == id,
                        DBGrant.client_sp_id == grant.client_sp_id,
                        DBGrant.resource_sp_id == grant.resource_sp_id,
                        DBGrant.is_active == True,
                    )
                    .all()
                )
                for g in all_app_grants:
                    revoke_app_assignment(az_client, g.client_sp_id, g.graph_id)
                    g.is_active = False
                    db.add(GrantEvent(
                        run_id=g.last_seen_run_id,
                        grant_id=g.id,
                        event_type="revoked",
                        detail={"action": action, "at": now_iso},
                    ))

        elif platform == "github":
            if not grant.graph_id.startswith("ghoauth_"):
                raise HTTPException(status_code=400, detail="GitHub App installations cannot be revoked via API")
            from collector.github.client import GitHubClient
            from collector.github.revoke import revoke_oauth_credential
            gh_client = GitHubClient(secret)
            credential_id = grant.graph_id[8:]  # strip "ghoauth_"
            revoke_oauth_credential(gh_client, grant.resource_sp_id, credential_id)
            grant.is_active = False
            db.add(GrantEvent(
                run_id=grant.last_seen_run_id,
                grant_id=grant.id,
                event_type="revoked",
                detail={"action": action, "at": now_iso},
            ))

        db.commit()
        add_flash(request, "success", "Access revoked successfully.")

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        msg = str(exc)
        if "403" in msg:
            if platform == "azure":
                add_flash(request, "error",
                    "Insufficient permissions — add Application.ReadWrite.All to your Azure app registration.")
            else:
                add_flash(request, "error",
                    "Insufficient permissions — ensure your PAT has admin:org scope.")
        else:
            add_flash(request, "error", f"Revocation failed: {msg[:300]}")

    return RedirectResponse(url=str(request.url_for("grants_list", id=id)), status_code=303)


def _compute_stats(rows: list[GrantRow]) -> dict:
    total = len(rows)
    delegated = sum(1 for r in rows if r.primary_grant.grant_type == "delegated")
    application = total - delegated

    risk_counts: dict[str, int] = {}
    for r in rows:
        for sig in r.risk_signals:
            bucket = normalize_risk_signal(sig)
            risk_counts[bucket] = risk_counts.get(bucket, 0) + 1

    return {
        "total": total,
        "delegated": delegated,
        "application": application,
        "risk": risk_counts,
    }

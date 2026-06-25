from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from web.db import get_db
from web.models import CollectionRun, DBGrant, GrantActivitySnapshot, Tenant, TenantGroup
from web.templating import templates
from web.utils import (
    RISK_SIGNAL_LABELS,
    GrantRow,
    add_flash,
    build_grant_rows,
    compute_grant_stats,
    normalize_risk_signal,
    pop_flash,
)

router = APIRouter(tags=["groups"])

PER_PAGE = 50


def _get_group(gid: int, db: Session) -> TenantGroup:
    group = db.get(TenantGroup, gid)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    return group


def _base_ctx(request: Request, db: Session, group: TenantGroup, **kwargs) -> dict:
    return {
        "request": request,
        "group": group,
        "tenant": None,
        "tenants": db.query(Tenant).order_by(Tenant.display_name).all(),
        "groups": db.query(TenantGroup).order_by(TenantGroup.display_name).all(),
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


@router.get("/groups/{gid}/grants", response_class=HTMLResponse, name="group_grants_list")
def group_grants_list(
    request: Request,
    gid: int,
    type: str = "",
    risk: str = "",
    resource: str = "",
    include_inactive: bool = False,
    search: str = "",
    page: int = 1,
    db: Session = Depends(get_db),
):
    group = _get_group(gid, db)
    member_ids = [t.id for t in group.tenants]

    if not member_ids:
        return templates.TemplateResponse(
            request, "grants/group_list.html",
            _base_ctx(
                request, db, group,
                rows=[], stats={"total": 0, "delegated": 0, "application": 0, "risk": {}},
                activity_available=False,
                tenant_by_id={},
                resources=[],
                risk_signal_labels=RISK_SIGNAL_LABELS,
                filter_type=type, filter_risk=risk, filter_resource=resource,
                filter_include_inactive=include_inactive, filter_search=search,
                page=1, total_pages=1, total=0,
            ),
        )

    # Build combined activity map from the latest successful run per tenant
    activity_by_id: dict[int, GrantActivitySnapshot] = {}
    last_runs: dict[int, CollectionRun] = {}
    for tid in member_ids:
        run = _latest_successful_run(tid, db)
        if run:
            last_runs[tid] = run
            activity_by_id.update(_activity_by_grant_id(run.id, db))

    # Base query across all member tenants
    query = db.query(DBGrant).filter(DBGrant.tenant_fk.in_(member_ids))
    if not include_inactive:
        query = query.filter(DBGrant.is_active == True)
    if type in ("delegated", "application"):
        query = query.filter(DBGrant.grant_type == type)
    if resource:
        query = query.filter(DBGrant.resource_sp_id == resource)
    if search:
        query = query.filter(DBGrant.client_display_name.ilike(f"%{search}%"))

    all_grants = query.order_by(DBGrant.client_display_name).all()

    rows = build_grant_rows(all_grants, activity_by_id)

    if risk:
        rows = [r for r in rows if risk in [normalize_risk_signal(s) for s in r.risk_signals]]

    stats = compute_grant_stats(rows)

    total = len(rows)
    offset = (page - 1) * PER_PAGE
    page_rows = rows[offset: offset + PER_PAGE]
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    # Resource filter options across all member tenants
    resources = (
        db.query(DBGrant.resource_sp_id, DBGrant.resource_display_name)
        .filter(DBGrant.tenant_fk.in_(member_ids))
        .distinct()
        .order_by(DBGrant.resource_display_name)
        .all()
    )

    tenant_by_id = {t.id: t for t in group.tenants}
    activity_available = any(r.activity_available for r in last_runs.values())

    return templates.TemplateResponse(
        request, "grants/group_list.html",
        _base_ctx(
            request, db, group,
            rows=page_rows,
            stats=stats,
            activity_available=activity_available,
            tenant_by_id=tenant_by_id,
            resources=resources,
            risk_signal_labels=RISK_SIGNAL_LABELS,
            filter_type=type,
            filter_risk=risk,
            filter_resource=resource,
            filter_include_inactive=include_inactive,
            filter_search=search,
            page=page,
            total_pages=total_pages,
            total=total,
        ),
    )


@router.post("/groups", name="groups_create")
def groups_create(
    request: Request,
    display_name: str = Form(...),
    db: Session = Depends(get_db),
):
    name = display_name.strip()
    if not name:
        add_flash(request, "error", "Group name cannot be empty.")
        return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)
    group = TenantGroup(display_name=name)
    db.add(group)
    db.commit()
    add_flash(request, "success", f"Group '{name}' created.")
    return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)


@router.post("/groups/{gid}/delete", name="groups_delete")
def groups_delete(
    request: Request,
    gid: int,
    db: Session = Depends(get_db),
):
    group = _get_group(gid, db)
    name = group.display_name
    # Nullify group_id on member tenants before deleting
    for t in group.tenants:
        t.group_id = None
    db.delete(group)
    db.commit()
    add_flash(request, "info", f"Group '{name}' deleted.")
    return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)

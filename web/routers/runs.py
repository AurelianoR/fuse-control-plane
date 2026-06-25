from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from web import jobs
from web.db import get_db
from web.models import CollectionRun, DBGrant, GrantEvent, Tenant
from web.templating import templates
from web.utils import add_flash, pop_flash

router = APIRouter(prefix="/tenants/{id}/runs", tags=["runs"])


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


@router.post("", name="runs_trigger")
def runs_trigger(request: Request, id: int, db: Session = Depends(get_db)):
    tenant = _get_tenant(id, db)

    run = CollectionRun(
        tenant_fk=tenant.id,
        status="pending",
        started_at=datetime.now(timezone.utc),
    )
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        add_flash(request, "warning", "A collection run is already in progress.")
        return RedirectResponse(
            url=request.url_for("grants_list", id=id), status_code=303
        )

    jobs.trigger(tenant.id, run.id)
    return RedirectResponse(
        url=request.url_for("runs_detail", id=id, run_id=run.id), status_code=303
    )


@router.get("/{run_id}/status", name="runs_status")
def runs_status(request: Request, id: int, run_id: int, db: Session = Depends(get_db)):
    _get_tenant(id, db)
    run = db.get(CollectionRun, run_id)
    if not run or run.tenant_fk != id:
        raise HTTPException(status_code=404)
    return JSONResponse({
        "status": run.status,
        "activity_available": run.activity_available,
        "error": run.error_message,
        "counts": {
            "total": run.total_grants,
            "new": run.new_grants,
            "removed": run.removed_grants,
            "changed": run.changed_grants,
        },
    })


@router.get("/{run_id}", response_class=HTMLResponse, name="runs_detail")
def runs_detail(request: Request, id: int, run_id: int, db: Session = Depends(get_db)):
    tenant = _get_tenant(id, db)
    run = db.get(CollectionRun, run_id)
    if not run or run.tenant_fk != id:
        raise HTTPException(status_code=404)

    poll_url = str(request.url_for("runs_status", id=id, run_id=run_id))

    if run.status not in ("success", "failed"):
        return templates.TemplateResponse(
            request, "runs/detail.html",
            _base_ctx(request, db, tenant, run=run, poll_url=poll_url,
                      new_events=[], removed_events=[], changed_events=[]),
        )

    # Load events for completed run
    events = (
        db.query(GrantEvent)
        .filter(GrantEvent.run_id == run_id)
        .join(DBGrant)
        .add_columns(DBGrant)
        .all()
    )

    new_events, removed_events, changed_events = [], [], []
    for event, grant in events:
        if event.event_type == "new":
            new_events.append(grant)
        elif event.event_type == "removed":
            removed_events.append(grant)
        elif event.event_type in ("permission_added", "permission_removed"):
            changed_events.append({"event": event, "grant": grant})

    return templates.TemplateResponse(
        request, "runs/detail.html",
        _base_ctx(
            request, db, tenant,
            run=run,
            poll_url=poll_url,
            new_events=new_events,
            removed_events=removed_events,
            changed_events=changed_events,
        ),
    )

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from web.db import get_db
from web.models import Tenant
from web.templating import templates
from web.utils import add_flash, pop_flash

router = APIRouter(prefix="/tenants", tags=["tenants"])


def _ctx(request: Request, db: Session, **kwargs) -> dict:
    return {
        "request": request,
        "tenants": db.query(Tenant).order_by(Tenant.display_name).all(),
        "flash": pop_flash(request),
        **kwargs,
    }


@router.get("", response_class=HTMLResponse, name="tenants_list")
def tenants_list(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "tenants/list.html", _ctx(request, db))


@router.post("", name="tenants_create")
def tenants_create(
    request: Request,
    platform: str = Form("azure"),
    display_name: str = Form(...),
    tenant_id: str = Form(...),
    client_id: str = Form(""),
    client_secret: str = Form(...),
    db: Session = Depends(get_db),
):
    from web.config import get_settings
    settings = get_settings()

    if platform not in ("azure", "github"):
        platform = "azure"

    if db.query(Tenant).filter_by(tenant_id=tenant_id).first():
        label = "Org" if platform == "github" else "Tenant ID"
        add_flash(request, "error", f"{label} '{tenant_id}' is already configured.")
        return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)

    tenant = Tenant(
        display_name=display_name,
        tenant_id=tenant_id,
        client_id=client_id or "",
        platform=platform,
    )
    tenant.set_secret(client_secret, settings.secret_encryption_key)
    db.add(tenant)
    db.commit()
    add_flash(request, "success", f"'{display_name}' added.")
    return RedirectResponse(url=request.url_for("grants_list", id=tenant.id), status_code=303)


@router.get("/{id}/edit", response_class=HTMLResponse, name="tenants_edit")
def tenants_edit(request: Request, id: int, db: Session = Depends(get_db)):
    tenant = db.get(Tenant, id)
    if not tenant:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, "tenants/edit.html", _ctx(request, db, tenant=tenant))


@router.post("/{id}/edit", name="tenants_edit_save")
def tenants_edit_save(
    request: Request,
    id: int,
    display_name: str = Form(...),
    client_id: str = Form(""),
    client_secret: str = Form(""),
    db: Session = Depends(get_db),
):
    from web.config import get_settings
    settings = get_settings()

    tenant = db.get(Tenant, id)
    if not tenant:
        raise HTTPException(status_code=404)
    tenant.display_name = display_name
    if (tenant.platform or "azure") == "azure":
        tenant.client_id = client_id
    if client_secret.strip():
        tenant.set_secret(client_secret, settings.secret_encryption_key)
    db.commit()
    add_flash(request, "success", "Tenant updated.")
    return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)


@router.post("/{id}/delete", name="tenants_delete")
def tenants_delete(request: Request, id: int, db: Session = Depends(get_db)):
    tenant = db.get(Tenant, id)
    if not tenant:
        raise HTTPException(status_code=404)
    name = tenant.display_name
    db.delete(tenant)
    db.commit()
    add_flash(request, "info", f"Tenant '{name}' deleted.")
    return RedirectResponse(url=request.url_for("tenants_list"), status_code=303)


@router.post("/{id}/test", name="tenants_test")
def tenants_test(request: Request, id: int, db: Session = Depends(get_db)):
    from web.config import get_settings
    settings = get_settings()

    tenant = db.get(Tenant, id)
    if not tenant:
        raise HTTPException(status_code=404)
    try:
        secret = tenant.get_secret(settings.secret_encryption_key)
        platform = tenant.platform or "azure"
        if platform == "github":
            from collector.github.client import GitHubClient
            client = GitHubClient(secret)
            client.get(f"/orgs/{tenant.tenant_id}")
        else:
            from collector.graph.client import GraphClient
            client = GraphClient(tenant.tenant_id, tenant.client_id, secret)
            client.get("/organization", params={"$select": "id,displayName"})
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})

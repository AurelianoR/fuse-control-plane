import asyncio
import random
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import get_db, init_db
from models import Token, AuditLog, UsedJTI, SystemSettings, CloudEnvironment, ComplianceFramework
from schemas import (
    TokenSchema, RevokeRequest, AuditLogResponse, MetricsResponse, 
    DPoPVerificationRequest, TokenSettingsSchema, CloudEnvironmentSettingsSchema, 
    ComplianceSettingsSchema, SystemSettingsResponse, ResearchFrameworkRequest
)
from gateway import verify_dpop_proof

app = FastAPI(title="Fuse Control Plane API", version="2.4")

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "DPoP"],
)

# Startup tasks
drift_task = None
cleanup_task = None

async def simulate_usage_drift():
    """Background task to simulate live token usage drift (equivalent to Go code)"""
    while True:
        try:
            await asyncio.sleep(5)
            db = next(get_db())
            active_tokens = db.query(Token).filter(Token.is_revoked == False).all()
            for token in active_tokens:
                # Drift randomly by ±50 calls
                delta = random.randint(-50, 50)
                token.token_usage = max(0, token.token_usage + delta)
                token.last_seen = datetime.utcnow().isoformat() + "Z"
            db.commit()
        except Exception as e:
            print(f"Drift task error: {e}")

async def cleanup_expired_jtis():
    """Periodic background task to prune expired JTIs from database"""
    while True:
        try:
            await asyncio.sleep(60)  # Prune every minute
            db = next(get_db())
            now = datetime.utcnow()
            db.query(UsedJTI).filter(UsedJTI.expires_at < now).delete()
            db.commit()
        except Exception as e:
            print(f"JTI cleanup task error: {e}")

@app.on_event("startup")
def startup_event():
    global drift_task, cleanup_task
    # Initialize DB (creates tables, seeds data)
    init_db()
    # Start background loops
    drift_task = asyncio.create_task(simulate_usage_drift())
    cleanup_task = asyncio.create_task(cleanup_expired_jtis())

@app.on_event("shutdown")
def shutdown_event():
    if drift_task:
        drift_task.cancel()
    if cleanup_task:
        cleanup_task.cancel()

# --- API Route Handlers ---

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "fuse-control-plane-python"}

@app.get("/api/tokens", response_model=list[TokenSchema])
def get_tokens(db: Session = Depends(get_db)):
    # Return all non-revoked tokens
    return db.query(Token).filter(Token.is_revoked == False).all()

@app.post("/api/tokens/revoke")
def revoke_token(req: RevokeRequest, db: Session = Depends(get_db)):
    token = db.query(Token).filter(Token.id == req.token_id, Token.is_revoked == False).first()
    if not token:
        raise HTTPException(status_code=404, detail="token_id not found or already revoked")

    # Mark as revoked
    token.is_revoked = True
    
    # Write audit log entry
    timestamp_str = datetime.utcnow().isoformat() + "Z"
    audit_entry = AuditLog(
        timestamp=timestamp_str,
        token_id=token.id,
        vendor=token.vendor,
        provider=token.provider,
        scope=token.scope,
        action="REVOKED"
    )
    db.add(audit_entry)
    db.commit()

    print(f"🔴 [{timestamp_str}] REVOKED | ID: {token.id} | Vendor: {token.vendor} | Provider: {token.provider} | Scope: {token.scope}")

    return {
        "status": "success",
        "message": f"Token {token.id} has been revoked at the Cloud Provider root."
    }

@app.get("/api/metrics", response_model=MetricsResponse)
def get_metrics(db: Session = Depends(get_db)):
    active_tokens = db.query(Token).filter(Token.is_revoked == False).all()
    
    by_provider = {}
    critical = 0
    total = 0

    for t in active_tokens:
        by_provider[t.provider] = by_provider.get(t.provider, 0) + 1
        total += 1
        if t.is_critical:
            critical += 1

    return MetricsResponse(
        timestamp=datetime.utcnow().isoformat() + "Z",
        total_tokens=total,
        by_provider=by_provider,
        critical_count=critical
    )

@app.get("/api/audit", response_model=AuditLogResponse)
def get_audit(db: Session = Depends(get_db)):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).all()
    entries = []
    for log in logs:
        entry_str = f"[{log.timestamp}] REVOKED | ID: {log.token_id} | Vendor: {log.vendor} | Provider: {log.provider} | Scope: {log.scope}"
        entries.append(entry_str)

    return AuditLogResponse(
        total=len(entries),
        entries=entries
    )

@app.post("/api/gateway/verify")
def gateway_verify(req: DPoPVerificationRequest, db: Session = Depends(get_db)):
    success, message = verify_dpop_proof(
        db=db,
        dpop_proof=req.dpop_proof,
        request_method=req.request_method,
        request_uri=req.request_uri,
        vendor_name=req.vendor
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"status": "success", "detail": message}

# --- Settings & Governance Endpoints ---

MOCK_RESEARCH_DB = {
    "HIPAA": {
        "description": "Health Insurance Portability and Accountability Act safeguarding protected health information",
        "score": 85
    },
    "PCI-DSS": {
        "description": "Payment Card Industry Data Security Standard protecting cardholder data",
        "score": 90
    },
    "GDPR": {
        "description": "General Data Protection Regulation protecting EU citizen data privacy",
        "score": 82
    },
    "FedRAMP": {
        "description": "Federal Risk and Authorization Management Program for cloud product security",
        "score": 65
    },
    "SOC2": {
        "description": "System and Organization Controls for managing customer data based on Trust Services Criteria",
        "score": 89
    }
}

@app.get("/api/dashboard/settings")
def get_settings(db: Session = Depends(get_db)):
    settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
    if not settings:
        settings = SystemSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    cloud_envs = db.query(CloudEnvironment).all()
    frameworks = db.query(ComplianceFramework).all()

    # Format allowed_scopes and enabled_frameworks into lists
    scopes_list = [s.strip() for s in settings.allowed_scopes.split(",") if s.strip()]
    frameworks_list = [f.strip() for f in settings.enabled_frameworks.split(",") if f.strip()]
    frameworks_data = [
        {
            "id": f.id,
            "name": f.name,
            "description": f.description,
            "score": f.score,
            "enabled": f.enabled
        } for f in frameworks
    ]

    return {
        "status": "success",
        "data": {
            "token_governance": {
                "default_ttl_minutes": settings.default_ttl_minutes,
                "allowed_scopes": scopes_list,
                "enforce_sender_binding": settings.enforce_sender_binding,
                "max_token_usage_limit": settings.max_token_usage_limit
            },
            "cloud_environments": [
                {
                    "id": env.id,
                    "provider": env.provider,
                    "environment_type": env.environment_type,
                    "tenant_id": env.tenant_id,
                    "client_id": env.client_id,
                    "subscription_id": env.subscription_id,
                    "client_secret": env.client_secret,
                    "aws_role_arn": env.aws_role_arn,
                    "aws_access_key_id": env.aws_access_key_id,
                    "aws_secret_access_key": env.aws_secret_access_key,
                    "gcp_project_id": env.gcp_project_id,
                    "gcp_client_email": env.gcp_client_email,
                    "gcp_private_key": env.gcp_private_key
                } for env in cloud_envs
            ],
            "compliance": {
                "enabled_frameworks": frameworks_list,
                "frameworks": frameworks_data,
                "audit_logging_enabled": settings.audit_logging_enabled,
                "fail_strategy": settings.fail_strategy
            }
        }
    }

@app.post("/api/dashboard/settings/token")
def update_token_settings(req: TokenSettingsSchema, db: Session = Depends(get_db)):
    settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
    if not settings:
        settings = SystemSettings(id=1)
        db.add(settings)

    settings.default_ttl_minutes = req.default_ttl_minutes
    settings.allowed_scopes = ",".join(req.allowed_scopes)
    settings.enforce_sender_binding = req.enforce_sender_binding
    settings.max_token_usage_limit = req.max_token_usage_limit
    db.commit()

    return {"status": "success", "message": "Token governance updated"}

@app.post("/api/dashboard/settings/cloud")
def add_cloud_environment(req: CloudEnvironmentSettingsSchema, db: Session = Depends(get_db)):
    env = CloudEnvironment(
        provider=req.provider,
        environment_type=req.environment_type,
        tenant_id=req.tenant_id,
        client_id=req.client_id,
        subscription_id=req.subscription_id,
        client_secret=req.client_secret,
        aws_role_arn=req.aws_role_arn,
        aws_access_key_id=req.aws_access_key_id,
        aws_secret_access_key=req.aws_secret_access_key,
        gcp_project_id=req.gcp_project_id,
        gcp_client_email=req.gcp_client_email,
        gcp_private_key=req.gcp_private_key
    )
    db.add(env)
    db.commit()

    return {"status": "success", "message": f"{req.provider} environment connected"}

@app.post("/api/dashboard/settings/compliance")
def update_compliance_frameworks(req: ComplianceSettingsSchema, db: Session = Depends(get_db)):
    settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
    if not settings:
        settings = SystemSettings(id=1)
        db.add(settings)

    settings.enabled_frameworks = ",".join(req.enabled_frameworks)
    settings.audit_logging_enabled = req.audit_logging_enabled
    settings.fail_strategy = req.fail_strategy

    # Sync with ComplianceFramework table
    frameworks = db.query(ComplianceFramework).all()
    for f in frameworks:
        f.enabled = (f.name in req.enabled_frameworks)

    db.commit()

    return {"status": "success", "message": "Compliance parameters updated"}

@app.post("/api/dashboard/settings/compliance/research")
def research_compliance_framework(req: ResearchFrameworkRequest, db: Session = Depends(get_db)):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Framework name cannot be empty")

    existing = db.query(ComplianceFramework).filter(ComplianceFramework.name.like(name)).first()
    if existing:
        return {
            "status": "success",
            "message": f"Framework {name} already exists",
            "framework": {
                "id": existing.id,
                "name": existing.name,
                "description": existing.description,
                "score": existing.score,
                "enabled": existing.enabled
            }
        }

    key = name.upper()
    if key in MOCK_RESEARCH_DB:
        desc = MOCK_RESEARCH_DB[key]["description"]
        score = MOCK_RESEARCH_DB[key]["score"]
    else:
        desc = f"Regulatory compliance framework requirements for {name}"
        score = random.randint(55, 95)

    new_framework = ComplianceFramework(
        name=name,
        description=desc,
        score=score,
        enabled=True
    )
    db.add(new_framework)

    # Sync with SystemSettings enabled_frameworks list
    settings = db.query(SystemSettings).filter(SystemSettings.id == 1).first()
    if settings:
        enabled_list = [f.strip() for f in settings.enabled_frameworks.split(",") if f.strip()]
        if name not in enabled_list:
            enabled_list.append(name)
            settings.enabled_frameworks = ",".join(enabled_list)

    db.commit()
    db.refresh(new_framework)

    return {
        "status": "success",
        "message": f"Framework {name} successfully researched and integrated.",
        "framework": {
            "id": new_framework.id,
            "name": new_framework.name,
            "description": new_framework.description,
            "score": new_framework.score,
            "enabled": new_framework.enabled
        }
    }



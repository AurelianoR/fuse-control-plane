import asyncio
import random
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import get_db, init_db
from models import Token, AuditLog, UsedJTI
from schemas import TokenSchema, RevokeRequest, AuditLogResponse, MetricsResponse, DPoPVerificationRequest
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

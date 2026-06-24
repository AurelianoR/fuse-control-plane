from sqlalchemy import Column, String, Integer, Boolean, DateTime
from datetime import datetime
from database import Base

class Token(Base):
    __tablename__ = "tokens"

    id = Column(String, primary_key=True, index=True)
    vendor = Column(String, index=True)
    provider = Column(String, index=True)  # azure, aws, gcp
    resource = Column(String)
    scope = Column(String)
    expires_in = Column(String)
    risk_level = Column(String)
    is_critical = Column(Boolean, default=False)
    last_seen = Column(String)
    token_usage = Column(Integer, default=0)
    usage_limit = Column(Integer, default=0)
    is_revoked = Column(Boolean, default=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(String, default=lambda: datetime.utcnow().isoformat() + "Z")
    token_id = Column(String, index=True)
    vendor = Column(String)
    provider = Column(String)
    scope = Column(String)
    action = Column(String)

class UsedJTI(Base):
    __tablename__ = "used_jtis"

    jti = Column(String, primary_key=True, index=True)
    expires_at = Column(DateTime, index=True)

class Route(Base):
    __tablename__ = "routes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vendor = Column(String, unique=True, index=True)
    target_url = Column(String)
    active = Column(Boolean, default=True)

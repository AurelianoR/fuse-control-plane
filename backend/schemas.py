from pydantic import BaseModel
from typing import Dict, List, Optional

class TokenSchema(BaseModel):
    id: str
    vendor: str
    provider: str
    resource: str
    scope: str
    expires_in: str
    risk_level: str
    is_critical: bool
    last_seen: str
    token_usage: int
    usage_limit: int

    class Config:
        from_attributes = True

class RevokeRequest(BaseModel):
    token_id: str

class AuditLogResponse(BaseModel):
    total: int
    entries: List[str]

class MetricsResponse(BaseModel):
    timestamp: str
    total_tokens: int
    by_provider: Dict[str, int]
    critical_count: int

class DPoPVerificationRequest(BaseModel):
    dpop_proof: str
    request_method: str
    request_uri: str
    vendor: str

class TokenSettingsSchema(BaseModel):
    default_ttl_minutes: int
    allowed_scopes: List[str]
    enforce_sender_binding: bool

class CloudEnvironmentSettingsSchema(BaseModel):
    provider: str
    tenant_id: str
    client_id: str
    subscription_id: str
    environment_type: str

class ComplianceSettingsSchema(BaseModel):
    enabled_frameworks: List[str]
    audit_logging_enabled: bool
    fail_strategy: str

class SystemSettingsResponse(BaseModel):
    status: str
    data: Dict


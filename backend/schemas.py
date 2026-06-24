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
    max_token_usage_limit: int

class CloudEnvironmentSettingsSchema(BaseModel):
    provider: str
    environment_type: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    subscription_id: Optional[str] = None
    client_secret: Optional[str] = None
    aws_role_arn: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    gcp_project_id: Optional[str] = None
    gcp_client_email: Optional[str] = None
    gcp_private_key: Optional[str] = None

class ComplianceSettingsSchema(BaseModel):
    enabled_frameworks: List[str]
    audit_logging_enabled: bool
    fail_strategy: str

class ResearchFrameworkRequest(BaseModel):
    name: str

class SystemSettingsResponse(BaseModel):
    status: str
    data: Dict

class ReviseComplianceRequest(BaseModel):
    id: int
    score: int
    description: str
    enabled: bool

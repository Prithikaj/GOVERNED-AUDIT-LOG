from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    COMPLIANCE = "compliance"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class LogIngest(BaseModel):
    prompt: str
    response: str
    agent_id: str
    timestamp: str
    user_id: str


class LogRecord(BaseModel):
    record_id: str
    prompt: str
    response: str
    agent_id: str
    timestamp: datetime
    user_id: str
    redacted_prompt: str
    redacted_response: str
    retention_category: str
    expiry_time: datetime
    entry_hash: str
    previous_hash: Optional[str] = None
    metadata: Dict[str, Any] = {}


class PIIRevealRequest(BaseModel):
    justification: str = Field(..., min_length=10, description="Why PII access is needed")
    reason_code: str = Field(default="other", description="Predefined reason: legal, audit, compliance, support, other")


class AccessAuditFilter(BaseModel):
    user_id: Optional[str] = None
    record_id: Optional[str] = None
    action: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    limit: int = Field(default=100, le=1000)


class ComplianceRequest(BaseModel):
    retention_category: Optional[str] = None
    legal_hold: Optional[bool] = None
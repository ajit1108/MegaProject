# ============================================================
# app/models/schemas.py — Pydantic Request/Response Schemas
# ============================================================
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


# ── Enums ─────────────────────────────────────────────────────
class UserRole(str, Enum):
    user = "user"
    admin = "admin"


class RiskLevel(str, Enum):
    low = "Low Risk"
    medium = "Medium Risk"
    high = "High Risk"


class PrivacyClass(str, Enum):
    public = "Public"
    internal = "Internal"
    confidential = "Confidential"
    restricted = "Restricted"


class ProcessingStatus(str, Enum):
    pending = "pending"
    processing = "processing"
    completed = "completed"
    failed = "failed"


# ── Auth ───────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def name_no_special(cls, v: str) -> str:
        return v.strip()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    name: str
    role: str


class UserOut(BaseModel):
    id: str
    name: str
    email: str
    role: str
    created_at: datetime


# ── Documents ─────────────────────────────────────────────────
class DocumentOut(BaseModel):
    id: str
    original_filename: str
    file_type: str
    file_size: int
    upload_timestamp: datetime
    processing_status: str


# ── Detection ─────────────────────────────────────────────────
class DetectionItem(BaseModel):
    entity_type: str
    matched_value: str          # masked/protected value
    original_value: str = ""    # only populated for owner-view, masked by default
    start: int
    end: int
    privacy_class: str
    classification_reason: str
    risk_points: float
    detection_method: str       # "regex" | "nlp" | "both"
    confidence: float


# ── Analysis ──────────────────────────────────────────────────
class AnalysisOut(BaseModel):
    id: str
    document_id: str
    document_name: str
    user_id: str
    total_detections: int
    detections: List[DetectionItem]
    risk_score: float
    risk_level: str
    class_summary: dict
    sanitization_status: str
    created_at: datetime


class AnalysisHistoryItem(BaseModel):
    id: str
    document_name: str
    total_detections: int
    risk_score: float
    risk_level: str
    sanitization_status: str
    created_at: datetime


# ── Sanitization ──────────────────────────────────────────────
class SanitizeRequest(BaseModel):
    mode: str = "redact"   # "redact" | "mask"


class SanitizedOut(BaseModel):
    analysis_id: str
    original_text_preview: str   # first 300 chars, masked
    sanitized_text: str
    mode: str
    remaining_detections: int
    warning: Optional[str] = None


# ── Privacy Gateway ───────────────────────────────────────────
class GatewayInspectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)
    allow_forward: bool = False


class GatewayInspectResponse(BaseModel):
    risk_score: float
    risk_level: str
    total_detections: int
    detections: List[DetectionItem]
    sanitized_text: str
    permit_forward: bool
    warnings: List[str]


# ── Dashboard ─────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_documents: int
    total_analyses: int
    total_detections: int
    high_risk: int
    medium_risk: int
    low_risk: int
    recent_analyses: List[AnalysisHistoryItem]
    class_distribution: dict
    risk_distribution: dict


# ── Reports ───────────────────────────────────────────────────
class ReportSummary(BaseModel):
    total_analyses: int
    total_detections: int
    risk_distribution: dict
    class_distribution: dict
    top_entity_types: List[dict]

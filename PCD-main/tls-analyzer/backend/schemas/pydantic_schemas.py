"""Pydantic schemas for request/response validation."""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# ── Auth ─────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    role: str = Field(default="end_user", pattern="^(end_user|app_owner|admin)$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str = ""
    token_type: str = "bearer"
    requires_2fa: bool = False


class OAuthGoogleRequest(BaseModel):
    credential: str   # Google ID token


class OAuthGithubRequest(BaseModel):
    code: str         # GitHub authorization code


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    totp_code: Optional[str] = None   # required when the account has 2FA enabled


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class SetRoleRequest(BaseModel):
    role: str = Field(pattern="^(end_user|app_owner)$")


class UserOut(BaseModel):
    id: int
    email: str
    name: Optional[str]
    company: Optional[str] = None
    phone: Optional[str] = None
    date_of_birth: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    totp_enabled: bool = False
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Applications ─────────────────────────────────────────────────────────

class AppSubmitRequest(BaseModel):
    package_name: str = Field(min_length=1, max_length=255)
    app_name: Optional[str] = None
    category: Optional[str] = None
    apk_path: Optional[str] = None


class AppOut(BaseModel):
    id: int
    package_name: str
    app_name: Optional[str]
    category: Optional[str]
    install_count: Optional[int]
    rating: Optional[float]
    description: Optional[str]
    owner_id: Optional[int]
    submitted_at: datetime
    scanned_at: Optional[datetime] = None
    made_public_at: Optional[datetime] = None
    scan_status: str
    is_public: bool = False
    # Denormalised from latest MLPrediction (injected by list endpoint)
    security_score: Optional[float] = None
    risk_level: Optional[str] = None
    pqc_readiness_score: Optional[float] = None

    model_config = {"from_attributes": True}


class DomainOut(BaseModel):
    id: int
    domain: str
    ip: Optional[str]
    country: Optional[str]
    is_third_party: bool
    domain_class: Optional[str]

    model_config = {"from_attributes": True}


class TLSResultOut(BaseModel):
    id: int
    domain_id: int
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    key_exchange: Optional[str]
    cert_expiry: Optional[datetime]
    cert_issuer: Optional[str]
    cert_validity_days: Optional[int]
    cert_key_type: Optional[str]
    cert_key_bits: Optional[int]
    supports_pqc: bool
    pqc_group: Optional[str]
    has_ecdh: bool
    has_rsa_key_exchange: bool
    flag_legacy_tls: bool
    flag_rc4_or_3des: bool
    cipher_strength_score: Optional[float]
    quantum_risk_score: Optional[float]
    security_score: Optional[float]
    scan_date: datetime
    scan_error: Optional[str]

    model_config = {"from_attributes": True}


class VulnerabilityOut(BaseModel):
    id: int
    tls_result_id: int
    cve_id: Optional[str]
    severity: str
    cvss_score: Optional[float]
    description: str
    reference_url: Optional[str]

    model_config = {"from_attributes": True}


class MLPredictionOut(BaseModel):
    id: int
    app_id: int
    security_score: float
    risk_level: str
    pqc_readiness_score: float
    confidence: Optional[float]
    feature_importances: Optional[dict]
    predicted_at: datetime

    model_config = {"from_attributes": True}


class WarrantyOut(BaseModel):
    id: int
    app_id: int
    status: str
    issued_at: datetime
    expires_at: Optional[datetime]
    justification: Optional[str]

    model_config = {"from_attributes": True}


# ── Admin ────────────────────────────────────────────────────────────────

class VisibilityUpdateRequest(BaseModel):
    is_public: bool


class RoleUpdateRequest(BaseModel):
    role: str = Field(pattern="^(end_user|app_owner|admin)$")


class SystemHealthOut(BaseModel):
    db_connected: bool
    total_users: int
    total_apps: int
    total_scans: int
    pending_scans: int
    ml_model_loaded: bool


# ── Report ───────────────────────────────────────────────────────────────

class AppReportOut(BaseModel):
    app: AppOut
    domains: list[DomainOut]
    tls_results: list[TLSResultOut]
    vulnerabilities: list[VulnerabilityOut]
    prediction: Optional[MLPredictionOut]
    warranty: Optional[WarrantyOut]


# ── Profile & Password ────────────────────────────────────────────────────────

class UpdateProfileRequest(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    company: Optional[str] = Field(default=None, max_length=255)
    phone: Optional[str] = Field(default=None, max_length=50)
    date_of_birth: Optional[str] = Field(default=None, max_length=20)
    location: Optional[str] = Field(default=None, max_length=255)
    bio: Optional[str] = Field(default=None, max_length=1000)


class TotpSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_data_url: str   # base64 PNG data URL


class TotpVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=128)


# ── Preferences ───────────────────────────────────────────────────────────────

class PreferencesOut(BaseModel):
    email_notifications: bool
    security_alerts: bool
    weekly_reports: bool
    product_updates: bool

    model_config = {"from_attributes": True}


class PreferencesUpdate(BaseModel):
    email_notifications: Optional[bool] = None
    security_alerts: Optional[bool] = None
    weekly_reports: Optional[bool] = None
    product_updates: Optional[bool] = None


# ── API Key ───────────────────────────────────────────────────────────────────

class ApiKeyOut(BaseModel):
    id: int
    key: str
    created_at: datetime
    last_used_at: Optional[datetime]

    model_config = {"from_attributes": True}


# ── Sessions ──────────────────────────────────────────────────────────────────

class SessionOut(BaseModel):
    id: int
    browser: Optional[str]
    os: Optional[str]
    ip: Optional[str]
    created_at: datetime
    last_seen_at: datetime
    is_active: bool

    model_config = {"from_attributes": True}


# ── Knowledge Bases ───────────────────────────────────────────────────────────

class KnowledgeBaseOut(BaseModel):
    id: int
    name: str
    type: str
    records: int
    size: Optional[str]
    status: str
    source: Optional[str]
    last_sync: Optional[datetime]

    model_config = {"from_attributes": True}


class SyncConfigOut(BaseModel):
    sync_interval: str
    backup_retention: str

    model_config = {"from_attributes": True}


class SyncConfigUpdate(BaseModel):
    sync_interval: Optional[str] = None
    backup_retention: Optional[str] = None


class SyncJobOut(BaseModel):
    id: int
    kb_id: Optional[int]
    kb_name: str
    operation: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    records_before: Optional[int]
    records_after: Optional[int]
    error_msg: Optional[str]
    triggered_by: str

    model_config = {"from_attributes": True}


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: int
    title: str
    date: datetime
    type: str
    apps_count: int
    status: str

    model_config = {"from_attributes": True}


# ── Contact ───────────────────────────────────────────────────────────────────

class ContactMessageRequest(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    email: EmailStr
    subject: str = Field(min_length=5, max_length=100)
    message: str = Field(min_length=20, max_length=2000)


class ContactMessageOut(BaseModel):
    id: int
    name: str
    email: str
    subject: str
    message: str
    created_at: datetime
    is_read: bool

    model_config = {"from_attributes": True}

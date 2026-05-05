"""SQLAlchemy ORM models for the TLS Security Analyzer."""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON,
    BigInteger,
)
from sqlalchemy.orm import relationship

from ..database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="end_user")  # end_user | app_owner | admin
    name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    date_of_birth = Column(String(20), nullable=True)   # ISO date: YYYY-MM-DD
    location = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    applications = relationship("Application", back_populates="owner")
    preferences = relationship("UserPreferences", back_populates="user", uselist=False, cascade="all, delete-orphan")
    api_key = relationship("UserApiKey", back_populates="user", uselist=False, cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    apk_path = Column(String(512), nullable=True)
    app_name = Column(String(255), nullable=True)
    category = Column(String(100), nullable=True)
    install_count = Column(BigInteger, nullable=True)
    rating = Column(Float, nullable=True)
    description = Column(Text, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    submitted_at = Column(DateTime(timezone=True), default=_utcnow)
    scanned_at = Column(DateTime(timezone=True), nullable=True)     # set when scan completes or fails
    made_public_at = Column(DateTime(timezone=True), nullable=True) # set when is_public toggled True
    scan_status = Column(String(20), default="pending")  # pending | scanning | completed | failed
    is_public = Column(Boolean, default=False)  # visible in public browse; always True for seeded data

    owner = relationship("User", back_populates="applications")
    domains = relationship("Domain", back_populates="application", cascade="all, delete-orphan")
    predictions = relationship("MLPrediction", back_populates="application", cascade="all, delete-orphan")
    warranties = relationship("SecurityWarranty", back_populates="application", cascade="all, delete-orphan")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(Integer, ForeignKey("applications.id"), nullable=False, index=True)
    domain = Column(String(255), nullable=False)
    ip = Column(String(45), nullable=True)
    country = Column(String(10), nullable=True)
    is_third_party = Column(Boolean, default=False)
    domain_class = Column(String(50), nullable=True)  # first_party, cdn, ads, google, etc.

    application = relationship("Application", back_populates="domains")
    tls_results = relationship("TLSResult", back_populates="domain_rel", cascade="all, delete-orphan")


class TLSResult(Base):
    __tablename__ = "tls_results"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=False, index=True)
    tls_version = Column(String(20), nullable=True)
    cipher_suite = Column(String(255), nullable=True)
    key_exchange = Column(String(100), nullable=True)
    cert_expiry = Column(DateTime(timezone=True), nullable=True)
    cert_issuer = Column(String(255), nullable=True)
    cert_validity_days = Column(Integer, nullable=True)
    cert_key_type = Column(String(20), nullable=True)
    cert_key_bits = Column(Integer, nullable=True)
    supports_pqc = Column(Boolean, default=False)
    pqc_group = Column(String(100), nullable=True)
    has_ecdh = Column(Boolean, default=False)
    has_rsa_key_exchange = Column(Boolean, default=False)
    flag_legacy_tls = Column(Boolean, default=False)
    flag_rc4_or_3des = Column(Boolean, default=False)
    cipher_strength_score = Column(Float, nullable=True)
    quantum_risk_score = Column(Float, nullable=True)
    security_score = Column(Float, nullable=True)
    scan_date = Column(DateTime(timezone=True), default=_utcnow)
    scan_error = Column(Text, nullable=True)

    domain_rel = relationship("Domain", back_populates="tls_results")
    vulnerabilities = relationship("Vulnerability", back_populates="tls_result", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    tls_result_id = Column(Integer, ForeignKey("tls_results.id"), nullable=False, index=True)
    cve_id = Column(String(30), nullable=True)
    severity = Column(String(20), nullable=False)  # Low | Medium | High | Critical
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=False)
    reference_url = Column(String(512), nullable=True)

    tls_result = relationship("TLSResult", back_populates="vulnerabilities")


class MLPrediction(Base):
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(Integer, ForeignKey("applications.id"), nullable=False, index=True)
    security_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)  # Low | Medium | High | Critical
    pqc_readiness_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=True)
    feature_importances = Column(JSON, nullable=True)
    predicted_at = Column(DateTime(timezone=True), default=_utcnow)

    application = relationship("Application", back_populates="predictions")


class SecurityWarranty(Base):
    __tablename__ = "security_warranties"

    id = Column(Integer, primary_key=True, index=True)
    app_id = Column(Integer, ForeignKey("applications.id"), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # Certified | Conditional | Not Certified
    issued_at = Column(DateTime(timezone=True), default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    justification = Column(Text, nullable=True)

    application = relationship("Application", back_populates="warranties")


class UserPreferences(Base):
    __tablename__ = "user_preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    email_notifications = Column(Boolean, default=True)
    security_alerts = Column(Boolean, default=True)
    weekly_reports = Column(Boolean, default=False)
    product_updates = Column(Boolean, default=True)

    user = relationship("User", back_populates="preferences")


class UserApiKey(Base):
    __tablename__ = "user_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    key = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="api_key")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    browser = Column(String(100), nullable=True)
    os = Column(String(100), nullable=True)
    ip = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    last_seen_at = Column(DateTime(timezone=True), default=_utcnow)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="sessions")


class KnowledgeBase(Base):
    __tablename__ = "knowledge_bases"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(100), nullable=False)
    records = Column(Integer, default=0)
    size = Column(String(20), nullable=True)
    status = Column(String(20), default="synced")  # synced | syncing | error
    source = Column(String(255), nullable=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)


class SyncConfig(Base):
    __tablename__ = "sync_configs"

    id = Column(Integer, primary_key=True, default=1)
    sync_interval = Column(String(10), default="6h")
    backup_retention = Column(String(10), default="30d")


class SyncJob(Base):
    __tablename__ = "sync_jobs"

    id = Column(Integer, primary_key=True, index=True)
    kb_id = Column(Integer, ForeignKey("knowledge_bases.id", ondelete="SET NULL"), nullable=True)
    kb_name = Column(String(255), nullable=False)
    operation = Column(String(20), nullable=False)   # sync | sync-all | import | export
    status = Column(String(20), default="running")   # running | success | error
    started_at = Column(DateTime(timezone=True), default=_utcnow)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    records_before = Column(Integer, nullable=True)
    records_after = Column(Integer, nullable=True)
    error_msg = Column(Text, nullable=True)
    triggered_by = Column(String(20), default="manual")  # manual | scheduler


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    date = Column(DateTime(timezone=True), nullable=False)
    type = Column(String(20), nullable=False)  # weekly | monthly | quarterly | custom
    apps_count = Column(Integer, default=0)
    status = Column(String(20), default="ready")  # ready | generating | failed
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class ContactMessage(Base):
    __tablename__ = "contact_messages"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False)
    subject = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    is_read = Column(Boolean, default=False)

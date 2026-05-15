"""
SENTINEL AI — Scan Control Models
Scans, Targets, Assets, Findings, Vulnerabilities, Attack Paths.
"""
from sqlalchemy import String, DateTime, Boolean, Integer, Float, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
import enum
import uuid

from ...common.database import Base, TimestampMixin, TenantMixin


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanType(str, enum.Enum):
    WEB = "web"
    NETWORK = "network"
    CODE = "code"
    CONTAINER = "container"
    FULL = "full"
    ADVANCED = "advanced"


class Asset(TimestampMixin, TenantMixin, Base):
    __tablename__ = "assets"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)  # server, web_app, api, container, repo
    target: Mapped[str] = mapped_column(String(500), nullable=False)  # IP, URL, repo URL
    environment: Mapped[str] = mapped_column(String(50), default="production")
    criticality: Mapped[str] = mapped_column(String(20), default="medium")  # critical, high, medium, low
    os_info: Mapped[str] = mapped_column(String(200), nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    location: Mapped[str] = mapped_column(String(200), nullable=True)


class Scan(TimestampMixin, TenantMixin, Base):
    __tablename__ = "scans"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), default="local")
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    target_raw: Mapped[str] = mapped_column(String(500), nullable=True)
    
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    
    tools_used: Mapped[dict] = mapped_column(JSON, default=list)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    
    schedule_cron: Mapped[str] = mapped_column(String(100), nullable=True)
    is_recurring: Mapped[bool] = mapped_column(Boolean, default=False)

    # Security scoring
    security_score: Mapped[float] = mapped_column(Float, nullable=True)
    risk_grade: Mapped[str] = mapped_column(String(20), nullable=True)
    input_type: Mapped[str] = mapped_column(String(30), nullable=True)

    # Drift detection — populated after recurring scan comparison
    drift_summary: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Storage — MinIO/S3 key for PDF report
    report_s3_key: Mapped[str] = mapped_column(String(500), nullable=True)


class Finding(TimestampMixin, TenantMixin, Base):
    __tablename__ = "findings"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str] = mapped_column(String(200), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=True)
    
    tool_name: Mapped[str] = mapped_column(String(50), nullable=False)
    tool_output: Mapped[dict] = mapped_column(JSON, default=dict)
    
    affected_component: Mapped[str] = mapped_column(String(500), nullable=True)
    affected_url: Mapped[str] = mapped_column(String(1000), nullable=True)
    
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    references: Mapped[dict] = mapped_column(JSON, default=list)
    
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False)
    duplicate_of: Mapped[str] = mapped_column(String(36), nullable=True)
    
    ai_risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    ai_analysis: Mapped[dict] = mapped_column(JSON, nullable=True)
    
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_details: Mapped[str] = mapped_column(Text, nullable=True)


class Vulnerability(TimestampMixin, TenantMixin, Base):
    """Deduplicated, AI-enriched vulnerability record."""
    __tablename__ = "vulnerabilities"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    cve_id: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    cwe_id: Mapped[str] = mapped_column(String(50), nullable=True)
    
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability: Mapped[float] = mapped_column(Float, default=0.0)
    asset_criticality: Mapped[float] = mapped_column(Float, default=0.0)
    exposure_level: Mapped[float] = mapped_column(Float, default=0.0)
    
    affected_assets: Mapped[dict] = mapped_column(JSON, default=list)
    related_findings: Mapped[dict] = mapped_column(JSON, default=list)
    
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[str] = mapped_column(Text, nullable=True)
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    
    status: Mapped[str] = mapped_column(String(20), default="open")  # open, mitigated, resolved, accepted


class AttackPath(TimestampMixin, TenantMixin, Base):
    __tablename__ = "attack_paths"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    
    chain_steps: Mapped[dict] = mapped_column(JSON, default=list)
    entry_point: Mapped[str] = mapped_column(String(500), nullable=True)
    final_impact: Mapped[str] = mapped_column(String(500), nullable=True)
    
    affected_assets: Mapped[dict] = mapped_column(JSON, default=list)
    related_vulns: Mapped[dict] = mapped_column(JSON, default=list)
    
    ai_analysis: Mapped[str] = mapped_column(Text, nullable=True)
    mitigation_steps: Mapped[dict] = mapped_column(JSON, default=list)


class AIFeedback(TimestampMixin, TenantMixin, Base):
    """Stores analyst corrections on AI predictions to feed the continual retrainer."""
    __tablename__ = "ai_feedback"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    
    # False Positive Metrics
    predicted_is_fp: Mapped[bool] = mapped_column(Boolean, nullable=True)
    actual_is_fp: Mapped[bool] = mapped_column(Boolean, nullable=False)
    
    # Risk Score Metrics
    predicted_risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    actual_risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    
    # Context
    analyst_notes: Mapped[str] = mapped_column(Text, nullable=True)
    retrained: Mapped[bool] = mapped_column(Boolean, default=False)


class AlertDLQ(TimestampMixin, TenantMixin, Base):
    """Dead Letter Queue for failed external alerts (SMTP / Slack)."""
    __tablename__ = "alerts_dlq"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False) # SMTP, SLACK
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending") # pending, failed, resolved


class KafkaFallbackDLQ(TimestampMixin, TenantMixin, Base):
    """Fallback Queue for Kafka dropping out, mapping exact JSON string dumps."""
    __tablename__ = "kafka_dlq"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    message_key: Mapped[str] = mapped_column(String(255), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, replayed, dead
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class PredictionLog(TimestampMixin, TenantMixin, Base):
    """Logs AI predictions for drift monitoring and reproducibility."""
    __tablename__ = "prediction_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_version: Mapped[str] = mapped_column(String(100), nullable=False)
    model_hash: Mapped[str] = mapped_column(String(100), nullable=True)
    input_features: Mapped[dict] = mapped_column(JSON, nullable=False)
    output_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)


"""SQLAlchemy ORM models and Pydantic schemas for Auto-pen."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Enums (shared between ORM and Pydantic)
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProfile(str, Enum):
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    CTF = "ctf"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# SQLAlchemy ORM models
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


def _new_uuid() -> str:
    return str(uuid.uuid4())


class DBSession(Base):
    """Represents a single pentest session."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    target: Mapped[str] = mapped_column(String(512))
    profile: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default=SessionStatus.PENDING)
    authorization_token: Mapped[str] = mapped_column(Text)
    scope_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    llm_provider: Mapped[str] = mapped_column(String(100), default="ollama")
    llm_model: Mapped[str] = mapped_column(String(100), default="llama3.1")
    step_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    findings: Mapped[list[DBFinding]] = relationship(
        "DBFinding", back_populates="session", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list[DBAuditLog]] = relationship(
        "DBAuditLog", back_populates="session", cascade="all, delete-orphan"
    )


class DBFinding(Base):
    """A single vulnerability or noteworthy discovery."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    severity: Mapped[str] = mapped_column(String(50), default=Severity.INFO)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    tool_name: Mapped[str] = mapped_column(String(100))
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), default=None)
    target: Mapped[str] = mapped_column(String(512))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[DBSession] = relationship("DBSession", back_populates="findings")


class DBAuditLog(Base):
    """Full audit trail of every action taken during a session."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    action: Mapped[str] = mapped_column(String(200))
    tool_name: Mapped[str | None] = mapped_column(String(100), default=None)
    params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_summary: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(50), default=RiskLevel.LOW)
    approved_by_human: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[DBSession] = relationship("DBSession", back_populates="audit_logs")


# ---------------------------------------------------------------------------
# Pydantic schemas (API request/response)
# ---------------------------------------------------------------------------


class ScopeConfig(BaseModel):
    """Defines the authorized attack surface for a pentest session."""

    allowed_hosts: list[str] = Field(
        description="Allowed IP addresses, CIDR ranges, or domain names (e.g. '192.168.1.0/24', 'example.com')"
    )
    allowed_ports: list[int] = Field(
        default=[], description="Allowed ports. Empty list means all ports are in scope."
    )
    exclude_hosts: list[str] = Field(
        default=[], description="Explicitly excluded hosts even if they fall within allowed_hosts ranges"
    )


class SessionCreate(BaseModel):
    """Input schema for creating a new pentest session."""

    target: str = Field(description="Primary target (IP, CIDR, URL, or hostname)")
    profile: ScanProfile = Field(description="Scan profile: web | network | cloud | ctf")
    authorization_token: str = Field(
        description="Written authorization statement confirming permission to test"
    )
    scope: ScopeConfig | None = Field(
        default=None,
        description="Scope config. If None, target is used as the sole allowed host.",
    )
    llm_provider: str = Field(default="ollama")
    llm_model: str = Field(default="llama3.1")


class SessionRead(BaseModel):
    """Output schema for a pentest session."""

    id: str
    target: str
    profile: str
    status: str
    llm_provider: str
    llm_model: str
    step_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingCreate(BaseModel):
    """Input schema for recording a new finding."""

    session_id: str
    severity: Severity
    title: str
    description: str
    tool_name: str
    evidence: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    target: str


class FindingRead(BaseModel):
    """Output schema for a finding."""

    id: str
    session_id: str
    severity: str
    title: str
    description: str
    tool_name: str
    evidence: str
    remediation: str
    cvss_score: float | None
    cvss_vector: str | None
    target: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class AuditLogRead(BaseModel):
    """Output schema for an audit log entry."""

    id: str
    session_id: str
    timestamp: datetime
    action: str
    tool_name: str | None
    params: dict[str, Any]
    result_summary: str
    risk_level: str
    approved_by_human: bool

    model_config = {"from_attributes": True}

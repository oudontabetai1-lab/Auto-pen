"""Session and finding persistence via SQLAlchemy."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session as OrmSession

from autopen.state.models import (
    Base,
    DBAuditLog,
    DBFinding,
    DBSession,
    FindingCreate,
    RiskLevel,
    ScopeConfig,
    SessionCreate,
    SessionStatus,
)


class SessionManager:
    """CRUD operations for pentest sessions, findings, and audit logs."""

    def __init__(self, db_url: str = "sqlite:///autopen.db") -> None:
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    def create_session(self, data: SessionCreate) -> DBSession:
        scope = data.scope or ScopeConfig(allowed_hosts=[data.target])
        with OrmSession(self.engine) as s:
            db_session = DBSession(
                target=data.target,
                profile=data.profile,
                status=SessionStatus.PENDING,
                authorization_token=data.authorization_token,
                scope_config=scope.model_dump(),
                llm_provider=data.llm_provider,
                llm_model=data.llm_model,
            )
            s.add(db_session)
            s.commit()
            s.refresh(db_session)
            # detach from session so it can be used outside
            s.expunge(db_session)
            return db_session

    def get_session(self, session_id: str) -> DBSession | None:
        with OrmSession(self.engine) as s:
            result = s.execute(select(DBSession).where(DBSession.id == session_id))
            row = result.scalar_one_or_none()
            if row:
                s.expunge(row)
            return row

    def list_sessions(self) -> list[DBSession]:
        with OrmSession(self.engine) as s:
            result = s.execute(select(DBSession).order_by(DBSession.created_at.desc()))
            rows = list(result.scalars().all())
            for r in rows:
                s.expunge(r)
            return rows

    def update_status(self, session_id: str, status: SessionStatus) -> None:
        with OrmSession(self.engine) as s:
            row = s.get(DBSession, session_id)
            if row:
                row.status = status
                row.updated_at = datetime.utcnow()
                s.commit()

    def increment_step(self, session_id: str) -> None:
        with OrmSession(self.engine) as s:
            row = s.get(DBSession, session_id)
            if row:
                row.step_count = (row.step_count or 0) + 1
                row.updated_at = datetime.utcnow()
                s.commit()

    def delete_session(self, session_id: str) -> bool:
        with OrmSession(self.engine) as s:
            row = s.get(DBSession, session_id)
            if row:
                s.delete(row)
                s.commit()
                return True
            return False

    # ------------------------------------------------------------------
    # Finding CRUD
    # ------------------------------------------------------------------

    def add_finding(self, data: FindingCreate) -> DBFinding:
        with OrmSession(self.engine) as s:
            finding = DBFinding(**data.model_dump())
            s.add(finding)
            s.commit()
            s.refresh(finding)
            s.expunge(finding)
            return finding

    def list_findings(self, session_id: str) -> list[DBFinding]:
        with OrmSession(self.engine) as s:
            result = s.execute(
                select(DBFinding)
                .where(DBFinding.session_id == session_id)
                .order_by(DBFinding.timestamp)
            )
            rows = list(result.scalars().all())
            for r in rows:
                s.expunge(r)
            return rows

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def log_action(
        self,
        session_id: str,
        action: str,
        tool_name: str | None = None,
        params: dict[str, Any] | None = None,
        result_summary: str = "",
        risk_level: RiskLevel = RiskLevel.LOW,
        approved_by_human: bool = False,
    ) -> DBAuditLog:
        with OrmSession(self.engine) as s:
            entry = DBAuditLog(
                session_id=session_id,
                action=action,
                tool_name=tool_name,
                params=params or {},
                result_summary=result_summary,
                risk_level=risk_level,
                approved_by_human=approved_by_human,
            )
            s.add(entry)
            s.commit()
            s.refresh(entry)
            s.expunge(entry)
            return entry

    def list_audit_logs(self, session_id: str) -> list[DBAuditLog]:
        with OrmSession(self.engine) as s:
            result = s.execute(
                select(DBAuditLog)
                .where(DBAuditLog.session_id == session_id)
                .order_by(DBAuditLog.timestamp)
            )
            rows = list(result.scalars().all())
            for r in rows:
                s.expunge(r)
            return rows

"""Unit tests for state management (SessionManager)."""

from __future__ import annotations

import pytest

from autopen.state.manager import SessionManager
from autopen.state.models import (
    FindingCreate,
    ScanProfile,
    ScopeConfig,
    SessionCreate,
    SessionStatus,
    Severity,
)


@pytest.fixture
def manager(tmp_path):
    db_file = tmp_path / "test.db"
    return SessionManager(db_url=f"sqlite:///{db_file}")


@pytest.fixture
def sample_session(manager):
    data = SessionCreate(
        target="192.168.1.1",
        profile=ScanProfile.NETWORK,
        authorization_token="test auth statement for unit test",
        scope=ScopeConfig(allowed_hosts=["192.168.1.1"]),
        llm_provider="ollama",
        llm_model="llama3.1",
    )
    return manager.create_session(data)


class TestSessionCRUD:
    def test_create_session(self, manager):
        data = SessionCreate(
            target="10.0.0.1",
            profile=ScanProfile.WEB,
            authorization_token="authorization statement for the unit test",
        )
        session = manager.create_session(data)
        assert session.id
        assert session.target == "10.0.0.1"
        assert session.status == SessionStatus.PENDING

    def test_get_session(self, manager, sample_session):
        fetched = manager.get_session(sample_session.id)
        assert fetched is not None
        assert fetched.id == sample_session.id

    def test_get_session_not_found(self, manager):
        assert manager.get_session("nonexistent-id") is None

    def test_list_sessions(self, manager, sample_session):
        sessions = manager.list_sessions()
        assert len(sessions) >= 1
        ids = [s.id for s in sessions]
        assert sample_session.id in ids

    def test_update_status(self, manager, sample_session):
        manager.update_status(sample_session.id, SessionStatus.RUNNING)
        updated = manager.get_session(sample_session.id)
        assert updated.status == SessionStatus.RUNNING

    def test_increment_step(self, manager, sample_session):
        manager.increment_step(sample_session.id)
        manager.increment_step(sample_session.id)
        updated = manager.get_session(sample_session.id)
        assert updated.step_count == 2

    def test_delete_session(self, manager, sample_session):
        result = manager.delete_session(sample_session.id)
        assert result is True
        assert manager.get_session(sample_session.id) is None

    def test_delete_nonexistent(self, manager):
        assert manager.delete_session("fake-id") is False

    def test_scope_defaults_to_target(self, manager):
        data = SessionCreate(
            target="example.com",
            profile=ScanProfile.WEB,
            authorization_token="authorization statement for the unit test",
            scope=None,
        )
        session = manager.create_session(data)
        assert "example.com" in session.scope_config["allowed_hosts"]


class TestFindingCRUD:
    def test_add_and_list_findings(self, manager, sample_session):
        finding_data = FindingCreate(
            session_id=sample_session.id,
            severity=Severity.HIGH,
            title="Open SSH port",
            description="SSH running on port 22",
            tool_name="nmap",
            target="192.168.1.1",
        )
        finding = manager.add_finding(finding_data)
        assert finding.id
        assert finding.title == "Open SSH port"

        findings = manager.list_findings(sample_session.id)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_multiple_findings_returned(self, manager, sample_session):
        for i in range(3):
            manager.add_finding(FindingCreate(
                session_id=sample_session.id,
                severity=Severity.LOW,
                title=f"Finding {i}",
                description="desc",
                tool_name="nmap",
                target="192.168.1.1",
            ))
        findings = manager.list_findings(sample_session.id)
        assert len(findings) == 3

    def test_findings_isolated_by_session(self, manager, sample_session):
        other = manager.create_session(SessionCreate(
            target="10.0.0.2",
            profile=ScanProfile.WEB,
            authorization_token="authorization statement for the unit test",
        ))
        manager.add_finding(FindingCreate(
            session_id=sample_session.id,
            severity=Severity.MEDIUM,
            title="Test",
            description="desc",
            tool_name="nmap",
            target="192.168.1.1",
        ))
        assert manager.list_findings(other.id) == []


class TestAuditLog:
    def test_log_and_retrieve(self, manager, sample_session):
        manager.log_action(
            session_id=sample_session.id,
            action="tool_executing",
            tool_name="nmap",
            result_summary="Running nmap scan",
        )
        logs = manager.list_audit_logs(sample_session.id)
        assert len(logs) == 1
        assert logs[0].tool_name == "nmap"
        assert logs[0].action == "tool_executing"

"""Integration tests for the FastAPI REST API."""

from __future__ import annotations

import json
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def app(tmp_path):
    from autopen.api.main import create_app
    db_url = f"sqlite:///{tmp_path}/test.db"
    return create_app(db_url=db_url)


@pytest.fixture
def session_payload():
    return {
        "target": "10.0.0.1",
        "profile": "network",
        "authorization_token": "authorized for testing",
        "scope": {"allowed_hosts": ["10.0.0.1"], "allowed_ports": [], "exclude_hosts": []},
        "llm_provider": "ollama",
        "llm_model": "llama3.1",
    }


@pytest_asyncio.fixture
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def created_session(client, session_payload):
    resp = await client.post("/api/v1/sessions", json=session_payload)
    assert resp.status_code == 201
    return resp.json()


class TestHealth:
    async def test_health_ok(self, client):
        resp = await client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestSessionCRUD:
    async def test_create_session(self, client, session_payload):
        resp = await client.post("/api/v1/sessions", json=session_payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["target"] == "10.0.0.1"
        assert data["profile"] == "network"
        assert data["status"] == "pending"
        assert "id" in data

    async def test_list_sessions_empty(self, client):
        resp = await client.get("/api/v1/sessions")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_sessions_after_create(self, client, created_session):
        resp = await client.get("/api/v1/sessions")
        assert resp.status_code == 200
        ids = [s["id"] for s in resp.json()]
        assert created_session["id"] in ids

    async def test_get_session(self, client, created_session):
        sid = created_session["id"]
        resp = await client.get(f"/api/v1/sessions/{sid}")
        assert resp.status_code == 200
        assert resp.json()["id"] == sid

    async def test_get_session_not_found(self, client):
        resp = await client.get("/api/v1/sessions/nonexistent-id")
        assert resp.status_code == 404

    async def test_delete_session(self, client, created_session):
        sid = created_session["id"]
        resp = await client.delete(f"/api/v1/sessions/{sid}")
        assert resp.status_code == 204
        # Confirm it's gone
        resp2 = await client.get(f"/api/v1/sessions/{sid}")
        assert resp2.status_code == 404

    async def test_delete_nonexistent(self, client):
        resp = await client.delete("/api/v1/sessions/fake-id")
        assert resp.status_code == 404


class TestRunEndpoint:
    async def test_run_invalid_provider_returns_400(self, client, created_session):
        sid = created_session["id"]
        resp = await client.post(
            f"/api/v1/sessions/{sid}/run",
            json={"llm_provider": "gemini", "llm_model": "gemini-pro"},
        )
        assert resp.status_code == 400
        assert "gemini" in resp.json()["detail"].lower() or "unknown" in resp.json()["detail"].lower()

    async def test_run_nonexistent_session(self, client):
        resp = await client.post(
            "/api/v1/sessions/fake-id/run",
            json={"llm_provider": "ollama", "llm_model": "llama3.1"},
        )
        assert resp.status_code == 404

    async def test_stop_nonexistent_session(self, client):
        resp = await client.post("/api/v1/sessions/fake-id/stop")
        assert resp.status_code == 404

    async def test_stop_not_running_session(self, client, created_session):
        sid = created_session["id"]
        resp = await client.post(f"/api/v1/sessions/{sid}/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "not_running"


class TestFindings:
    async def test_list_findings_empty(self, client, created_session):
        sid = created_session["id"]
        resp = await client.get(f"/api/v1/sessions/{sid}/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_add_and_list_finding(self, client, created_session):
        sid = created_session["id"]
        finding_data = {
            "session_id": sid,
            "severity": "high",
            "title": "Open SSH port",
            "description": "SSH running on port 22",
            "tool_name": "nmap",
            "target": "10.0.0.1",
            "evidence": "",
            "remediation": "",
        }
        resp = await client.post(f"/api/v1/sessions/{sid}/findings", json=finding_data)
        assert resp.status_code == 201
        assert resp.json()["title"] == "Open SSH port"

        list_resp = await client.get(f"/api/v1/sessions/{sid}/findings")
        assert len(list_resp.json()) == 1

    async def test_findings_nonexistent_session(self, client):
        resp = await client.get("/api/v1/sessions/fake-id/findings")
        assert resp.status_code == 404


class TestAuditLog:
    async def test_audit_log_empty(self, client, created_session):
        sid = created_session["id"]
        resp = await client.get(f"/api/v1/sessions/{sid}/audit-log")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_audit_log_nonexistent(self, client):
        resp = await client.get("/api/v1/sessions/fake-id/audit-log")
        assert resp.status_code == 404


class TestReport:
    async def test_report_markdown(self, client, created_session):
        sid = created_session["id"]
        resp = await client.get(f"/api/v1/sessions/{sid}/report")
        assert resp.status_code == 200
        assert "Penetration Test Report" in resp.text

    async def test_report_json(self, client, created_session):
        sid = created_session["id"]
        resp = await client.get(f"/api/v1/sessions/{sid}/report?format=json")
        assert resp.status_code == 200
        data = json.loads(resp.text)
        assert "session" in data
        assert "findings" in data

    async def test_report_nonexistent(self, client):
        resp = await client.get("/api/v1/sessions/fake-id/report")
        assert resp.status_code == 404


class TestTools:
    async def test_list_tools(self, client):
        resp = await client.get("/api/v1/tools")
        assert resp.status_code == 200
        tools = resp.json()
        assert len(tools) > 0
        names = [t["name"] for t in tools]
        assert "nmap" in names
        assert "record_finding" in names

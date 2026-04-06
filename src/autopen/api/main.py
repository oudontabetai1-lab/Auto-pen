"""FastAPI application factory."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from autopen.llm.factory import get_provider
from autopen.reporting.generator import ReportGenerator
from autopen.security.confirm import HumanConfirmation
from autopen.security.scope import ScopeValidator
from autopen.state.manager import SessionManager
from autopen.state.models import (
    FindingCreate,
    FindingRead,
    ScopeConfig,
    SessionCreate,
    SessionRead,
    SessionStatus,
    AuditLogRead,
)
from autopen.tools.registry import ToolRegistry

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

_manager: SessionManager | None = None
_registry: ToolRegistry | None = None
_report_gen: ReportGenerator | None = None


def create_app(db_url: str = "sqlite:///autopen.db", tool_config: dict | None = None) -> FastAPI:
    global _manager, _registry, _report_gen

    _manager = SessionManager(db_url=db_url)
    _registry = ToolRegistry(tool_config=tool_config or {})
    _report_gen = ReportGenerator(_manager)

    app = FastAPI(
        title="Auto-pen API",
        description="LLM-powered automated penetration testing tool",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Sessions ──────────────────────────────────────────────────────

    @app.post("/api/v1/sessions", response_model=SessionRead, status_code=201)
    async def create_session(data: SessionCreate) -> Any:
        return _manager.create_session(data)

    @app.get("/api/v1/sessions", response_model=list[SessionRead])
    async def list_sessions() -> Any:
        return _manager.list_sessions()

    @app.get("/api/v1/sessions/{session_id}", response_model=SessionRead)
    async def get_session(session_id: str) -> Any:
        s = _manager.get_session(session_id)
        if not s:
            raise HTTPException(status_code=404, detail="Session not found")
        return s

    @app.delete("/api/v1/sessions/{session_id}", status_code=204)
    async def delete_session(session_id: str) -> None:
        if not _manager.delete_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")

    class RunRequest(BaseModel):
        llm_provider: str = "ollama"
        llm_model: str = "llama3.1"
        max_steps: int = 40

    @app.post("/api/v1/sessions/{session_id}/run")
    async def run_session(session_id: str, req: RunRequest) -> dict[str, Any]:
        """Start the agent loop for a session (runs in background)."""
        s = _manager.get_session(session_id)
        if not s:
            raise HTTPException(status_code=404, detail="Session not found")
        if s.status == SessionStatus.RUNNING:
            raise HTTPException(status_code=409, detail="Session is already running")

        from autopen.agent.loop import AgentLoop

        scope_config = ScopeConfig(**s.scope_config)
        scope_validator = ScopeValidator(scope_config)
        confirmation = HumanConfirmation(interactive=False, auto_approve=False)
        llm = get_provider(req.llm_provider, req.llm_model)

        agent = AgentLoop(
            session_id=session_id,
            llm=llm,
            registry=_registry,
            manager=_manager,
            scope_validator=scope_validator,
            confirmation=confirmation,
            max_steps=req.max_steps,
        )
        asyncio.create_task(agent.run())
        return {"status": "started", "session_id": session_id}

    # ── Findings ─────────────────────────────────────────────────────

    @app.get("/api/v1/sessions/{session_id}/findings", response_model=list[FindingRead])
    async def list_findings(session_id: str) -> Any:
        if not _manager.get_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        return _manager.list_findings(session_id)

    @app.post("/api/v1/sessions/{session_id}/findings", response_model=FindingRead, status_code=201)
    async def add_finding(session_id: str, data: FindingCreate) -> Any:
        data.session_id = session_id
        return _manager.add_finding(data)

    # ── Audit log ────────────────────────────────────────────────────

    @app.get("/api/v1/sessions/{session_id}/audit-log", response_model=list[AuditLogRead])
    async def get_audit_log(session_id: str) -> Any:
        if not _manager.get_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        return _manager.list_audit_logs(session_id)

    # ── Reports ──────────────────────────────────────────────────────

    @app.get("/api/v1/sessions/{session_id}/report")
    async def get_report(session_id: str, format: str = "markdown") -> Any:
        if not _manager.get_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        if format == "json":
            from fastapi.responses import Response
            return Response(content=_report_gen.generate_json(session_id), media_type="application/json")
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(content=_report_gen.generate_markdown(session_id))

    # ── Tools ────────────────────────────────────────────────────────

    @app.get("/api/v1/tools")
    async def list_tools() -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "risk_level": t.risk_level,
                "available": t.is_available(),
            }
            for t in _registry.all_tools()
        ]

    # ── Health ───────────────────────────────────────────────────────

    @app.get("/api/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    return app

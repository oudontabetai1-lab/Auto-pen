"""FastAPI application factory with WebSocket support."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any

from fastapi import (
    Body,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from autopen.llm.factory import LLMConfigError, get_provider
from autopen.reporting.generator import ReportGenerator
from autopen.security.confirm import ConfirmationBroker, WebSocketHumanConfirmation
from autopen.security.scope import ScopeValidator
from autopen.state.manager import InvalidStatusTransitionError, SessionManager
from autopen.state.models import (
    AuditLogRead,
    FindingCreate,
    FindingRead,
    ScopeConfig,
    SessionCreate,
    SessionRead,
    SessionStatus,
)
from autopen.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Real-time broadcast layer
# ---------------------------------------------------------------------------


class SessionBroadcaster:
    """Manages WebSocket connections per session and broadcasts JSON messages."""

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    def connect(self, session_id: str, ws: WebSocket) -> None:
        self._connections[session_id].append(ws)

    def disconnect(self, session_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(session_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, session_id: str, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in list(self._connections.get(session_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(session_id, ws)

    def get_emitter(self, session_id: str):
        """Return an async callable that broadcasts to a specific session."""

        async def _emit(msg: dict[str, Any]) -> None:
            await self.broadcast(session_id, msg)

        return _emit

    def has_connections(self, session_id: str) -> bool:
        return bool(self._connections.get(session_id))


# ---------------------------------------------------------------------------
# Per-session access tokens for WebSocket auth (C2)
# ---------------------------------------------------------------------------


class SessionTokenStore:
    """Mints and validates short-lived tokens that gate WS connections.

    A token is issued when a session is created and again every time the
    session is started. Knowing a session UUID alone is no longer enough to
    subscribe to its WebSocket — the caller must also present this token.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}

    def issue(self, session_id: str) -> str:
        token = secrets.token_urlsafe(32)
        self._tokens[session_id] = token
        return token

    def verify(self, session_id: str, token: str | None) -> bool:
        expected = self._tokens.get(session_id)
        if not expected or not token:
            return False
        return secrets.compare_digest(expected, token)

    def revoke(self, session_id: str) -> None:
        self._tokens.pop(session_id, None)


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (H7)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Token-bucket-ish per-IP limiter scoped to specific endpoint keys."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._buckets[key]
        # Drop expired hits
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

_manager: SessionManager | None = None
_registry: ToolRegistry | None = None
_report_gen: ReportGenerator | None = None
_broadcaster: SessionBroadcaster | None = None
_broker: ConfirmationBroker | None = None
_tokens: SessionTokenStore | None = None
_running_tasks: dict[str, asyncio.Task] = {}


class RunRequest(BaseModel):
    llm_provider: str = Field(default="ollama", max_length=50, pattern=r"^[a-zA-Z][a-zA-Z0-9_\-]*$")
    llm_model: str = Field(default="llama3.1", max_length=100, pattern=r"^[a-zA-Z0-9_./:\-]+$")
    max_steps: int = Field(default=40, ge=1, le=200)


def _allowed_origins() -> list[str]:
    """Parse AUTOPEN_ALLOWED_ORIGINS env var; default to local Next.js dev."""
    raw = os.environ.get("AUTOPEN_ALLOWED_ORIGINS", "http://localhost:3000")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    # Refuse the wildcard when credentials would be needed.
    return [o for o in origins if o != "*"] or ["http://localhost:3000"]


def create_app(db_url: str = "sqlite:///autopen.db", tool_config: dict | None = None) -> FastAPI:
    global _manager, _registry, _report_gen, _broadcaster, _broker, _tokens

    _manager = SessionManager(db_url=db_url)
    _registry = ToolRegistry(tool_config=tool_config or {})
    _report_gen = ReportGenerator(_manager)
    _broadcaster = SessionBroadcaster()
    _broker = ConfirmationBroker()
    _tokens = SessionTokenStore()

    rate_limiter = RateLimiter(max_requests=60, window_seconds=60.0)
    create_limiter = RateLimiter(max_requests=10, window_seconds=60.0)

    app = FastAPI(
        title="Auto-pen API",
        description="LLM-powered automated penetration testing tool",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins(),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "anonymous"

    # ── WebSocket ─────────────────────────────────────────────────────

    @app.websocket("/ws/sessions/{session_id}")
    async def ws_session(ws: WebSocket, session_id: str, token: str | None = None) -> None:
        """
        Bidirectional WebSocket per session.

        Auth: the caller must supply ``?token=…`` matching the value returned
        by ``POST /api/v1/sessions`` (or ``/run``). The first-time WS request
        carrying an unknown session or bad token is refused with 4401/4404.
        """
        if not _manager.get_session(session_id):
            await ws.close(code=4004, reason="Session not found")
            return
        if not _tokens.verify(session_id, token):
            await ws.close(code=4401, reason="Invalid or missing session token")
            return

        await ws.accept()
        _broadcaster.connect(session_id, ws)

        s = _manager.get_session(session_id)
        await ws.send_json({
            "type": "session_status",
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": {"status": s.status, "step_count": s.step_count},
        })

        try:
            while True:
                data = await ws.receive_json()
                msg_type = data.get("type", "")
                payload = data.get("payload", {})

                if msg_type == "confirmation_response":
                    request_id = payload.get("request_id", "")
                    approved = bool(payload.get("approved", False))
                    _broker.resolve(request_id, approved)

                elif msg_type == "ping":
                    await ws.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})

        except WebSocketDisconnect:
            pass
        finally:
            _broadcaster.disconnect(session_id, ws)

    # ── Sessions ──────────────────────────────────────────────────────

    @app.post("/api/v1/sessions", status_code=201)
    async def create_session(request: Request, data: SessionCreate = Body(...)) -> dict[str, Any]:
        if not create_limiter.check(_client_ip(request)):
            raise HTTPException(status_code=429, detail="Too many session-create requests")
        session = _manager.create_session(data)
        ws_token = _tokens.issue(session.id)
        return {
            "session": SessionRead.model_validate(session, from_attributes=True).model_dump(mode="json"),
            "ws_token": ws_token,
        }

    @app.get("/api/v1/sessions", response_model=list[SessionRead])
    async def list_sessions(request: Request) -> Any:
        if not rate_limiter.check(_client_ip(request)):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
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
        _tokens.revoke(session_id)

    @app.post("/api/v1/sessions/{session_id}/run")
    async def run_session(session_id: str, req: RunRequest) -> dict[str, Any]:
        """Start the agent loop for a session (runs as a background asyncio task)."""
        s = _manager.get_session(session_id)
        if not s:
            raise HTTPException(status_code=404, detail="Session not found")
        if s.status == SessionStatus.RUNNING:
            raise HTTPException(status_code=409, detail="Session is already running")
        if session_id in _running_tasks and not _running_tasks[session_id].done():
            raise HTTPException(status_code=409, detail="Session task is already active")

        from autopen.agent.loop import AgentLoop

        scope_config = ScopeConfig(**s.scope_config)
        scope_validator = ScopeValidator(scope_config)
        emitter = _broadcaster.get_emitter(session_id)

        confirmation = WebSocketHumanConfirmation(
            session_id=session_id,
            broker=_broker,
            event_emitter=emitter,
            timeout=120.0,
        )
        try:
            llm = get_provider(req.llm_provider, req.llm_model)
        except (ValueError, LLMConfigError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        agent = AgentLoop(
            session_id=session_id,
            llm=llm,
            registry=_registry,
            manager=_manager,
            scope_validator=scope_validator,
            confirmation=confirmation,
            max_steps=req.max_steps,
            event_emitter=emitter,
        )

        task = asyncio.create_task(agent.run())
        _running_tasks[session_id] = task
        task.add_done_callback(lambda _t: _running_tasks.pop(session_id, None))

        # Re-issue a fresh token so the UI can subscribe with current creds.
        ws_token = _tokens.issue(session_id)
        return {"status": "started", "session_id": session_id, "ws_token": ws_token}

    @app.post("/api/v1/sessions/{session_id}/stop")
    async def stop_session(session_id: str) -> dict[str, Any]:
        """Cancel a running session's agent task."""
        if not _manager.get_session(session_id):
            raise HTTPException(status_code=404, detail="Session not found")

        task = _running_tasks.get(session_id)
        if task and not task.done():
            _broker.cancel_all()
            task.cancel()
            return {"status": "stopping", "session_id": session_id}

        return {"status": "not_running", "session_id": session_id}

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
            content = await asyncio.to_thread(_report_gen.generate_json, session_id)
            return Response(content=content, media_type="application/json")
        from fastapi.responses import PlainTextResponse
        content = await asyncio.to_thread(_report_gen.generate_markdown, session_id)
        return PlainTextResponse(content=content, media_type="text/markdown")

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

    # ── Friendly handler for invalid status transitions ───────────────

    @app.exception_handler(InvalidStatusTransitionError)
    async def _on_invalid_transition(_request: Request, exc: InvalidStatusTransitionError):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    return app

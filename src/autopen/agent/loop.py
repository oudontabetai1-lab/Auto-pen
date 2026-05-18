"""
ReAct agent loop — the core of Auto-pen.

Flow per iteration:
  1. REASON  — LLM analyzes state and decides next tool call
  2. SAFETY  — scope validation + human confirmation gate
  3. ACT     — tool execution
  4. OBSERVE — results fed back to LLM
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Awaitable, Callable

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule

from autopen.agent.prompts import (
    REPORT_DONE_TOOL,
    build_denial_message,
    build_initial_user_message,
    build_scope_violation_message,
    build_system_prompt,
)
from autopen.llm.base import BaseLLMProvider, LLMMessage, ToolCall
from autopen.security.confirm import HumanConfirmation
from autopen.security.scope import ScopeValidator, ScopeViolationError
from autopen.state.manager import SessionManager
from autopen.state.models import (
    FindingCreate,
    RiskLevel,
    ScopeConfig,
    Severity,
    SessionStatus,
)
from autopen.tools.base import BaseTool
from autopen.tools.registry import ToolRegistry

console = Console()

_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class AgentLoop:
    """
    Orchestrates the LLM ↔ tool interaction loop.

    The LLM acts as a full autonomous agent that:
    - reasons about the current pentest state
    - selects the next tool and parameters
    - receives tool output and updates its understanding
    - repeats until the assessment is complete or max_steps is reached
    """

    def __init__(
        self,
        session_id: str,
        llm: BaseLLMProvider,
        registry: ToolRegistry,
        manager: SessionManager,
        scope_validator: ScopeValidator,
        confirmation: HumanConfirmation,
        max_steps: int = 40,
        step_timeout: float = 300.0,
        event_emitter: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> None:
        self.session_id = session_id
        self.llm = llm
        self.registry = registry
        self.manager = manager
        self.scope_validator = scope_validator
        self.confirmation = confirmation
        self.max_steps = max_steps
        self.step_timeout = step_timeout
        self._event_emitter = event_emitter

    async def _emit(self, msg: dict[str, Any]) -> None:
        """Send an event to the WebSocket broadcaster (no-op if not configured)."""
        if self._event_emitter:
            try:
                await self._event_emitter(msg)
            except Exception:
                pass  # Never let WS errors crash the agent loop

    def _ts(self) -> str:
        return datetime.utcnow().isoformat()

    async def run(self) -> dict[str, Any]:
        """Start/resume the agent loop for this session. Returns final summary."""
        session = self.manager.get_session(self.session_id)
        if not session:
            raise ValueError(f"Session {self.session_id} not found")

        scope_config = ScopeConfig(**session.scope_config)
        scope_desc = ", ".join(scope_config.allowed_hosts)

        # Build system prompt
        system_prompt = build_system_prompt(
            target=session.target,
            profile=session.profile,
            scope_description=scope_desc,
            authorization_token=session.authorization_token,
        )

        # Get tool schemas (only available tools + report_done)
        tool_schemas = self.registry.get_llm_schemas(only_available=True)
        tool_schemas.append(REPORT_DONE_TOOL)

        # Initialize conversation
        messages: list[LLMMessage] = [
            LLMMessage(
                role="user",
                content=build_initial_user_message(session.target, session.profile),
            )
        ]

        # Inject prior-work context when resuming a paused session
        if session.step_count > 0:
            ctx = self._build_resume_context(session)
            messages.append(LLMMessage(role="assistant", content="Understood. Let me review prior progress before continuing."))
            messages.append(LLMMessage(role="user", content=ctx))

        self.manager.update_status(self.session_id, SessionStatus.RUNNING)
        self.manager.log_action(
            session_id=self.session_id,
            action="agent_started",
            result_summary=f"Target: {session.target}, Profile: {session.profile}",
        )
        await self._emit({
            "type": "session_status",
            "session_id": self.session_id,
            "timestamp": self._ts(),
            "payload": {"status": "running", "step_count": session.step_count},
        })

        console.print(Rule(f"[bold cyan]Auto-pen — Session {self.session_id[:8]}[/bold cyan]"))
        console.print(f"[dim]Target:[/dim] {session.target}  [dim]Profile:[/dim] {session.profile}")
        console.print(f"[dim]LLM:[/dim] {session.llm_provider}/{session.llm_model}\n")

        step = session.step_count
        final_summary: dict[str, Any] = {}

        try:
            while step < self.max_steps:
                step += 1
                console.print(Rule(f"[dim]Step {step}/{self.max_steps}[/dim]", style="dim"))

                # ── REASON ────────────────────────────────────────────
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    transient=True,
                ) as progress:
                    progress.add_task("LLM reasoning...", total=None)
                    try:
                        response = await asyncio.wait_for(
                            self.llm.chat_with_tools(
                                messages=messages,
                                tools=tool_schemas,
                                system_prompt=system_prompt,
                            ),
                            timeout=self.step_timeout,
                        )
                    except asyncio.TimeoutError:
                        console.print(f"[red]LLM reasoning timed out after {self.step_timeout}s[/red]")
                        await self._emit({
                            "type": "error",
                            "session_id": self.session_id,
                            "timestamp": self._ts(),
                            "payload": {"code": "step_timeout", "message": f"LLM reasoning timed out after {self.step_timeout}s"},
                        })
                        self.manager.update_status(self.session_id, SessionStatus.TIMED_OUT)
                        await self._emit({
                            "type": "session_status",
                            "session_id": self.session_id,
                            "timestamp": self._ts(),
                            "payload": {"status": SessionStatus.TIMED_OUT.value, "step_count": step},
                        })
                        return final_summary

                self.manager.increment_step(self.session_id)

                # Display LLM reasoning/text
                if response.content:
                    console.print(
                        Panel(
                            response.content,
                            title="[bold green]LLM Reasoning[/bold green]",
                            border_style="green",
                            expand=False,
                        )
                    )
                    await self._emit({
                        "type": "log",
                        "session_id": self.session_id,
                        "timestamp": self._ts(),
                        "payload": {
                            "level": "reasoning",
                            "message": response.content,
                            "step": step,
                        },
                    })

                # No tool calls → LLM decided to stop without calling report_done
                if not response.tool_calls:
                    console.print("[yellow]LLM stopped without calling report_done. Ending loop.[/yellow]")
                    await self._emit({
                        "type": "log",
                        "session_id": self.session_id,
                        "timestamp": self._ts(),
                        "payload": {"level": "warning", "message": "LLM stopped without calling report_done.", "step": step},
                    })
                    break

                # Add assistant message to history
                messages.append(
                    LLMMessage(
                        role="assistant",
                        content=response.content,
                        tool_calls=response.tool_calls,
                    )
                )

                # ── Process each tool call ─────────────────────────────
                for tool_call in response.tool_calls:
                    result_content = await self._handle_tool_call(
                        tool_call=tool_call,
                        reasoning=response.content or "",
                    )
                    messages.append(
                        LLMMessage(
                            role="tool",
                            tool_call_id=tool_call.id,
                            content=result_content,
                        )
                    )

                    # Check if agent signaled completion
                    if tool_call.name == "report_done":
                        final_summary = tool_call.arguments
                        console.print(
                            Panel(
                                f"[bold]Assessment complete.[/bold]\n{final_summary.get('summary', '')}",
                                title="[bold cyan]DONE[/bold cyan]",
                                border_style="cyan",
                            )
                        )
                        self.manager.update_status(self.session_id, SessionStatus.COMPLETED)
                        await self._emit({
                            "type": "session_status",
                            "session_id": self.session_id,
                            "timestamp": self._ts(),
                            "payload": {
                                "status": "completed",
                                "step_count": step,
                                "summary": final_summary.get("summary", ""),
                            },
                        })
                        return final_summary

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user. Session paused.[/yellow]")
            self.manager.update_status(self.session_id, SessionStatus.PAUSED)
            await self._emit({
                "type": "session_status",
                "session_id": self.session_id,
                "timestamp": self._ts(),
                "payload": {"status": "paused", "step_count": step},
            })
        except asyncio.CancelledError:
            self.manager.update_status(self.session_id, SessionStatus.PAUSED)
            await self._emit({
                "type": "session_status",
                "session_id": self.session_id,
                "timestamp": self._ts(),
                "payload": {"status": "paused", "step_count": step},
            })
            raise
        except Exception as e:
            console.print(f"[red]Agent loop error: {e}[/red]")
            self.manager.update_status(self.session_id, SessionStatus.FAILED)
            self.manager.log_action(
                session_id=self.session_id,
                action="agent_error",
                result_summary=str(e),
            )
            await self._emit({
                "type": "error",
                "session_id": self.session_id,
                "timestamp": self._ts(),
                "payload": {"code": "agent_error", "message": str(e)},
            })
            raise

        if not final_summary:
            # report_done was never called. Distinguish "ran out of steps"
            # (INCOMPLETE) from the natural completion path (only reached when
            # report_done is invoked, which returns early above).
            terminal_status = (
                SessionStatus.INCOMPLETE if step >= self.max_steps else SessionStatus.COMPLETED
            )
            self.manager.update_status(self.session_id, terminal_status)
            await self._emit({
                "type": "session_status",
                "session_id": self.session_id,
                "timestamp": self._ts(),
                "payload": {"status": terminal_status.value, "step_count": step},
            })

        return final_summary

    # ------------------------------------------------------------------
    # Tool call handler
    # ------------------------------------------------------------------

    async def _handle_tool_call(self, tool_call: ToolCall, reasoning: str) -> str:
        """Process a single tool call: validate scope, confirm if needed, execute."""
        name = tool_call.name
        params = tool_call.arguments

        console.print(
            f"\n[bold cyan]Tool:[/bold cyan] {name}  "
            f"[dim]params: {self._truncate_params(params)}[/dim]"
        )

        # report_done is a virtual tool — no execution needed
        if name == "report_done":
            return "Report generation triggered."

        # record_finding is a virtual tool — persist to DB and emit WS event
        if name == "record_finding":
            return await self._handle_record_finding(params)

        # ── Lookup tool ──────────────────────────────────────────────
        try:
            tool: BaseTool = self.registry.get(name)
        except KeyError:
            return f"Error: Unknown tool '{name}'. Available tools: {[t.name for t in self.registry.all_tools()]}"

        # ── Scope validation ─────────────────────────────────────────
        target = self._extract_target_from_params(params)
        if target:
            try:
                self.scope_validator.assert_in_scope(target)
            except ScopeViolationError as e:
                msg = build_scope_violation_message(name, target)
                console.print(f"[red]SCOPE VIOLATION:[/red] {e}")
                self.manager.log_action(
                    session_id=self.session_id,
                    action="scope_violation_blocked",
                    tool_name=name,
                    params=params,
                    result_summary=str(e),
                    risk_level=tool.risk_level,
                )
                return msg

        # ── Human confirmation gate ──────────────────────────────────
        needs_confirmation = self.confirmation.needs_confirmation(tool.risk_level)
        approved_by_human = False
        if needs_confirmation:
            approved = await self.confirmation.ask(
                tool_name=name,
                risk_level=tool.risk_level,
                params=params,
                reasoning=reasoning,
            )
            if not approved:
                msg = build_denial_message(name)
                self.manager.log_action(
                    session_id=self.session_id,
                    action="human_denied",
                    tool_name=name,
                    params=params,
                    result_summary="Denied by operator",
                    risk_level=tool.risk_level,
                    approved_by_human=False,
                )
                return msg
            approved_by_human = True

        # ── Execute ──────────────────────────────────────────────────
        self.manager.log_action(
            session_id=self.session_id,
            action="tool_executing",
            tool_name=name,
            params=params,
            risk_level=tool.risk_level,
            approved_by_human=approved_by_human,
        )
        await self._emit({
            "type": "tool_start",
            "session_id": self.session_id,
            "timestamp": self._ts(),
            "payload": {
                "tool_name": name,
                "params": params,
                "risk_level": str(tool.risk_level),
            },
        })

        with Progress(
            SpinnerColumn(),
            TextColumn(f"[progress.description]Running {name}..."),
            transient=True,
        ) as progress:
            progress.add_task("", total=None)
            result = await tool.execute(params)

        # Log result
        self.manager.log_action(
            session_id=self.session_id,
            action="tool_completed",
            tool_name=name,
            params=params,
            result_summary=result.output[:500],
            risk_level=tool.risk_level,
        )
        await self._emit({
            "type": "tool_complete",
            "session_id": self.session_id,
            "timestamp": self._ts(),
            "payload": {
                "tool_name": name,
                "success": result.success,
                "output_preview": result.output[:500],
                "duration_seconds": result.duration_seconds,
            },
        })

        # Display result
        status = "[green]OK[/green]" if result.success else "[red]FAILED[/red]"
        console.print(
            Panel(
                result.output[:2000] + ("..." if len(result.output) > 2000 else ""),
                title=f"[bold]{name}[/bold] {status} ({result.duration_seconds:.1f}s)",
                border_style="blue" if result.success else "red",
            )
        )

        return result.output

    # ------------------------------------------------------------------
    # record_finding handler
    # ------------------------------------------------------------------

    async def _handle_record_finding(self, params: dict[str, Any]) -> str:
        """Persist an LLM-reported finding to the database."""
        try:
            raw_severity = params.get("severity", "info").lower()
            try:
                severity = Severity(raw_severity)
            except ValueError:
                severity = Severity.INFO

            cvss_score = params.get("cvss_score")
            if cvss_score is None and severity != Severity.INFO:
                from autopen.reporting.cvss import default_score_for_severity
                cvss_score = default_score_for_severity(severity)

            finding = self.manager.add_finding(
                FindingCreate(
                    session_id=self.session_id,
                    severity=severity,
                    title=params.get("title", "Untitled Finding"),
                    description=params.get("description", ""),
                    tool_name=params.get("tool_name", "agent"),
                    evidence=params.get("evidence", ""),
                    remediation=params.get("remediation", ""),
                    cvss_score=cvss_score,
                    target=params.get("target", ""),
                )
            )
            self.manager.log_action(
                session_id=self.session_id,
                action="finding_recorded",
                tool_name="record_finding",
                result_summary=f"[{severity.upper()}] {finding.title}",
                risk_level=RiskLevel.LOW,
            )
            await self._emit({
                "type": "finding_discovered",
                "session_id": self.session_id,
                "timestamp": self._ts(),
                "payload": {
                    "id": finding.id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "target": finding.target,
                    "cvss_score": finding.cvss_score,
                },
            })
            console.print(
                f"[bold magenta]Finding recorded:[/bold magenta] "
                f"[{finding.severity.upper()}] {finding.title}"
            )
            return f"Finding recorded: [{finding.severity.upper()}] {finding.title} (id: {finding.id})"
        except Exception as exc:
            return f"Error recording finding: {exc}"

    # ------------------------------------------------------------------
    # Resume context builder
    # ------------------------------------------------------------------

    def _build_resume_context(self, session: Any) -> str:
        """Summarise prior audit log entries and findings for a resumed session."""
        logs = self.manager.list_audit_logs(session.id)
        findings = self.manager.list_findings(session.id)

        tool_lines: list[str] = []
        for log in logs:
            if log.action == "tool_completed" and log.tool_name:
                snippet = (log.result_summary or "")[:300]
                tool_lines.append(f"- {log.tool_name}: {snippet}")
            elif log.action == "human_denied" and log.tool_name:
                tool_lines.append(f"- {log.tool_name}: DENIED by operator")
            elif log.action == "scope_violation_blocked" and log.tool_name:
                tool_lines.append(f"- {log.tool_name}: BLOCKED (out of scope)")

        finding_lines = [
            f"  [{f.severity.upper()}] {f.title} (target: {f.target})"
            for f in findings
        ]

        parts = [
            f"SESSION RESUMED — {session.step_count} steps previously completed.",
            "",
            "== Tools Already Run ==",
            *(tool_lines[:50] if tool_lines else ["(none)"]),
            "",
            f"== Findings Recorded So Far ({len(findings)}) ==",
            *(finding_lines if finding_lines else ["(none)"]),
            "",
            "Do NOT repeat work already completed above. Continue the assessment from where it left off.",
        ]
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_target_from_params(self, params: dict[str, Any]) -> str | None:
        """Extract the primary target from tool params for scope validation."""
        for key in ("target", "url", "host", "domain"):
            if key in params and params[key]:
                return str(params[key])
        return None

    def _truncate_params(self, params: dict[str, Any]) -> str:
        s = str(params)
        return s[:120] + "..." if len(s) > 120 else s

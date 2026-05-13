"""Human confirmation gate for HIGH/CRITICAL risk operations."""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from autopen.tools.base import RiskLevel

console = Console()

RISK_COLORS = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}


class HumanConfirmation:
    """
    Prompts the user to approve or deny HIGH/CRITICAL risk tool executions.

    In non-interactive mode (e.g. API server), defaults to deny for safety.
    """

    def __init__(
        self,
        interactive: bool = True,
        auto_approve: bool = False,
        auto_confirm_medium: bool = True,
    ) -> None:
        self.interactive = interactive
        self.auto_approve = auto_approve
        self.auto_confirm_medium = auto_confirm_medium

    def needs_confirmation(self, risk_level: RiskLevel) -> bool:
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return True
        if risk_level == RiskLevel.MEDIUM and not self.auto_confirm_medium:
            return True
        return False

    async def ask(
        self,
        tool_name: str,
        risk_level: RiskLevel,
        params: dict[str, Any],
        reasoning: str = "",
    ) -> bool:
        if self.auto_approve:
            console.print(
                f"[yellow]AUTO-APPROVE:[/yellow] {tool_name} (risk: {risk_level})"
            )
            return True

        if not self.interactive or not sys.stdin.isatty():
            console.print(
                f"[red]DENIED (non-interactive):[/red] {tool_name} requires human approval "
                f"but no TTY is available."
            )
            return False

        self._display_prompt(tool_name, risk_level, params, reasoning)

        try:
            answer = input("\n[auto-pen] Approve this action? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[red]Denied by interrupt.[/red]")
            return False

        approved = answer in ("y", "yes")
        if approved:
            console.print("[green]Approved.[/green]")
        else:
            console.print("[red]Denied.[/red]")
        return approved

    def _display_prompt(
        self,
        tool_name: str,
        risk_level: RiskLevel,
        params: dict[str, Any],
        reasoning: str,
    ) -> None:
        color = RISK_COLORS.get(risk_level, "white")

        title = Text()
        title.append("  ACTION REQUIRES APPROVAL  ", style=f"bold {color} on default")

        table = Table(show_header=True, header_style="bold cyan", expand=True)
        table.add_column("Parameter", style="cyan", width=20)
        table.add_column("Value")

        for k, v in params.items():
            val_str = str(v)
            if len(val_str) > 120:
                val_str = val_str[:120] + "..."
            table.add_row(k, val_str)

        content = (
            f"[bold]Tool:[/bold]       {tool_name}\n"
            f"[bold]Risk Level:[/bold] [{color}]{risk_level.upper()}[/{color}]\n"
        )
        if reasoning:
            content += f"\n[bold]LLM Reasoning:[/bold]\n{reasoning[:400]}\n"

        console.print()
        console.print(Panel(content, title=str(title), border_style=color))
        console.print(table)


class PendingConfirmation:
    """
    Represents a single in-flight approval request.
    The agent loop awaits `wait()` while the WebSocket handler calls `resolve()`.
    """

    def __init__(self, request_id: str, timeout: float = 120.0) -> None:
        self.request_id = request_id
        self.timeout = timeout
        self._event: asyncio.Event = asyncio.Event()
        self._approved: bool | None = None

    def resolve(self, approved: bool) -> None:
        """Called by the WebSocket message handler when the user responds."""
        self._approved = approved
        self._event.set()

    async def wait(self) -> bool:
        try:
            await asyncio.wait_for(self._event.wait(), timeout=self.timeout)
            return self._approved if self._approved is not None else False
        except asyncio.TimeoutError:
            return False


class ConfirmationBroker:
    """
    Registry of PendingConfirmation objects keyed by request_id.
    """

    def __init__(self) -> None:
        self._pending: dict[str, PendingConfirmation] = {}

    def create(self, request_id: str | None = None, timeout: float = 120.0) -> PendingConfirmation:
        rid = request_id or str(uuid.uuid4())
        pc = PendingConfirmation(rid, timeout)
        self._pending[rid] = pc
        return pc

    def resolve(self, request_id: str, approved: bool) -> bool:
        """Returns True if the request_id was found and resolved."""
        if request_id in self._pending:
            self._pending[request_id].resolve(approved)
            del self._pending[request_id]
            return True
        return False

    def cancel_all(self) -> None:
        """Deny all pending confirmations (e.g. on session stop)."""
        for pc in self._pending.values():
            pc.resolve(False)
        self._pending.clear()


class WebSocketHumanConfirmation(HumanConfirmation):
    """
    HumanConfirmation subclass that uses a WebSocket channel for approval.
    """

    def __init__(
        self,
        session_id: str,
        broker: ConfirmationBroker,
        event_emitter: Callable[[dict[str, Any]], Awaitable[None]],
        timeout: float = 120.0,
    ) -> None:
        super().__init__(interactive=False, auto_approve=False)
        self.session_id = session_id
        self.broker = broker
        self.emit = event_emitter
        self.timeout = timeout

    async def ask(
        self,
        tool_name: str,
        risk_level: RiskLevel,
        params: dict[str, Any],
        reasoning: str = "",
    ) -> bool:
        pc = self.broker.create(timeout=self.timeout)

        await self.emit(
            {
                "type": "confirmation_request",
                "session_id": self.session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "payload": {
                    "request_id": pc.request_id,
                    "tool_name": tool_name,
                    "risk_level": str(risk_level),
                    "params": params,
                    "reasoning": reasoning[:400],
                    "timeout_seconds": self.timeout,
                },
            }
        )

        return await pc.wait()

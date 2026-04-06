"""Human confirmation gate for HIGH/CRITICAL risk operations."""

from __future__ import annotations

import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from autopen.tools.base import RiskLevel

console = Console()

# Risk level colors for display
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

    def __init__(self, interactive: bool = True, auto_approve: bool = False) -> None:
        self.interactive = interactive
        self.auto_approve = auto_approve

    def needs_confirmation(self, risk_level: RiskLevel) -> bool:
        return risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    async def ask(
        self,
        tool_name: str,
        risk_level: RiskLevel,
        params: dict[str, Any],
        reasoning: str = "",
    ) -> bool:
        """
        Display the proposed action and ask for user approval.
        Returns True if approved, False if denied.
        """
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

    # ------------------------------------------------------------------

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

        # Parameters table
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

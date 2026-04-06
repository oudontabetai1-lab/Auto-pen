"""
Auto-pen CLI — entry point for all user-facing commands.

Usage examples:
  auto-pen scan --target 192.168.1.1 --profile network --auth-token "I have permission..."
  auto-pen scan --target https://example.com --profile web --llm openai/gpt-4o
  auto-pen sessions list
  auto-pen sessions show <id>
  auto-pen report <session-id>
  auto-pen server
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="auto-pen",
    help="LLM-powered automated penetration testing tool.",
    add_completion=False,
    rich_markup_mode="markdown",
)
sessions_app = typer.Typer(help="Manage pentest sessions.")
app.add_typer(sessions_app, name="sessions")

console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_config(config_path: Optional[str] = None) -> dict:
    default = Path(__file__).parent.parent.parent / "config" / "default.yaml"
    path = Path(config_path) if config_path else default
    if path.exists():
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _get_manager(cfg: dict):
    from autopen.state.manager import SessionManager
    db_url = cfg.get("database", {}).get("url", "sqlite:///autopen.db")
    return SessionManager(db_url=db_url)


def _get_registry(cfg: dict):
    from autopen.tools.registry import ToolRegistry
    return ToolRegistry(tool_config=cfg.get("tools", {}))


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP, CIDR, URL, or hostname"),
    profile: str = typer.Option("web", "--profile", "-p",
                                 help="Scan profile: web | network | cloud | ctf"),
    auth_token: str = typer.Option(..., "--auth-token", "-a",
                                    help="Written authorization statement"),
    llm: str = typer.Option("ollama/llama3.1", "--llm",
                             help="LLM in format provider/model (e.g. ollama/llama3.1, openai/gpt-4o)"),
    scope: Optional[list[str]] = typer.Option(None, "--scope", "-s",
                                               help="Additional allowed hosts/CIDRs (repeatable)"),
    max_steps: int = typer.Option(40, "--max-steps", help="Max agent loop iterations"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config YAML"),
    auto_approve: bool = typer.Option(False, "--auto-approve",
                                       help="Auto-approve HIGH risk operations (use with caution)"),
) -> None:
    """Start a new automated penetration test."""

    # Parse LLM provider/model
    if "/" in llm:
        provider, model = llm.split("/", 1)
    else:
        provider, model = "ollama", llm

    cfg = _load_config(config)
    manager = _get_manager(cfg)
    registry = _get_registry(cfg)

    # Build scope
    from autopen.state.models import ScopeConfig, SessionCreate, ScanProfile
    from autopen.security.scope import ScopeValidator
    from autopen.security.confirm import HumanConfirmation
    from autopen.llm.factory import get_provider
    from autopen.agent.loop import AgentLoop

    allowed_hosts = [target] + (scope or [])
    scope_config = ScopeConfig(allowed_hosts=allowed_hosts)

    # Validate profile
    try:
        scan_profile = ScanProfile(profile.lower())
    except ValueError:
        console.print(f"[red]Invalid profile '{profile}'. Choose: web, network, cloud, ctf[/red]")
        raise typer.Exit(1)

    # Create session
    session_data = SessionCreate(
        target=target,
        profile=scan_profile,
        authorization_token=auth_token,
        scope=scope_config,
        llm_provider=provider,
        llm_model=model,
    )
    session = manager.create_session(session_data)
    console.print(f"[green]Session created:[/green] {session.id}")

    # Set up agent
    llm_cfg = cfg.get("llm", {})
    llm_provider_inst = get_provider(
        provider=provider,
        model=model,
        base_url=llm_cfg.get("base_url"),
        timeout=llm_cfg.get("timeout", 120),
        temperature=llm_cfg.get("temperature", 0.1),
    )

    scope_validator = ScopeValidator(scope_config)
    confirmation = HumanConfirmation(interactive=True, auto_approve=auto_approve)

    agent = AgentLoop(
        session_id=session.id,
        llm=llm_provider_inst,
        registry=registry,
        manager=manager,
        scope_validator=scope_validator,
        confirmation=confirmation,
        max_steps=max_steps,
        step_timeout=cfg.get("agent", {}).get("step_timeout", 300),
    )

    asyncio.run(agent.run())


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------

@sessions_app.command("list")
def sessions_list(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """List all pentest sessions."""
    cfg = _load_config(config)
    manager = _get_manager(cfg)
    sessions = manager.list_sessions()

    if not sessions:
        console.print("[dim]No sessions found.[/dim]")
        return

    table = Table(title="Pentest Sessions", show_lines=True)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Target")
    table.add_column("Profile")
    table.add_column("Status")
    table.add_column("Steps")
    table.add_column("Created")

    for s in sessions:
        status_style = {
            "running": "bold yellow",
            "completed": "bold green",
            "failed": "bold red",
            "paused": "yellow",
        }.get(s.status, "white")

        table.add_row(
            s.id[:8],
            s.target,
            s.profile,
            f"[{status_style}]{s.status}[/{status_style}]",
            str(s.step_count),
            s.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


@sessions_app.command("show")
def sessions_show(
    session_id: str = typer.Argument(..., help="Session ID or prefix"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Show details of a specific session."""
    cfg = _load_config(config)
    manager = _get_manager(cfg)

    # Support prefix matching
    all_sessions = manager.list_sessions()
    matches = [s for s in all_sessions if s.id.startswith(session_id)]
    if not matches:
        console.print(f"[red]No session found matching '{session_id}'[/red]")
        raise typer.Exit(1)
    session = matches[0]

    from autopen.state.models import ScopeConfig
    scope = ScopeConfig(**session.scope_config)
    findings = manager.list_findings(session.id)

    console.print(f"\n[bold cyan]Session: {session.id}[/bold cyan]")
    console.print(f"  Target:    {session.target}")
    console.print(f"  Profile:   {session.profile}")
    console.print(f"  Status:    {session.status}")
    console.print(f"  LLM:       {session.llm_provider}/{session.llm_model}")
    console.print(f"  Steps:     {session.step_count}")
    console.print(f"  Scope:     {', '.join(scope.allowed_hosts)}")
    console.print(f"  Created:   {session.created_at}")
    console.print(f"  Findings:  {len(findings)}")

    if findings:
        from autopen.reporting.cvss import sort_findings_by_severity, SEVERITY_EMOJI
        for f in sort_findings_by_severity(findings):
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            console.print(f"    {emoji} [{f.severity.upper()}] {f.title} ({f.tool_name})")


@sessions_app.command("resume")
def sessions_resume(
    session_id: str = typer.Argument(...),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    auto_approve: bool = typer.Option(False, "--auto-approve"),
) -> None:
    """Resume a paused session."""
    cfg = _load_config(config)
    manager = _get_manager(cfg)
    registry = _get_registry(cfg)

    all_sessions = manager.list_sessions()
    matches = [s for s in all_sessions if s.id.startswith(session_id)]
    if not matches:
        console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)
    session = matches[0]

    from autopen.state.models import ScopeConfig
    from autopen.security.scope import ScopeValidator
    from autopen.security.confirm import HumanConfirmation
    from autopen.llm.factory import get_provider
    from autopen.agent.loop import AgentLoop

    scope_config = ScopeConfig(**session.scope_config)
    llm_cfg = cfg.get("llm", {})
    llm = get_provider(
        session.llm_provider, session.llm_model,
        base_url=llm_cfg.get("base_url"),
        timeout=llm_cfg.get("timeout", 120),
    )

    agent = AgentLoop(
        session_id=session.id,
        llm=llm,
        registry=registry,
        manager=manager,
        scope_validator=ScopeValidator(scope_config),
        confirmation=HumanConfirmation(interactive=True, auto_approve=auto_approve),
    )
    asyncio.run(agent.run())


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID or prefix"),
    format: str = typer.Option("markdown", "--format", "-f",
                                help="Output format: markdown | json"),
    output: Optional[str] = typer.Option(None, "--output", "-o",
                                          help="Save to file (default: print to stdout)"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Generate a penetration test report."""
    cfg = _load_config(config)
    manager = _get_manager(cfg)

    from autopen.reporting.generator import ReportGenerator
    gen = ReportGenerator(manager)

    all_sessions = manager.list_sessions()
    matches = [s for s in all_sessions if s.id.startswith(session_id)]
    if not matches:
        console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)
    sid = matches[0].id

    if format == "json":
        content = gen.generate_json(sid)
    else:
        content = gen.generate_markdown(sid)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]Report saved to: {output}[/green]")
    else:
        print(content)


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

@app.command()
def server(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8080, "--port"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Start the REST API server."""
    import uvicorn
    cfg = _load_config(config)
    db_url = cfg.get("database", {}).get("url", "sqlite:///autopen.db")

    from autopen.api.main import create_app
    api_app = create_app(db_url=db_url, tool_config=cfg.get("tools", {}))

    console.print(f"[bold green]Auto-pen API server starting on http://{host}:{port}[/bold green]")
    uvicorn.run(api_app, host=host, port=port)


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

@app.command()
def tools(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """List all available security tools and their status."""
    cfg = _load_config(config)
    registry = _get_registry(cfg)

    table = Table(title="Security Tools", show_lines=True)
    table.add_column("Name", style="cyan")
    table.add_column("Risk Level")
    table.add_column("Available")
    table.add_column("Description")

    risk_colors = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}

    for tool in registry.all_tools():
        color = risk_colors.get(tool.risk_level, "white")
        avail = "[green]yes[/green]" if tool.is_available() else "[red]no[/red]"
        table.add_row(
            tool.name,
            f"[{color}]{tool.risk_level.upper()}[/{color}]",
            avail,
            tool.description[:80] + "...",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()

"""Metasploit RPC wrapper — exploit framework integration."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class MetasploitTool(BaseTool):
    name = "metasploit"
    description = (
        "Metasploit Framework integration via RPC. "
        "Can search for modules, run auxiliary scanners, and execute exploits. "
        "CRITICAL risk: direct exploitation, may crash services or create persistent access. "
        "Requires msfrpcd to be running: `msfrpcd -P msf -S`"
    )
    risk_level = RiskLevel.CRITICAL
    parameters_schema = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["search", "run_auxiliary", "run_exploit"],
                "description": (
                    "search=find modules by keyword, "
                    "run_auxiliary=run scanner/auxiliary module, "
                    "run_exploit=run an exploit module"
                ),
            },
            "module": {
                "type": "string",
                "description": "Module path (e.g. 'auxiliary/scanner/http/title', 'exploit/unix/ftp/vsftpd_234_backdoor')",
                "default": "",
            },
            "search_query": {
                "type": "string",
                "description": "Search query for 'search' action",
                "default": "",
            },
            "options": {
                "type": "object",
                "description": "Module options as key-value pairs (e.g. {'RHOSTS': '192.168.1.1', 'RPORT': '21'})",
                "default": {},
            },
            "payload": {
                "type": "string",
                "description": "Payload for exploit modules (e.g. 'generic/shell_reverse_tcp')",
                "default": "",
            },
        },
        "required": ["action"],
    }

    def __init__(
        self,
        rpc_host: str = "127.0.0.1",
        rpc_port: int = 55553,
        rpc_user: str = "msf",
        rpc_pass: str = "msf",
    ) -> None:
        self.rpc_host = rpc_host
        self.rpc_port = rpc_port
        self.rpc_user = rpc_user
        self.rpc_pass = rpc_pass
        self.binary = "msfconsole"  # used only for is_available() check

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        action = params["action"]

        if action == "search":
            return await self._search(params.get("search_query", ""))
        if action in ("run_auxiliary", "run_exploit"):
            return await self._run_module(
                module=params.get("module", ""),
                options=params.get("options", {}),
                payload=params.get("payload", ""),
            )

        return ToolResult(
            tool_name=self.name,
            success=False,
            output=f"Unknown action: {action}",
        )

    async def _search(self, query: str) -> ToolResult:
        """Use msfconsole -x to search modules."""
        if not query:
            return ToolResult(
                tool_name=self.name, success=False, output="search_query is required"
            )
        cmd = ["msfconsole", "-q", "-x", f"search {query}; exit"]
        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=60)
        duration = time.monotonic() - t0

        modules = self._parse_search_output(stdout)
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_search(modules, query),
            raw_output=stdout,
            metadata={"modules": modules},
            duration_seconds=duration,
        )

    async def _run_module(
        self, module: str, options: dict[str, Any], payload: str
    ) -> ToolResult:
        if not module:
            return ToolResult(
                tool_name=self.name, success=False, output="module path is required"
            )

        # Build a resource script
        rc_lines = [f"use {module}"]
        for k, v in options.items():
            rc_lines.append(f"set {k} {v}")
        if payload:
            rc_lines.append(f"set PAYLOAD {payload}")
        rc_lines.append("run -z")
        rc_lines.append("exit -y")
        rc_script = "\n".join(rc_lines)

        # Write to temp file and execute
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
            f.write(rc_script)
            rc_path = f.name

        cmd = ["msfconsole", "-q", "-r", rc_path]
        t0 = time.monotonic()
        try:
            stdout, stderr, rc = await self._run_command(cmd, timeout=300)
        finally:
            try:
                os.unlink(rc_path)
            except OSError:
                pass
        duration = time.monotonic() - t0

        output = stdout + (stderr or "")
        success = "session opened" in output.lower() or "success" in output.lower()

        return ToolResult(
            tool_name=self.name,
            success=success,
            output=output[-3000:] if len(output) > 3000 else output,
            raw_output=output,
            duration_seconds=duration,
        )

    def _parse_search_output(self, output: str) -> list[dict[str, str]]:
        modules = []
        in_table = False
        for line in output.splitlines():
            if "Name" in line and "Rank" in line:
                in_table = True
                continue
            if in_table and line.strip() and not line.startswith("="):
                parts = line.split()
                if len(parts) >= 2 and "/" in parts[0]:
                    modules.append(
                        {
                            "name": parts[0],
                            "rank": parts[1] if len(parts) > 1 else "",
                            "description": " ".join(parts[3:]) if len(parts) > 3 else "",
                        }
                    )
        return modules[:20]

    def _format_search(self, modules: list[dict[str, str]], query: str) -> str:
        if not modules:
            return f"No Metasploit modules found for: {query}"
        lines = [f"Metasploit modules matching '{query}' (top {len(modules)}):\n"]
        for m in modules:
            lines.append(f"  [{m['rank']}] {m['name']}  {m['description']}")
        return "\n".join(lines)

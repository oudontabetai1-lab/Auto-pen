"""whois wrapper — domain/IP WHOIS lookup."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class WhoisTool(BaseTool):
    name = "whois"
    description = (
        "Perform WHOIS lookups on a domain or IP address to retrieve registration, "
        "ownership, and network information. Useful for passive reconnaissance."
    )
    risk_level = RiskLevel.LOW
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Domain name or IP address to look up (e.g. 'example.com', '8.8.8.8')",
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "whois") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        cmd = [self.binary, target]
        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=30)
        duration = time.monotonic() - t0

        if rc != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"whois failed: {stderr}",
                raw_output=stderr,
                error=stderr,
                duration_seconds=duration,
            )

        output = stdout[:3000]
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=output,
            raw_output=stdout,
            duration_seconds=duration,
        )

"""dig wrapper — DNS record enumeration."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class DigTool(BaseTool):
    name = "dig"
    description = (
        "Query DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME, and SOA "
        "record types. Useful for DNS enumeration during reconnaissance."
    )
    risk_level = RiskLevel.LOW
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Domain name to query (e.g. 'example.com')",
            },
            "record_type": {
                "type": "string",
                "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
                "description": "DNS record type to query",
                "default": "A",
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "dig") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        record_type = params.get("record_type", "A")
        cmd = [self.binary, "+noall", "+answer", record_type, target]
        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=30)
        duration = time.monotonic() - t0

        if rc != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"dig failed: {stderr}",
                raw_output=stderr,
                error=stderr,
                duration_seconds=duration,
            )

        output = stdout.strip() or f"No {record_type} records found for {target}."
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=output,
            raw_output=stdout,
            duration_seconds=duration,
        )

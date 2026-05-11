"""whatweb wrapper — web technology fingerprinting."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class WhatwebTool(BaseTool):
    name = "whatweb"
    description = (
        "Fingerprint web technologies used by a target website. Identifies CMS, frameworks, "
        "server software, JavaScript libraries, and more. Useful for passive/active recon."
    )
    risk_level = RiskLevel.LOW
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "URL or hostname to fingerprint (e.g. 'https://example.com', 'example.com')",
            },
            "aggression": {
                "type": "integer",
                "description": "Aggression level: 1=stealthy, 2=aggressive, 3=heavy",
                "default": 1,
                "minimum": 1,
                "maximum": 3,
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "whatweb") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        aggression = params.get("aggression", 1)
        cmd = [self.binary, "--aggression", str(aggression), "--log-brief=-", target]
        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=60)
        duration = time.monotonic() - t0

        if rc != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"whatweb failed: {stderr}",
                raw_output=stderr,
                error=stderr,
                duration_seconds=duration,
            )

        output = stdout.strip() or stderr.strip() or "No results returned."
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=output,
            raw_output=stdout,
            duration_seconds=duration,
        )

"""nikto wrapper — web server vulnerability scanner."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class NiktoTool(BaseTool):
    name = "nikto"
    description = (
        "Web server scanner that checks for dangerous files, outdated software, "
        "misconfigurations, and common vulnerabilities. "
        "Best used during the web application enumeration phase."
    )
    risk_level = RiskLevel.MEDIUM
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target URL or host (e.g. 'http://192.168.1.1', 'https://example.com')",
            },
            "port": {
                "type": "integer",
                "description": "Target port. Auto-detected from URL if not specified.",
                "default": 0,
            },
            "tuning": {
                "type": "string",
                "description": (
                    "Nikto tuning options (combined): "
                    "1=Interesting files, 2=Misconfigurations, 3=Info disclosure, "
                    "4=Injection, 8=Command execution, 9=SQL injection. Default: 123"
                ),
                "default": "123",
            },
            "ssl": {
                "type": "boolean",
                "description": "Force SSL/TLS",
                "default": False,
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "nikto") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        port = params.get("port", 0)
        tuning = params.get("tuning", "123")
        ssl = params.get("ssl", False)

        cmd = [self.binary, "-h", target, "-Tuning", tuning, "-nointeractive", "-Format", "txt"]
        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=300)
        duration = time.monotonic() - t0

        output = stdout or stderr
        if not output.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                output="nikto produced no output.",
                error=stderr,
                duration_seconds=duration,
            )

        findings = self._extract_findings(output)
        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_findings(findings),
            raw_output=output,
            metadata={"findings": findings},
            duration_seconds=duration,
        )

    def _extract_findings(self, output: str) -> list[dict[str, str]]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("+ ") and not line.startswith("+ Target"):
                findings.append({"finding": line[2:].strip()})
        return findings

    def _format_findings(self, findings: list[dict[str, str]]) -> str:
        if not findings:
            return "No notable findings from nikto."
        lines = [f"nikto found {len(findings)} item(s):"]
        for f in findings:
            lines.append(f"  - {f['finding']}")
        return "\n".join(lines)

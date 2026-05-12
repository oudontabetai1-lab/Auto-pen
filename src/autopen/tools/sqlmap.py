"""sqlmap wrapper — SQL injection detection and exploitation."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class SqlmapTool(BaseTool):
    name = "sqlmap"
    description = (
        "Automated SQL injection detection and database extraction tool. "
        "Can detect SQLi vulnerabilities and optionally dump database contents. "
        "HIGH risk: sends many requests; can alter database state with --level>=3."
    )
    risk_level = RiskLevel.HIGH
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Target URL with parameter(s) to test (e.g. 'http://site.com/page?id=1')",
            },
            "data": {
                "type": "string",
                "description": "POST data string for testing POST parameters",
                "default": "",
            },
            "level": {
                "type": "integer",
                "description": "Test level 1-5 (1=basic, 5=thorough). Default: 1",
                "default": 1,
            },
            "risk": {
                "type": "integer",
                "description": "Risk level 1-3 (higher may modify data). Default: 1",
                "default": 1,
            },
            "dump": {
                "type": "boolean",
                "description": "Attempt to dump database contents after SQLi confirmed",
                "default": False,
            },
            "dbms": {
                "type": "string",
                "description": "Target DBMS hint (mysql, postgresql, mssql, oracle, sqlite)",
                "default": "",
            },
            "cookie": {
                "type": "string",
                "description": "HTTP cookie header value for authenticated requests",
                "default": "",
            },
        },
        "required": ["url"],
    }

    def __init__(self, binary: str = "sqlmap") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        url = params["url"]
        data = params.get("data", "")
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        dump = params.get("dump", False)
        dbms = params.get("dbms", "")
        cookie = params.get("cookie", "")

        cmd = [
            self.binary,
            "-u", url,
            "--level", str(level),
            "--risk", str(risk),
            "--batch",          # non-interactive
            "--output-dir", "/tmp/sqlmap_output",
        ]
        if data:
            cmd.extend(["--data", data])
        if dump:
            cmd.append("--dump")
        if dbms:
            cmd.extend(["--dbms", dbms])
        if cookie:
            cmd.extend(["--cookie", cookie])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=600)
        duration = time.monotonic() - t0

        output = stdout + ("\n" + stderr if stderr else "")
        injectable = "is vulnerable" in output.lower() or "sqlmap identified" in output.lower()
        payloads = self._extract_payloads(output)

        summary = self._format_summary(output, injectable, payloads)
        return ToolResult(
            tool_name=self.name,
            success=rc == 0,
            output=summary,
            raw_output=output,
            metadata={"injectable": injectable, "payloads": payloads},
            duration_seconds=duration,
        )

    def _extract_payloads(self, output: str) -> list[str]:
        payloads = []
        for line in output.splitlines():
            if "payload:" in line.lower():
                payloads.append(line.strip())
        return payloads[:10]

    def _format_summary(
        self, output: str, injectable: bool, payloads: list[str]
    ) -> str:
        if injectable:
            lines = ["[VULNERABLE] SQL injection detected!"]
            lines.extend(payloads)
            # Look for database banner
            for line in output.splitlines():
                if "web server operating system:" in line.lower():
                    lines.append(line.strip())
                if "back-end dbms:" in line.lower():
                    lines.append(line.strip())
                if "available databases" in line.lower():
                    lines.append(line.strip())
            return "\n".join(lines)
        if "not injectable" in output.lower():
            return "[NOT VULNERABLE] Target does not appear to be SQL injectable."
        return output[-2000:] if len(output) > 2000 else output

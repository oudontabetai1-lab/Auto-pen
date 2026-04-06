"""hydra wrapper — online password brute-forcing."""

from __future__ import annotations

import time
from typing import Any

from autopen.tools.base import BaseTool, RiskLevel, ToolResult


class HydraTool(BaseTool):
    name = "hydra"
    description = (
        "Online brute-force/credential-stuffing tool supporting many protocols: "
        "ssh, ftp, http-get, http-post-form, smb, rdp, mysql, and more. "
        "HIGH risk: generates login noise, may lock accounts. Use carefully."
    )
    risk_level = RiskLevel.HIGH
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target host or IP",
            },
            "service": {
                "type": "string",
                "description": "Service to attack (ssh, ftp, http-get, http-post-form, smb, rdp, mysql, postgres, telnet, etc.)",
            },
            "usernames": {
                "type": "string",
                "description": "Single username or path to username wordlist file",
            },
            "passwords": {
                "type": "string",
                "description": "Single password or path to password wordlist file",
                "default": "/usr/share/wordlists/rockyou.txt",
            },
            "port": {
                "type": "integer",
                "description": "Target port (auto-detected if not specified)",
                "default": 0,
            },
            "http_path": {
                "type": "string",
                "description": "For http-post-form: form path and parameters (e.g. '/login:user=^USER^&pass=^PASS^:F=incorrect')",
                "default": "",
            },
            "threads": {
                "type": "integer",
                "description": "Number of parallel connections (default: 4)",
                "default": 4,
            },
            "stop_on_first": {
                "type": "boolean",
                "description": "Stop after first valid credential found",
                "default": True,
            },
        },
        "required": ["target", "service", "usernames"],
    }

    def __init__(self, binary: str = "hydra") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        service = params["service"]
        usernames = params["usernames"]
        passwords = params.get("passwords", "/usr/share/wordlists/rockyou.txt")
        port = params.get("port", 0)
        http_path = params.get("http_path", "")
        threads = params.get("threads", 4)
        stop_on_first = params.get("stop_on_first", True)

        # Determine if input is a file path or literal value
        u_flag = "-L" if "/" in usernames else "-l"
        p_flag = "-P" if "/" in passwords else "-p"

        cmd = [
            self.binary,
            "-t", str(threads),
            u_flag, usernames,
            p_flag, passwords,
            "-V",       # verbose: show attempt per line
        ]
        if stop_on_first:
            cmd.append("-f")
        if port:
            cmd.extend(["-s", str(port)])

        if service == "http-post-form" and http_path:
            cmd.extend([target, f"http-post-form", http_path])
        else:
            cmd.extend([target, service])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=600)
        duration = time.monotonic() - t0

        output = stdout + ("\n" + stderr if stderr else "")
        credentials = self._extract_credentials(output)

        return ToolResult(
            tool_name=self.name,
            success=True,
            output=self._format_output(credentials, target, service),
            raw_output=output,
            metadata={"credentials": credentials},
            duration_seconds=duration,
        )

    def _extract_credentials(self, output: str) -> list[dict[str, str]]:
        creds = []
        for line in output.splitlines():
            line_lower = line.lower()
            if "[" in line and "] login:" in line_lower:
                # Hydra success line: [port][service] host: <ip>  login: <user>  password: <pass>
                try:
                    login_part = line.split("login:")[1].split("password:")[0].strip()
                    pass_part = line.split("password:")[1].strip()
                    creds.append({"login": login_part, "password": pass_part})
                except IndexError:
                    creds.append({"raw": line.strip()})
        return creds

    def _format_output(
        self, creds: list[dict[str, str]], target: str, service: str
    ) -> str:
        if not creds:
            return f"hydra: No valid credentials found for {service}://{target}"
        lines = [f"[CREDENTIALS FOUND] {len(creds)} valid credential(s) for {service}://{target}:"]
        for c in creds:
            if "raw" in c:
                lines.append(f"  {c['raw']}")
            else:
                lines.append(f"  login: {c['login']}  password: {c['password']}")
        return "\n".join(lines)

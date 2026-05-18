"""hydra wrapper — online password brute-forcing."""

from __future__ import annotations

import os
import time
from typing import Any

from autopen.security.args import UnsafeArgumentError, assert_file_path_safe
from autopen.tools.base import BaseTool, RiskLevel, ToolResult


def _is_file_path(value: str) -> bool:
    """Heuristic: only treat as a file path when it actually points at a readable file.

    The previous implementation used "/" in value, which broke for usernames like
    ``admin/test`` and unsafely accepted anything containing a slash.
    """
    return ("/" in value or "\\" in value) and os.path.isfile(value)


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

        # Reject obvious shell metacharacters in any LLM-supplied string.
        try:
            for label, val in (
                ("target", target),
                ("service", service),
                ("usernames", usernames),
                ("passwords", passwords),
                ("http_path", http_path),
            ):
                if val and any(c in val for c in "`$;&|\n\r"):
                    raise UnsafeArgumentError(f"{label} contains shell metacharacters: {val!r}")
            # Wordlist paths additionally must exist on disk before we pass -L/-P.
            if _is_file_path(usernames):
                assert_file_path_safe(usernames)
            if _is_file_path(passwords):
                assert_file_path_safe(passwords)
        except UnsafeArgumentError as exc:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"hydra refused unsafe arguments: {exc}",
                error=str(exc),
            )

        u_flag = "-L" if _is_file_path(usernames) else "-l"
        p_flag = "-P" if _is_file_path(passwords) else "-p"

        cmd = [
            self.binary,
            "-t", str(int(threads)),
            u_flag, usernames,
            p_flag, passwords,
            "-V",       # verbose: show attempt per line
        ]
        if stop_on_first:
            cmd.append("-f")
        if port:
            cmd.extend(["-s", str(port)])

        if service == "http-post-form" and http_path:
            # Hydra http-post-form syntax: target "http-post-form" "path:params:failure"
            cmd.extend([target, "http-post-form", http_path])
        elif service.startswith("http") and not http_path:
            # No form path provided; fall back to http-get
            cmd.extend([target, "http-get"])
        else:
            cmd.extend([target, service])

        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=600)
        duration = time.monotonic() - t0

        output = stdout + ("\n" + stderr if stderr else "")
        credentials = self._extract_credentials(output)

        if rc != 0 and not stdout.strip():
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"hydra failed: {stderr or 'unknown error'}",
                raw_output=output,
                error=stderr,
                duration_seconds=duration,
            )

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
            if "[" in line and "login:" in line_lower and "password:" in line_lower:
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

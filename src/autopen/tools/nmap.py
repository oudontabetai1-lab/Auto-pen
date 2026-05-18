"""nmap wrapper — port scanning and service enumeration."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Any

from autopen.security.args import UnsafeArgumentError, split_extra_args
from autopen.tools.base import BaseTool, RiskLevel, ToolResult

# Allow-list of nmap flag prefixes accepted via extra_args. Anything that
# could read/write the filesystem or execute scripts beyond stock NSE is
# explicitly excluded.
_NMAP_EXTRA_ARG_PREFIXES = (
    "-p", "-sV", "-sS", "-sT", "-sU", "-sn", "-Pn", "-A", "-T",
    "-O", "-n", "-R", "--top-ports", "--open", "--reason",
    "--min-rate", "--max-rate", "--max-retries", "--host-timeout",
    "--script=", "--script-args=",
)


class NmapTool(BaseTool):
    name = "nmap"
    description = (
        "Network scanner for host discovery, port scanning, and service/version detection. "
        "Use for reconnaissance and enumeration phases. "
        "Supports TCP/UDP scans, OS detection, and NSE scripts."
    )
    risk_level = RiskLevel.MEDIUM
    parameters_schema = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP, hostname, or CIDR range (e.g. '192.168.1.1', '10.0.0.0/24')",
            },
            "ports": {
                "type": "string",
                "description": "Port specification (e.g. '22,80,443', '1-1000', '-'  for all). Default: top 1000",
                "default": "",
            },
            "scan_type": {
                "type": "string",
                "enum": ["basic", "version", "aggressive", "stealth", "udp", "vuln"],
                "description": (
                    "basic=fast TCP scan, version=service versions, "
                    "aggressive=OS+version+scripts, stealth=SYN scan, udp=UDP scan, vuln=vulnerability scripts"
                ),
                "default": "version",
            },
            "extra_args": {
                "type": "string",
                "description": "Additional nmap arguments (advanced use)",
                "default": "",
            },
        },
        "required": ["target"],
    }

    def __init__(self, binary: str = "nmap") -> None:
        self.binary = binary

    async def execute(self, params: dict[str, Any]) -> ToolResult:
        target = params["target"]
        ports = params.get("ports", "")
        scan_type = params.get("scan_type", "version")
        extra_args = params.get("extra_args", "")

        try:
            cmd = self._build_command(target, ports, scan_type, extra_args)
        except UnsafeArgumentError as exc:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"nmap refused unsafe arguments: {exc}",
                error=str(exc),
            )
        t0 = time.monotonic()
        stdout, stderr, rc = await self._run_command(cmd, timeout=300)
        duration = time.monotonic() - t0

        if rc != 0 and not stdout:
            return ToolResult(
                tool_name=self.name,
                success=False,
                output=f"nmap failed: {stderr}",
                raw_output=stderr,
                error=stderr,
                duration_seconds=duration,
            )

        parsed = self._parse_xml(stdout)

        if parsed.get("parse_error"):
            return ToolResult(
                tool_name=self.name,
                success=False,
                output="nmap: failed to parse XML output",
                raw_output=stdout,
                error="XML parse error",
                metadata=parsed,
                duration_seconds=duration,
            )

        summary = self._format_summary(parsed)

        return ToolResult(
            tool_name=self.name,
            success=True,
            output=summary,
            raw_output=stdout,
            metadata=parsed,
            duration_seconds=duration,
        )

    # ------------------------------------------------------------------

    def _build_command(
        self, target: str, ports: str, scan_type: str, extra_args: str
    ) -> list[str]:
        cmd = [self.binary, "-oX", "-"]  # XML output to stdout

        type_flags = {
            "basic": ["-T4"],
            "version": ["-sV", "-T4"],
            "aggressive": ["-A", "-T4"],
            "stealth": ["-sS", "-T4"],
            "udp": ["-sU", "-T4"],
            "vuln": ["-sV", "--script=vuln", "-T4"],
        }
        cmd.extend(type_flags.get(scan_type, ["-sV", "-T4"]))

        if ports:
            # nmap port spec: digits, commas, dashes, and protocol prefixes (T:, U:).
            if not all(c.isalnum() or c in ",-:" for c in ports):
                raise UnsafeArgumentError(f"Invalid nmap port spec: {ports!r}")
            cmd.extend(["-p", ports])

        if extra_args:
            cmd.extend(
                split_extra_args(extra_args, allowed_prefixes=_NMAP_EXTRA_ARG_PREFIXES)
            )

        # Reject targets beginning with '-' so they can't be confused for flags.
        if target.startswith("-"):
            raise UnsafeArgumentError(f"Target starts with '-': {target!r}")
        cmd.append(target)
        return cmd

    def _parse_xml(self, xml_output: str) -> dict[str, Any]:
        """Parse nmap XML output into a structured dict."""
        hosts: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return {"hosts": hosts, "parse_error": True}

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue

            addr_el = host.find("address[@addrtype='ipv4']")
            hostname_el = host.find(".//hostname")
            ip = addr_el.get("addr", "") if addr_el is not None else ""
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""

            ports_info: list[dict[str, Any]] = []
            for port in host.findall(".//port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc_el = port.find("service")
                try:
                    portid = int(port.get("portid") or 0)
                except ValueError:
                    portid = 0
                ports_info.append(
                    {
                        "port": portid,
                        "protocol": port.get("protocol", "tcp"),
                        "service": svc_el.get("name", "") if svc_el is not None else "",
                        "version": svc_el.get("version", "") if svc_el is not None else "",
                        "product": svc_el.get("product", "") if svc_el is not None else "",
                    }
                )

            os_el = host.find(".//osmatch")
            os_guess = os_el.get("name", "") if os_el is not None else ""

            scripts: list[dict[str, Any]] = []
            for script in host.findall(".//script"):
                scripts.append({"id": script.get("id"), "output": script.get("output", "")[:500]})

            hosts.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "ports": ports_info,
                    "os_guess": os_guess,
                    "scripts": scripts,
                }
            )

        return {"hosts": hosts}

    def _format_summary(self, parsed: dict[str, Any]) -> str:
        lines = []
        for host in parsed.get("hosts", []):
            name = host["hostname"] or host["ip"]
            lines.append(f"Host: {name} ({host['ip']})")
            if host.get("os_guess"):
                lines.append(f"  OS: {host['os_guess']}")
            for p in host.get("ports", []):
                svc = f"{p['product']} {p['version']}".strip()
                lines.append(
                    f"  {p['port']}/{p['protocol']}  open  {p['service']}  {svc}"
                )
            for s in host.get("scripts", []):
                lines.append(f"  [script:{s['id']}] {s['output'][:200]}")
        return "\n".join(lines) if lines else "No open ports found."

"""Tool registry: discovers and provides access to all tool wrappers."""

from __future__ import annotations

from typing import Any

from autopen.tools.base import BaseTool


class ToolRegistry:
    """Central registry of available security tools."""

    def __init__(self, tool_config: dict[str, Any] | None = None) -> None:
        self._tools: dict[str, BaseTool] = {}
        self._config = tool_config or {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        from autopen.tools.dig import DigTool
        from autopen.tools.duckduckgo import DuckDuckGoTool
        from autopen.tools.ffuf import FfufTool
        from autopen.tools.gobuster import GobusterTool
        from autopen.tools.hydra import HydraTool
        from autopen.tools.metasploit import MetasploitTool
        from autopen.tools.nikto import NiktoTool
        from autopen.tools.nmap import NmapTool
        from autopen.tools.nuclei import NucleiTool
        from autopen.tools.sqlmap import SqlmapTool
        from autopen.tools.whatweb import WhatwebTool
        from autopen.tools.whois import WhoisTool

        tools: list[BaseTool] = [
            NmapTool(binary=self._config.get("nmap", "nmap")),
            NiktoTool(binary=self._config.get("nikto", "nikto")),
            NucleiTool(binary=self._config.get("nuclei", "nuclei")),
            SqlmapTool(binary=self._config.get("sqlmap", "sqlmap")),
            GobusterTool(binary=self._config.get("gobuster", "gobuster")),
            FfufTool(binary=self._config.get("ffuf", "ffuf")),
            HydraTool(binary=self._config.get("hydra", "hydra")),
            MetasploitTool(
                rpc_host=self._config.get("msfrpc_host", "127.0.0.1"),
                rpc_port=int(self._config.get("msfrpc_port", 55553)),
                rpc_user=self._config.get("msfrpc_user", "msf"),
                rpc_pass=self._config.get("msfrpc_pass", "msf"),
            ),
            WhoisTool(binary=self._config.get("whois", "whois")),
            DigTool(binary=self._config.get("dig", "dig")),
            WhatwebTool(binary=self._config.get("whatweb", "whatweb")),
            DuckDuckGoTool(),
        ]
        for tool in tools:
            self._tools[tool.name] = tool

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' not found in registry.")
        return self._tools[name]

    def all_tools(self) -> list[BaseTool]:
        return list(self._tools.values())

    def available_tools(self) -> list[BaseTool]:
        """Return only tools whose binary is installed."""
        return [t for t in self._tools.values() if t.is_available()]

    def get_llm_schemas(self, only_available: bool = True) -> list[dict]:
        """Return tool schemas for LLM tool-calling, optionally filtering unavailable tools."""
        tools = self.available_tools() if only_available else self.all_tools()
        return [t.to_llm_schema() for t in tools]

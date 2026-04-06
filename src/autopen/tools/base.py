"""Abstract base class for security tool wrappers."""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel


class RiskLevel(str, Enum):
    """Risk classification for tool execution.

    LOW      — passive info gathering, no interaction with target (e.g. DNS lookup)
    MEDIUM   — active scanning, sends packets but non-destructive (e.g. nmap port scan)
    HIGH     — potentially disruptive or exploitative (e.g. sqlmap, hydra brute-force)
    CRITICAL — direct exploitation or code execution (e.g. metasploit exploits)
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolResult(BaseModel):
    """Output from a tool execution."""

    tool_name: str
    success: bool
    output: str                        # raw / parsed text returned to the LLM
    raw_output: str = ""               # unprocessed stdout/stderr
    error: str = ""
    metadata: dict[str, Any] = {}      # structured data (parsed XML, JSON, etc.)
    duration_seconds: float = 0.0


class BaseTool(ABC):
    """Every security tool wrapper must inherit from this class."""

    name: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    parameters_schema: dict[str, Any] = {}   # JSON Schema for LLM tool calling

    # Path to the binary (can be overridden via config)
    binary: str = ""

    def is_available(self) -> bool:
        """Return True if the underlying binary/tool is installed."""
        return bool(shutil.which(self.binary)) if self.binary else False

    @abstractmethod
    async def execute(self, params: dict[str, Any]) -> ToolResult:
        """Execute the tool and return a ToolResult."""

    def to_llm_schema(self) -> dict[str, Any]:
        """Return the OpenAI-compatible function/tool schema for LLM tool calling."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters_schema,
        }

    async def _run_command(
        self,
        cmd: list[str],
        timeout: float = 300.0,
    ) -> tuple[str, str, int]:
        """Run a subprocess command and return (stdout, stderr, returncode)."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return "", f"Command timed out after {timeout}s", -1

        return stdout_bytes.decode("utf-8", errors="replace"), stderr_bytes.decode(
            "utf-8", errors="replace"
        ), proc.returncode or 0

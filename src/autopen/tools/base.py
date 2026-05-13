"""Abstract base class for security tool wrappers."""

from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

from pydantic import BaseModel


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    output: str
    raw_output: str = ""
    error: str = ""
    metadata: dict[str, Any] = {}
    duration_seconds: float = 0.0


class BaseTool(ABC):
    name: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    parameters_schema: dict[str, Any] = {}
    binary: str = ""

    def is_available(self) -> bool:
        return bool(shutil.which(self.binary)) if self.binary else False

    @abstractmethod
    async def execute(self, params: dict[str, Any]) -> ToolResult:
        """Execute the tool and return a ToolResult."""

    def to_llm_schema(self) -> dict[str, Any]:
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
        ), proc.returncode if proc.returncode is not None else -1

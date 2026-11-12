"""
BaseTool ABC and BaseOutputParser ABC.
All security tool integrations extend BaseTool.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from modules.context_management.state_schema import ToolResult
from modules.tool_invocation.executor import SubprocessExecutor
from utils.clip import clip_marked


class BaseOutputParser(ABC):
    """Parse raw tool stdout into a structured dict."""

    @abstractmethod
    def parse(self, stdout: str, stderr: str = "") -> dict:
        ...


class BaseTool(ABC):
    name: str
    timeout: int = 120
    parser: BaseOutputParser

    @abstractmethod
    def build_command(self, params: dict) -> list[str]:
        """Build the command list from params dict. No shell=True expansion."""
        ...

    def run(self, params: dict) -> ToolResult:
        cmd = self.build_command(params)
        raw = SubprocessExecutor.run(cmd, timeout=self.timeout)

        success = raw.returncode == 0 and not raw.timed_out
        parsed = {}
        error_msg = None

        if raw.returncode == -2:
            # Tool not found — no output to parse（给 LLM 可执行的替代路径）
            error_msg = (
                f"Tool '{self.name}' 不可用（未安装或不在 PATH）。"
                f"下一步（可执行）：改用其他已安装工具完成该步骤。"
                f"原始错误: {raw.stderr[:200]}")
        else:
            if raw.timed_out:
                error_msg = (
                    f"Tool '{self.name}' timed out after {self.timeout}s。"
                    f"下一步（可执行）：缩小参数范围重发（如 nmap 换更少 ports、"
                    f"dirsearch 换更短 extensions）；原参数会被重复检测拦截。")
            elif raw.returncode not in (0, 1):  # sqlmap returns 1 on findings
                error_msg = raw.stderr[:500] if raw.stderr else None

            # Always attempt to parse whatever output was captured
            try:
                parsed = self.parser.parse(raw.stdout, raw.stderr)
            except Exception as e:
                if error_msg is None:
                    error_msg = f"Parser error: {e}"

        return ToolResult(
            tool=self.name,
            command=" ".join(cmd),
            raw_stdout=clip_marked(raw.stdout, 50000),  # Truncate with explicit marker
            raw_stderr=clip_marked(raw.stderr, 5000),
            parsed=parsed,
            success=success,
            elapsed_seconds=raw.elapsed_seconds,
            error_message=error_msg,
            timestamp=datetime.utcnow(),
        )

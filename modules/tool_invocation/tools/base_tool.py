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


# 工具带着错误输出退出时 harness 给模型的下一步（ERROR 行里只有这句话，原文在不可信区块）
EXIT_GUIDANCE = ("下一步（可执行）：按错误输出判断原因（目标不可达、参数不被接受、权限不足），"
                 "换参数或换工具重试，不要原样重试。")
PARSE_GUIDANCE = "解析工具输出时出错。下一步（可执行）：换用其他工具获取同类信息。"


def error_lines(text: str, limit: int = 10) -> list[str]:
    """工具的错误输出（stderr、异常消息）按行放进 parsed["tool_error"]。

    这段文字可能被目标影响，所以渲染在不可信标记之内、由守卫逐行检查；
    ERROR 行（渲染在标记之外、模型被明确告知可以信任）只留 harness 自己写的
    原因和下一步。"""
    lines = [line.strip()[:300] for line in str(text or "").splitlines()]
    return [line for line in lines if line][:limit]


class BaseTool(ABC):
    name: str
    timeout: int = 120
    parser: BaseOutputParser

    @abstractmethod
    def build_command(self, params: dict) -> list[str]:
        """Build the command list from params dict. No shell=True expansion."""
        ...

    def preview(self, params: dict) -> str:
        """The exact text that would be executed, built without running anything.

        The approval gate matches against this, so it judges the real command
        line instead of the model's raw params.
        """
        return " ".join(self.build_command(params))

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
            elif raw.stderr.strip() and (raw.returncode not in (0, 1) or not success):
                # 退出码 1 不算报错（sqlmap 有发现时就是 1），但也算不上成功。失败却带着
                # stderr 时必须把原因带给模型：实测 nmap -sU 以非 root 运行时退出码为 1，
                # stderr 写着 "requires root privileges"，模型只看到一次没有解释的失败。
                # stderr 原文按行放进 parsed（渲染在不可信标记之内，守卫逐行看）；
                # ERROR 行只留 harness 自己写的原因和下一步。
                parsed["tool_error"] = error_lines(raw.stderr)
                error_msg = (
                    f"Tool '{self.name}' 以退出码 {raw.returncode} 结束，错误输出见下。"
                    + EXIT_GUIDANCE)

            # Always attempt to parse whatever output was captured
            try:
                parsed.update(self.parser.parse(raw.stdout, raw.stderr))
            except Exception as e:
                if error_msg is None:
                    error_msg = PARSE_GUIDANCE
                parsed["tool_error"] = [f"Parser error: {e}"[:300]]

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

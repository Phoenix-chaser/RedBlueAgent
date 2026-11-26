"""
ToolInvoker - routes ActionDecision to the appropriate BaseTool.
"""
from __future__ import annotations

from modules.context_management.state_schema import ActionDecision, ToolResult
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.tools.nmap_tool import NmapTool
from modules.tool_invocation.tools.dirsearch_tool import DirsearchTool
from modules.tool_invocation.tools.nikto_tool import NiktoTool
from modules.tool_invocation.tools.sqlmap_tool import SqlmapTool
from modules.tool_invocation.tools.metasploit_tool import MetasploitTool
from modules.tool_invocation.tools.read_url_tool import ReadUrlTool
from modules.tool_invocation.tools.base_tool import BaseTool, error_lines
from datetime import datetime


class ToolInvoker:
    """
    Dispatches ActionDecision to the correct tool and returns a ToolResult.
    New tools can be registered at runtime via register().
    """

    def __init__(self):
        self._tools: dict[str, BaseTool] = {
            "nmap": NmapTool(),
            "dirsearch": DirsearchTool(),
            "nikto": NiktoTool(),
            "sqlmap": SqlmapTool(),
            "metasploit": MetasploitTool(),
            "read_url": ReadUrlTool(),
        }

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def available_tools(self) -> list[str]:
        return list(self._tools.keys())

    def preview(self, action: ActionDecision) -> str | None:
        """Command text an action would execute, without running it.

        None for an unknown tool or params the interpreter rejects: those never
        reach a subprocess (invoke() returns the interpreter's error instead).
        """
        tool = self._tools.get((action.tool or "").lower().strip())
        if tool is None:
            return None
        try:
            return tool.preview(action.params or {})
        except (ParamError, ValueError):
            return None

    def invoke(self, action: ActionDecision) -> ToolResult:
        tool_name = (action.tool or "").lower().strip()
        tool = self._tools.get(tool_name)

        if tool is None:
            return ToolResult(
                tool=tool_name,
                command="",
                success=False,
                error_message=f"Unknown tool: '{tool_name}'. Available: {self.available_tools()}",
                timestamp=datetime.utcnow(),
            )

        try:
            return tool.run(action.params)
        except ParamError as e:
            # Param interpreter rejected the LLM's args. The message is written
            # to teach the LLM the correct value — pass it through verbatim.
            return ToolResult(
                tool=tool_name,
                command="",
                success=False,
                error_message=str(e),
                timestamp=datetime.utcnow(),
            )
        except ValueError as e:
            return ToolResult(
                tool=tool_name,
                command="",
                success=False,
                error_message=f"Invalid parameters for '{tool_name}': {e}",
                timestamp=datetime.utcnow(),
            )
        except Exception as e:
            # 异常消息里可能带着工具输出或服务端给的原文：进不可信区块，不进 ERROR 行
            return ToolResult(
                tool=tool_name,
                command="",
                success=False,
                error_message=(f"Unexpected error running '{tool_name}'，原因见错误输出。"
                               "下一步（可执行）：换用其他工具或参数重试。"),
                parsed={"tool_error": error_lines(f"{type(e).__name__}: {e}")},
                timestamp=datetime.utcnow(),
            )

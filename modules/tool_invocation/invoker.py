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
from modules.tool_invocation.tools.base_tool import BaseTool
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
        }

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def available_tools(self) -> list[str]:
        return list(self._tools.keys())

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
            return ToolResult(
                tool=tool_name,
                command="",
                success=False,
                error_message=f"Unexpected error running '{tool_name}': {e}",
                timestamp=datetime.utcnow(),
            )

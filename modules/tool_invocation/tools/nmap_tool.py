"""
NmapTool - host discovery and port scanning.
Param interpretation lives in params/nmap_params.py; output parsing in
parsers/nmap_parser.py. This tool wires the two together and translates the
one failure the agent cannot fix by retrying: scans that need root.
"""
from __future__ import annotations

from modules.context_management.state_schema import ToolResult
from modules.tool_invocation.params.nmap_params import NmapParamInterpreter
from modules.tool_invocation.parsers.nmap_parser import NmapParser
from modules.tool_invocation.tools.base_tool import BaseTool

# The agent image runs as an unprivileged user, so these scan types can never
# succeed there (seen in a live run: the model asked for a UDP scan).
_NEEDS_ROOT = (
    "nmap: 该扫描类型需要 root 权限，而 agent 以非 root 运行（UDP 扫描 -sU、"
    "OS 检测 -O 都属于此类），重试同样的参数不会成功。"
    "下一步（可执行）：改用 TCP 扫描（scan_type=service / full / quick）。")


class NmapTool(BaseTool):
    name = "nmap"
    timeout = 300
    parser = NmapParser()
    params_interpreter = NmapParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        return self.params_interpreter.build(params)

    def run(self, params: dict) -> ToolResult:
        result = super().run(params)
        if not result.success and "root privileges" in (result.raw_stderr or ""):
            result.error_message = _NEEDS_ROOT          # harness 自己写的，已经说明了原因
            result.parsed = {k: v for k, v in result.parsed.items() if k != "tool_error"}
        return result

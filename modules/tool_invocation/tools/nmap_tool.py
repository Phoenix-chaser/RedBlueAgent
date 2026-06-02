"""
NmapTool - host discovery and port scanning.
Param interpretation lives in params/nmap_params.py; output parsing in
parsers/nmap_parser.py. This tool just wires the two together.
"""
from __future__ import annotations

from modules.tool_invocation.params.nmap_params import NmapParamInterpreter
from modules.tool_invocation.parsers.nmap_parser import NmapParser
from modules.tool_invocation.tools.base_tool import BaseTool


class NmapTool(BaseTool):
    name = "nmap"
    timeout = 300
    parser = NmapParser()
    params_interpreter = NmapParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        return self.params_interpreter.build(params)

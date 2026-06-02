"""
SqlmapTool - automated SQL injection detection and exploitation.
Param interpretation lives in params/sqlmap_params.py; output parsing in
parsers/sqlmap_parser.py.
"""
from __future__ import annotations

from modules.tool_invocation.params.sqlmap_params import SqlmapParamInterpreter
from modules.tool_invocation.parsers.sqlmap_parser import SqlmapParser
from modules.tool_invocation.tools.base_tool import BaseTool


class SqlmapTool(BaseTool):
    name = "sqlmap"
    timeout = 300
    parser = SqlmapParser()
    params_interpreter = SqlmapParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        return self.params_interpreter.build(params)

"""
DirsearchTool - web directory and file enumeration.
Param interpretation lives in params/dirsearch_params.py; output parsing in
parsers/dirsearch_parser.py.
"""
from __future__ import annotations

from modules.tool_invocation.params.dirsearch_params import DirsearchParamInterpreter
from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
from modules.tool_invocation.tools.base_tool import BaseTool


class DirsearchTool(BaseTool):
    name = "dirsearch"
    timeout = 300
    parser = DirsearchParser()
    params_interpreter = DirsearchParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        return self.params_interpreter.build(params)

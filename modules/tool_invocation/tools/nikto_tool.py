"""
NiktoTool - web vulnerability scanner.
Param interpretation lives in params/nikto_params.py; output parsing in
parsers/nikto_parser.py. nikto can't stream JSON to stdout, so we write to a
temp file and read it back in run().
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime

from modules.tool_invocation.params.nikto_params import NiktoParamInterpreter
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.parsers.nikto_parser import NiktoParser
from modules.tool_invocation.tools.base_tool import BaseTool
from modules.context_management.state_schema import ToolResult


class NiktoTool(BaseTool):
    name = "nikto"
    timeout = 300
    parser = NiktoParser()
    params_interpreter = NiktoParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        # Reserve the JSON output path here so run() (via super().run) can read
        # it back. mkstemp creates+opens the file; close the fd and let nikto
        # overwrite it (avoids mktemp's deprecation and its name-reuse race).
        fd, self._json_tmp = tempfile.mkstemp(suffix=".json", prefix="nikto_")
        os.close(fd)
        return self.params_interpreter.build(params, self._json_tmp)

    def run(self, params: dict) -> ToolResult:
        try:
            result = super().run(params)
        except ParamError as e:
            return ToolResult(
                tool=self.name,
                command="nikto",
                success=False,
                error_message=str(e),
                timestamp=datetime.utcnow(),
            )

        tmp = getattr(self, "_json_tmp", None)
        if tmp and os.path.exists(tmp):
            try:
                with open(tmp, encoding="utf-8", errors="replace") as fh:
                    json_content = fh.read().strip()
                if json_content:
                    result.raw_stdout = json_content
                    result.parsed = self.parser.parse(json_content, result.raw_stderr)
            except Exception:
                pass  # keep plain-text parse from super().run as fallback
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            self._json_tmp = None

        return result

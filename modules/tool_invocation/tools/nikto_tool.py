"""
NiktoTool - web vulnerability scanner.
Param interpretation lives in params/nikto_params.py; output parsing in
parsers/nikto_parser.py. nikto can't stream JSON to stdout, so we write to a
temp file and read it back in run(). nikto builds without a JSON reporter
(2.1.5, the Ubuntu/Debian package — the one in the agent image) fall back to
plain text on stdout.
"""
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime

from modules.tool_invocation.params.nikto_params import NiktoParamInterpreter
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.parsers.nikto_parser import NiktoParser
from modules.tool_invocation.tools.base_tool import BaseTool
from modules.context_management.state_schema import ToolResult

# nikto reports its own errors as "+ ERROR: …" lines and still exits 0. When the
# target has no web service it prints "+ No web server found on host:port" and
# also exits 0 — that is not "0 findings": the scan never happened (seen in the
# agent image against a closed port).
_NIKTO_ERROR = re.compile(r"^[+-]\s*(?:ERROR:\s*(.+)|(No web server found[^\n]*))", re.M)


def _nikto_error(result: ToolResult) -> str | None:
    """The first error nikto printed, or None."""
    match = _NIKTO_ERROR.search(f"{result.raw_stdout}\n{result.raw_stderr}")
    return (match.group(1) or match.group(2)).strip() if match else None


class NiktoTool(BaseTool):
    name = "nikto"
    timeout = 300
    parser = NiktoParser()
    params_interpreter = NiktoParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        if getattr(self, "_text_mode", False):
            return self.params_interpreter.build(params)
        # Reserve the JSON output path here so run() (via super().run) can read
        # it back. mkstemp creates+opens the file; close the fd and let nikto
        # overwrite it (avoids mktemp's deprecation and its name-reuse race).
        fd, self._json_tmp = tempfile.mkstemp(suffix=".json", prefix="nikto_")
        os.close(fd)
        return self.params_interpreter.build(params, self._json_tmp)

    def preview(self, params: dict) -> str:
        # build_command() reserves a temp JSON file as a side effect; a preview
        # must not, so ask the interpreter with a placeholder path instead.
        return " ".join(self.params_interpreter.build(params, "<json-output>"))

    def _execute(self, params: dict) -> ToolResult:
        try:
            return super().run(params)
        except ParamError as e:
            return ToolResult(
                tool=self.name,
                command="nikto",
                success=False,
                error_message=str(e),
                timestamp=datetime.utcnow(),
            )

    def run(self, params: dict) -> ToolResult:
        self._text_mode = False
        result = self._execute(params)
        self._read_json_report(result)

        error = _nikto_error(result)
        if error and "invalid output format" in error.lower():
            # This nikto has no JSON reporter: same scan, plain text on stdout
            self._text_mode = True
            result = self._execute(params)
            error = _nikto_error(result)

        if error and not (result.parsed or {}).get("findings"):
            # nikto exits 0 on errors. Reported as a success, "0 findings"
            # reaches the model as the valid conclusion that the site is clean
            result.success = False
            result.error_message = (
                "nikto 报错且没有产出任何结果。"
                "下一步（可执行）：检查 target/port 是否正确；"
                "或改用 dirsearch + read_url 枚举路径，再逐个验证。")
            # 报错原文来自 nikto 的输出，可能带着目标给的文字：进不可信区块，不进 ERROR 行
            result.parsed = dict(result.parsed or {})
            result.parsed["tool_error"] = [error.strip()[:300]]
        return result

    def _read_json_report(self, result: ToolResult) -> None:
        tmp, self._json_tmp = getattr(self, "_json_tmp", None), None
        if not tmp or not os.path.exists(tmp):
            return
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

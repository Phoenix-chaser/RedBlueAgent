"""
DirsearchTool - web directory and file enumeration.
Param interpretation lives in params/dirsearch_params.py; output parsing in
parsers/dirsearch_parser.py.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime

from modules.tool_invocation.params.dirsearch_params import DirsearchParamInterpreter
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
from modules.tool_invocation.tools.base_tool import BaseTool
from modules.tool_invocation.executor import SubprocessExecutor
from modules.context_management.state_schema import ToolResult
from utils.clip import clip_marked

# dirsearch ≥0.5 用 -O/--output-formats，旧版用 --format；首次使用时探测
_FMT_FLAG_CACHE: str | None = None


def _detect_format_flag() -> str:
    global _FMT_FLAG_CACHE
    if _FMT_FLAG_CACHE is None:
        try:
            probe = SubprocessExecutor.run(["dirsearch", "-h"], timeout=15)
            help_text = (probe.stdout + probe.stderr).lower()
            _FMT_FLAG_CACHE = "-O" if "output-formats" in help_text else "--format"
        except Exception:
            _FMT_FLAG_CACHE = "--format"
    return _FMT_FLAG_CACHE


class DirsearchTool(BaseTool):
    name = "dirsearch"
    timeout = 300
    parser = DirsearchParser()
    params_interpreter = DirsearchParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        # Not used directly — run() handles the temp report lifecycle.
        return self.params_interpreter.build(params)

    def run(self, params: dict) -> ToolResult:
        try:
            cmd = self.params_interpreter.build(params)
        except ParamError as e:
            return ToolResult(
                tool=self.name,
                command="dirsearch",
                success=False,
                error_message=str(e),
                timestamp=datetime.utcnow(),
            )

        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="dirsearch_")
        os.close(fd)
        cmd = cmd + [_detect_format_flag(), "json", "-o", report_path]

        try:
            raw = SubprocessExecutor.run(cmd, timeout=self.timeout)
            report = ""
            try:
                with open(report_path, encoding="utf-8", errors="replace") as f:
                    report = f.read()
            except OSError:
                pass  # report unreadable — fall back to parsing CLI stdout
        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

        success = raw.returncode in (0, 1) and not raw.timed_out
        parsed = {}
        error_msg = None

        if raw.timed_out:
            error_msg = f"Dirsearch timed out after {self.timeout}s"
        elif raw.returncode == -2:
            error_msg = raw.stderr
        elif raw.returncode not in (0, 1) and not report:
            error_msg = raw.stderr[:500] if raw.stderr else None

        # report 文件是纯 JSON（主解析路径）；CLI stdout 混有进度行，仅作
        # 文本 fallback 与 LLM 可见输出
        try:
            parsed = self.parser.parse(report or raw.stdout, raw.stderr)
        except Exception as e:
            if error_msg is None:
                error_msg = f"Parser error: {e}"

        return ToolResult(
            tool=self.name,
            command=" ".join(cmd),
            raw_stdout=clip_marked(raw.stdout, 50000),
            raw_stderr=clip_marked(raw.stderr, 5000),
            parsed=parsed,
            success=success,
            elapsed_seconds=raw.elapsed_seconds,
            error_message=error_msg,
            timestamp=datetime.utcnow(),
        )

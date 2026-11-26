"""
DirsearchTool - web directory and file enumeration.
Param interpretation lives in params/dirsearch_params.py; output parsing in
parsers/dirsearch_parser.py.
"""
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime

from modules.tool_invocation.params.dirsearch_params import DirsearchParamInterpreter
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
from modules.tool_invocation.tools.base_tool import EXIT_GUIDANCE, PARSE_GUIDANCE, BaseTool, error_lines
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

    # dirsearch prints this and still exits 0 when nothing answers on the target
    # port (seen in the agent image against a closed port)
    _UNREACHABLE = re.compile(r"^Cannot connect to:[^\n]*", re.M)

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
            # 执行器自己写的「未安装」
            error_msg = ("Tool 'dirsearch' 不可用（未安装或不在 PATH）。"
                         "下一步（可执行）：改用其他已安装工具完成该步骤。")
        elif raw.returncode not in (0, 1) and raw.stderr.strip():
            # stderr 原文进不可信区块，ERROR 行只留 harness 自己写的话
            parsed["tool_error"] = error_lines(raw.stderr)
            error_msg = f"dirsearch 以退出码 {raw.returncode} 结束，错误输出见下。" + EXIT_GUIDANCE

        # report 文件是纯 JSON（主解析路径）；CLI stdout 混有进度行，仅作
        # 文本 fallback 与 LLM 可见输出
        try:
            parsed.update(self.parser.parse(report or raw.stdout, raw.stderr))
        except Exception as e:
            if error_msg is None:
                error_msg = PARSE_GUIDANCE
            parsed["tool_error"] = [f"Parser error: {e}"[:300]]

        unreachable = (self._UNREACHABLE.search(raw.stdout)
                       if not parsed.get("paths") else None)
        if unreachable and error_msg is None:
            # 端口没人应答：不是「0 条路径」，这次根本没扫成
            success = False
            parsed["tool_error"] = [unreachable.group(0).strip()[:300]]
            error_msg = ("dirsearch 连不上目标。下一步（可执行）：用 nmap scan_type='service' "
                         "确认端口开放且为 HTTP(S)，或换用其他已发现的端口。")

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

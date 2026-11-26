"""
MetasploitTool - vulnerability exploitation via msfconsole resource scripts.
Param interpretation (the .rc body) lives in params/metasploit_params.py;
output parsing in parsers/metasploit_parser.py.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime

from modules.tool_invocation.params.metasploit_params import MetasploitParamInterpreter
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.parsers.metasploit_parser import MetasploitParser
from modules.tool_invocation.tools.base_tool import EXIT_GUIDANCE, PARSE_GUIDANCE, BaseTool, error_lines
from modules.tool_invocation.executor import SubprocessExecutor
from modules.context_management.state_schema import ToolResult


class MetasploitTool(BaseTool):
    name = "metasploit"
    timeout = 180
    parser = MetasploitParser()
    params_interpreter = MetasploitParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        # Not used directly — run() handles the temp .rc lifecycle.
        return ["msfconsole", "-q", "-r", "/tmp/msf_resource.rc"]

    def preview(self, params: dict) -> str:
        # msfconsole executes the resource script, not build_command().
        return self.params_interpreter.build(params)

    def run(self, params: dict) -> ToolResult:
        try:
            rc_content = self.params_interpreter.build(params)
        except ParamError as e:
            return ToolResult(
                tool=self.name,
                command="msfconsole",
                success=False,
                error_message=str(e),
                timestamp=datetime.utcnow(),
            )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rc", delete=False, prefix="msf_"
        ) as tf:
            tf.write(rc_content)
            rc_path = tf.name

        # The interpreter is fixed to "msfconsole": the executable must never be
        # chosen by model-supplied params.
        cmd = ["msfconsole", "-q", "-r", rc_path]

        try:
            raw = SubprocessExecutor.run(cmd, timeout=self.timeout)
        finally:
            try:
                os.unlink(rc_path)
            except OSError:
                pass

        success = raw.returncode in (0, 1) and not raw.timed_out
        parsed = {}
        error_msg = None

        if raw.timed_out:
            error_msg = (
                f"Metasploit timed out after {self.timeout}s。"
                "下一步（可执行）：换用更轻量的模块或缩小 rhosts 范围；"
                "或改用 sqlmap / nmap 脚本验证同一问题。")
        elif raw.returncode == -2:
            # agent 镜像故意不装 msfconsole（体积考虑），这条路径一定会走到：
            # 给模型的必须是指向已安装工具的下一步，不只是一句"未找到"
            error_msg = (
                "Tool 'metasploit' 不可用（msfconsole 未安装或不在 PATH）。"
                "下一步（可执行）：改用其他已安装工具完成该步骤——"
                "注入类问题用 sqlmap 验证，服务版本类问题用 nmap 脚本复核。"
                f"原始错误: {raw.stderr[:200]}")

        if error_msg is None and not success and raw.stderr.strip():
            # 以别的退出码结束、又没有带超时/缺依赖的说明：stderr 原文进不可信区块
            parsed["tool_error"] = error_lines(raw.stderr)
            error_msg = f"metasploit 以退出码 {raw.returncode} 结束，错误输出见下。" + EXIT_GUIDANCE

        try:
            parsed.update(self.parser.parse(raw.stdout, raw.stderr))
            if parsed.get("exploit_success"):
                success = True
        except Exception as e:
            if error_msg is None:
                error_msg = PARSE_GUIDANCE
            parsed["tool_error"] = [f"Parser error: {e}"[:300]]

        return ToolResult(
            tool=self.name,
            command=f"msfconsole -q -r <resource_script>\n# RC content:\n{rc_content}",
            raw_stdout=raw.stdout[:50000],
            raw_stderr=raw.stderr[:5000],
            parsed=parsed,
            success=success,
            elapsed_seconds=raw.elapsed_seconds,
            error_message=error_msg,
            timestamp=datetime.utcnow(),
        )

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
from modules.tool_invocation.tools.base_tool import BaseTool
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

        msfconsole = params.get("msfconsole_path", "msfconsole")
        cmd = [msfconsole, "-q", "-r", rc_path]

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
            error_msg = f"Metasploit timed out after {self.timeout}s"
        elif raw.returncode == -2:
            error_msg = raw.stderr

        try:
            parsed = self.parser.parse(raw.stdout, raw.stderr)
            if parsed.get("exploit_success"):
                success = True
        except Exception as e:
            if error_msg is None:
                error_msg = f"Parser error: {e}"

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

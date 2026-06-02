"""
MetasploitParser - parses msfconsole text output from resource script execution.
"""
from __future__ import annotations

import re
from modules.tool_invocation.parsers.base_parser import BaseOutputParser


class MetasploitParser(BaseOutputParser):
    def parse(self, stdout: str, stderr: str = "") -> dict:
        result = {
            "exploit_success": False,
            "session_opened": False,
            "session_type": None,
            "shell_output": [],
            "error_messages": [],
            "module_used": None,
            "target_info": None,
            "raw_summary": "",
        }

        if not stdout.strip():
            return result

        lines = stdout.splitlines()

        for line in lines:
            line_stripped = line.strip()

            # Session opened
            if re.search(r"meterpreter session \d+ opened", line_stripped, re.IGNORECASE):
                result["session_opened"] = True
                result["exploit_success"] = True
                result["session_type"] = "meterpreter"
            elif re.search(r"command shell session \d+ opened", line_stripped, re.IGNORECASE):
                result["session_opened"] = True
                result["exploit_success"] = True
                result["session_type"] = "shell"

            # Exploit result
            if re.search(r"\[\+\].*exploit.*complet", line_stripped, re.IGNORECASE):
                result["exploit_success"] = True
            elif re.search(r"\[-\].*exploit.*fail", line_stripped, re.IGNORECASE):
                result["exploit_success"] = False

            # Error messages
            if line_stripped.startswith("[-]") or "error" in line_stripped.lower():
                result["error_messages"].append(line_stripped[:200])

            # Shell output (lines after session open)
            if result["session_opened"] and line_stripped and not line_stripped.startswith("msf"):
                result["shell_output"].append(line_stripped[:200])

            # Module used
            if re.search(r"using module", line_stripped, re.IGNORECASE) or "exploit/" in line_stripped:
                m = re.search(r"(exploit/\S+|auxiliary/\S+|post/\S+)", line_stripped)
                if m:
                    result["module_used"] = m.group(1)

        result["raw_summary"] = "\n".join(lines[-30:])
        return result

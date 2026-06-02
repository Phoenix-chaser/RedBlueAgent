"""
MetasploitParamInterpreter - builds an msfconsole resource (.rc) script body
from LLM params. Output side lives in parsers/metasploit_parser.py.

Unlike the other tools, msfconsole is driven by a resource script rather than
a flat argv, so this interpreter returns the .rc text; the tool writes it to a
temp file and runs `msfconsole -q -r <file>`.
"""
from __future__ import annotations

from modules.tool_invocation.params.common import ParamError, as_bool, as_int


class MetasploitParamInterpreter:
    """Recognized params:
      module (required)  e.g. exploit/unix/webapp/wp_admin_shell_upload
      rhosts (required)  target IP/host (alias: target)
      rport              target port
      payload            e.g. linux/x86/meterpreter/reverse_tcp
      lhost / lport      reverse-shell callback (lport default 4444)
      extra_options      dict of additional `set KEY VALUE` options
    Returns the resource-script text (newline-terminated).
    """

    def build(self, params: dict) -> str:
        module = str(params.get("module", "")).strip().strip("'\"")
        rhosts = str(params.get("rhosts") or params.get("target") or "").strip()
        if not module:
            raise ParamError("metasploit requires a 'module' (e.g. exploit/.../name)")
        if not rhosts:
            raise ParamError("metasploit requires 'rhosts' (target IP/host)")

        lines = [f"use {module}", f"set RHOSTS {rhosts}"]

        if rport := params.get("rport"):
            lines.append(f"set RPORT {as_int(rport, name='rport', lo=1, hi=65535)}")
        if payload := params.get("payload"):
            lines.append(f"set payload {str(payload).strip()}")
        if lhost := params.get("lhost"):
            lines.append(f"set LHOST {str(lhost).strip()}")

        lines.append(f"set LPORT {as_int(params.get('lport', 4444), name='lport', lo=1, hi=65535)}")

        extra = params.get("extra_options") or {}
        if isinstance(extra, dict):
            for key, val in extra.items():
                lines.append(f"set {str(key).strip()} {str(val).strip()}")

        lines += ["run", "exit -y"]
        return "\n".join(lines) + "\n"

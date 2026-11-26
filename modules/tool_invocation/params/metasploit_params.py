"""
MetasploitParamInterpreter - builds an msfconsole resource (.rc) script body
from LLM params. Output side lives in parsers/metasploit_parser.py.

Unlike the other tools, msfconsole is driven by a resource script rather than
a flat argv, so this interpreter returns the .rc text; the tool writes it to a
temp file and runs `msfconsole -q -r <file>`.
"""
from __future__ import annotations

import re

from modules.tool_invocation.params.common import ParamError, as_bool, as_int

# Options that own a dedicated param above. extra_options may never set them:
# a later `set RHOSTS ...` would silently replace the value that passed the
# scope check.
_RESERVED_OPTIONS = {"rhosts", "rhost", "lhost", "lport", "rport", "payload"}
_OPTION_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_MAX_OPTION_VALUE = 500


class MetasploitParamInterpreter:
    """Recognized params:
      module (required)  e.g. exploit/unix/webapp/wp_admin_shell_upload
      rhosts (required)  target IP/host (alias: target)
      rport              target port
      payload            e.g. linux/x86/meterpreter/reverse_tcp
      lhost / lport      reverse-shell callback (lport default 4444)
      extra_options      dict of additional `set KEY VALUE` module options
    Returns the resource-script text (newline-terminated).

    The text becomes an msfconsole script, so every value must be a single
    line: a newline inside a value would inject further console commands.
    """

    def build(self, params: dict) -> str:
        module = self._one_line(params.get("module"), "module").strip("'\"")
        rhosts = self._one_line(params.get("rhosts") or params.get("target"), "rhosts")
        if not module:
            raise ParamError("metasploit requires a 'module' (e.g. exploit/.../name)")
        if not rhosts:
            raise ParamError("metasploit requires an 'rhosts' (target IP/host)")

        lines = [f"use {module}", f"set RHOSTS {rhosts}"]

        if rport := params.get("rport"):
            lines.append(f"set RPORT {as_int(rport, name='rport', lo=1, hi=65535)}")
        if payload := params.get("payload"):
            lines.append(f"set payload {self._one_line(payload, 'payload')}")
        if lhost := params.get("lhost"):
            lines.append(f"set LHOST {self._one_line(lhost, 'lhost')}")

        lines.append(f"set LPORT {as_int(params.get('lport', 4444), name='lport', lo=1, hi=65535)}")

        extra = params.get("extra_options") or {}
        if not isinstance(extra, dict):
            raise ParamError("'extra_options' must be an object of {OPTION: value}")
        for key, val in extra.items():
            name = str(key).strip()
            if not _OPTION_NAME.match(name):
                raise ParamError(f"extra_options key {key!r} is not a valid option name")
            if name.lower() in _RESERVED_OPTIONS:
                raise ParamError(
                    f"extra_options cannot override {name}; pass it as its own param")
            lines.append(f"set {name} {self._one_line(val, f'extra_options.{name}')}")

        lines += ["run", "exit -y"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _one_line(value, name: str) -> str:
        text = "" if value is None else str(value).strip()
        if not text:
            return ""
        if len(text) > _MAX_OPTION_VALUE or any(ch in text for ch in "\r\n\x00"):
            raise ParamError(f"'{name}' must be a single line without control characters")
        return text

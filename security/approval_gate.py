"""
DangerousOperationApprovalGate - interactive or policy-based approval for
high-impact operations like running exploit modules.
"""
from __future__ import annotations

import os
import re
from typing import Any


# Operations that always require explicit human approval
ALWAYS_REQUIRE_APPROVAL = [
    (r"metasploit", r"exploit/"),
    (r"sqlmap", r"--os-shell"),
    (r"sqlmap", r"--file-write"),
    (r"nmap", r"--script.*(exploit|brute|dos)"),
]

# Operations that are dangerous but can be auto-approved via config
AUTO_APPROVABLE = [
    (r"sqlmap", r"--level=[3-5]"),
    (r"metasploit", r"auxiliary/"),
]


class DangerousOperationApprovalGate:
    """
    Gate for dangerous penetration testing operations.

    In interactive mode: prompts the user via stdin.
    In automated mode: follows the auto_approve_scans_only policy.
    """

    def __init__(self, require_approval: bool = True, interactive: bool = True):
        self.require_approval = require_approval
        self.interactive = interactive

    def is_dangerous(self, action: Any) -> bool:
        tool = (getattr(action, "tool", "") or "").lower()
        params_str = str(getattr(action, "params", {}))
        cmd = getattr(action, "_cmd_str", "")
        combined = f"{tool} {params_str} {cmd}".lower()

        for tool_pattern, op_pattern in ALWAYS_REQUIRE_APPROVAL:
            if re.search(tool_pattern, combined) and re.search(op_pattern, combined):
                return True
        return False

    def request_approval(self, action: Any) -> bool:
        if not self.require_approval:
            return True

        tool = getattr(action, "tool", "unknown")
        params = getattr(action, "params", {})

        if self.interactive:
            print(f"\n[!] DANGEROUS OPERATION REQUESTED")
            print(f"    Tool   : {tool}")
            print(f"    Params : {params}")
            answer = input("    Approve? [y/N]: ").strip().lower()
            return answer in ("y", "yes")
        else:
            # Non-interactive: deny by default
            return False

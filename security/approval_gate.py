"""
DangerousOperationApprovalGate - policy-based approval for
high-impact operations like running exploit modules.

Policies:
- interactive:       prompt on stdin (default for CLI runs on a TTY)
- reject:            deny dangerous operations headless, no prompting
- auto-approve-scan: auto-approve scan-flavored dangerous ops (nmap
                     brute/auth script scans), deny destructive ones headless
- file:              park a request under <approvals_dir>/<sid>/pending/<id>.json
                     and poll <approvals_dir>/<sid>/decisions/<id>.json for the
                     answer; default deny on timeout

Policy source priority: constructor arg > env SECURITY_APPROVAL_POLICY >
config security.approval_policy > auto (interactive on TTY, reject headless).

Which operations count as dangerous comes from guardrails.yaml
(`dangerous_operations`, `scan_flavored_exempt`) via GuardrailEngine; without
a policy file the built-in lists below apply.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Operations that always require explicit human approval (policy-independent;
# the auto-approve-scan policy cannot clear these unless they are scan-flavored)
ALWAYS_REQUIRE_APPROVAL = [
    (r"metasploit", r"exploit/"),
    (r"sqlmap", r"--os-shell"),
    (r"sqlmap", r"--file-write"),
    (r"nmap", r"--script.*(exploit|brute|dos)"),
]

VALID_POLICIES = ("interactive", "reject", "auto-approve-scan", "file")

# nmap scripts whose name contains one of these keywords — and neither "dos"
# nor "exploit" — are scan-flavored: auto-approve-scan may clear them.
DEFAULT_SCAN_FLAVORED = ("brute", "auth", "discovery")


def _scan_flavored_keywords(entries) -> tuple[str, ...]:
    """Read the "tool:keyword" list of a policy file; fall back to the default."""
    keywords = tuple(
        entry.split(":", 1)[1] for entry in entries or []
        if isinstance(entry, str) and ":" in entry and entry.split(":", 1)[0] == "nmap")
    return keywords or DEFAULT_SCAN_FLAVORED


class DangerousOperationApprovalGate:
    """
    Gate for dangerous penetration testing operations.

    In interactive mode: prompts the user via stdin.
    In automated modes: follows the configured policy (see module docstring).
    """

    def __init__(
        self,
        require_approval: bool = True,
        interactive: bool = True,
        policy: str | None = None,
        approvals_dir: str = "data/approvals",
        poll_timeout: float = 300.0,
        poll_interval: float = 2.0,
        dangerous_patterns: list[tuple[str, str]] | None = None,
        scan_flavored: list[str] | None = None,
    ):
        if policy is None:
            policy = "interactive" if interactive else "reject"
        if policy not in VALID_POLICIES:
            raise ValueError(
                f"Unknown approval policy {policy!r}; expected one of {VALID_POLICIES}"
            )
        self.require_approval = require_approval
        self.policy = policy
        self.approvals_dir = Path(approvals_dir)
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval
        self._session_id = "session"
        self._request_counter = 0
        # (tool_pattern, op_pattern) regex pairs. An absent or empty policy falls
        # back to the built-in list: an empty file must not disable the gate.
        self.dangerous_patterns = [tuple(p) for p in dangerous_patterns or []] or ALWAYS_REQUIRE_APPROVAL
        self.scan_flavored = _scan_flavored_keywords(scan_flavored)

    def set_session(self, session_id: str) -> None:
        """Give the gate the session id (names the file-mode request dirs)."""
        if session_id:
            self._session_id = session_id

    def is_dangerous(self, action: Any, command: str = "") -> bool:
        """Decide whether an action needs explicit human approval.

        `command` is the text the tool would execute (ToolInvoker.preview). The
        patterns are matched against it too, so a flag the interpreter builds —
        "--os-shell" from {"os_shell": true} — is seen even though it never
        appears in the model's raw params.
        """
        tool = (getattr(action, "tool", "") or "").lower()
        params = getattr(action, "params", {}) or {}
        combined = f"{tool} {params} {command}".lower()

        for tool_pattern, op_pattern in self.dangerous_patterns:
            if re.search(tool_pattern, combined) and re.search(op_pattern, combined):
                return True

        # Fallback for callers that have no built command: the params dict
        # carries structured values, so {"scripts": "ssh-brute"} never contains
        # the text "--script". "scripts" is the key nmap's interpreter reads.
        if tool == "nmap" and re.search(r"(exploit|brute|dos)", self._nmap_scripts(params)):
            return True
        return False

    @staticmethod
    def _nmap_scripts(params: dict) -> str:
        scripts = params.get("scripts", "") or ""
        if isinstance(scripts, (list, tuple, set)):
            scripts = ",".join(str(s) for s in scripts)
        return str(scripts).lower()

    def _is_scan_flavored(self, action: Any) -> bool:
        """Scan-flavored dangerous op: nmap brute/auth script scans.

        Destructive operations (metasploit exploits, sqlmap shells,
        file writes, DoS scripts) are never scan-flavored and stay gated.
        """
        tool = (getattr(action, "tool", "") or "").lower()
        params = getattr(action, "params", {}) or {}
        if tool != "nmap":
            return False
        script = self._nmap_scripts(params)
        if not script:
            return False
        return (
            any(keyword in script for keyword in self.scan_flavored)
            and not any(x in script for x in ("dos", "exploit"))
        )

    def request_approval(self, action: Any) -> bool:
        if not self.require_approval:
            return True

        if self.policy == "auto-approve-scan":
            return self._is_scan_flavored(action)
        if self.policy == "reject":
            return False
        if self.policy == "file":
            return self._request_via_file(action)

        # interactive
        tool = getattr(action, "tool", "unknown")
        params = getattr(action, "params", {})
        print(f"\n[!] DANGEROUS OPERATION REQUESTED")
        print(f"    Tool   : {tool}")
        print(f"    Params : {params}")
        answer = input("    Approve? [y/N]: ").strip().lower()
        return answer in ("y", "yes")

    def _request_via_file(self, action: Any) -> bool:
        """Park a request file and poll for a decision file (default deny)."""
        self._request_counter += 1
        req_id = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{self._request_counter}"

        session_dir = self.approvals_dir / self._session_id
        pending_dir = session_dir / "pending"
        decisions_dir = session_dir / "decisions"
        pending_dir.mkdir(parents=True, exist_ok=True)
        decisions_dir.mkdir(parents=True, exist_ok=True)

        request_file = pending_dir / f"{req_id}.json"
        request_file.write_text(
            json.dumps(
                {
                    "id": req_id,
                    "session_id": self._session_id,
                    "tool": getattr(action, "tool", None),
                    "params": getattr(action, "params", {}),
                    "created_at": datetime.utcnow().isoformat(),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        decision_file = decisions_dir / f"{req_id}.json"
        print(f"[ApprovalGate] 危险操作等待审批: {request_file}")
        print(
            f"[ApprovalGate] 应答示例: "
            f"echo '{{\"id\": \"{req_id}\", \"approved\": true}}' > {decision_file}"
        )

        deadline = time.monotonic() + self.poll_timeout
        while time.monotonic() < deadline:
            if decision_file.exists():
                try:
                    decision = json.loads(decision_file.read_text(encoding="utf-8"))
                    return bool(decision.get("approved"))
                except (json.JSONDecodeError, OSError):
                    pass  # torn/partial write — keep polling until timeout
            time.sleep(self.poll_interval)

        print(
            f"[ApprovalGate] 审批超时（{self.poll_timeout}s），默认拒绝: {request_file}"
        )
        return False

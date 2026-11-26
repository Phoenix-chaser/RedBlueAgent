"""
SecurityBoundaryController - cross-cutting guard for all tool invocations.
Every action passes through scope validation and dangerous-op approval.
"""
from __future__ import annotations

from collections.abc import Sequence

from modules.context_management.state_schema import ActionDecision, PentestState
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.scope_validator import TargetScopeValidator


# Params that may carry a target host/URL. dirsearch and sqlmap pass their
# destination via "url", metasploit via "rhosts" (alias "target"), and nmap
# accepts "host" and "ip" as aliases of "target"; every alias an interpreter
# reads must be listed here, or an out-of-scope host can ride one of them.
TARGET_PARAM_KEYS = ("target", "url", "host", "ip", "rhosts")

# Why the last validate() call failed: "SCOPE_VIOLATION", "APPROVAL_DENIED",
# or None when the action was allowed.
SCOPE_VIOLATION = "SCOPE_VIOLATION"
APPROVAL_DENIED = "APPROVAL_DENIED"


class SecurityBoundaryController:
    def __init__(
        self,
        scope_validator: TargetScopeValidator | None = None,
        approval_gate: DangerousOperationApprovalGate | None = None,
        audit_logger: AuditLogger | None = None,
        target_param_keys: Sequence[str] | None = None,
    ):
        self.scope_validator = scope_validator or TargetScopeValidator()
        self.approval_gate = approval_gate or DangerousOperationApprovalGate()
        self.audit_logger = audit_logger or AuditLogger()
        self.last_violation: str | None = None
        # Which params carry a target. The built-in list already covers every
        # alias the interpreters read; a policy file may add to it.
        self.target_param_keys = tuple(target_param_keys) if target_param_keys else TARGET_PARAM_KEYS

    def setup(self, session_id: str, target: str, scope: list[str]) -> None:
        # File-mode approval gates name their request dirs after the session
        set_session = getattr(self.approval_gate, "set_session", None)
        if callable(set_session):
            set_session(session_id)
        self.audit_logger.log_session_start(session_id, target, scope)

    def validate(
        self, action: ActionDecision, state: PentestState, command: str = ""
    ) -> bool:
        """Scope-check the action, then gate dangerous operations.

        `command` is the text the tool would execute (ToolInvoker.preview);
        pass it so the approval gate judges the built command line. The reason
        a rejected action failed is left in `last_violation`.
        """
        self.last_violation = None
        # 1. Scope check — validate EVERY target-bearing param; only fall back
        #    to the engagement target when the action carries none of them.
        targets = []
        for key in self.target_param_keys:
            value = str(action.params.get(key) or "").strip()
            if value:
                targets.append(value)
        if not targets:
            targets = [state.target]
        for t in targets:
            if not self.scope_validator.is_in_scope(t, state.scope):
                self.audit_logger.log_violation(SCOPE_VIOLATION, action)
                self.last_violation = SCOPE_VIOLATION
                return False

        # 2. Dangerous operation check
        if self.approval_gate.is_dangerous(action, command):
            approved = self.approval_gate.request_approval(action)
            self.audit_logger.log_approval_decision(action, approved)
            self.last_violation = None if approved else APPROVAL_DENIED
            return approved

        self.audit_logger.log_allowed(action)
        return True

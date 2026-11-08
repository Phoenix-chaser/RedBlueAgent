"""
SecurityBoundaryController - cross-cutting guard for all tool invocations.
Every action passes through scope validation and dangerous-op approval.
"""
from __future__ import annotations

from modules.context_management.state_schema import ActionDecision, PentestState
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.scope_validator import TargetScopeValidator


# Params that may carry a target host/URL. dirsearch and sqlmap pass their
# destination via "url", metasploit via "rhosts" (alias "target"); every
# target-bearing param must pass scope validation.
TARGET_PARAM_KEYS = ("target", "url", "host", "rhosts")


class SecurityBoundaryController:
    def __init__(
        self,
        scope_validator: TargetScopeValidator | None = None,
        approval_gate: DangerousOperationApprovalGate | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.scope_validator = scope_validator or TargetScopeValidator()
        self.approval_gate = approval_gate or DangerousOperationApprovalGate()
        self.audit_logger = audit_logger or AuditLogger()

    def setup(self, session_id: str, target: str, scope: list[str]) -> None:
        # File-mode approval gates name their request dirs after the session
        set_session = getattr(self.approval_gate, "set_session", None)
        if callable(set_session):
            set_session(session_id)
        self.audit_logger.log_session_start(session_id, target, scope)

    def validate(self, action: ActionDecision, state: PentestState) -> bool:
        # 1. Scope check — validate EVERY target-bearing param; only fall back
        #    to the engagement target when the action carries none of them.
        targets = []
        for key in TARGET_PARAM_KEYS:
            value = str(action.params.get(key) or "").strip()
            if value:
                targets.append(value)
        if not targets:
            targets = [state.target]
        for t in targets:
            if not self.scope_validator.is_in_scope(t, state.scope):
                self.audit_logger.log_violation("SCOPE_VIOLATION", action)
                return False

        # 2. Dangerous operation check
        if self.approval_gate.is_dangerous(action):
            approved = self.approval_gate.request_approval(action)
            self.audit_logger.log_approval_decision(action, approved)
            return approved

        self.audit_logger.log_allowed(action)
        return True

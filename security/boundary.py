"""
SecurityBoundaryController - cross-cutting guard for all tool invocations.
Every action passes through scope validation and dangerous-op approval.
"""
from __future__ import annotations

from modules.context_management.state_schema import ActionDecision, PentestState
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.scope_validator import TargetScopeValidator


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
        self.audit_logger.log_session_start(session_id, target, scope)

    def validate(self, action: ActionDecision, state: PentestState) -> bool:
        # 1. Scope check
        target_from_params = action.params.get("target", "") or state.target
        if not self.scope_validator.is_in_scope(target_from_params, state.scope):
            self.audit_logger.log_violation("SCOPE_VIOLATION", action)
            return False

        # 2. Dangerous operation check
        if self.approval_gate.is_dangerous(action):
            approved = self.approval_gate.request_approval(action)
            self.audit_logger.log_approval_decision(action, approved)
            return approved

        self.audit_logger.log_allowed(action)
        return True

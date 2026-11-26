"""Unit tests for SecurityBoundaryController scope enforcement.

Regression tests for the url/rhosts blind spot: dirsearch and sqlmap pass
their destination via "url" and metasploit via "rhosts" — every
target-bearing param must be scope-checked, not just "target".
"""
import pytest
import sys
import os

from modules.context_management.state_schema import ActionDecision, PentestState
from security.approval_gate import DangerousOperationApprovalGate
from security.boundary import SecurityBoundaryController
from security.scope_validator import TargetScopeValidator


class RecordingAuditLogger:
    def __init__(self):
        self.events = []

    def log_allowed(self, action):
        self.events.append("ALLOWED")

    def log_violation(self, violation_type, action):
        self.events.append(f"VIOLATION:{violation_type}")

    def log_approval_decision(self, action, approved):
        self.events.append(f"APPROVAL:{approved}")


def make_controller() -> tuple[SecurityBoundaryController, RecordingAuditLogger]:
    audit = RecordingAuditLogger()
    controller = SecurityBoundaryController(
        scope_validator=TargetScopeValidator(),
        approval_gate=DangerousOperationApprovalGate(interactive=False),
        audit_logger=audit,
    )
    return controller, audit


def make_state() -> PentestState:
    return PentestState(target="192.168.1.100", scope=["192.168.1.100"])


def test_url_param_out_of_scope_rejected():
    controller, audit = make_controller()
    action = ActionDecision(tool="dirsearch", params={"url": "http://evil.example/"})
    assert controller.validate(action, make_state()) is False
    assert "VIOLATION:SCOPE_VIOLATION" in audit.events


def test_url_param_in_scope_allowed():
    controller, audit = make_controller()
    action = ActionDecision(tool="dirsearch", params={"url": "http://192.168.1.100:5000/"})
    assert controller.validate(action, make_state()) is True
    assert audit.events == ["ALLOWED"]


def test_sqlmap_url_to_other_host_rejected():
    """The original blind spot: sqlmap url param never reached scope validation."""
    controller, _ = make_controller()
    action = ActionDecision(
        tool="sqlmap",
        params={"url": "http://10.99.99.99/vuln.php?id=1", "level": 1, "risk": 1},
    )
    assert controller.validate(action, make_state()) is False


def test_rhosts_param_scope_checked():
    controller, _ = make_controller()
    action = ActionDecision(
        tool="metasploit",
        params={"module": "auxiliary/scanner/ssh/ssh_version", "rhosts": "10.99.99.99"},
    )
    assert controller.validate(action, make_state()) is False

    ok = ActionDecision(
        tool="metasploit",
        params={"module": "auxiliary/scanner/ssh/ssh_version", "rhosts": "192.168.1.100"},
    )
    assert controller.validate(ok, make_state()) is True


def test_target_fallback_when_no_target_params():
    """Actions without any target-bearing param fall back to the engagement target."""
    controller, audit = make_controller()
    action = ActionDecision(tool="nmap", params={"ports": "1-1000"})
    assert controller.validate(action, make_state()) is True
    assert audit.events == ["ALLOWED"]


def test_second_target_param_also_checked():
    """If one param is in scope but another is not, the action is rejected."""
    controller, _ = make_controller()
    action = ActionDecision(
        tool="nikto",
        params={"target": "192.168.1.100", "url": "http://evil.example/"},
    )
    assert controller.validate(action, make_state()) is False


def test_ip_alias_is_scope_checked():
    """nmap's interpreter reads "ip" as an alias of "target". The boundary must
    check that alias too, or an out-of-scope host can ride it."""
    controller, audit = make_controller()
    assert controller.validate(
        ActionDecision(tool="nmap", params={"ip": "10.99.99.99"}), make_state()) is False
    assert "VIOLATION:SCOPE_VIOLATION" in audit.events
    assert controller.last_violation == "SCOPE_VIOLATION"

    controller, _ = make_controller()
    assert controller.validate(
        ActionDecision(tool="nmap", params={"ip": "192.168.1.100"}), make_state()) is True
    assert controller.last_violation is None


def test_built_command_reaches_the_approval_gate():
    """validate() forwards the built command, so a flag the interpreter builds
    from structured params is judged; the reason is left in last_violation."""
    from modules.tool_invocation.invoker import ToolInvoker

    controller, audit = make_controller()  # approval policy: reject
    action = ActionDecision(
        tool="sqlmap", params={"url": "http://192.168.1.100/x?id=1", "os_shell": True})
    command = ToolInvoker().preview(action)
    assert "--os-shell" in command
    assert controller.validate(action, make_state(), command) is False
    assert audit.events == ["APPROVAL:False"]
    assert controller.last_violation == "APPROVAL_DENIED"
    # Without the built command the gate only sees "os_shell" in the params.
    assert controller.validate(action, make_state()) is True

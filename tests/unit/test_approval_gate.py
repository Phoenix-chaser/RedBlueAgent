"""Unit tests for DangerousOperationApprovalGate policies (P0-5)."""
import json
import threading
import time
import pytest
import sys
import os

from modules.context_management.state_schema import ActionDecision
from security.approval_gate import DangerousOperationApprovalGate


def msf_exploit_action():
    return ActionDecision(
        tool="metasploit", params={"module": "exploit/multi/handler", "rhosts": "127.0.0.1"}
    )


def nmap_brute_action():
    # "scripts" is the key nmap's param interpreter reads
    return ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "scripts": "ssh-brute"}
    )


def test_reject_policy_denies_headless():
    gate = DangerousOperationApprovalGate(interactive=False)
    assert gate.policy == "reject"
    assert gate.request_approval(msf_exploit_action()) is False


def test_interactive_backcompat_default():
    gate = DangerousOperationApprovalGate()
    assert gate.policy == "interactive"


def test_invalid_policy_rejected():
    with pytest.raises(ValueError):
        DangerousOperationApprovalGate(policy="yolo")


def test_require_approval_false_passes_all():
    gate = DangerousOperationApprovalGate(interactive=False, require_approval=False)
    assert gate.request_approval(msf_exploit_action()) is True


def test_auto_approve_scan_allows_brute_scans_denies_exploits():
    gate = DangerousOperationApprovalGate(policy="auto-approve-scan")
    assert gate.request_approval(nmap_brute_action()) is True
    assert gate.request_approval(msf_exploit_action()) is False
    os_shell = ActionDecision(
        tool="sqlmap", params={"url": "http://127.0.0.1/x?id=1", "os_shell": True}
    )
    assert gate.request_approval(os_shell) is False


def test_is_dangerous_patterns():
    gate = DangerousOperationApprovalGate(interactive=False)
    assert gate.is_dangerous(msf_exploit_action()) is True
    # Structured script param must be flagged (semantic check — the literal
    # "--script" regex never matched str(params) of dict values)
    assert gate.is_dangerous(nmap_brute_action()) is True
    assert gate.is_dangerous(ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "scripts": ["default", "ssh-brute"]}
    )) is True
    # Literal flag text in params still matches via the regex table
    literal_flag = ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "extra": "--script ssh-dos"}
    )
    assert gate.is_dangerous(literal_flag) is True
    plain_nmap = ActionDecision(tool="nmap", params={"target": "127.0.0.1"})
    assert gate.is_dangerous(plain_nmap) is False
    # Benign nmap scripts are not dangerous
    benign_script = ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "scripts": "http-title"}
    )
    assert gate.is_dangerous(benign_script) is False
    # "script" (singular) is ignored by the interpreter, so the command line
    # never carries it: not dangerous, and no approval prompt is needed.
    stale_key = ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "script": "ssh-brute"}
    )
    assert gate.is_dangerous(stale_key) is False


def test_built_command_reveals_flags_the_interpreter_builds():
    """The gate judges the command line, not only the model's raw params."""
    from modules.tool_invocation.invoker import ToolInvoker

    gate = DangerousOperationApprovalGate(interactive=False)
    invoker = ToolInvoker()
    # sqlmap's interpreter turns {"os_shell": true} into "--os-shell", a flag
    # that never appears in the params dict.
    os_shell = ActionDecision(
        tool="sqlmap", params={"url": "http://127.0.0.1/x?id=1", "os_shell": True}
    )
    assert gate.is_dangerous(os_shell, invoker.preview(os_shell)) is True
    plain = ActionDecision(tool="sqlmap", params={"url": "http://127.0.0.1/x?id=1"})
    assert gate.is_dangerous(plain, invoker.preview(plain)) is False


def test_auto_approve_scan_reads_the_scripts_key():
    # list form of "scripts" is classified the same as the comma-string form
    gate = DangerousOperationApprovalGate(policy="auto-approve-scan")
    assert gate.request_approval(ActionDecision(
        tool="nmap", params={"target": "127.0.0.1", "scripts": ["default", "ssh-brute"]})) is True


def test_file_mode_approved_via_decision_file(tmp_path, capsys):
    gate = DangerousOperationApprovalGate(
        policy="file", approvals_dir=str(tmp_path),
        poll_timeout=10, poll_interval=0.05,
    )
    gate.set_session("s1")

    result = {}
    worker = threading.Thread(
        target=lambda: result.__setitem__("ok", gate.request_approval(msf_exploit_action()))
    )
    worker.start()

    pending_dir = tmp_path / "s1" / "pending"
    deadline = time.monotonic() + 10
    request_file = None
    while time.monotonic() < deadline:
        files = list(pending_dir.glob("*.json")) if pending_dir.exists() else []
        if files:
            request_file = files[0]
            break
        time.sleep(0.02)
    assert request_file is not None, "request file was never parked"

    request = json.loads(request_file.read_text(encoding="utf-8"))
    assert request["tool"] == "metasploit"

    decision = tmp_path / "s1" / "decisions" / f"{request['id']}.json"
    decision.write_text(json.dumps({"id": request["id"], "approved": True}))

    worker.join(timeout=10)
    assert result.get("ok") is True
    assert "等待审批" in capsys.readouterr().out


def test_file_mode_times_out_and_denies(tmp_path):
    gate = DangerousOperationApprovalGate(
        policy="file", approvals_dir=str(tmp_path),
        poll_timeout=0.2, poll_interval=0.05,
    )
    gate.set_session("s1")
    assert gate.request_approval(msf_exploit_action()) is False


def test_file_mode_denial_via_decision_file(tmp_path):
    gate = DangerousOperationApprovalGate(
        policy="file", approvals_dir=str(tmp_path),
        poll_timeout=10, poll_interval=0.05,
    )
    gate.set_session("s1")

    result = {}
    worker = threading.Thread(
        target=lambda: result.__setitem__("ok", gate.request_approval(msf_exploit_action()))
    )
    worker.start()

    pending_dir = tmp_path / "s1" / "pending"
    deadline = time.monotonic() + 10
    request_file = None
    while time.monotonic() < deadline:
        files = list(pending_dir.glob("*.json")) if pending_dir.exists() else []
        if files:
            request_file = files[0]
            break
        time.sleep(0.02)

    request = json.loads(request_file.read_text(encoding="utf-8"))
    decision = tmp_path / "s1" / "decisions" / f"{request['id']}.json"
    decision.write_text(json.dumps({"id": request["id"], "approved": False}))

    worker.join(timeout=10)
    assert result.get("ok") is False

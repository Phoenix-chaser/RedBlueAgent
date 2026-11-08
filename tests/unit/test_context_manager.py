"""Unit tests for ContextManager state merging."""
import pytest
import sys
import os

from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    ActionDecision,
    PentestState,
    ToolResult,
    Severity,
)


def make_state() -> PentestState:
    return PentestState(target="192.168.1.100", scope=["192.168.1.100"])


def make_nmap_result() -> ToolResult:
    return ToolResult(
        tool="nmap",
        command="nmap -oX - 192.168.1.100",
        success=True,
        parsed={
            "hosts": [
                {
                    "ip": "192.168.1.100",
                    "hostname": "target.local",
                    "state": "up",
                    "os": {"name": "Linux 4.15", "accuracy": "90"},
                    "ports": [
                        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.49", "banner": None},
                        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 7.4", "banner": None},
                    ],
                }
            ],
            "total_hosts_up": 1,
            "total_ports_open": 2,
        },
    )


def test_nmap_result_merges_host():
    ctx = ContextManager()
    state = make_state()
    action = ActionDecision(type="tool", tool="nmap", params={"target": "192.168.1.100"})

    state = ctx.update(state, "Scanning target", action, make_nmap_result())

    assert len(state.hosts) == 1
    host = state.hosts[0]
    assert host.ip == "192.168.1.100"
    assert host.hostname == "target.local"
    assert len(host.services) == 2
    ports = {s.port for s in host.services}
    assert 80 in ports
    assert 22 in ports


def test_nmap_deduplicates_services():
    ctx = ContextManager()
    state = make_state()
    action = ActionDecision(type="tool", tool="nmap", params={})

    # Run twice with same data
    state = ctx.update(state, "First scan", action, make_nmap_result())
    state = ctx.update(state, "Second scan", action, make_nmap_result())

    # Should not duplicate services
    assert len(state.hosts) == 1
    assert len(state.hosts[0].services) == 2


def test_dirsearch_result_merges_paths():
    ctx = ContextManager()
    state = make_state()
    action = ActionDecision(type="tool", tool="dirsearch", params={})
    result = ToolResult(
        tool="dirsearch",
        command="dirsearch -u http://target",
        success=True,
        parsed={
            "paths": [
                {"path": "/admin", "status": 200, "size": 1234, "redirect": None},
                {"path": "/login", "status": 301, "size": 0, "redirect": None},
            ],
            "total_found": 2,
        },
    )
    state = ctx.update(state, "Dir scan", action, result)
    assert "/admin" in state.web_paths
    assert "/login" in state.web_paths


def test_sqlmap_adds_vulnerability():
    ctx = ContextManager()
    state = make_state()
    action = ActionDecision(type="tool", tool="sqlmap", params={})
    result = ToolResult(
        tool="sqlmap",
        command="sqlmap -u http://target/page?id=1",
        success=True,
        parsed={
            "injectable": True,
            "parameters": ["id"],
            "databases": ["dvwa", "mysql"],
            "raw_summary": "SQL injection found",
        },
    )
    state = ctx.update(state, "Testing SQL injection", action, result)
    assert len(state.vulnerabilities) == 1
    assert state.vulnerabilities[0].severity == Severity.CRITICAL


def test_llm_turns_recorded():
    ctx = ContextManager()
    state = make_state()
    action = ActionDecision(type="tool", tool="nmap", params={})
    obs = "Tool ran successfully"
    state = ctx.update(state, "Thinking", action, obs)
    assert len(state.llm_turns) == 1
    assert state.llm_turns[0].thought == "Thinking"


def test_state_snapshot_includes_key_info():
    ctx = ContextManager()
    state = make_state()
    state = ctx.update(state, "Scan", ActionDecision(type="tool", tool="nmap", params={}), make_nmap_result())
    snapshot = ctx.build_state_snapshot(state)
    assert "192.168.1.100" in snapshot
    assert "http" in snapshot.lower()

# -*- coding: utf-8 -*-
"""Unit tests for audit sessionization (P1-5) and attack-tree advisory
integration into the ReAct loop (P1-7)."""
from __future__ import annotations

import json
import sys
from pathlib import Path


from agent.react_loop import ReActLoop
from agent.llm_kernel import AIMessage
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    PentestState,
    PentestStage,
    Severity,
    ToolResult,
    Vulnerability,
)
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.attack_tree import AttackTree
from modules.task_planning.stage_manager import StageManager
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController


# -- P1-5: audit sessionization ------------------------------------------------


def test_audit_splits_per_session(tmp_path, capsys):
    global_log = tmp_path / "audit.log"
    logger = AuditLogger(log_file=str(global_log))
    logger.log_session_start("pre", "10.0.0.1", ["10.0.0.1"])  # pre-session

    sessions = tmp_path / "sessions"
    logger.set_session("s1", sessions)
    assert "本会话审计日志" in capsys.readouterr().out

    logger.log_allowed(type("A", (), {"tool": "nmap", "params": {}})())
    logger.log_violation("SCOPE_VIOLATION", type("A", (), {"tool": "nmap", "params": {}})())

    # Pre-session event in global file only; session events in session file only
    global_events = [json.loads(l) for l in global_log.read_text().splitlines()]
    assert [e["event"] for e in global_events] == ["SESSION_START"]

    session_file = sessions / "s1" / "audit.jsonl"
    session_events = [json.loads(l) for l in session_file.read_text().splitlines()]
    assert [e["event"] for e in session_events] == ["ALLOWED", "VIOLATION"]


# -- P1-7: attack tree advisory loop integration --------------------------------


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=self.responses.pop(0))


class FixedInvoker:
    def __init__(self, success: bool, parsed: dict | None = None):
        self.success = success
        self.parsed = parsed or {}

    def invoke(self, action):
        return ToolResult(
            tool=action.tool or "stub", command="stub", parsed=self.parsed,
            success=self.success, elapsed_seconds=0.01,
            error_message=None if self.success else "exploit failed")


def _tool_xml(tool, params):
    return (f"<thought>try</thought>"
            f'<action>{{"type":"tool","tool":"{tool}","params":{json.dumps(params)}}}</action>')


FINISH_XML = '<thought>done</thought><action>{"type":"finish"}</action>'


def make_loop(llm, invoker) -> ReActLoop:
    audit = AuditLogger(log_file="/tmp/test_attack_tree_audit.log")
    security = SecurityBoundaryController(
        approval_gate=DangerousOperationApprovalGate(interactive=False),
        audit_logger=audit)
    return ReActLoop(
        llm=llm, invoker=invoker, context_mgr=ContextManager(),
        summarizer=HierarchicalSummarizer(llm=None, keep_recent=20),
        stage_manager=StageManager(audit_logger=audit),
        security=security, rag_kb=None, context_guard=None,
        max_iterations=6, max_stage_iterations=10)


def make_exploit_state(*vulns):
    state = PentestState(
        session_id="atk", target="192.168.1.100", scope=["192.168.1.100"])
    state.current_stage = PentestStage.VULNERABILITY_EXPLOITATION
    for v in vulns:
        state.add_vulnerability(v)
    return state


def vuln(title, severity):
    return Vulnerability(
        title=title, severity=severity, affected_component="/login",
        description="auto-created test vuln",
        discovered_by_tool="nikto", evidence="found by scan")


def test_attack_plan_injected_and_success_marks_node():
    llm = ScriptedLLM([
        _tool_xml("sqlmap", {"url": "http://192.168.1.100/login?u=a"}),
        FINISH_XML,
    ])
    loop = make_loop(llm, FixedInvoker(success=True, parsed={"injectable": True}))
    state = loop.run(make_exploit_state(
        vuln("SQL Injection in /login", Severity.HIGH)))

    # Prompt carries the advisory plan with the seeded hypothesis
    assert "Attack Plan" in llm.prompts[0]
    assert "SQL Injection in /login" in llm.prompts[0]
    assert "建议优先尝试" in llm.prompts[0]
    # Successful tool run feeds back: node marked SUCCEEDED. Note the sqlmap
    # merge may register a NEW vulnerability ("SQL Injection Vulnerability"),
    # which the tree correctly seeds as a fresh pending candidate.
    nodes = loop.attack_tree.get_all_nodes()
    by_hyp = {n.hypothesis: n.status.value for n in nodes}
    assert by_hyp["SQL Injection in /login"] == "succeeded"


def test_failure_marks_node_and_backtracks_to_sibling():
    llm = ScriptedLLM([
        _tool_xml("sqlmap", {"url": "http://192.168.1.100/login?u=a"}),
        FINISH_XML,
    ])
    loop = make_loop(llm, FixedInvoker(success=False))
    state = loop.run(make_exploit_state(
        vuln("SQL Injection in /login", Severity.CRITICAL),
        vuln("Backup File Exposed", Severity.HIGH)))

    # The critical (higher-priority) node was suggested first
    assert "SQL Injection in /login" in llm.prompts[0]
    statuses = {n.hypothesis: n.status.value for n in loop.attack_tree.get_all_nodes()}
    assert statuses["SQL Injection in /login"] == "failed"
    assert statuses["Backup File Exposed"] == "pending"  # sibling untouched
    # Backtracking moved the pointer to the sibling
    assert loop._current_candidate.hypothesis == "Backup File Exposed"


def test_kb_drives_attack_plan_in_gathering_stage():
    """v0.3（[8][9]）：Attack Plan 全阶段注入——信息收集阶段由内置
    ATT&CK 知识库驱动，prompt 应含战术/技术标注与可执行动作建议。"""
    state = PentestState(session_id="atk2", target="192.168.1.100",
                         scope=["192.168.1.100"])
    state.current_stage = PentestStage.INFORMATION_GATHERING

    llm = ScriptedLLM([FINISH_XML])
    loop = make_loop(llm, FixedInvoker(success=True))
    loop.run(state)
    assert "Attack Plan" in llm.prompts[0]
    assert "T1595" in llm.prompts[0]               # ATT&CK 技术标注
    assert "nmap" in llm.prompts[0]                # 可执行动作建议


def test_exploited_vulns_not_seeded_but_kb_may_be():
    """漏洞全部已利用时不播种漏洞树；知识库候选（如后渗透数据枚举）
    仍可存在——两者来源独立。"""
    v = vuln("Already Done", Severity.HIGH)
    v.exploited = True
    state = make_exploit_state(v)
    state.current_stage = PentestStage.POST_EXPLOITATION

    llm = ScriptedLLM([FINISH_XML])
    loop = make_loop(llm, FixedInvoker(success=True))
    loop.run(state)
    nodes = {n.hypothesis for n in loop.attack_tree.get_all_nodes()}
    assert "Already Done" not in nodes             # 漏洞不播种

# -*- coding: utf-8 -*-
"""内置 ATT&CK 知识库与失败感知回退的有效性验证（paper-informed [8][9]）。

[8] Guided Reasoning（arXiv:2509.07939）：确定性任务树约束推理，中小模型
    完成率 4-5×——对应 KB 建议全阶段注入 + 战术/技术标注。
[9] RefPentester（arXiv:2505.07089）：阶段+上下文条件检索、两级回退
    （低层错退一步/高层错退两步）——对应 suggest_actions 条件过滤与
    _feedback_attack_tree 的失败类型感知。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from modules.task_planning.attack_kb import suggest_actions
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
from modules.task_planning.stage_manager import StageManager
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController


def state_with_services(stage: PentestStage) -> PentestState:
    s = PentestState(session_id="kb", target="192.168.1.100", scope=["192.168.1.100"])
    s.current_stage = stage
    s.hosts.append(type("H", (), {
        "ip": "192.168.1.100", "hostname": "", "os": "", "is_alive": True,
        "services": [type("S", (), {
            "port": 5000, "protocol": "tcp", "service": "http",
            "version": "Werkzeug", "banner": "", "state": "open",
        })()],
    })())
    s.web_paths = ["/login"]
    return s


# ── 条件检索 ─────────────────────────────────────────────────────


def test_gathering_stage_suggests_service_scan():
    s = state_with_services(PentestStage.INFORMATION_GATHERING)
    sugg = suggest_actions(s)
    assert any(x["tool"] == "nmap" and "service" in x["params"].get("scan_type", "")
               for x in sugg)
    assert all("T1" in x["technique"] or x["technique"] for x in sugg)


def test_scanning_stage_requires_web_condition():
    s = state_with_services(PentestStage.VULNERABILITY_SCANNING)
    sugg = suggest_actions(s)
    tools = {x["tool"] for x in sugg}
    assert {"nikto", "dirsearch"} <= tools          # 有 web 服务 → web 扫描建议
    blob = json.dumps([x["params"] for x in sugg])
    assert "{host}" not in blob and "{url}" not in blob and "{param_url}" not in blob


def test_no_web_service_suppresses_web_suggestions():
    s = PentestState(session_id="kb2", target="10.0.0.9", scope=["10.0.0.9"])
    s.current_stage = PentestStage.VULNERABILITY_SCANNING
    assert suggest_actions(s) == []                 # 无 web 条件 → 无建议


def test_exploit_stage_fills_param_url():
    s = state_with_services(PentestStage.VULNERABILITY_EXPLOITATION)
    sugg = suggest_actions(s)
    sqlmap = [x for x in sugg if x["tool"] == "sqlmap"]
    assert sqlmap and "id=1" in sqlmap[0]["params"]["url"]   # 参数 URL 已构造
    assert "192.168.1.100" in sqlmap[0]["params"]["url"]     # host 已填充


def test_executed_actions_are_excluded():
    s = state_with_services(PentestStage.INFORMATION_GATHERING)
    first = suggest_actions(s)
    h = hash(("nmap", json.dumps(first[0]["params"], sort_keys=True, ensure_ascii=False)))
    # 用第一条建议的实际哈希排除后再取
    all_nmap = {hash((x["tool"], json.dumps(x["params"], sort_keys=True, ensure_ascii=False)))
                for x in first}
    again = suggest_actions(s, executed_hashes=all_nmap)
    assert all(x["tool"] != "nmap" or
               hash((x["tool"], json.dumps(x["params"], sort_keys=True, ensure_ascii=False))) not in all_nmap
               for x in again)


# ── 两级回退（失败类型感知）──────────────────────────────────────


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []
    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=self.responses.pop(0))


class ResultInvoker:
    def __init__(self, error_message=None, success=False, command="nmap -p 1 t"):
        self.error_message = error_message
        self.success = success
        self.command = command
    def invoke(self, action):
        return ToolResult(tool=action.tool or "stub", command=self.command,
                          success=self.success, error_message=self.error_message,
                          elapsed_seconds=0.01)


def make_loop(llm, invoker):
    audit = AuditLogger(log_file="/tmp/test_kb_audit.log")
    return ReActLoop(
        llm=llm, invoker=invoker, context_mgr=ContextManager(),
        summarizer=HierarchicalSummarizer(llm=None),
        stage_manager=StageManager(audit_logger=audit),
        security=SecurityBoundaryController(
            approval_gate=DangerousOperationApprovalGate(interactive=False),
            audit_logger=audit),
        rag_kb=None, context_guard=None, max_iterations=4, max_stage_iterations=6)


def tool_xml(tool, params):
    return (f"<thought>go</thought>"
            f'<action>{{"type":"tool","tool":"{tool}","params":{json.dumps(params)}}}</action>')


FINISH = '<thought>done</thought><action>{"type":"finish"}</action>'


def test_low_level_failure_keeps_candidate_pending():
    """参数类错误（requires…且命令未真正执行）→ 候选保持 PENDING（退一步
    修正重试），不误杀整个技术方向。"""
    state = state_with_services(PentestStage.INFORMATION_GATHERING)
    llm = ScriptedLLM([
        tool_xml("nmap", {"target": "192.168.1.100", "scan_type": "service"}),
        FINISH,
    ])
    loop = make_loop(llm, ResultInvoker(
        error_message="nmap requires a 'target' (IP, hostname, or CIDR)",
        success=False, command="nmap"))
    loop.run(state)
    nodes = loop.attack_tree.get_all_nodes()
    kb_nodes = [n for n in nodes if n.hypothesis.startswith("T")]
    assert kb_nodes, "KB candidates never seeded"
    assert all(n.status.value == "pending" for n in kb_nodes)


def test_high_level_failure_marks_failed_and_backtracks():
    """工具真实执行但失败（命令已下发）→ FAILED + backtrack（换技术方向）。"""
    state = state_with_services(PentestStage.INFORMATION_GATHERING)
    llm = ScriptedLLM([
        tool_xml("nmap", {"target": "192.168.1.100", "scan_type": "service"}),
        FINISH,
    ])
    loop = make_loop(llm, ResultInvoker(
        error_message="scan produced no results", success=False,
        command="nmap -sV 192.168.1.100"))
    loop.run(state)
    nodes = loop.attack_tree.get_all_nodes()
    executed = [n for n in nodes if n.hypothesis.startswith("T1595.002")]
    assert executed and executed[0].status.value == "failed"

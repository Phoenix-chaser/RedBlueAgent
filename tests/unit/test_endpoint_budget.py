# -*- coding: utf-8 -*-
"""语义级端点预算（同 tool+host/path 计数拦截）——Juice Shop 实测发现的
参数微调绕过（同端点 5 连发）的回归防线。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.react_loop import ReActLoop
from agent.llm_kernel import AIMessage
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import PentestState, PentestStage
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.stage_manager import StageManager
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController

URL = "http://192.168.1.100:5000/login"


class ScriptedLLM:
    def __init__(self, n):
        self.responses = [
            '<thought>go</thought><action>{"type":"tool","tool":"sqlmap",'
            f'"params":{{"url":"{URL}?id={i}","level":{3 + i % 3},"risk":{1 + i % 3},"technique":"{"BTU"[i % 3]}"}}}}'
            f'</action>'.replace("}}}}", "}}") for i in range(n)
        ] + ['<thought>done</thought><action>{"type":"finish"}</action>']
        self.prompts = []
    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=self.responses.pop(0))


class CountingInvoker:
    def __init__(self):
        self.calls = []
    def invoke(self, action):
        self.calls.append(json.dumps(action.params, sort_keys=True))
        from modules.context_management.state_schema import ToolResult
        return ToolResult(tool=action.tool or "s", command="sqlmap", success=True,
                          elapsed_seconds=0.01)


def make_loop(llm, invoker):
    audit = AuditLogger(log_file="/tmp/test_ep_audit.log")
    return ReActLoop(
        llm=llm, invoker=invoker, context_mgr=ContextManager(),
        summarizer=HierarchicalSummarizer(llm=None),
        stage_manager=StageManager(audit_logger=audit),
        security=SecurityBoundaryController(
            approval_gate=DangerousOperationApprovalGate(interactive=False),
            audit_logger=audit),
        rag_kb=None, context_guard=None, max_iterations=10, max_stage_iterations=10)


def make_state():
    s = PentestState(session_id="ep", target="192.168.1.100", scope=["192.168.1.100"])
    s.current_stage = PentestStage.VULNERABILITY_EXPLOITATION
    return s


def test_same_endpoint_blocked_after_budget():
    """参数微调（query/level/risk/technique 各不相同）不再绕过：第 4 次
    同端点动作被 SEMANTIC_REPEAT 拦截，且提示换端点。"""
    llm = ScriptedLLM(5)
    inv = CountingInvoker()
    loop = make_loop(llm, inv)
    state = loop.run(make_state())

    # 前 3 次真实执行（阈值 MAX_SAME_ENDPOINT=3），第 4/5 次被拦
    assert len(inv.calls) == 3
    blocked = [t for t in state.llm_turns if "SEMANTIC_REPEAT_BLOCKED" in t.observation]
    assert len(blocked) == 2
    assert "换用其他已发现的端点" in blocked[0].observation


def test_different_endpoint_not_blocked():
    """不同 path 是不同端点，各自享有预算。"""
    class TwoEndpointLLM(ScriptedLLM):
        def __init__(self):
            super().__init__(0)
            self.responses = [
                f'<thought>go</thought><action>{{"type":"tool","tool":"sqlmap","params":{{"url":"http://192.168.1.100:5000/p{i}?id=1"}}}}</action>'
                for i in range(4)
            ] + ['<thought>done</thought><action>{"type":"finish"}</action>']
    inv = CountingInvoker()
    loop = make_loop(TwoEndpointLLM(), inv)
    loop.run(make_state())
    assert len(inv.calls) == 4        # 四个不同端点全部执行


def test_endpoint_budget_survives_resume():
    """端点计数从事件日志重建（resume 后预算仍然生效）。"""
    from agent.session_log import collect_endpoint_counts
    events = [
        {"seq": i, "t": "action", "d": {"action": {
            "tool": "sqlmap", "params": {"url": f"{URL}?x={i}"}}}}
        for i in range(1, 4)
    ]
    counts = collect_endpoint_counts(events)
    llm = ScriptedLLM(1)   # 再发一次同端点（不同参数）→ 应被拦
    inv = CountingInvoker()
    loop = make_loop(llm, inv)
    state = PentestState(session_id="ep2", target="192.168.1.100", scope=["192.168.1.100"])
    state.current_stage = PentestStage.VULNERABILITY_EXPLOITATION
    loop.run(state, seed_endpoint_counts=counts)
    assert len(inv.calls) == 0        # 预算已满，立即拦截
    assert any("SEMANTIC_REPEAT" in t.observation for t in state.llm_turns)

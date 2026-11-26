# -*- coding: utf-8 -*-
"""在 agent 镜像内运行，由 tests/integration/test_docker_live.py 驱动：
真实工具 × 内置靶场 × 生产主循环（ReActLoop），不调用 LLM。

模型由一段固定的动作序列代替，所以这里验证的是执行链路——真实的
nmap / nikto / dirsearch / read_url、真实的准入检查、审批门对真实命令的
判定、蜜标闭环——而不是模型的决策质量。
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agent.llm_kernel import AIMessage
from agent.react_loop import ReActLoop
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import PentestState, PentestStage
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.stage_manager import StageManager
from modules.tool_invocation.invoker import ToolInvoker
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController
from security.context_guard import ContextGuard
from security.guardrail_engine import GuardrailEngine

pytestmark = pytest.mark.skipif(
    os.environ.get("REDBLUEAGENT_IN_CONTAINER") != "1",
    reason="runs inside the agent image against the built-in range (tests/integration/test_docker_live.py)")

TARGET = os.environ.get("REDBLUEAGENT_TARGET", "http://172.20.0.10:5000")
HOST = TARGET.split("//", 1)[1].split(":", 1)[0]
HONEY_CREDENTIAL = "AKIAI44QH8DHTEXAMPLE"      # what the range's honeytoken endpoint serves


class ScriptedLLM:
    """ Plays a fixed action list through the production loop's message interface."""

    def __init__(self, actions):
        self.actions = list(actions)
        self.prompts: list[str] = []

    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        action = self.actions.pop(0) if self.actions else {"type": "finish"}
        return AIMessage(content=f"<thought>step</thought>"
                                 f"<action>{json.dumps(action)}</action>")


class RecordingInvoker:
    def __init__(self):
        self.real = ToolInvoker()
        self.calls: list[tuple] = []

    def preview(self, action):
        return self.real.preview(action)

    def invoke(self, action):
        self.calls.append((action.tool, dict(action.params or {})))
        return self.real.invoke(action)


def tool(tool_name, **params):
    return {"type": "tool", "tool": tool_name, "params": params}


def run_loop(actions, *, guard=None, honeytokens=()):
    llm, invoker = ScriptedLLM(actions), RecordingInvoker()
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLogger(log_file=str(Path(td) / "audit.log"))
        policy = Path(td) / "guardrails.yaml"
        policy.write_text(yaml.safe_dump({"honeytokens": list(honeytokens)}))
        loop = ReActLoop(
            llm=llm, invoker=invoker, context_mgr=ContextManager(),
            summarizer=HierarchicalSummarizer(llm=None),
            stage_manager=StageManager(audit_logger=audit),
            security=SecurityBoundaryController(
                approval_gate=DangerousOperationApprovalGate(interactive=False), audit_logger=audit),
            rag_kb=None, context_guard=guard, max_iterations=12, max_stage_iterations=10,
            guardrail_engine=GuardrailEngine(policy))
        state = PentestState(session_id="live", target=HOST, scope=[HOST])
        with contextlib.redirect_stdout(io.StringIO()):
            state = loop.run(state)
    return state, llm, invoker


def observations(state):
    return [t.observation for t in state.llm_turns]


def test_target_is_reachable_from_the_agent_container():
    with urllib.request.urlopen(f"{TARGET}/health", timeout=10) as response:
        assert response.status == 200 and response.read() == b"OK"


def test_real_scans_flow_through_the_production_loop():
    """nmap → nikto → dirsearch → read_url against the real range: every tool
    runs, its real output is parsed, and the page text reaches the next prompt."""
    state, llm, invoker = run_loop([
        tool("nmap", target=HOST, scan_type="host_discovery"),
        tool("nmap", target=HOST, scan_type="service", ports="5000"),
        tool("nikto", target=f"{TARGET}"),
        tool("dirsearch", url=TARGET, extensions="php,html,txt,bak,json", threads="10"),
        tool("read_url", url=f"{TARGET}/robots.txt"),
        {"type": "finish"},
    ])

    assert [name for name, _ in invoker.calls] == ["nmap", "nmap", "nikto", "dirsearch", "read_url"]
    for turn in state.llm_turns[:-1]:
        assert not turn.observation.startswith("ERROR"), turn.observation[:200]
        assert "BLOCKED" not in turn.observation and "not found" not in turn.observation.lower()
    host = next(h for h in state.hosts if h.ip == HOST)
    assert any(s.port == 5000 and s.state == "open" for s in host.services)
    assert state.web_paths, "dirsearch found no paths on the built-in range"
    # robots.txt is target-authored text; it is what the model sees next turn
    assert any("Disallow: /admin" in prompt for prompt in llm.prompts)
    assert any("HTTP 200 text/plain" in obs for obs in observations(state))


def test_scope_boundary_blocks_a_real_out_of_scope_scan():
    state, _, invoker = run_loop([
        tool("nmap", target="172.20.0.99", scan_type="service"),
        {"type": "finish"},
    ])
    assert invoker.calls == []                       # nmap never ran
    assert "BLOCKED by security boundary" in observations(state)[0]


def test_approval_gate_judges_the_real_sqlmap_command():
    state, _, invoker = run_loop([
        tool("sqlmap", url=f"{TARGET}/login?user=admin", os_shell=True),
        {"type": "finish"},
    ])
    assert invoker.calls == []                       # sqlmap never ran
    assert "APPROVAL_DENIED" in observations(state)[0]
    assert "目标不在授权范围" not in observations(state)[0]


def test_honeytoken_line_is_live_against_the_real_target():
    """read_url fetches the range's honeytoken: the visit is audited, the
    response is registered as taint, and using it is blocked."""
    audit_events = []

    class RecordingAudit:
        def log_guard_event(self, d):
            audit_events.append(d)

    class TrapDetector:
        def predict_proba(self, texts):
            return [[0.99, 0.01] for _ in texts]

    guard = ContextGuard(TrapDetector(), threshold=0.5, audit_logger=RecordingAudit())
    state, llm, invoker = run_loop([
        tool("read_url", url=f"{TARGET}/honeytoken-9f8e7d.txt"),
        tool("read_url", url=f"{TARGET}/search?q={HONEY_CREDENTIAL}"),
        {"type": "finish"},
    ], guard=guard, honeytokens=["honeytoken-"])

    assert [name for name, _ in invoker.calls] == ["read_url"]     # the second fetch never ran
    assert any(e["event"] == "HONEYTOKEN_VISIT" for e in audit_events)
    assert any("akiai44qh8dhtexample" in t for t in guard.taints)
    assert "HONEYTOKEN WARNING" in observations(state)[0]
    assert "TAINTED_ACTION_BLOCKED" in observations(state)[1]
    assert HONEY_CREDENTIAL in llm.prompts[1]                       # the page did reach the model

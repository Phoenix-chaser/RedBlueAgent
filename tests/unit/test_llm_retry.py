# -*- coding: utf-8 -*-
"""Unit tests for LLM transport resilience (P1-3).

Kernel layer: transient errors (429/5xx/network) retry with exponential
backoff; permanent errors (401/402/403) fail fast with actionable hints;
429 arms an account-level cooldown gate across invocations.
Loop layer: consecutive-failure counter injects a system note at >=2 and
aborts the loop (snapshot resumable) at MAX_CONSECUTIVE_LLM_FAILURES.
"""
from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest


import agent.llm_kernel as kernel
from agent.llm_kernel import AIMessage, HumanMessage, LLMError, MinimalLLMClient
from agent.react_loop import ReActLoop
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import PentestState
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.stage_manager import StageManager
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController

OK_BODY = {"choices": [{"message": {"content": "pong"}}]}


class FakeResponse:
    def __init__(self, body: dict):
        self._body = body

    def read(self):
        return json.dumps(self._body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code: int, body: str = "err"):
    return urllib.error.HTTPError(
        "http://llm.test", code, "err", hdrs=None, fp=io.BytesIO(body.encode()))


def make_client(**kw):
    sleeps: list[float] = []
    client = MinimalLLMClient(
        "openai", "test-model", "k",
        sleep_fn=sleeps.append, now_fn=lambda: 1000.0, **kw)
    return client, sleeps


def invoke_with(monkeypatch, side_effects, client):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        item = side_effects[calls["n"]]
        calls["n"] += 1
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(kernel.urllib.request, "urlopen", fake_urlopen)
    return client.invoke([HumanMessage(content="hi")]), calls["n"]


# -- kernel: classification & retry ------------------------------------------


def test_429_retries_then_succeeds(monkeypatch):
    client, sleeps = make_client()
    resp, n = invoke_with(
        monkeypatch,
        [http_error(429), http_error(429), FakeResponse(OK_BODY)],
        client)
    assert resp.content == "pong"
    assert n == 3
    assert sleeps == [5.0, 10.0]  # exponential backoff 5s, 10s


def test_permanent_401_fails_fast_with_hint(monkeypatch):
    client, sleeps = make_client()
    with pytest.raises(LLMError, match="API Key"):
        invoke_with(monkeypatch, [http_error(401, "bad key")], client)
    assert sleeps == []  # no retries for auth errors


def test_429_exhausted_raises_and_arms_gate(monkeypatch):
    client, sleeps = make_client()
    with pytest.raises(LLMError, match="429"):
        invoke_with(monkeypatch, [http_error(429)] * 4, client)
    assert sleeps == [5.0, 10.0, 20.0]  # 3 retries then give up

    # Gate is armed: 4 rate-limited attempts -> strikes=4 -> cooldown
    # 5*2^3=40s waits before the next invoke's first attempt
    sleeps.clear()
    with pytest.raises(LLMError):
        invoke_with(monkeypatch, [http_error(429)] * 4, client)
    assert sleeps[0] == 40.0  # gate wait precedes the first new backoff


def test_5xx_and_network_errors_retry(monkeypatch):
    client, sleeps = make_client()
    resp, n = invoke_with(
        monkeypatch,
        [http_error(503), urllib.error.URLError("connection reset"),
         FakeResponse(OK_BODY)],
        client)
    assert resp.content == "pong"
    assert n == 3
    assert sleeps == [5.0, 10.0]


def test_success_resets_gate(monkeypatch):
    client, sleeps = make_client()
    resp, _ = invoke_with(
        monkeypatch, [http_error(429), FakeResponse(OK_BODY)], client)
    assert resp.content == "pong"
    assert client._strikes == 0

    sleeps.clear()
    resp2, n2 = invoke_with(monkeypatch, [FakeResponse(OK_BODY)], client)
    assert resp2.content == "pong"
    assert n2 == 1 and sleeps == []  # no gate wait after recovery


# -- loop layer: consecutive-failure self-heal --------------------------------


class AlwaysFailingLLM:
    def __init__(self):
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        raise RuntimeError("provider exploded")


class FlakyThenDeadLLM:
    """fail, fail, succeed, then fail forever — counter must reset on success."""

    def __init__(self):
        self.script = [False, False, True]
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        if self.script and self.script.pop(0):
            return AIMessage(content="<thought>t</thought><action>{\"type\":\"finish\"}</action>")
        raise RuntimeError("boom")


def make_loop(llm) -> ReActLoop:
    audit = AuditLogger(log_file="/tmp/test_llm_retry_audit.log")
    security = SecurityBoundaryController(
        approval_gate=DangerousOperationApprovalGate(interactive=False),
        audit_logger=audit)
    return ReActLoop(
        llm=llm, invoker=None, context_mgr=ContextManager(),
        summarizer=HierarchicalSummarizer(llm=None, keep_recent=20),
        stage_manager=StageManager(audit_logger=audit),
        security=security, rag_kb=None, context_guard=None,
        max_iterations=50, max_stage_iterations=100)


def make_state():
    return PentestState(session_id="llm-retry", target="192.168.1.100",
                        scope=["192.168.1.100"])


def test_loop_aborts_after_consecutive_failures():
    llm = AlwaysFailingLLM()
    loop = make_loop(llm)
    state = loop.run(make_state())
    # Loop stopped exactly at the threshold, not after burning max_iterations
    assert llm.calls == ReActLoop.MAX_CONSECUTIVE_LLM_FAILURES
    assert len(state.llm_turns) == ReActLoop.MAX_CONSECUTIVE_LLM_FAILURES
    # From the 2nd failure on, the observation carries the system note
    assert all("系统注记" in t.observation for t in state.llm_turns[1:])
    assert "系统注记" not in state.llm_turns[0].observation


def test_loop_counter_resets_on_success():
    llm = FlakyThenDeadLLM()
    loop = make_loop(llm)
    state = loop.run(make_state())
    # fail, fail (note), succeed (finish) — the run ends via FINISH, not abort
    assert state.current_stage.value == "report_generation"
    assert len(state.llm_turns) == 3
    assert "系统注记" in state.llm_turns[1].observation

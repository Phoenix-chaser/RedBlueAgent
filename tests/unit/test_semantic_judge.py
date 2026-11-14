# -*- coding: utf-8 -*-
"""SemanticJudge（LLM-as-judge 语义累积检测）的有效性验证。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.llm_kernel import AIMessage, HumanMessage
from security.semantic_judge import SemanticJudge, JudgeResult


class FakeLLM:
    def __init__(self, verdict: dict):
        self.verdict = verdict
        self.prompts = []
    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=json.dumps(self.verdict))


ATTACK_VERDICT = {"coordinated_attack": True, "confidence": 0.85,
                  "reasoning": "gradual trust-building to override",
                  "triggering": [0, 2, 4]}
CLEAN_VERDICT = {"coordinated_attack": False, "confidence": 0.1,
                 "reasoning": "normal scan output", "triggering": []}


def test_observe_collects_subthreshold():
    """只收集阈值 40%-100% 之间的亚阈值内容。"""
    class NeverLLM:
        def invoke(self, m): raise RuntimeError("should not be called")
    j = SemanticJudge(NeverLLM(), judge_interval=100)
    j.observe("attack text", 0.45, 0.5)   # 0.45 在 [0.2, 0.5) → 收集
    j.observe("strong attack", 0.9, 0.5)  # 0.9 ≥ 0.5 → 已被隔离，不收集
    j.observe("clean text", 0.1, 0.5)     # 0.1 < 0.2 → 不收集
    assert len(j._pending) == 1


def test_judge_triggers_at_interval():
    llm = FakeLLM(ATTACK_VERDICT)
    j = SemanticJudge(llm, judge_interval=3, confidence_threshold=0.7)
    for i in range(3):
        j.observe(f"suspicious content {i}", 0.3, 0.5)
    assert j.should_judge()
    result = j.judge()
    assert result is not None
    assert result.is_coordinated_attack is True
    assert result.confidence == 0.85
    assert j._alerts == 1
    # 判定后清空
    assert len(j._pending) == 0


def test_judge_not_triggered_below_interval():
    llm = FakeLLM(ATTACK_VERDICT)
    j = SemanticJudge(llm, judge_interval=5)
    j.observe("text", 0.3, 0.5)
    assert j.should_judge() is False
    assert j.judge() is None


def test_clean_verdict_no_alert():
    llm = FakeLLM(CLEAN_VERDICT)
    j = SemanticJudge(llm, judge_interval=2, confidence_threshold=0.7)
    j.observe("a", 0.3, 0.5)
    j.observe("b", 0.3, 0.5)
    result = j.judge()
    assert result is not None
    assert result.is_coordinated_attack is False
    assert j._alerts == 0


def test_llm_failure_degrades_to_none():
    class FailingLLM:
        def invoke(self, m): raise RuntimeError("API down")
    j = SemanticJudge(FailingLLM(), judge_interval=1)
    j.observe("text", 0.3, 0.5)
    assert j.judge() is None  # 失败不阻断，返回 None


def test_prompt_contains_observations():
    llm = FakeLLM(CLEAN_VERDICT)
    j = SemanticJudge(llm, judge_interval=2)
    j.observe("first suspicious item", 0.3, 0.5)
    j.observe("second suspicious item", 0.3, 0.5)
    j.judge()
    assert "first suspicious item" in llm.prompts[0]
    assert "COORDINATED" in llm.prompts[0]  # 判定 prompt 的关键词

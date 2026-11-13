# -*- coding: utf-8 -*-
"""CHAP 式结构化 handoff 压缩（[11]）的有效性验证：压缩产物必须是
六字段协议（targets/findings/attempted/succeeded/next_hypothesis/
open_questions），退化路径同样结构化，断点恢复消费格式统一。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.llm_kernel import AIMessage, HumanMessage
from modules.context_management.state_schema import (
    ActionDecision,
    LLMTurn,
    PentestState,
    PentestStage,
)
from modules.context_management.summarizer import HANDOFF_PROMPT, HierarchicalSummarizer


def make_state(n_turns=30) -> PentestState:
    s = PentestState(session_id="chap", target="192.168.1.100", scope=["192.168.1.100"])
    s.current_stage = PentestStage.VULNERABILITY_EXPLOITATION
    for i in range(n_turns):
        s.llm_turns.append(LLMTurn(
            iteration=i + 1, thought=f"think {i}",
            action_type="tool",
            action_tool="nmap" if i % 2 == 0 else "sqlmap",
            action_params={"target": "192.168.1.100"} if i % 2 == 0 else {"url": "http://t/p"},
            observation=("ERROR: blocked" if i % 3 == 0 else "✓ 完成 Success") + f" iter{i}",
        ))
    return s


class CaptureLLM:
    def __init__(self, reply):
        self.reply = reply
        self.prompts = []
    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=self.reply)


GOOD = """## HANDOFF
### targets
- 192.168.1.100:5000 http Werkzeug
### findings
- SQLi on /login (critical)
### attempted
- sqlmap /search?q= failed: not injectable
### succeeded
- nmap service scan
### next_hypothesis
- try os-shell via login
### open_questions
- db version"""


def test_llm_compress_uses_handoff_protocol():
    llm = CaptureLLM(GOOD)
    s = HierarchicalSummarizer(llm=llm, keep_recent=5, token_budget=1).summarize_if_needed(make_state())
    # 压缩 prompt 携带协议与全部六字段
    assert "## HANDOFF" in llm.prompts[0]
    for field in ("targets", "findings", "attempted", "succeeded",
                  "next_hypothesis", "open_questions"):
        assert field in llm.prompts[0]
    # 产物结构化并保留在状态里
    assert "## HANDOFF" in s.summary_chunks[0]
    assert "### attempted" in s.summary_chunks[0]
    assert len(s.llm_turns) == 5  # keep_recent 保留


def test_non_protocol_output_is_wrapped():
    llm = CaptureLLM("- some bullet\n- another")   # 模型没按协议
    s = HierarchicalSummarizer(llm=llm, keep_recent=5, token_budget=1).summarize_if_needed(make_state())
    assert s.summary_chunks[0].startswith("## HANDOFF")


def test_fallback_compress_is_structured():
    s = HierarchicalSummarizer(llm=None, keep_recent=5,
                               token_budget=1).summarize_if_needed(make_state())
    chunk = s.summary_chunks[0]
    assert "## HANDOFF" in chunk and "### attempted" in chunk and "### succeeded" in chunk
    assert "ERROR: blocked" in chunk          # 失败原因保留
    assert "fallback compress" in chunk       # 标注退化来源


def test_multiple_chunks_accumulate():
    llm = CaptureLLM(GOOD)
    summ = HierarchicalSummarizer(llm=llm, keep_recent=5, token_budget=1)
    s = summ.summarize_if_needed(make_state())
    for i in range(10):                        # 积累新 turns 后再次触发
        s.llm_turns.append(LLMTurn(
            iteration=100 + i, thought="t", action_type="tool", action_tool="nikto",
            action_params={"target": "192.168.1.100"}, observation="✓ 完成"))
    s2 = summ.summarize_if_needed(s)
    assert len(s2.summary_chunks) >= 2

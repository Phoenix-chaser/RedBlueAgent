"""
HierarchicalSummarizer - prevents context window overflow for long test sessions.
Compresses older LLM turns using the LLM itself.

v0.3（[11] CHAP）：压缩产物为结构化 HANDOFF 协议（六字段）而非自由
bullet——把「过程性知识」（失败尝试/假设/开放问题）从对话流提炼为字段，
这正是结构化状态（hosts/vulnerabilities）覆盖不到、旧 turns 压缩时
最容易丢失的部分；协议化移交也使断点恢复后的上下文可预测。
"""
from __future__ import annotations

from modules.context_management.state_schema import LLMTurn, PentestState

HANDOFF_PROMPT = """You are handing off an in-progress penetration test to a fresh agent (context-relay protocol). \
Compress the actions below into EXACTLY this structure (English, facts only, never invent):

## HANDOFF
### targets
- one line per CONFIRMED alive host/service: host:port service version
### findings
- key vulnerabilities / credentials / sensitive paths, with evidence gist
### attempted
- actions tried that FAILED or were blocked: tool + target + why (one line each, to avoid re-treading)
### succeeded
- key actions that succeeded
### next_hypothesis
- current attack hypotheses and recommended next steps (1-3 lines)
### open_questions
- unresolved questions

Rules: preserve ALL facts (services/versions/credentials/failure reasons); \
max 8 lines per section; output ONLY this structure.
"""


class HierarchicalSummarizer:
    """
    Strategy:
    - Keep last N=20 turns verbatim (recent memory)
    - Compress older turns into structured HANDOFF chunks via LLM [11]
    - Structured state (PentestState fields) is ALWAYS preserved verbatim
    """

    def __init__(self, llm=None, keep_recent: int = 20, token_budget: int = 130_000):
        self.llm = llm
        self.keep_recent = keep_recent
        self.token_budget = token_budget

    def estimate_tokens(self, state: PentestState) -> int:
        """Rough estimate: 1 token ≈ 4 chars."""
        total_chars = sum(
            len(t.thought) + len(t.observation) + len(str(t.action_params))
            for t in state.llm_turns
        )
        total_chars += sum(len(c) for c in state.summary_chunks)
        return total_chars // 4

    def summarize_if_needed(
        self, state: PentestState, token_budget: int | None = None
    ) -> PentestState:
        budget = token_budget if token_budget is not None else self.token_budget
        estimated = self.estimate_tokens(state)
        if estimated < budget or len(state.llm_turns) <= self.keep_recent:
            return state

        turns_to_compress = state.llm_turns[: -self.keep_recent]
        if not turns_to_compress:
            return state

        chunk_summary = self._compress_turns(turns_to_compress)
        state.summary_chunks.append(chunk_summary)
        state.llm_turns = state.llm_turns[-self.keep_recent :]
        return state

    def _compress_turns(self, turns: list[LLMTurn]) -> str:
        if not turns:
            return ""

        if self.llm is None:
            # Fallback: structured text summary without LLM
            return self._simple_compress(turns)

        # Build compression prompt
        turns_text = "\n\n".join(
            f"[Iteration {t.iteration}]\n"
            f"Thought: {t.thought[:300]}\n"
            f"Action: {t.action_tool} {t.action_params}\n"
            f"Observation: {t.observation[:300]}"
            for t in turns
        )

        try:
            from agent.llm_kernel import HumanMessage
            response = self.llm.invoke(
                [HumanMessage(content=HANDOFF_PROMPT + "\n" + turns_text)])
            out = str(response.content)
            # 宽容兜底：模型若没按协议起头，包一层标记（消费端可识别）
            if "## HANDOFF" not in out:
                out = "## HANDOFF\n" + out
            return out
        except Exception:
            return self._simple_compress(turns)

    def _simple_compress(self, turns: list[LLMTurn]) -> str:
        """无 LLM 时的结构化退化：attempted/succeeded 从观察文本启发式
        推导（失败标志词），保留协议字段使消费端格式统一。"""
        attempted, succeeded = [], []
        fail_marks = ("error", "✗", "blocked", "timed out", "failed", "0 ")
        for t in turns:
            obs = (t.observation or "").lower()
            line = (f"- iter {t.iteration}: {t.action_tool or t.action_type} "
                    f"{dict(t.action_params or {}).get('url', dict(t.action_params or {}).get('target', ''))}")
            if any(m in obs for m in fail_marks):
                attempted.append(line + f" | {t.observation[:80]}")
            else:
                succeeded.append(line)
        return (
            f"## HANDOFF\n### attempted\n" + "\n".join(attempted[:12]) +
            "\n### succeeded\n" + "\n".join(succeeded[:12]) +
            f"\n### note\n- fallback compress of iterations "
            f"{turns[0].iteration}-{turns[-1].iteration} (no LLM)")

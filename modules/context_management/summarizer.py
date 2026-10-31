"""
HierarchicalSummarizer - prevents context window overflow for long test sessions.
Compresses older LLM turns using the LLM itself.
"""
from __future__ import annotations

from modules.context_management.state_schema import LLMTurn, PentestState


class HierarchicalSummarizer:
    """
    Strategy:
    - Keep last N=20 turns verbatim (recent memory)
    - Compress older turns into summary chunks via LLM
    - Structured state (PentestState fields) is ALWAYS preserved verbatim
    """

    def __init__(self, llm=None, keep_recent: int = 20):
        self.llm = llm
        self.keep_recent = keep_recent

    def estimate_tokens(self, state: PentestState) -> int:
        """Rough estimate: 1 token ≈ 4 chars."""
        total_chars = sum(
            len(t.thought) + len(t.observation) + len(str(t.action_params))
            for t in state.llm_turns
        )
        total_chars += sum(len(c) for c in state.summary_chunks)
        return total_chars // 4

    def summarize_if_needed(
        self, state: PentestState, token_budget: int = 130_000
    ) -> PentestState:
        estimated = self.estimate_tokens(state)
        if estimated < token_budget or len(state.llm_turns) <= self.keep_recent:
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

        prompt = (
            "You are a penetration testing assistant. "
            "Summarize the following penetration testing actions, "
            "preserving ALL of: discovered services and their versions, "
            "vulnerabilities found, failed attack paths, and key findings. "
            "Be concise but complete. Output as bullet points.\n\n"
            f"{turns_text}"
        )

        try:
            from agent.llm_kernel import HumanMessage
            response = self.llm.invoke([HumanMessage(content=prompt)])
            return response.content
        except Exception:
            return self._simple_compress(turns)

    def _simple_compress(self, turns: list[LLMTurn]) -> str:
        lines = [f"[Compressed summary of iterations {turns[0].iteration}-{turns[-1].iteration}]"]
        for t in turns:
            lines.append(
                f"- Iter {t.iteration}: [{t.action_tool}] {t.thought[:100]}... "
                f"-> {t.observation[:150]}"
            )
        return "\n".join(lines)

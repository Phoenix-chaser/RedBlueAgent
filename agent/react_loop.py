"""
ReActLoop - the core Think-Act-Observe engine for the penetration testing agent.
Implements the ReAct paradigm: Reason → Act → Observe → repeat.
"""
from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    ActionDecision,
    PentestState,
    PentestStage,
    ToolResult,
)
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.stage_manager import StageManager
from modules.tool_invocation.invoker import ToolInvoker
from security.boundary import SecurityBoundaryController
from agent.prompts.system_prompt import SYSTEM_PROMPT, TOOL_FORMAT_REMINDER
from agent.prompts.stage_prompts import get_stage_prompt

if TYPE_CHECKING:
    pass


class ReActLoop:
    def __init__(
        self,
        llm,
        invoker: ToolInvoker,
        context_mgr: ContextManager,
        summarizer: HierarchicalSummarizer,
        stage_manager: StageManager,
        security: SecurityBoundaryController,
        rag_kb=None,
        max_iterations: int = 200,
        max_stage_iterations: int = 30,
    ):
        self.llm = llm
        self.invoker = invoker
        self.context_mgr = context_mgr
        self.summarizer = summarizer
        self.stage_manager = stage_manager
        self.security = security
        self.rag_kb = rag_kb
        self.max_iterations = max_iterations
        self.max_stage_iterations = max_stage_iterations
        self._stage_iteration_counts: dict[str, int] = {}
        # Caches to avoid recomputing unchanged context on every iteration
        self._rag_cache: tuple[frozenset, str] = (frozenset(), "")  # (service_keys, context)

    def run(self, state: PentestState) -> PentestState:
        from rich.console import Console
        console = Console()

        for iteration in range(self.max_iterations):
            # Check if stage is stuck
            stage_key = state.current_stage.value
            self._stage_iteration_counts[stage_key] = (
                self._stage_iteration_counts.get(stage_key, 0) + 1
            )
            if self._stage_iteration_counts[stage_key] > self.max_stage_iterations:
                console.print(
                    f"[yellow]Stage '{stage_key}' exceeded {self.max_stage_iterations} iterations. "
                    f"Force-advancing.[/yellow]"
                )
                state = self.stage_manager.force_advance(state)
                self._stage_iteration_counts[state.current_stage.value] = 0

            if state.current_stage == PentestStage.FINISHED:
                break

            # ---------------------------------------------------------------
            # THINK - call the LLM
            # ---------------------------------------------------------------
            try:
                messages = self._build_messages(state)
                response = self.llm.invoke(messages)
                llm_content = response.content if hasattr(response, "content") else str(response)
            except Exception as e:
                console.print(f"[red]LLM call failed: {e}[/red]")
                # Add error turn and continue
                state = self.context_mgr.update(
                    state,
                    thought=f"LLM call failed: {e}",
                    action=ActionDecision(type="wait"),
                    observation=f"Error: {e}",
                )
                continue

            thought, action = self._parse_llm_response(llm_content)
            console.print(f"\n[bold cyan]Iteration {iteration + 1}[/bold cyan] | Stage: {state.current_stage.value}")
            console.print(f"[dim]Thought:[/dim] {thought[:200]}...")

            # ---------------------------------------------------------------
            # FINISH check
            # ---------------------------------------------------------------
            if action.type == "finish":
                console.print("[green]Agent signalled FINISH[/green]")
                state = self.context_mgr.update(state, thought, action, "Agent decided to finish.")
                state.current_stage = PentestStage.REPORT_GENERATION
                break

            # ---------------------------------------------------------------
            # ACT - validate + invoke tool
            # ---------------------------------------------------------------
            observation: ToolResult | str

            if action.type == "tool" and action.tool:
                console.print(f"[bold]Tool:[/bold] {action.tool} | Params: {action.params}")

                if not self.security.validate(action, state):
                    observation = ToolResult(
                        tool=action.tool or "unknown",
                        command="",
                        success=False,
                        error_message="BLOCKED by security boundary controller",
                    )
                    console.print(f"[red]Action BLOCKED by security[/red]")
                else:
                    observation = self.invoker.invoke(action)
                    if observation.success:
                        console.print(f"[green]✓ Tool completed in {observation.elapsed_seconds:.1f}s[/green]")
                    else:
                        console.print(f"[red]✗ Tool error: {observation.error_message}[/red]")
            else:
                observation = "No tool action taken this iteration."

            # ---------------------------------------------------------------
            # OBSERVE - update state
            # ---------------------------------------------------------------
            state = self.context_mgr.update(state, thought, action, observation)
            state = self.stage_manager.maybe_advance(state)

            # Periodic summarization
            if iteration % 10 == 9:
                state = self.summarizer.summarize_if_needed(state)

        return state

    # -----------------------------------------------------------------------
    # Prompt Construction
    # -----------------------------------------------------------------------

    def _build_messages(self, state: PentestState) -> list:
        from langchain_core.messages import SystemMessage, HumanMessage

        # System message
        system_content = SYSTEM_PROMPT

        # Build human message with all context
        parts = []

        # Compressed history summaries
        if state.summary_chunks:
            parts.append("## Compressed History\n" + "\n".join(state.summary_chunks[-3:]))

        # Current state snapshot
        parts.append(self.context_mgr.build_state_snapshot(state))

        # Stage guidance
        stage_guidance = get_stage_prompt(state.current_stage.value)
        parts.append(stage_guidance)

        # RAG context
        if self.rag_kb:
            rag_context = self._get_rag_context(state)
            if rag_context:
                parts.append(f"## Relevant Security Knowledge\n{rag_context}")

        # Recent turns (last 10 for brevity)
        if state.llm_turns:
            recent_turns = state.llm_turns[-10:]
            turns_text = "\n\n".join(
                f"[Iter {t.iteration}] Thought: {t.thought[:200]}\n"
                f"Action: {t.action_tool} {t.action_params}\n"
                f"Observation: {t.observation[:400]}"
                for t in recent_turns
            )
            parts.append(f"## Recent Actions\n{turns_text}")

        # Format reminder
        parts.append(TOOL_FORMAT_REMINDER)

        human_content = "\n\n---\n\n".join(parts)

        return [
            SystemMessage(content=system_content),
            HumanMessage(content=human_content),
        ]

    def _get_rag_context(self, state: PentestState) -> str:
        if not self.rag_kb:
            return ""
        try:
            services = state.get_open_services()[:5]
            service_keys = frozenset((s.service, s.version or "") for s in services)
            if service_keys == self._rag_cache[0]:
                return self._rag_cache[1]
            contexts = []
            for svc in services:
                docs = self.rag_kb.query_for_service(svc.service, svc.version or "")
                for doc in docs[:2]:
                    contexts.append(doc.page_content[:300])
            result = "\n".join(contexts[:500])
            self._rag_cache = (service_keys, result)
            return result
        except Exception:
            return ""

    # -----------------------------------------------------------------------
    # Response Parsing
    # -----------------------------------------------------------------------

    def _parse_llm_response(self, content: str) -> tuple[str, ActionDecision]:
        thought = ""
        action = ActionDecision(type="wait")

        # Extract <thought>
        thought_match = re.search(r"<thought>(.*?)</thought>", content, re.DOTALL | re.IGNORECASE)
        if thought_match:
            thought = thought_match.group(1).strip()

        # Extract <action>
        action_match = re.search(r"<action>(.*?)</action>", content, re.DOTALL | re.IGNORECASE)
        if action_match:
            action_json_str = action_match.group(1).strip()
            try:
                action_dict = json.loads(action_json_str)
                action_type = action_dict.get("type", "tool")
                # LLM sometimes puts tool name in "type" field instead of "tool"
                valid_types = {"tool", "finish", "wait"}
                if action_type not in valid_types:
                    action_dict.setdefault("tool", action_type)
                    action_type = "tool"
                action = ActionDecision(
                    type=action_type,
                    tool=action_dict.get("tool"),
                    params=action_dict.get("params", {}),
                    rationale=action_dict.get("rationale", ""),
                )
            except json.JSONDecodeError:
                # Try to extract type at minimum
                if "finish" in action_json_str.lower():
                    action = ActionDecision(type="finish", rationale="finish detected in malformed JSON")

        if not thought:
            thought = content[:500]

        return thought, action

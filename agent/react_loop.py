"""
ReActLoop - the core Think-Act-Observe engine for the penetration testing agent.
Implements the ReAct paradigm: Reason → Act → Observe → repeat.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    ActionDecision,
    AttackNodeStatus,
    PentestState,
    PentestStage,
    ToolResult,
)
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.attack_tree import AttackNode, AttackTree
from modules.task_planning.stage_manager import StageManager
from modules.tool_invocation.invoker import ToolInvoker
from security.boundary import SecurityBoundaryController
from agent.prompts.system_prompt import SYSTEM_PROMPT, TOOL_FORMAT_REMINDER
from agent.prompts.stage_prompts import get_stage_prompt
from utils.clip import clip_marked

if TYPE_CHECKING:
    pass


class ReActLoop:
    # LLM 连续失败达到该次数即中止循环（会话已快照，可 --session-id 恢复），
    # 防止服务故障时静默烧光迭代预算
    MAX_CONSECUTIVE_LLM_FAILURES = 5

    # attack_tree 建议制：漏洞严重度 → UCB1 优先级
    _SEVERITY_PRIORITY = {
        "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3,
    }

    # parallel 扇出的并发护栏（SPECTRE WAVE 滚动窗思想的单机版）
    PARALLEL_MAX_WORKERS = 3

    def __init__(
        self,
        llm,
        invoker: ToolInvoker,
        context_mgr: ContextManager,
        summarizer: HierarchicalSummarizer,
        stage_manager: StageManager,
        security: SecurityBoundaryController,
        rag_kb=None,
        context_guard=None,
        max_iterations: int = 200,
        max_stage_iterations: int = 30,
        attack_tree: AttackTree | None = None,
    ):
        self.llm = llm
        self.invoker = invoker
        self.context_mgr = context_mgr
        self.summarizer = summarizer
        self.stage_manager = stage_manager
        self.security = security
        self.rag_kb = rag_kb
        # 蓝队上下文守卫（RedBlueAgent 融合层）：Act→Observe 之间隔离工具输出中的
        # 提示注入载荷，防止目标内容劫持 LLM（间接注入）。None = 守卫禁用。
        self.context_guard = context_guard
        self.max_iterations = max_iterations
        self.max_stage_iterations = max_stage_iterations
        self._stage_iteration_counts: dict[str, int] = {}
        # 重复动作检测：相同 (tool, params) 直接拦截，不重复执行
        self._action_hashes: set[int] = set()
        self._llm_consecutive_failures = 0
        # 攻击树（建议制）：利用/后渗透阶段把 UCB1 排序候选注入提示词，
        # 成败回喂驱动回溯。激活原本已实现但从未接线的 AttackTree。
        self.attack_tree = attack_tree or AttackTree()
        self._current_candidate: AttackNode | None = None
        # Caches to avoid recomputing unchanged context on every iteration
        self._rag_cache: tuple[frozenset, str] = (frozenset, "")  # (service_keys, context)

    # -----------------------------------------------------------------------
    # Attack tree（建议制）
    # -----------------------------------------------------------------------

    def _sync_attack_tree(self, state: PentestState) -> None:
        """把未利用漏洞播种为根节点（按严重度给优先级），幂等。"""
        existing = {n.hypothesis for n in self.attack_tree.get_all_nodes()}
        for vuln in state.vulnerabilities:
            if vuln.exploited or vuln.title in existing:
                continue
            self.attack_tree.add_root_node(AttackNode(
                hypothesis=vuln.title,
                stage=state.current_stage.value,
                tool="",
                suggested_params={"component": vuln.affected_component},
                priority=self._SEVERITY_PRIORITY.get(vuln.severity.value, 0.4),
            ))

    def _feedback_attack_tree(self, action: ActionDecision, observation) -> None:
        """候选动作成败回喂：成功标记 SUCCEEDED，失败标记 FAILED 并回溯。"""
        cand = self._current_candidate
        if cand is None or action.type != "tool":
            return
        # 仅当 LLM 实际采纳了候选建议的工具时归因（建议制，不强制）
        if cand.tool and action.tool and cand.tool != action.tool:
            return
        if not isinstance(observation, ToolResult):
            return
        if observation.success:
            self.attack_tree.mark_node(
                cand.node_id, AttackNodeStatus.SUCCEEDED,
                evidence=(observation.error_message or "")[:200])
        else:
            self.attack_tree.mark_node(cand.node_id, AttackNodeStatus.FAILED)
            self.attack_tree.backtrack(cand.node_id)

    def run(
        self,
        state: PentestState,
        event_log=None,
        seed_action_hashes: set[int] | None = None,
    ) -> PentestState:
        from rich.console import Console
        console = Console()

        if seed_action_hashes:
            # Resume: preserve the no-repeat invariant across restarts
            self._action_hashes |= seed_action_hashes

        def _log(t: str, d: dict) -> None:
            if event_log is not None:
                event_log.append(t, d)

        def _checkpoint() -> None:
            if event_log is not None:
                event_log.checkpoint(state)

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
                prev_stage = state.current_stage.value
                state = self.stage_manager.force_advance(state)
                self._stage_iteration_counts[state.current_stage.value] = 0
                if state.current_stage.value != prev_stage:
                    _log("stage_advance", {"from": prev_stage, "to": state.current_stage.value,
                                           "iteration": state.total_iterations, "forced": True})
                    _checkpoint()

            if state.current_stage == PentestStage.FINISHED:
                break

            # ---------------------------------------------------------------
            # THINK - call the LLM
            # ---------------------------------------------------------------
            try:
                messages = self._build_messages(state)
                response = self.llm.invoke(messages)
                llm_content = response.content if hasattr(response, "content") else str(response)
                self._llm_consecutive_failures = 0
            except Exception as e:
                console.print(f"[red]LLM call failed: {e}[/red]")
                # Add error turn and continue（内核已按退避重试过）
                self._llm_consecutive_failures += 1
                fails = self._llm_consecutive_failures
                note = (
                    f" [系统注记: LLM 已连续失败 {fails} 次（内核已按退避重试）。"
                    f"若持续请检查 API 配额/网络后中止，用 --session-id 恢复。]"
                    if fails >= 2 else ""
                )
                error_thought = f"LLM call failed: {e}"
                error_action = ActionDecision(type="wait")
                error_obs = f"Error: {e}{note}"
                state = self.context_mgr.update(
                    state,
                    thought=error_thought,
                    action=error_action,
                    observation=error_obs,
                )
                _log("llm_error", {
                    "iteration": state.total_iterations,
                    "thought": error_thought,
                    "action": error_action.model_dump(),
                    "kind": "text",
                    "payload": error_obs,
                    "consecutive": fails,
                })
                if fails >= self.MAX_CONSECUTIVE_LLM_FAILURES:
                    console.print(
                        f"[red]LLM 连续失败 {fails} 次，中止循环——"
                        f"会话已快照，可用 --session-id 恢复[/red]")
                    break
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
                _log("finish", {"iterations": state.total_iterations,
                                "vulnerabilities": len(state.vulnerabilities)})
                _checkpoint()
                break

            # ---------------------------------------------------------------
            # ACT - validate + invoke tool
            # ---------------------------------------------------------------
            observation: ToolResult | str

            if action.type == "tool" and action.tool:
                console.print(f"[bold]Tool:[/bold] {action.tool} | Params: {action.params}")

                action_hash = hash((action.tool, json.dumps(action.params, sort_keys=True, ensure_ascii=False)))
                if action_hash in self._action_hashes:
                    observation = ToolResult(
                        tool=action.tool or "unknown",
                        command="",
                        success=False,
                        error_message=(
                            "REPEATED_ACTION_BLOCKED: 该命令已执行过，禁止重复。"
                            "请基于已有结果推进分析，或换用不同参数/工具。"),
                    )
                    console.print("[yellow]Repeated action blocked[/yellow]")
                elif not self.security.validate(action, state):
                    observation = ToolResult(
                        tool=action.tool or "unknown",
                        command="",
                        success=False,
                        error_message="BLOCKED by security boundary controller",
                    )
                    console.print(f"[red]Action BLOCKED by security[/red]")
                else:
                    self._action_hashes.add(action_hash)
                    # WAL 契约：动作先落账（flush+fsync）再执行副作用——
                    # 崩溃不可能丢失「已发生副作用」的记录
                    _log("action", {
                        "iteration": state.total_iterations + 1,
                        "thought": thought,
                        "action": action.model_dump(),
                    })
                    observation = self.invoker.invoke(action)
                    # 蓝队守卫：工具输出进 LLM 上下文前的隔离检查点
                    if self.context_guard is not None and isinstance(observation, ToolResult):
                        observation = self.context_guard.guard_observation(observation)
                    # 全文存档：截断发生时 LLM 仍知道原始输出去处
                    if event_log is not None and isinstance(observation, ToolResult):
                        observation.archive_path = event_log.save_tool_output(
                            observation, state.total_iterations + 1)
                    if observation.success:
                        console.print(f"[green]✓ Tool completed in {observation.elapsed_seconds:.1f}s[/green]")
                    else:
                        console.print(f"[red]✗ Tool error: {observation.error_message}[/red]")
            elif action.type == "parallel":
                # ── 并行扇出（仅限相互独立的扫描动作）────────────────────
                sub_actions: list[ActionDecision] = []
                skips: list[str] = []
                for raw in (action.params.get("actions") or []):
                    if not isinstance(raw, dict):
                        continue
                    try:
                        sub = ActionDecision(**raw)
                    except Exception:
                        continue
                    if sub.type != "tool" or not sub.tool:
                        continue
                    h = hash((sub.tool, json.dumps(sub.params, sort_keys=True, ensure_ascii=False)))
                    if h in self._action_hashes:
                        skips.append(
                            f"[{sub.tool}] REPEATED_ACTION_BLOCKED: 该命令已执行过，"
                            f"请基于已有结果推进或换用不同参数。")
                        continue
                    # 危险动作不允许并行：审批必须逐个走，不给批量放行的口子
                    if self.security.approval_gate.is_dangerous(sub):
                        skips.append(
                            f"[{sub.tool}] 危险动作不允许并行执行，请单独发起以走审批流程。")
                        continue
                    if not self.security.validate(sub, state):
                        skips.append(f"[{sub.tool}] BLOCKED by security boundary (scope).")
                        continue
                    self._action_hashes.add(h)
                    sub_actions.append(sub)

                # WAL 契约：全部子动作先落账，再并行执行副作用
                for sub in sub_actions:
                    _log("action", {
                        "iteration": state.total_iterations + 1,
                        "thought": thought,
                        "action": sub.model_dump(),
                        "parallel": True,
                    })

                results: list[tuple[ActionDecision, ToolResult]] = []
                if sub_actions:
                    with ThreadPoolExecutor(
                        max_workers=min(self.PARALLEL_MAX_WORKERS, len(sub_actions))
                    ) as pool:
                        futures = {pool.submit(self.invoker.invoke, s): s for s in sub_actions}
                        for fut in as_completed(futures):
                            sub = futures[fut]
                            try:
                                results.append((sub, fut.result()))
                            except Exception as e:
                                results.append((sub, ToolResult(
                                    tool=sub.tool or "unknown", command="",
                                    success=False,
                                    error_message=f"parallel invoke error: {e}")))
                    # 按提交顺序回放，保证状态更新与事件日志确定性
                    order = {s.tool + json.dumps(s.params, sort_keys=True): i
                             for i, s in enumerate(sub_actions)}
                    results.sort(key=lambda r: order[r[0].tool + json.dumps(r[0].params, sort_keys=True)])

                for sub, obs in results:
                    if self.context_guard is not None:
                        obs = self.context_guard.guard_observation(obs)
                    if event_log is not None:
                        obs.archive_path = event_log.save_tool_output(
                            obs, state.total_iterations + 1)
                    state = self.context_mgr.update(state, thought, sub, obs)
                    _log("observation", {
                        "iteration": state.total_iterations,
                        "thought": thought,
                        "action": sub.model_dump(),
                        "kind": "tool_result",
                        "payload": obs.model_dump(),
                    })

                for skip_msg in skips:
                    state = self.context_mgr.update(
                        state, thought, ActionDecision(type="wait"), skip_msg)
                    _log("observation", {
                        "iteration": state.total_iterations,
                        "thought": thought,
                        "action": {"type": "wait"},
                        "kind": "text",
                        "payload": skip_msg,
                    })

                console.print(
                    f"[cyan]Parallel batch: {len(results)} executed, "
                    f"{len(skips)} skipped[/cyan]")

                if not results and not skips:
                    # 诚实回执：空批次不是静默成功
                    note = ("Parallel batch was empty: no valid sub-actions "
                            "provided. Use 2-3 independent scan actions.")
                    state = self.context_mgr.update(
                        state, thought, ActionDecision(type="wait"), note)
                    _log("observation", {
                        "iteration": state.total_iterations,
                        "thought": thought,
                        "action": {"type": "wait"},
                        "kind": "text",
                        "payload": note,
                    })

                # 阶段推进 + 快照（与单动作路径一致的尾部处理）
                prev_stage = state.current_stage.value
                state = self.stage_manager.maybe_advance(state)
                if state.current_stage.value != prev_stage:
                    _log("stage_advance", {"from": prev_stage, "to": state.current_stage.value,
                                           "iteration": state.total_iterations, "forced": False})
                    _checkpoint()
                continue

            else:
                observation = "No tool action taken this iteration."

            # ---------------------------------------------------------------
            # OBSERVE - update state
            # ---------------------------------------------------------------
            state = self.context_mgr.update(state, thought, action, observation)
            if isinstance(observation, ToolResult):
                obs_kind, obs_payload = "tool_result", observation.model_dump()
            else:
                obs_kind, obs_payload = "text", str(observation)
            _log("observation", {
                "iteration": state.total_iterations,
                "thought": thought,
                "action": action.model_dump(),
                "kind": obs_kind,
                "payload": obs_payload,
            })

            # 攻击树回喂：候选建议被采纳且失败 → 标记并回溯换下一个
            self._feedback_attack_tree(action, observation)

            prev_stage = state.current_stage.value
            state = self.stage_manager.maybe_advance(state)
            if state.current_stage.value != prev_stage:
                _log("stage_advance", {"from": prev_stage, "to": state.current_stage.value,
                                       "iteration": state.total_iterations, "forced": False})
                _checkpoint()

            # Periodic summarization + checkpoint
            if iteration % 10 == 9:
                state = self.summarizer.summarize_if_needed(state)
            if iteration % 20 == 19:
                _checkpoint()

        return state

    # -----------------------------------------------------------------------
    # Prompt Construction
    # -----------------------------------------------------------------------

    def _build_messages(self, state: PentestState) -> list:
        from agent.llm_kernel import SystemMessage, HumanMessage

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

        # Attack plan (advisory): 利用/后渗透阶段注入 UCB1 排序候选。
        # 建议制——LLM 保留自主性，成败结果回喂驱动回溯。
        if state.current_stage in (PentestStage.VULNERABILITY_EXPLOITATION,
                                   PentestStage.POST_EXPLOITATION):
            self._sync_attack_tree(state)
            if self.attack_tree.pending_count() > 0:
                candidate = self.attack_tree.get_next_candidate()
                if candidate is not None:
                    self._current_candidate = candidate
                    parts.append(
                        "## Attack Plan (advisory, UCB1-ordered)\n"
                        + self.attack_tree.to_prompt_summary()
                        + f"\n建议优先尝试: {candidate.hypothesis}")

        # RAG context
        if self.rag_kb:
            rag_context = self._get_rag_context(state)
            if rag_context:
                parts.append(f"## Relevant Security Knowledge\n{rag_context}")

        # Recent turns (last 10 for brevity)
        if state.llm_turns:
            recent_turns = state.llm_turns[-10:]
            turns_text = "\n\n".join(
                f"[Iter {t.iteration}] Thought: {clip_marked(t.thought, 200)}\n"
                f"Action: {t.action_tool} {t.action_params}\n"
                f"Observation: {clip_marked(t.observation, 400)}"
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
                valid_types = {"tool", "finish", "wait", "parallel"}
                if action_type not in valid_types:
                    action_dict.setdefault("tool", action_type)
                    action_type = "tool"
                params = action_dict.get("params", {}) or {}
                # parallel 宽容：actions 允许出现在顶层或 params 内（两种
                # 形状 LLM 都会写，不硬拒——AGENTS.md 枚举/形状归一原则）
                if action_type == "parallel" and "actions" in action_dict:
                    params.setdefault("actions", action_dict["actions"])
                action = ActionDecision(
                    type=action_type,
                    tool=action_dict.get("tool"),
                    params=params,
                    rationale=action_dict.get("rationale", ""),
                )
            except json.JSONDecodeError:
                # Try to extract type at minimum
                if "finish" in action_json_str.lower():
                    action = ActionDecision(type="finish", rationale="finish detected in malformed JSON")

        if not thought:
            thought = content[:500]

        return thought, action

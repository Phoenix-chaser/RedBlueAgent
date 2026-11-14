"""
PentestAgent - main orchestrator and entry point for the automated
penetration testing system.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import (
    ActionDecision,
    PentestState,
    PentestStage,
)
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.report_generation.generator import ReportGenerator
from modules.task_planning.stage_manager import StageManager
from modules.tool_invocation.invoker import ToolInvoker
from security.audit_logger import AuditLogger
from security.approval_gate import DangerousOperationApprovalGate
from security.boundary import SecurityBoundaryController
from security.scope_validator import TargetScopeValidator
from agent.react_loop import ReActLoop
from agent.session_log import (
    EventLog,
    SessionLock,
    collect_action_hashes,
    collect_endpoint_counts,
    replay_into_state,
)


class PentestAgent:
    """
    Top-level agent that wires all modules together and runs a full
    penetration test against the specified target.

    Usage:
        agent = PentestAgent()
        report = agent.run(target="192.168.1.100", scope=["192.168.1.100"])
    """

    def __init__(self, config_path: str = "config.yaml", interactive: bool = True):
        load_dotenv()

        # Load config
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file) as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {}

        self.interactive = interactive
        self._setup_components()

    def _setup_components(self) -> None:
        llm_cfg = self.config.get("llm", {})

        # Use the provider factory - supports Claude, DeepSeek, Kimi, GLM, OpenAI
        from agent.llm_factory import create_llm

        provider = os.getenv("LLM_PROVIDER") or llm_cfg.get("provider") or None
        model = os.getenv("LLM_MODEL") or llm_cfg.get("model") or None
        max_tokens = int(os.getenv("LLM_MAX_TOKENS", llm_cfg.get("max_tokens", 8192)))
        temperature = float(llm_cfg.get("temperature", 0.1))
        # base_url 覆盖：env LLM_BASE_URL > config llm.base_url > provider 默认
        # （例：智谱 Coding Plan 专用端点 https://open.bigmodel.cn/api/coding/paas/v4）
        base_url = os.getenv("LLM_BASE_URL") or llm_cfg.get("base_url") or None

        self.llm = create_llm(
            provider=provider,
            model=model or None,
            base_url=base_url,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        # RAG knowledge base (optional)
        self.rag_kb = None
        try:
            from modules.context_management.rag.knowledge_base import RAGKnowledgeBase
            rag_cfg = self.config.get("rag", {})
            kb_dir = rag_cfg.get("vector_store_dir", "data/knowledge_base/vector_store")
            if Path(kb_dir).exists():
                self.rag_kb = RAGKnowledgeBase(persist_dir=kb_dir)
            else:
                # 显式降级：RAG 不可用必须可感知，并给出可行动指引
                print(
                    f"[RAG] 知识库目录不存在（{kb_dir}），RAG 已禁用——决策将仅依赖模型自身知识。\n"
                    "  构建: python scripts/setup_knowledge_base.py\n"
                    "  关闭: 删除 config.yaml 的 rag 节即可消除本提示。"
                )
        except Exception as e:
            print(f"[RAG] 知识库加载失败，RAG 已禁用: {e}")

        # Security components
        security_cfg = self.config.get("security", {})
        audit_log = self.config.get("storage", {}).get("audit_log", "data/audit.log")

        audit_logger = AuditLogger(log_file=audit_log)
        scope_validator = TargetScopeValidator()
        # Approval policy: env SECURITY_APPROVAL_POLICY > config
        # security.approval_policy > auto (interactive on TTY, reject headless)
        approval_policy = (
            os.getenv("SECURITY_APPROVAL_POLICY")
            or security_cfg.get("approval_policy")
            or None
        )
        approval_gate = DangerousOperationApprovalGate(
            require_approval=security_cfg.get("require_approval_for_exploits", True),
            interactive=self.interactive,
            policy=approval_policy,
        )
        self.security = SecurityBoundaryController(
            scope_validator=scope_validator,
            approval_gate=approval_gate,
            audit_logger=audit_logger,
        )

        # Core modules
        self.invoker = ToolInvoker()
        self.context_mgr = ContextManager()
        self.summarizer = HierarchicalSummarizer(
            llm=self.llm,
            keep_recent=self.config.get("llm", {}).get("keep_recent_turns", 20),
            token_budget=int(self.config.get("llm", {}).get("context_window_budget", 130_000)),
        )
        self.stage_manager = StageManager(audit_logger=audit_logger)
        self.report_generator = ReportGenerator(llm=self.llm)

        # Agent loop
        agent_cfg = self.config.get("agent", {})
        # 蓝队上下文守卫（可选）：加载 blueteam 检测器，隔离工具输出中的提示注入
        from security.context_guard import ContextGuard
        guard_cfg = self.config.get("context_guard", {})
        guard_strict = (
            guard_cfg.get("strict", False)
            or os.getenv("GUARD_STRICT", "").lower() in ("1", "true", "yes")
        )
        self.context_guard = None
        if guard_cfg.get("enabled", True):
            self.context_guard = ContextGuard.create(
                audit_logger=audit_logger,
                honeypot_threshold=guard_cfg.get("honeypot_threshold", 2),
                strict=guard_strict,
                use_l2=guard_cfg.get("use_l2", False))
        # Guardrail DSL 引擎 + 渐进信任管理器
        from security.guardrail_engine import GuardrailEngine
        from security.trust_manager import TrustManager
        guardrails_file = security_cfg.get("guardrails_file", "guardrails.yaml")
        self.guardrail_engine = GuardrailEngine(guardrails_file)
        self.trust_manager = TrustManager(self.guardrail_engine)

        self.react_loop = ReActLoop(
            llm=self.llm,
            invoker=self.invoker,
            context_mgr=self.context_mgr,
            summarizer=self.summarizer,
            stage_manager=self.stage_manager,
            security=self.security,
            rag_kb=self.rag_kb,
            context_guard=self.context_guard,
            max_iterations=agent_cfg.get("max_iterations", 200),
            max_stage_iterations=agent_cfg.get("max_stage_iterations", 30),
            taint_policy=security_cfg.get("taint_policy", "block"),
            honeytokens=security_cfg.get("honeytokens", []),
            semantic_judge=self._build_semantic_judge(security_cfg),
            guardrail_engine=self.guardrail_engine,
            trust_manager=self.trust_manager,
        )

    def _build_semantic_judge(self, security_cfg: dict):
        """语义累积 LLM-as-judge（可选）。config security.llm_judge: true
        启用；复用已配置的 LLM 客户端，不额外创建连接。"""
        if not security_cfg.get("llm_judge", False):
            return None
        try:
            from security.semantic_judge import SemanticJudge
            return SemanticJudge(
                self.llm,
                judge_interval=int(security_cfg.get("llm_judge_interval", 5)))
        except Exception as e:
            print(f"[SemanticJudge] 初始化失败（不阻断主流程）: {e}")
            return None

    def _sessions_dir(self) -> Path:
        return Path(self.config.get("storage", {}).get("sessions_dir", "data/sessions"))

    def run(
        self,
        target: str | None = None,
        scope: list[str] | None = None,
        session_id: str | None = None,
    ):
        """
        Run a full penetration test against the target.

        Args:
            target: IP address or hostname to test
            scope: List of in-scope IPs/CIDRs/hostnames (defaults to [target])
            session_id: Optional session ID. If a session with this id already
                has an event log on disk, the run RESUMES it (events replayed,
                snapshot restored, interrupted turn detected); otherwise a new
                session with this id is started.

        Returns:
            PentestReport dataclass
        """
        sessions_dir = self._sessions_dir()

        if session_id and (sessions_dir / session_id / "events.jsonl").exists():
            return self._resume(session_id, sessions_dir)

        if not target:
            raise ValueError("target is required for a new session (or pass an existing --session-id to resume)")

        if scope is None:
            scope = [target]

        state = PentestState(target=target, scope=scope)
        if session_id:
            state.session_id = session_id
        return self._execute(state, sessions_dir, fresh=True)

    def resume(self, session_id: str):
        """Resume an interrupted session by id (see run())."""
        return self._resume(session_id, self._sessions_dir())

    def _resume(self, session_id: str, sessions_dir: Path):
        from rich.console import Console
        console = Console()

        session_dir = sessions_dir / session_id
        log = EventLog(session_dir).open()
        events = log.read_all()

        snap = log.load_snapshot()
        if snap is not None:
            state, seq = snap
            state.session_id = session_id
        else:
            state, seq = None, 0
            for e in events:
                if e.get("t") == "start":
                    d = e.get("d") or {}
                    state = PentestState(
                        target=d.get("target", ""), scope=list(d.get("scope") or []))
                    state.session_id = session_id
                    break
        if state is None:
            log.close()
            raise FileNotFoundError(
                f"会话 {session_id} 无可恢复数据（无快照且无 start 事件）: {session_dir}")

        tail = [e for e in events if int(e.get("seq", 0)) > seq]
        state, interrupted, _ = replay_into_state(state, tail, self.context_mgr)
        # 重复动作哈希必须覆盖全量历史（含快照之前的动作），否则恢复后
        # 旧动作可被原样重跑（live test M2 发现）
        action_hashes = collect_action_hashes(events)
        console.print(
            f"[cyan]会话恢复: 重放 {len(tail)} 个事件"
            f"（快照 seq={seq}，日志 seq={log.seq}，阶段={state.current_stage.value}）[/cyan]")

        if interrupted is not None:
            # 腰斩回合：动作已落账但无观察——提示 LLM 先核对副作用再行动
            note = (
                "[系统续跑] 上一动作在进程中断前已记录，但未观察到结果。"
                "先核对该动作是否已产生副作用、结果是否可查询，再决定下一步；"
                "不要盲目重复不可逆操作。"
            )
            log.append("resume", {"note": note, "action": interrupted.get("action")})
            state = self.context_mgr.update(
                state, thought="系统续跑注记",
                action=ActionDecision(type="wait"), observation=note)

        return self._execute(
            state, sessions_dir, fresh=False, event_log=log, seed_hashes=action_hashes,
            seed_endpoints=collect_endpoint_counts(events))

    def _execute(
        self,
        state: PentestState,
        sessions_dir: Path,
        fresh: bool,
        event_log: EventLog | None = None,
        seed_hashes: set[int] | None = None,
        seed_endpoints: dict[tuple[str, str], int] | None = None,
    ):
        import signal
        from rich.console import Console
        from rich.panel import Panel

        console = Console()
        session_dir = sessions_dir / state.session_id

        # 实例锁：同一会话禁止双进程并发运行（陈旧锁自动回收）
        lock = SessionLock(session_dir / "session.lock")
        if not lock.acquire():
            lock_pid = (session_dir / "session.lock").read_text().strip()
            raise RuntimeError(
                f"会话 {state.session_id} 正在被 PID {lock_pid} 运行"
                f"（锁文件 {session_dir / 'session.lock'}）")
        log = event_log if event_log is not None else EventLog(session_dir).open()

        # SIGTERM → 走 KeyboardInterrupt 路径：快照 + 部分报告 + 释放锁
        old_term = None
        try:
            old_term = signal.getsignal(signal.SIGTERM)

            def _term_handler(signum, frame):
                raise KeyboardInterrupt()

            signal.signal(signal.SIGTERM, _term_handler)
        except ValueError:
            pass  # not the main thread — no signal handling

        try:
            console.print(Panel(
                f"[bold green]Penetration Testing Agent {'Resuming' if not fresh else 'Starting'}[/bold green]\n"
                f"Target: [cyan]{state.target}[/cyan]\n"
                f"Scope: [cyan]{', '.join(state.scope)}[/cyan]\n"
                f"Session: [dim]{state.session_id}[/dim]\n"
                f"Model: [dim]{self.llm.model}[/dim]",
                title="PentestAgent",
            ))

            # 审计日志切换到本会话文件（会话前事件留在全局文件）
            audit_set_session = getattr(self.security.audit_logger, "set_session", None)
            if callable(audit_set_session):
                audit_set_session(state.session_id, sessions_dir)
            self.security.setup(state.session_id, state.target, list(state.scope))
            if fresh:
                log.append("start", {"target": state.target, "scope": list(state.scope)})
            log.checkpoint(state)

            try:
                state = self.react_loop.run(
                    state, event_log=log, seed_action_hashes=seed_hashes,
                    seed_endpoint_counts=seed_endpoints)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted. Saving snapshot and generating partial report...[/yellow]")

            log.checkpoint(state)
            self.security.audit_logger.log_session_end(
                state.session_id, len(state.vulnerabilities))

            # Generate report
            state.current_stage = PentestStage.REPORT_GENERATION
            reports_dir = self.config.get("storage", {}).get("reports_dir", "data/reports")
            report = self.report_generator.generate(state, session_dir=reports_dir)

            console.print(Panel(
                f"[bold green]Test Complete[/bold green]\n"
                f"Vulnerabilities found: [red]{len(state.vulnerabilities)}[/red]\n"
                f"Stages completed: {', '.join(state.stages_completed)}\n"
                f"Total iterations: {state.total_iterations}\n"
                f"Report saved to: [cyan]{reports_dir}/{state.session_id}[/cyan]\n"
                f"Resume with: [dim]--session-id {state.session_id}[/dim]",
                title="Summary",
            ))

            return report
        finally:
            if old_term is not None:
                signal.signal(signal.SIGTERM, old_term)
            lock.release()
            log.close()

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
from modules.context_management.state_schema import PentestState, PentestStage
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.report_generation.generator import ReportGenerator
from modules.task_planning.stage_manager import StageManager
from modules.tool_invocation.invoker import ToolInvoker
from security.audit_logger import AuditLogger
from security.approval_gate import DangerousOperationApprovalGate
from security.boundary import SecurityBoundaryController
from security.scope_validator import TargetScopeValidator
from agent.react_loop import ReActLoop


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

        self.llm = create_llm(
            provider=provider,
            model=model or None,
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
        except Exception:
            pass  # RAG is optional

        # Security components
        security_cfg = self.config.get("security", {})
        audit_log = self.config.get("storage", {}).get("audit_log", "data/audit.log")

        audit_logger = AuditLogger(log_file=audit_log)
        scope_validator = TargetScopeValidator()
        approval_gate = DangerousOperationApprovalGate(
            require_approval=security_cfg.get("require_approval_for_exploits", True),
            interactive=self.interactive,
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
        )
        self.stage_manager = StageManager(audit_logger=audit_logger)
        self.report_generator = ReportGenerator(llm=self.llm)

        # Agent loop
        agent_cfg = self.config.get("agent", {})
        self.react_loop = ReActLoop(
            llm=self.llm,
            invoker=self.invoker,
            context_mgr=self.context_mgr,
            summarizer=self.summarizer,
            stage_manager=self.stage_manager,
            security=self.security,
            rag_kb=self.rag_kb,
            max_iterations=agent_cfg.get("max_iterations", 200),
            max_stage_iterations=agent_cfg.get("max_stage_iterations", 30),
        )

    def run(
        self,
        target: str,
        scope: list[str] | None = None,
        session_id: str | None = None,
    ):
        """
        Run a full penetration test against the target.

        Args:
            target: IP address or hostname to test
            scope: List of in-scope IPs/CIDRs/hostnames (defaults to [target])
            session_id: Optional session ID for resuming or tracking

        Returns:
            PentestReport dataclass
        """
        from rich.console import Console
        from rich.panel import Panel
        from datetime import datetime

        console = Console()

        if scope is None:
            scope = [target]

        # Initialize state
        state = PentestState(
            target=target,
            scope=scope,
        )
        if session_id:
            state.session_id = session_id

        console.print(Panel(
            f"[bold green]Penetration Testing Agent Starting[/bold green]\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Scope: [cyan]{', '.join(scope)}[/cyan]\n"
            f"Session: [dim]{state.session_id}[/dim]\n"
            f"Model: [dim]{self.llm.model}[/dim]",
            title="PentestAgent",
        ))

        # Setup security boundary
        self.security.setup(state.session_id, target, scope)

        # Save initial state
        self._save_state(state)

        # Run the ReAct loop
        try:
            state = self.react_loop.run(state)
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user. Generating partial report...[/yellow]")

        # Generate report
        state.current_stage = PentestStage.REPORT_GENERATION
        reports_dir = self.config.get("storage", {}).get("reports_dir", "data/reports")
        report = self.report_generator.generate(state, session_dir=reports_dir)

        console.print(Panel(
            f"[bold green]Test Complete[/bold green]\n"
            f"Vulnerabilities found: [red]{len(state.vulnerabilities)}[/red]\n"
            f"Stages completed: {', '.join(state.stages_completed)}\n"
            f"Total iterations: {state.total_iterations}\n"
            f"Report saved to: [cyan]{reports_dir}/{state.session_id}[/cyan]",
            title="Summary",
        ))

        return report

    def _save_state(self, state: PentestState) -> None:
        sessions_dir = Path(self.config.get("storage", {}).get("sessions_dir", "data/sessions"))
        sessions_dir.mkdir(parents=True, exist_ok=True)
        state_file = sessions_dir / f"{state.session_id}.json"
        state_file.write_text(state.model_dump_json(indent=2))

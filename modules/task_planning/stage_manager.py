"""
StageManager - Finite State Machine for the 7 penetration testing stages.
Defines advancement criteria and stage transition logic.
"""
from __future__ import annotations

from modules.context_management.state_schema import PentestStage, PentestState
from security.audit_logger import AuditLogger


# Stage advancement preconditions as callable checks
def _can_advance_to_info_gathering(state: PentestState) -> bool:
    """Target must have at least 1 alive host."""
    return bool(state.hosts) and any(h.is_alive for h in state.hosts)


def _can_advance_to_vuln_scanning(state: PentestState) -> bool:
    """At least 1 open port with an identified service."""
    return any(h.services for h in state.hosts)


def _can_advance_to_vuln_analysis(state: PentestState) -> bool:
    """All discovered web services scanned (nikto/dirsearch attempted)."""
    # Simple heuristic: web_paths populated or no web services found
    web_services = [s for s in state.get_services_by_type("http")]
    if not web_services:
        return True  # No web services, nothing to enumerate
    return bool(state.web_paths) or bool(state.vulnerabilities)


def _can_advance_to_exploitation(state: PentestState) -> bool:
    """Has findings to investigate."""
    return bool(state.vulnerabilities) or bool(state.web_paths)


def _can_advance_to_post_exploitation(state: PentestState) -> bool:
    """At least 1 exploitation attempt made."""
    exploited_count = sum(1 for v in state.vulnerabilities if v.exploited)
    return exploited_count > 0 or len(state.attack_paths) > 0


def _can_advance_to_report(state: PentestState) -> bool:
    """Always can generate report after attempting exploitation."""
    return True


STAGE_TRANSITIONS: dict[PentestStage, tuple[PentestStage, callable]] = {
    PentestStage.TARGET_CONFIRMATION: (
        PentestStage.INFORMATION_GATHERING,
        _can_advance_to_info_gathering,
    ),
    PentestStage.INFORMATION_GATHERING: (
        PentestStage.VULNERABILITY_SCANNING,
        _can_advance_to_vuln_scanning,
    ),
    PentestStage.VULNERABILITY_SCANNING: (
        PentestStage.VULNERABILITY_ANALYSIS,
        _can_advance_to_vuln_analysis,
    ),
    PentestStage.VULNERABILITY_ANALYSIS: (
        PentestStage.VULNERABILITY_EXPLOITATION,
        _can_advance_to_exploitation,
    ),
    PentestStage.VULNERABILITY_EXPLOITATION: (
        PentestStage.POST_EXPLOITATION,
        _can_advance_to_post_exploitation,
    ),
    PentestStage.POST_EXPLOITATION: (
        PentestStage.REPORT_GENERATION,
        _can_advance_to_report,
    ),
    PentestStage.REPORT_GENERATION: (
        PentestStage.FINISHED,
        lambda _: True,
    ),
}


class StageManager:
    def __init__(self, audit_logger: AuditLogger | None = None):
        self.audit_logger = audit_logger or AuditLogger()

    def _complete_and_advance(
        self, state: PentestState, current: PentestStage, next_stage: PentestStage
    ) -> None:
        if current.value not in state.stages_completed:
            state.stages_completed.append(current.value)
        state.current_stage = next_stage
        self.audit_logger.log_stage_transition(current.value, next_stage.value)

    def maybe_advance(self, state: PentestState) -> PentestState:
        current = state.current_stage
        transition = STAGE_TRANSITIONS.get(current)

        if transition is None:
            return state  # Already finished

        next_stage, condition = transition
        if condition(state):
            self._complete_and_advance(state, current, next_stage)

        return state

    def force_advance(self, state: PentestState) -> PentestState:
        current = state.current_stage
        transition = STAGE_TRANSITIONS.get(current)
        if transition:
            next_stage, _ = transition
            self._complete_and_advance(state, current, next_stage)
        return state

    def get_stage_objective(self, stage: PentestStage) -> str:
        objectives = {
            PentestStage.TARGET_CONFIRMATION: (
                "Confirm the target is alive and reachable. "
                "Use nmap with host_discovery scan type."
            ),
            PentestStage.INFORMATION_GATHERING: (
                "Identify all open ports, running services, and their versions. "
                "Use nmap with service scan. Identify web applications, databases, SSH, FTP."
            ),
            PentestStage.VULNERABILITY_SCANNING: (
                "Scan all discovered services for known vulnerabilities. "
                "Run nikto and dirsearch against web services. "
                "Check for outdated software versions against CVE database."
            ),
            PentestStage.VULNERABILITY_ANALYSIS: (
                "Analyze scan results. Cross-reference with CVE database. "
                "Prioritize exploitable vulnerabilities. "
                "Build attack hypotheses in the attack tree."
            ),
            PentestStage.VULNERABILITY_EXPLOITATION: (
                "Attempt to exploit identified vulnerabilities. "
                "Use sqlmap for SQL injection, metasploit for known exploits. "
                "Document all attempts (successful and failed)."
            ),
            PentestStage.POST_EXPLOITATION: (
                "If access obtained: gather system info, check privilege level, "
                "document evidence. If no access: summarize what was attempted."
            ),
            PentestStage.REPORT_GENERATION: (
                "Compile findings into a structured report. "
                "Signal finish when report is ready."
            ),
        }
        return objectives.get(stage, "Continue penetration testing.")

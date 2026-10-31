"""
AuditLogger - append-only structured log of all agent actions.
Every tool invocation, approval decision, and security violation is recorded.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, log_file: str = "data/audit.log"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, event_type: str, data: dict[str, Any]) -> None:
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            **data,
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def log_allowed(self, action: Any) -> None:
        self._write("ALLOWED", {
            "tool": getattr(action, "tool", None),
            "params": getattr(action, "params", {}),
        })

    def log_violation(self, violation_type: str, action: Any) -> None:
        self._write("VIOLATION", {
            "violation_type": violation_type,
            "tool": getattr(action, "tool", None),
            "params": getattr(action, "params", {}),
        })

    def log_approval_decision(self, action: Any, approved: bool) -> None:
        self._write("APPROVAL_DECISION", {
            "approved": approved,
            "tool": getattr(action, "tool", None),
            "params": getattr(action, "params", {}),
        })

    def log_guard_event(self, data: dict[str, Any]) -> None:
        """蓝队守卫事件：隔离 / 蜜罐标记（RedBlueAgent 融合层）。"""
        self._write("GUARD_EVENT", data)

    def log_stage_transition(self, from_stage: str, to_stage: str) -> None:
        self._write("STAGE_TRANSITION", {
            "from": from_stage,
            "to": to_stage,
        })

    def log_session_start(self, session_id: str, target: str, scope: list[str]) -> None:
        self._write("SESSION_START", {
            "session_id": session_id,
            "target": target,
            "scope": scope,
        })

    def log_session_end(self, session_id: str, vuln_count: int) -> None:
        self._write("SESSION_END", {
            "session_id": session_id,
            "vulnerabilities_found": vuln_count,
        })

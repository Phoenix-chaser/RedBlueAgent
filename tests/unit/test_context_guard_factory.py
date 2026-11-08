"""Unit tests for ContextGuard.create() degradation visibility (P0-3).

The guard silently passing through on model-load failure is a defense gap:
degradation must be visible (console banner + GUARD_DEGRADED audit event)
and strict mode must fail-fast.
"""
import pytest
import sys
import os

from security.context_guard import ContextGuard


class RecordingAudit:
    def __init__(self):
        self.guard_events = []

    def log_guard_event(self, data):
        self.guard_events.append(data)


def test_degradation_returns_none_but_is_visible(tmp_path, capsys):
    audit = RecordingAudit()
    guard = ContextGuard.create(audit_logger=audit, blueteam_root=tmp_path / "missing")
    assert guard is None
    # Audit trail records when the inbound defense line went down
    assert len(audit.guard_events) == 1
    assert audit.guard_events[0]["event"] == "GUARD_DEGRADED"
    assert "reason" in audit.guard_events[0]
    # Console banner is printed
    assert "守卫降级" in capsys.readouterr().out


def test_strict_mode_fails_fast(tmp_path):
    audit = RecordingAudit()
    with pytest.raises(RuntimeError, match="strict"):
        ContextGuard.create(
            audit_logger=audit, blueteam_root=tmp_path / "missing", strict=True
        )


def test_degradation_without_audit_logger_still_works(tmp_path):
    guard = ContextGuard.create(audit_logger=None, blueteam_root=tmp_path / "missing")
    assert guard is None

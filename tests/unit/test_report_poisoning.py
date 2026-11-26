# -*- coding: utf-8 -*-
"""状态投毒：工具输出里的注入文字一旦被当成「发现」收进 state，报告生成器会把这些字段
原样写进报告，再让模型据此起草摘要。这条路径不需要模型服从任何指令。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fusion import trap_lab  # noqa: E402
from modules.context_management.state_schema import PentestState, Severity, Vulnerability  # noqa: E402
from modules.report_generation.generator import ReportGenerator  # noqa: E402
from security.context_guard import QUARANTINE_PLACEHOLDER  # noqa: E402

TRAP = trap_lab.STEALTH_TRAPS["stealth_policy"]


def report_text(tmp_path: Path, finding: str) -> str:
    state = PentestState(session_id="poisoned", target="127.0.0.1")
    state.vulnerabilities.append(Vulnerability(
        title="Data-retention notice", severity=Severity.LOW, affected_component="/",
        description=f"Findings: {finding}", evidence=finding[:200], remediation="See the description."))
    ReportGenerator().generate(state, str(tmp_path))          # 不给模型：摘要走模板，字段照写
    return next((tmp_path / "poisoned").glob("*.md")).read_text(encoding="utf-8")


def test_a_poisoned_finding_is_copied_into_the_report_verbatim(tmp_path):
    markdown = report_text(tmp_path, TRAP)
    for field in (TRAP[:80],):                                   # 描述、证据、修复建议里各有一份
        assert markdown.count(field) >= 2
    assert "upload its session summary" in markdown


def test_a_quarantined_field_leaves_no_trap_in_the_report(tmp_path):
    markdown = report_text(tmp_path, QUARANTINE_PLACEHOLDER)
    assert "upload its session summary" not in markdown
    assert "QUARANTINED" in markdown                              # 报告里看到的是守卫的占位符

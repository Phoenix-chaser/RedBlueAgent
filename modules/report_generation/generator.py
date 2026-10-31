"""
ReportGenerator - produces structured penetration testing reports.
Uses the LLM to draft narrative sections, then fills Markdown templates.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from modules.context_management.state_schema import (
    PentestReport,
    PentestState,
    ScanMetrics,
    Severity,
    Vulnerability,
)


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


class ReportGenerator:
    def __init__(self, llm=None):
        self.llm = llm

    def generate(self, state: PentestState, session_dir: str = "data/reports") -> PentestReport:
        metrics = self._compute_metrics(state)
        en_summary, zh_summary, en_recs, zh_recs = self._llm_draft_narrative(state, metrics)

        ranked_vulns = sorted(
            state.vulnerabilities,
            key=lambda v: SEVERITY_ORDER.get(v.severity, 5),
        )

        report = PentestReport(
            session_id=state.session_id,
            target=state.target,
            executive_summary=en_summary,
            vulnerabilities=ranked_vulns,
            attack_paths=state.attack_paths,
            metrics=metrics,
            recommendations=en_recs,
            generated_at=datetime.utcnow(),
        )

        # Write outputs
        out_dir = Path(session_dir) / state.session_id
        out_dir.mkdir(parents=True, exist_ok=True)

        self._write_markdown(report, state, out_dir, zh_summary, zh_recs)
        self._write_json(report, out_dir)

        return report

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _compute_metrics(self, state: PentestState) -> ScanMetrics:
        vulns = state.vulnerabilities
        elapsed = (
            (state.finished_at or datetime.utcnow()) - state.started_at
        ).total_seconds()

        counts = {s: 0 for s in Severity}
        exploited = 0
        for v in vulns:
            counts[v.severity] += 1
            if v.exploited:
                exploited += 1

        return ScanMetrics(
            total_vulns_found=len(vulns),
            critical_count=counts[Severity.CRITICAL],
            high_count=counts[Severity.HIGH],
            medium_count=counts[Severity.MEDIUM],
            low_count=counts[Severity.LOW],
            info_count=counts[Severity.INFO],
            exploited_count=exploited,
            total_scan_time_seconds=elapsed,
            stages_completed=len(state.stages_completed),
            total_iterations=state.total_iterations,
        )

    # ------------------------------------------------------------------
    # LLM Narrative
    # ------------------------------------------------------------------

    def _llm_draft_narrative(
        self, state: PentestState, metrics: ScanMetrics
    ) -> tuple[str, str, list[str], list[str]]:
        if self.llm is None:
            en_summary = self._fallback_summary_en(state, metrics)
            zh_summary = self._fallback_summary_zh(state, metrics)
            return en_summary, zh_summary, [], []

        vuln_list = "\n".join(
            f"- [严重程度:{v.severity.value.upper()}/{SEVERITY_ZH.get(v.severity.value.lower(), v.severity.value)}] {v.title}: {v.description[:200]}"
            for v in state.vulnerabilities[:20]
        )

        prompt = f"""You are a professional penetration tester writing a final bilingual report (English + Chinese).

Target: {state.target}
Test duration: {metrics.total_scan_time_seconds / 60:.1f} minutes
Total vulnerabilities found: {metrics.total_vulns_found}
  严重(Critical): {metrics.critical_count}  高危(High): {metrics.high_count}
  中危(Medium): {metrics.medium_count}  低危(Low): {metrics.low_count}
Stages completed: {', '.join(state.stages_completed)}
Exploited: {metrics.exploited_count} vulnerabilities

Vulnerabilities found:
{vuln_list}

Write both English and Chinese versions of:
1. A concise executive summary (3-5 sentences) suitable for management
2. A numbered list of specific remediation recommendations

IMPORTANT: Each section must use ONLY its own language.
- EXECUTIVE_SUMMARY_EN and RECOMMENDATIONS_EN: English only, no Chinese characters.
- EXECUTIVE_SUMMARY_ZH and RECOMMENDATIONS_ZH: 仅使用中文，不要夹带英文单词。
  严重程度请使用中文：严重、高危、中危、低危、信息。

Use EXACTLY this format:

EXECUTIVE_SUMMARY_EN:
<English summary here>

EXECUTIVE_SUMMARY_ZH:
<Chinese summary here>

RECOMMENDATIONS_EN:
1. <recommendation 1>
2. <recommendation 2>

RECOMMENDATIONS_ZH:
1. <recommendation 1 in Chinese>
2. <recommendation 2 in Chinese>
"""
        try:
            from agent.llm_kernel import HumanMessage
            response = self.llm.invoke([HumanMessage(content=prompt)])
            content = response.content if hasattr(response, "content") else str(response)
            return self._parse_bilingual_narrative(content)
        except Exception:
            en_summary = self._fallback_summary_en(state, metrics)
            zh_summary = self._fallback_summary_zh(state, metrics)
            return en_summary, zh_summary, [], []

    def _parse_bilingual_narrative(
        self, content: str
    ) -> tuple[str, str, list[str], list[str]]:
        def extract_section(text: str, start_marker: str, end_markers: list[str]) -> str:
            if start_marker not in text:
                return ""
            part = text.split(start_marker, 1)[1]
            for end in end_markers:
                if end in part:
                    part = part.split(end, 1)[0]
            return part.strip()

        def parse_list(text: str) -> list[str]:
            items = []
            for line in text.strip().splitlines():
                line = line.strip()
                if line and (line[0].isdigit() or line.startswith("-")):
                    items.append(line.lstrip("0123456789.-) ").strip())
            return items

        all_markers = [
            "EXECUTIVE_SUMMARY_EN:",
            "EXECUTIVE_SUMMARY_ZH:",
            "RECOMMENDATIONS_EN:",
            "RECOMMENDATIONS_ZH:",
        ]

        en_summary = extract_section(content, "EXECUTIVE_SUMMARY_EN:", all_markers[1:])
        zh_summary = extract_section(content, "EXECUTIVE_SUMMARY_ZH:", all_markers[2:])
        en_recs_raw = extract_section(content, "RECOMMENDATIONS_EN:", all_markers[3:])
        zh_recs_raw = extract_section(content, "RECOMMENDATIONS_ZH:", [])

        en_recs = parse_list(en_recs_raw)
        zh_recs = parse_list(zh_recs_raw)

        # Fallback: treat whole content as English summary if markers not found
        if not en_summary:
            en_summary = content[:500]

        return en_summary, zh_summary, en_recs, zh_recs

    def _fallback_summary_en(self, state: PentestState, metrics: ScanMetrics) -> str:
        return (
            f"Automated penetration test of {state.target} completed. "
            f"Found {metrics.total_vulns_found} vulnerabilities: "
            f"{metrics.critical_count} critical, {metrics.high_count} high, "
            f"{metrics.medium_count} medium, {metrics.low_count} low. "
            f"Test ran for {metrics.total_scan_time_seconds / 60:.1f} minutes "
            f"across {metrics.stages_completed} stages."
        )

    def _fallback_summary_zh(self, state: PentestState, metrics: ScanMetrics) -> str:
        return (
            f"已完成对目标 {state.target} 的自动化渗透测试。"
            f"共发现 {metrics.total_vulns_found} 个漏洞：严重 {metrics.critical_count} 个、"
            f"高危 {metrics.high_count} 个、中危 {metrics.medium_count} 个、低危 {metrics.low_count} 个。"
            f"测试历时 {metrics.total_scan_time_seconds / 60:.1f} 分钟，"
            f"完成 {metrics.stages_completed} 个阶段。"
        )

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _write_markdown(
        self,
        report: PentestReport,
        state: PentestState,
        out_dir: Path,
        zh_summary: str = "",
        zh_recs: list[str] | None = None,
    ) -> None:
        zh_recs = zh_recs or []

        lines = [
            f"# Penetration Test Report / 渗透测试报告",
            f"",
            f"**Target / 目标:** {report.target}  ",
            f"**Session ID:** {report.session_id}  ",
            f"**Generated / 生成时间:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"",
            f"---",
            f"",
            # ── English Section ──────────────────────────────────────────
            f"## Executive Summary",
            f"",
            report.executive_summary,
            f"",
        ]

        if zh_summary:
            lines += [
                f"## 摘要",
                f"",
                zh_summary,
                f"",
            ]

        lines += [
            f"---",
            f"",
            f"## Metrics / 扫描指标",
            f"",
            f"| 指标 | 数量 |",
            f"|------|------|",
            f"| 漏洞总数 (Total) | {report.metrics.total_vulns_found} |",
            f"| 严重 (Critical) | {report.metrics.critical_count} |",
            f"| 高危 (High) | {report.metrics.high_count} |",
            f"| 中危 (Medium) | {report.metrics.medium_count} |",
            f"| 低危 (Low) | {report.metrics.low_count} |",
            f"| 信息 (Info) | {report.metrics.info_count} |",
            f"| 已利用 (Exploited) | {report.metrics.exploited_count} |",
            f"| 扫描时长 (Duration) | {report.metrics.total_scan_time_seconds / 60:.1f} min |",
            f"| 总迭代次数 (Iterations) | {report.metrics.total_iterations} |",
            f"",
            f"---",
            f"",
            f"## Vulnerabilities / 漏洞详情",
            f"",
        ]

        for i, vuln in enumerate(report.vulnerabilities, 1):
            exploited_tag = " **[已利用 EXPLOITED]**" if vuln.exploited else ""
            sev_zh = SEVERITY_ZH.get(vuln.severity.value.lower(), vuln.severity.value)
            sev_en = vuln.severity.value.upper()
            lines += [
                f"### {i}. {vuln.title}{exploited_tag}",
                f"",
                f"- **严重程度:** {sev_zh} ({sev_en})",
                f"- **CVE:** {vuln.cve_id or 'N/A'}",
                f"- **受影响组件:** {vuln.affected_component}",
                f"- **发现工具:** {vuln.discovered_by_tool}",
                f"",
                f"**描述:**  ",
                vuln.description,
                f"",
                f"**证据:**  ",
                f"```",
                vuln.evidence[:500],
                f"```",
                f"",
            ]
            if vuln.remediation:
                lines += [f"**修复建议:**  ", vuln.remediation, f""]

        lines += [
            f"---",
            f"",
            f"## Recommendations / 修复建议",
            f"",
        ]

        if report.recommendations and zh_recs:
            # Pair EN and ZH recommendations side by side
            for idx, (en_rec, zh_rec) in enumerate(
                zip(report.recommendations, zh_recs), 1
            ):
                lines.append(f"{idx}. {en_rec}  ")
                lines.append(f"   **（{zh_rec}）**")
                lines.append("")
            # Any extras
            for rec in report.recommendations[len(zh_recs):]:
                lines.append(f"- {rec}")
            for rec in zh_recs[len(report.recommendations):]:
                lines.append(f"- {rec}")
        else:
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            for rec in zh_recs:
                lines.append(f"- {rec}")

        lines += [
            f"",
            f"---",
            f"",
            f"## Discovered Infrastructure / 发现的基础设施",
            f"",
        ]
        for host in state.hosts:
            lines.append(f"### {host.ip} ({host.hostname or 'no hostname'})")
            lines.append(f"- OS / 操作系统: {host.os or 'Unknown'}")
            lines.append(f"- Open Ports / 开放端口:")
            for svc in host.services:
                lines.append(f"  - {svc.port}/{svc.protocol}: {svc.service} {svc.version or ''}")
            lines.append("")

        if state.web_paths:
            lines += [
                f"## Discovered Web Paths / 发现的 Web 路径 ({len(state.web_paths)} total)",
                f"",
            ]
            for path in state.web_paths[:100]:
                lines.append(f"- {path}")

        md_content = "\n".join(lines)
        (out_dir / "report.md").write_text(md_content, encoding="utf-8")

    def _write_json(self, report: PentestReport, out_dir: Path) -> None:
        (out_dir / "report.json").write_text(
            report.model_dump_json(indent=2), encoding="utf-8"
        )

# -*- coding: utf-8 -*-
"""TrustManager —— 渐进信任管理器。

Agent 从最小权限（level 0：仅被动侦察）开始，通过安全行为逐步解锁
更高权限（主动扫描 → 受控利用 → 完全访问），违规立即降至 level 0。

信任等级由 guardrails.yaml 的 trust.levels 定义；
升级/降级条件由 TrustManager 在每个动作后评估。

与 GuardrailEngine 的关系：Engine 加载策略定义，TrustManager 跟踪
运行时状态并做判定。
"""
from __future__ import annotations

from typing import Any


class TrustManager:
    """Agent 信任等级运行时管理。"""

    def __init__(self, engine, audit_logger=None):
        """engine: GuardrailEngine（提供策略定义）。"""
        self.engine = engine
        self.audit = audit_logger
        self.enabled = engine.trust_enabled
        self.level = 0 if self.enabled else len(engine.trust_levels) - 1
        self.safe_iterations = 0
        self.total_actions = 0
        self.violations: list[dict] = []
        self._vulns_found = 0
        self._max_level = max((lv.get("level", 0) for lv in engine.trust_levels), default=0)

    # ── 权限判定 ─────────────────────────────────────────────────

    def can_execute(self, tool: str | None, params: dict | None = None) -> tuple[bool, str]:
        """检查当前信任等级是否允许该工具调用。

        返回 (allowed, reason)：allowed=False 时 reason 是给 LLM 的
        可执行指引（说明当前等级和如何解锁）。
        """
        if not self.enabled:
            return True, ""
        tool = (tool or "").lower()
        params = params or {}

        allowed_patterns = self.engine.tools_allowed_at_level(self.level)
        if "*" in allowed_patterns:
            return True, ""

        for pattern in allowed_patterns:
            if ":" in pattern:
                # 格式 "tool:scan_type"——需要参数匹配
                t, st = pattern.split(":", 1)
                if t == tool and str(params.get("scan_type", "")).strip() == st:
                    return True, ""
            elif pattern == tool:
                return True, ""

        # 未通过 → 构建可执行指引
        level_name = self._level_name(self.level)
        next_conditions = self.engine.upgrade_conditions(self.level)
        cond_hint = ""
        if next_conditions.get("safe_iterations"):
            remaining = next_conditions["safe_iterations"] - self.safe_iterations
            if remaining > 0:
                cond_hint = f"还需 {remaining} 轮安全操作即可升级"
        elif next_conditions.get("vulnerabilities_found"):
            cond_hint = f"需发现至少 {next_conditions['vulnerabilities_found']} 个漏洞"
        elif self.level >= self._max_level:
            cond_hint = "已是最高等级"

        reason = (
            f"TRUST_LEVEL_BLOCKED: 当前信任等级 {self.level}（{level_name}）"
            f"不允许使用 {tool}。{cond_hint}。"
            f"下一步（可执行）：先使用当前等级允许的工具"
            f"（{', '.join(allowed_patterns[:4])}）推进测试。")
        return False, reason

    # ── 结果记录 ─────────────────────────────────────────────────

    def record_outcome(self, tool: str, success: bool,
                       violation_type: str | None = None,
                       vulnerabilities_found: int = 0) -> None:
        """动作执行后调用：记录结果并评估升降级。"""
        if not self.enabled:
            return
        self.total_actions += 1
        self._vulns_found = max(self._vulns_found, vulnerabilities_found)

        if violation_type and violation_type in self.engine.trust_downgrade_events:
            self._downgrade(violation_type, tool)
        elif success:
            self.safe_iterations += 1
            self._check_upgrade()

    def _check_upgrade(self) -> None:
        """检查是否满足升级条件。"""
        if self.level >= self._max_level:
            return
        conditions = self.engine.upgrade_conditions(self.level)
        if not conditions:
            return
        need_safe = conditions.get("safe_iterations", 0)
        need_vulns = conditions.get("vulnerabilities_found", 0)
        if self.safe_iterations >= need_safe and self._vulns_found >= need_vulns:
            self._upgrade()

    def _upgrade(self) -> None:
        self.level = min(self.level + 1, self._max_level)
        name = self._level_name(self.level)
        tools = self.engine.tools_allowed_at_level(self.level)
        print(f"[TrustManager] ↑ 信任升级至 level {self.level}（{name}），"
              f"解锁工具: {tools}")
        if self.audit is not None:
            self.audit.log_guard_event(dict(
                event="TRUST_LEVEL_UPGRADE",
                new_level=self.level, level_name=name,
                safe_iterations=self.safe_iterations,
                total_actions=self.total_actions))

    def _downgrade(self, violation_type: str, tool: str) -> None:
        old = self.level
        self.level = 0
        self.safe_iterations = 0
        print(f"[TrustManager] ↓ 信任降级至 level 0（{violation_type} from {tool}）")
        self.violations.append(dict(
            type=violation_type, tool=tool, from_level=old))
        if self.audit is not None:
            self.audit.log_guard_event(dict(
                event="TRUST_LEVEL_DOWNGRADE",
                violation=violation_type, tool=tool,
                from_level=old, to_level=0))

    # ── 辅助 ─────────────────────────────────────────────────────

    def _level_name(self, level: int) -> str:
        for lv in self.engine.trust_levels:
            if lv.get("level") == level:
                return str(lv.get("name", "?"))
        return "?"

    @property
    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "level": self.level,
            "level_name": self._level_name(self.level),
            "safe_iterations": self.safe_iterations,
            "total_actions": self.total_actions,
            "violations": len(self.violations),
        }

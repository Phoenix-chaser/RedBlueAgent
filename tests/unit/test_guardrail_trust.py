# -*- coding: utf-8 -*-
"""GuardrailEngine（声明式策略 DSL）+ TrustManager（渐进信任）的有效性验证。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from security.guardrail_engine import GuardrailEngine
from security.trust_manager import TrustManager


@pytest.fixture
def engine():
    return GuardrailEngine(Path(__file__).resolve().parents[2] / "guardrails.yaml")


@pytest.fixture
def trust_on(engine):
    """trust 启用版引擎 + 管理器。"""
    engine._policy["trust"]["enabled"] = True
    return TrustManager(engine)


class RecordingAudit:
    def __init__(self):
        self.events = []
    def log_guard_event(self, d):
        self.events.append(d)


# ── GuardrailEngine ──────────────────────────────────────────────


def test_engine_loads_guardrails_yaml(engine):
    assert engine.max_same_endpoint == 3
    assert engine.taint_policy in ("block", "warn")
    assert len(engine.dangerous_patterns) >= 4
    assert "target" in engine.target_param_keys


def test_engine_defaults_when_no_file(tmp_path):
    e = GuardrailEngine(tmp_path / "nonexistent.yaml")
    assert e.max_same_endpoint == 3
    assert e.taint_policy == "block"
    assert not e.trust_enabled


def test_engine_hot_reload(engine, tmp_path):
    """修改 YAML 后 reload() 即生效——策略从改代码变为改配置。"""
    import yaml as _yaml
    p = tmp_path / "test_guardrails.yaml"
    p.write_text(_yaml.dump({"max_same_endpoint": 7, "taint_policy": "warn"}))
    e = GuardrailEngine(p)
    assert e.max_same_endpoint == 7  # 加载了文件值
    assert e.taint_policy == "warn"
    # 写入新值后重载
    p.write_text(_yaml.dump({"max_same_endpoint": 7, "taint_policy": "warn",
                             "dangerous_operations": [], "target_param_keys": [],
                             "scan_flavored_exempt": [], "max_consecutive_llm_failures": 3,
                             "parallel_max_workers": 2, "honeytokens": [],
                             "context_guard": {}, "semantic_judge": {}, "trust": {}}))
    e.reload()
    assert e.max_same_endpoint == 7
    assert e.taint_policy == "warn"
    assert e.parallel_max_workers == 2


def test_engine_override_deep_merge(tmp_path):
    """深合并：override 只覆盖指定键，其余保留默认值。"""
    import yaml as _yaml
    p = tmp_path / "partial.yaml"
    p.write_text("max_same_endpoint: 10")
    e = GuardrailEngine(p)
    assert e.max_same_endpoint == 10  # 覆盖
    assert e.taint_policy == "block"   # 保留默认
    assert e.parallel_max_workers == 3  # 保留默认


# ── TrustManager ─────────────────────────────────────────────────


def test_trust_disabled_allows_everything(engine):
    trust = TrustManager(engine)  # engine.trust_enabled=False
    assert not trust.enabled
    for tool in ("nmap", "nikto", "dirsearch", "sqlmap", "metasploit"):
        ok, _ = trust.can_execute(tool)
        assert ok, f"{tool} should be allowed when trust disabled"


def test_trust_level0_only_host_discovery(trust_on):
    ok, _ = trust_on.can_execute("nmap", {"scan_type": "host_discovery"})
    assert ok
    for tool, params in [("nikto", {}), ("sqlmap", {}), ("nmap", {"scan_type": "service"})]:
        ok, reason = trust_on.can_execute(tool, params)
        assert not ok
        assert "TRUST_LEVEL_BLOCKED" in reason
        assert "下一步" in reason  # 可执行指引


def test_trust_upgrade_after_safe_iterations(trust_on):
    for _ in range(3):
        trust_on.record_outcome("nmap", success=True)
    assert trust_on.level == 1
    ok, _ = trust_on.can_execute("nikto")
    assert ok


def test_trust_downgrade_on_violation(trust_on):
    audit = RecordingAudit()
    trust_on.audit = audit
    for _ in range(3):
        trust_on.record_outcome("nmap", success=True)
    assert trust_on.level == 1
    trust_on.record_outcome("sqlmap", success=False, violation_type="SCOPE_VIOLATION")
    assert trust_on.level == 0
    assert trust_on.safe_iterations == 0
    assert any(e["event"] == "TRUST_LEVEL_DOWNGRADE" for e in audit.events)


def test_trust_upgrade_requires_vulnerabilities(trust_on):
    """L1→L2 需要 safe_iterations≥10 且 vulns≥1。"""
    for _ in range(10):
        trust_on.record_outcome("nikto", success=True)
    # 10 轮安全但 0 漏洞 → 仍 L1
    assert trust_on.level == 1
    # 发现 1 个漏洞 → L2
    trust_on.record_outcome("sqlmap", success=True, vulnerabilities_found=1)
    assert trust_on.level == 2
    ok, _ = trust_on.can_execute("sqlmap")
    assert ok


def test_trust_non_downgrade_event_stays(trust_on):
    """不在 downgrade_on 列表的违规不降级。"""
    for _ in range(3):
        trust_on.record_outcome("nmap", success=True)
    assert trust_on.level == 1
    trust_on.record_outcome("nikto", success=False, violation_type="SOME_OTHER_EVENT")
    assert trust_on.level == 1  # 不降级（SOME_OTHER_EVENT 不在 downgrade_on 列表）


def test_trust_guidance_mentions_current_level_tools(trust_on):
    """拦截文案包含当前等级可用工具列表——LLM 知道该用什么替代。"""
    _, reason = trust_on.can_execute("sqlmap")
    assert "nmap" in reason  # L0 允许的工具在指引中

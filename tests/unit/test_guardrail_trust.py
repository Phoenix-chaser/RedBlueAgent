# -*- coding: utf-8 -*-
"""GuardrailEngine（声明式策略 DSL）+ TrustManager（渐进信任）的有效性验证。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from security.guardrail_engine import GuardrailEngine
from security.trust_manager import TrustManager
from agent.core import PentestAgent
from modules.context_management.state_schema import ActionDecision, PentestState, ToolResult
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController
from security.context_guard import ContextGuard


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


# ── 策略文件与运行配置：优先级与接线 ─────────────────────────────────


class NullAudit:
    def log_allowed(self, action):
        pass

    def log_violation(self, violation_type, action):
        pass

    def log_approval_decision(self, action, approved):
        pass


def test_run_config_overrides_beat_the_policy_file_and_survive_reload(tmp_path):
    policy = tmp_path / "guardrails.yaml"
    policy.write_text(yaml.safe_dump({"taint_policy": "block", "honeytokens": ["from-policy/"]}))
    engine = GuardrailEngine(policy)

    engine.apply_overrides(taint_policy=None, honeytokens=[])  # nothing configured
    assert (engine.taint_policy, engine.honeytokens) == ("block", ["from-policy/"])
    engine.apply_overrides(taint_policy="warn", honeytokens=["from-config/"])
    assert (engine.taint_policy, engine.honeytokens) == ("warn", ["from-config/"])

    policy.write_text(yaml.safe_dump({"taint_policy": "block", "max_same_endpoint": 9}))
    engine.reload()
    assert (engine.taint_policy, engine.honeytokens, engine.max_same_endpoint) == (
        "warn", ["from-config/"], 9)


def test_policy_file_drives_the_gate_and_the_boundary(tmp_path):
    """dangerous_operations / target_param_keys / scan_flavored_exempt used to be
    read by nothing: the gate and the boundary matched hard-coded lists."""
    policy = tmp_path / "guardrails.yaml"
    policy.write_text(yaml.safe_dump({
        "dangerous_operations": [{"tool": "sqlmap", "op": "--dump"}],
        "target_param_keys": ["target", "destination"],
    }))
    engine = GuardrailEngine(policy)
    gate = DangerousOperationApprovalGate(
        interactive=False, dangerous_patterns=engine.dangerous_patterns)
    boundary = SecurityBoundaryController(
        approval_gate=gate, audit_logger=NullAudit(),
        target_param_keys=engine.target_param_keys)
    state = PentestState(target="192.168.1.100", scope=["192.168.1.100"])

    # this policy gates --dump and nothing else
    dump = ActionDecision(tool="sqlmap", params={"url": "http://192.168.1.100/?id=1", "dump": True})
    assert gate.is_dangerous(
        dump, "sqlmap -u http://192.168.1.100/?id=1 --batch --level 2 --risk 1 --dump") is True
    exploit = ActionDecision(tool="metasploit", params={"module": "exploit/x", "rhosts": "192.168.1.100"})
    assert gate.is_dangerous(exploit, "use exploit/x") is False
    # "destination" carries a target in this policy
    assert boundary.target_param_keys == ("target", "destination")
    assert boundary.validate(ActionDecision(tool="x", params={"destination": "10.0.0.1"}), state) is False
    # an empty policy never disables the gate
    empty = GuardrailEngine(tmp_path / "none.yaml")
    assert DangerousOperationApprovalGate(
        interactive=False, dangerous_patterns=empty.dangerous_patterns
    ).dangerous_patterns == DangerousOperationApprovalGate(interactive=False).dangerous_patterns


def test_policy_file_defines_which_scans_are_scan_flavored(tmp_path):
    policy = tmp_path / "fuzz.yaml"
    policy.write_text(yaml.safe_dump({
        "dangerous_operations": [{"tool": "nmap", "op": "--script.*(exploit|brute|dos)"}],
        "scan_flavored_exempt": ["nmap:fuzz"],
    }))
    engine = GuardrailEngine(policy)
    gate = DangerousOperationApprovalGate(
        policy="auto-approve-scan", dangerous_patterns=engine.dangerous_patterns,
        scan_flavored=engine.scan_flavored_exempt)
    assert gate.request_approval(ActionDecision(
        tool="nmap", params={"target": "10.0.0.1", "scripts": "fuzz-brute"})) is True
    # "brute" is not scan-flavored under this policy, so it is denied
    assert gate.request_approval(ActionDecision(
        tool="nmap", params={"target": "10.0.0.1", "scripts": "ssh-brute"})) is False


def test_agent_wires_policy_file_and_run_config(tmp_path, monkeypatch):
    """PentestAgent must hand the policy to the gate, the boundary and the loop.

    security.taint_policy / honeytokens in the run config used to be silently
    replaced by guardrails.yaml, so config.live.yaml's honeytokens had no effect.
    """
    monkeypatch.setenv("LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    monkeypatch.delenv("SECURITY_APPROVAL_POLICY", raising=False)
    policy = tmp_path / "guardrails.yaml"
    policy.write_text(yaml.safe_dump({
        "dangerous_operations": [{"tool": "sqlmap", "op": "--os-shell"},
                                 {"tool": "metasploit", "op": "exploit/"}],
        "target_param_keys": ["target", "url", "host", "ip", "rhosts"],
        "max_same_endpoint": 9,
        "taint_policy": "warn",
        "honeytokens": ["from-policy/"],
        "context_guard": {"honeypot_threshold": 4, "aggregate_multiplier": 3,
                          "aggregate_min_fields": 2},
        "semantic_judge": {"enabled": True, "interval": 2, "confidence_threshold": 0.9},
    }))
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        # the run config names a honeytoken but no taint policy
        "security": {"guardrails_file": str(policy), "approval_policy": "reject",
                     "honeytokens": ["from-config/"]},
        "context_guard": {"enabled": True},
        "storage": {"audit_log": str(tmp_path / "audit.log"),
                    "sessions_dir": str(tmp_path / "sessions"),
                    "reports_dir": str(tmp_path / "reports")},
        "rag": {"vector_store_dir": str(tmp_path / "no-knowledge-base")},
    }), encoding="utf-8")
    # the blueteam model is not trained here: capture what the guard is built with
    created = {}

    def fake_create(cls, **kwargs):
        created.update(kwargs)
        return "guard-sentinel"

    monkeypatch.setattr(ContextGuard, "create", classmethod(fake_create))

    agent = PentestAgent(config_path=str(config), interactive=False)

    # values only the policy file sets reach the loop
    assert agent.guardrail_engine.taint_policy == "warn"
    assert agent.react_loop.taint_policy == "warn"
    assert agent.react_loop.engine.max_same_endpoint == 9
    # the run config's honeytoken wins over the policy file's
    assert agent.react_loop.honeytokens == ["from-config/"]
    assert agent.security.target_param_keys == ("target", "url", "host", "ip", "rhosts")
    assert agent.security.approval_gate.policy == "reject"
    assert agent.security.approval_gate.dangerous_patterns == [
        ("sqlmap", "--os-shell"), ("metasploit", "exploit/")]
    assert agent.trust_manager.engine is agent.guardrail_engine
    assert agent.react_loop.trust is agent.trust_manager
    # guard thresholds and the semantic judge come from the policy file too
    assert agent.react_loop.context_guard == "guard-sentinel"
    assert (created["honeypot_threshold"], created["aggregate_multiplier"],
            created["aggregate_min_fields"]) == (4, 3, 2)
    judge = agent.react_loop.semantic_judge
    assert (judge.judge_interval, judge.confidence_threshold) == (2, 0.9)


def test_run_config_overrides_guard_and_judge_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    policy = tmp_path / "guardrails.yaml"
    policy.write_text(yaml.safe_dump({
        "context_guard": {"honeypot_threshold": 4},
        "semantic_judge": {"enabled": True, "interval": 2, "confidence_threshold": 0.9},
    }))
    config = tmp_path / "config.yaml"
    config.write_text(yaml.safe_dump({
        "security": {"guardrails_file": str(policy)},
        "context_guard": {"enabled": True, "honeypot_threshold": 6},
        "storage": {"audit_log": str(tmp_path / "audit.log"),
                    "sessions_dir": str(tmp_path / "sessions"),
                    "reports_dir": str(tmp_path / "reports")},
    }), encoding="utf-8")
    created = {}

    def fake_create(cls, **kwargs):
        created.update(kwargs)
        return "guard-sentinel"

    monkeypatch.setattr(ContextGuard, "create", classmethod(fake_create))
    agent = PentestAgent(config_path=str(config), interactive=False)
    engine = agent.guardrail_engine

    assert created["honeypot_threshold"] == 6            # run config wins
    assert created["aggregate_multiplier"] == 5          # policy default
    # security.llm_judge in the run config decides the switch; absent → policy file
    assert agent._build_semantic_judge({"llm_judge": False}, engine) is None
    assert agent._build_semantic_judge(
        {"llm_judge": True, "llm_judge_interval": 7}, engine).judge_interval == 7
    assert agent._build_semantic_judge({}, engine).judge_interval == 2
    assert agent._build_semantic_judge({}, GuardrailEngine(tmp_path / "none.yaml")) is None


def test_aggregate_alert_uses_policy_parameters():
    class FixedDetector:
        def predict_proba(self, texts):
            return [[0.6, 0.4] for _ in texts]     # every field just below a 0.5 threshold

    def feed(multiplier, min_fields):
        audit = RecordingAudit()
        guard = ContextGuard(FixedDetector(), threshold=0.5, audit_logger=audit,
                             aggregate_multiplier=multiplier, aggregate_min_fields=min_fields)
        for i in range(4):
            guard.guard_observation(ToolResult(
                tool="nikto", command="nikto", success=True, parsed={"f": f"field number {i} is fine"}))
        return [e["event"] for e in audit.events if e["event"] == "SESSION_AGGREGATE_PRESSURE"]

    # 4 fields score 1.6 in total: with ×3 / every 2 fields that crosses 1.5 at the
    # 4th field (one alert); the default ×5 needs 2.5 and is never reached
    assert feed(3, 2) == ["SESSION_AGGREGATE_PRESSURE"]
    assert feed(5, 5) == []

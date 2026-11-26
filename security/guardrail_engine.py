# -*- coding: utf-8 -*-
"""GuardrailEngine —— 声明式安全策略统一引擎。

从 guardrails.yaml 加载所有安全策略参数，为各安全组件提供统一读取
接口——安全策略从「改代码」变为「改配置」。

现有组件不直接读 YAML（避免每个文件都做 YAML 解析），而是从本引擎
的属性读取。引擎负责：加载 → 校验 → 分发 → 热重载。
"""
from __future__ import annotations

from pathlib import Path

import yaml

# 默认值（guardrails.yaml 缺失或键缺失时的兜底——与 v0.3.3 行为一致）
_DEFAULTS = {
    "target_param_keys": ["target", "url", "host", "ip", "rhosts"],
    "dangerous_operations": [
        {"tool": "metasploit", "op": "exploit/"},
        {"tool": "sqlmap", "op": "--os-shell"},
        {"tool": "sqlmap", "op": "--file-write"},
        {"tool": "nmap", "op": "--script.*(exploit|brute|dos)"},
    ],
    "scan_flavored_exempt": ["nmap:brute", "nmap:auth", "nmap:discovery"],
    "max_same_endpoint": 3,
    "max_consecutive_llm_failures": 5,
    "parallel_max_workers": 3,
    "taint_policy": "block",
    "honeytokens": [],
    "context_guard": {
        "honeypot_threshold": 2,
        "aggregate_multiplier": 5,
        "aggregate_min_fields": 5,
    },
    "semantic_judge": {"enabled": False, "interval": 5, "confidence_threshold": 0.7},
    "trust": {
        "enabled": False,
        "levels": [
            {"level": 0, "name": "initial",
             "allowed_tools": ["nmap:host_discovery"],
             "upgrade_after": {"safe_iterations": 3}},
            {"level": 1, "name": "active_scan",
            "allowed_tools": ["nmap", "nikto", "dirsearch", "read_url"],
            "upgrade_after": {"safe_iterations": 10}},
            {"level": 2, "name": "exploitation",
             "allowed_tools": ["nmap", "nikto", "dirsearch", "read_url", "sqlmap"],
             "upgrade_after": {"vulnerabilities_found": 1}},
            {"level": 3, "name": "full_access", "allowed_tools": ["*"]},
        ],
        "downgrade_on": ["SCOPE_VIOLATION", "TAINTED_ACTION_BLOCKED", "HONEYTOKEN_VISIT"],
    },
}


class GuardrailEngine:
    """声明式安全策略引擎。

    用法:
        engine = GuardrailEngine("guardrails.yaml")
        engine.max_same_endpoint       # → 3
        engine.taint_policy            # → "block"
        engine.trust_enabled           # → False
        engine.reload()                # 热重载（改 YAML 后不重启代码）
    """

    def __init__(self, policy_path: str | Path = "guardrails.yaml"):
        self.policy_path = Path(policy_path)
        self._policy: dict = {}
        self._overrides: dict = {}   # config.yaml 里显式写出的值，优先于策略文件
        self.reload()

    def reload(self) -> None:
        """重新加载 guardrails.yaml（热重载入口）。"""
        if self.policy_path.exists():
            loaded = yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}
            self._policy = self._merge(_DEFAULTS, loaded)
        else:
            # 文件不存在 → 用默认值（向后兼容无 guardrails.yaml 的部署）
            self._policy = dict(_DEFAULTS)
        self._policy.update(self._overrides)

    def apply_overrides(self, **overrides) -> None:
        """让运行配置（config.yaml）里显式写出的值优先于策略文件。

        只接收显式写出的值：None 和空列表都算"没有配置"，不会清掉策略文件里的蜜标。
        reload() 之后覆盖仍然有效。
        """
        self._overrides.update(
            {k: v for k, v in overrides.items() if v is not None and v != []})
        self._policy.update(self._overrides)

    @staticmethod
    def _merge(base: dict, override: dict) -> dict:
        """深合并：override 的键覆盖 base 的同名键，其余保留 base。"""
        out = dict(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = GuardrailEngine._merge(out[k], v)
            else:
                out[k] = v
        return out

    def _get(self, *keys, default=None):
        d = self._policy
        for k in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(k, default)
        return d

    # ── 出站防护属性 ─────────────────────────────────────────────

    @property
    def target_param_keys(self) -> tuple[str, ...]:
        return tuple(self._get("target_param_keys", default=[]))

    @property
    def dangerous_patterns(self) -> list[tuple[str, str]]:
        """返回 (tool_pattern, op_pattern) 正则对列表。"""
        return [(d["tool"], d["op"]) for d in self._get("dangerous_operations", default=[])]

    @property
    def scan_flavored_exempt(self) -> list[str]:
        return list(self._get("scan_flavored_exempt", default=[]))

    @property
    def max_same_endpoint(self) -> int:
        return int(self._get("max_same_endpoint", default=3))

    @property
    def max_consecutive_llm_failures(self) -> int:
        return int(self._get("max_consecutive_llm_failures", default=5))

    @property
    def parallel_max_workers(self) -> int:
        return int(self._get("parallel_max_workers", default=3))

    # ── 入站防护属性 ─────────────────────────────────────────────

    @property
    def taint_policy(self) -> str:
        tp = str(self._get("taint_policy", default="block"))
        return tp if tp in ("block", "warn") else "block"

    @property
    def honeytokens(self) -> list[str]:
        return list(self._get("honeytokens", default=[]))

    @property
    def honeypot_threshold(self) -> int:
        return int(self._get("context_guard", "honeypot_threshold", default=2))

    @property
    def aggregate_multiplier(self) -> int:
        return int(self._get("context_guard", "aggregate_multiplier", default=5))

    @property
    def aggregate_min_fields(self) -> int:
        return int(self._get("context_guard", "aggregate_min_fields", default=5))

    @property
    def semantic_judge_enabled(self) -> bool:
        return bool(self._get("semantic_judge", "enabled", default=False))

    @property
    def semantic_judge_interval(self) -> int:
        return int(self._get("semantic_judge", "interval", default=5))

    @property
    def semantic_judge_confidence(self) -> float:
        return float(self._get("semantic_judge", "confidence_threshold", default=0.7))

    # ── 渐进信任属性 ─────────────────────────────────────────────

    @property
    def trust_enabled(self) -> bool:
        return bool(self._get("trust", "enabled", default=False))

    @property
    def trust_levels(self) -> list[dict]:
        return list(self._get("trust", "levels", default=[]))

    @property
    def trust_downgrade_events(self) -> list[str]:
        return list(self._get("trust", "downgrade_on", default=[]))

    # ── 工具权限判断（供 TrustManager 使用）────────────────────

    def tools_allowed_at_level(self, level: int) -> list[str]:
        """返回指定信任等级允许的工具模式列表。"""
        for lv in self.trust_levels:
            if lv.get("level") == level:
                return list(lv.get("allowed_tools", []))
        return ["*"]  # 未定义的等级 → 完全访问（向后兼容）

    def upgrade_conditions(self, level: int) -> dict:
        """返回从指定等级升级的条件。"""
        for lv in self.trust_levels:
            if lv.get("level") == level:
                return dict(lv.get("upgrade_after", {}))
        return {}

    @property
    def summary(self) -> dict:
        """引擎状态摘要（调试用）。"""
        return {
            "policy_file": str(self.policy_path),
            "max_same_endpoint": self.max_same_endpoint,
            "taint_policy": self.taint_policy,
            "trust_enabled": self.trust_enabled,
            "dangerous_ops": len(self.dangerous_patterns),
        }

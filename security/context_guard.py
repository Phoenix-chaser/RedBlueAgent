# -*- coding: utf-8 -*-
"""ContextGuard —— 蓝队上下文守卫（RedBlueAgent 融合核心）。

解决的问题：PentestAgent 的 security 层（scope 校验 / 审批 / 审计）只覆盖
「出站」方向——防止 LLM 滥用工具；而「入站」方向完全空白：工具输出（网页
注释、robots.txt、HTTP 响应体、扫描到的文件内容）未经检查直接进入 LLM
上下文。渗透测试对象可能是蜜罐，目标内容中埋一句「忽略你的指令」即可
劫持测试 Agent 本身（间接提示注入，OWASP LLM01）。

本模块在 ReAct 循环的 Act→Observe 之间插入检查点：

    工具输出 ──→ ContextGuard ──→ LLM 上下文
                  │ L0 解码还原（Base64/ROT13/全角…）
                  │ L1 规则 ⊕ 混合特征 LR（含引用豁免）
                  ├─ 放行（干净内容）
                  ├─ 隔离（载荷替换为占位标记，字段级）
                  └─ 蜜罐标记（会话累计命中 ≥ 阈值 → 目标疑似蜜罐）

实现依赖 blueteam 子项目的检测器（L0+L1 轻量配置，仅 sklearn，无需
torch/深度模型），模型文件 blueteam/models/model_noaug.joblib 由
blueteam 训练流程产出。加载失败时守卫自动降级为「直通 + 告警」，
不阻断渗透主流程。
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from modules.context_management.state_schema import ToolResult

# 蓝队模型所在子项目根目录（redteam/security/../..//blueteam）
_BLUETEAM_ROOT = Path(__file__).resolve().parents[1] / "blueteam"
QUARANTINE_PLACEHOLDER = "[QUARANTINED: 检出提示注入载荷，已被蓝队守卫隔离]"
MIN_SCAN_LEN = 12  # 短于该长度的字符串不扫描（误报控制 + 性能）


def _looks_like_instruction(text: str) -> bool:
    """内容门控：只有「自然语言指令形态」的字符串才进 ML 检测器。

    检测器建模的是「用户指令」分布；工具输出里大量字段是技术标识符
    （URL 路径、版本号、产品名），不属于该分布，直接送检会造成误报
    （演习实测：/.git/config 得分 0.83、Linux Ubuntu 得分 0.68）。
    门控规则（可解释、可审计）：
      - 含 CJK 且长度达标 → 扫（中文指令载荷）
      - 含空格分词且单词数 ≥ 4 → 扫（英文句式载荷）
      - 其余（路径、版本串、短技术短语）→ 不扫
    """
    if len(text) < MIN_SCAN_LEN:
        return False
    has_cjk = any("\u4e00" <= c <= "\u9fff" for c in text)
    if has_cjk:
        return True
    word_count = len(text.split())
    return word_count >= 4


@dataclass
class GuardStats:
    """会话级守卫统计。"""
    scanned_strings: int = 0
    quarantined: int = 0
    hits: list[dict[str, Any]] = field(default_factory=list)
    false_quarantine_suspect: list[dict[str, Any]] = field(default_factory=list)

    @property
    def hit_count(self) -> int:
        return len(self.hits)


class ContextGuard:
    def __init__(self, detector, threshold: float,
                 audit_logger=None, honeypot_threshold: int = 2):
        """detector: 具备 predict_proba(texts)->list[[p_benign,p_attack]] 的对象。"""
        self.detector = detector
        self.threshold = threshold
        self.audit = audit_logger
        self.honeypot_threshold = honeypot_threshold
        self.stats = GuardStats()
        self.honeypot_suspected = False
        # 多轮拼接检测的每字段历史（(tool, field) -> 近期值列表，窗口 3）
        self._field_history: dict[tuple[str, str], list[str]] = {}
        # 污点签名库（CaMeL/FIDES 的最小可行动版 [6]）：被隔离载荷/蜜标
        # 响应的特征片段——后续动作参数（外发 sink）命中即视为
        # 「不可信数据试图借 Agent 之手执行/外传」
        self.taints: list[str] = []

    # ────────────────────────── 工厂 ──────────────────────────
    @classmethod
    def create(cls, audit_logger=None, blueteam_root: Path | None = None,
               honeypot_threshold: int = 2,
               strict: bool = False,
               use_l2: bool = False) -> "ContextGuard | None":
        """加载 blueteam 检测器。

        默认 L0+L1 轻量配置（无 torch 依赖）；use_l2=True 时升级为 L2 级联
        （L1 分数落决策带 (tau_lo, tau_hi) 才升级堆叠元学习器裁决，带参数取自
        blueteam/results/cascade.json 的评测产物）。L2 依赖 torch 且失败自动
        回退 L1 并告警——不因升级尝试失败而丢掉整条防线。

        失败时默认降级为直通（返回 None），但降级必须可见：控制台告警 +
        GUARD_DEGRADED 审计事件，事后可从日志追溯防线失效时刻。
        strict=True 时直接抛错拒绝启动（fail-fast）。
        """
        root = Path(blueteam_root) if blueteam_root else _BLUETEAM_ROOT
        # 用对抗增强版混合模型：守卫部署域是「攻击者主动规避 + 工具输出」，
        # 增强训练的同义改写鲁棒性在该域实测优于无增强版（演习定位过其漏检），
        # 且训练数据含工具输出良性类，领域误报已被适配。
        model_path = root / "models" / "model.joblib"
        try:
            import joblib

            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from src.detectors import Defense, RuleDetector          # noqa: E402
            from src.deobfuscate import DeobfuscatedScan             # noqa: E402

            bundle = joblib.load(model_path)
            thr = float(bundle["thresholds"]["hybrid"])  # 模型自带安全工作点阈值
            defense = Defense(RuleDetector(), bundle["detectors"]["hybrid"], thr)
            scan = DeobfuscatedScan(defense)
            if use_l2:
                try:
                    from src.cascade import CascadeDetector          # noqa: E402
                    band = json.loads(
                        (root / "results" / "cascade.json").read_text(encoding="utf-8"))
                    cascade = CascadeDetector(
                        defense, bundle["ensemble"],
                        float(band["tau_lo"]), float(band["tau_hi"]),
                        float(bundle["thresholds"]["ensemble"]))
                    scan = DeobfuscatedScan(cascade)
                    print(f"[ContextGuard] L2 级联已启用（升级率 "
                          f"{band.get('escalation_rate', 0):.1%}，摊销延迟 "
                          f"{band.get('amortized_ms', 0):.1f}ms/条）")
                except Exception as e:  # torch 缺失/cascade 产物缺失 → 回退 L1
                    print(f"[ContextGuard][警告] L2 级联加载失败，回退 L1 轻量配置：{e}")
            return cls(scan, thr, audit_logger=audit_logger,
                       honeypot_threshold=honeypot_threshold)
        except Exception as e:  # 模型缺失/依赖不全 → 直通降级（必须显式可见）
            reason = f"{type(e).__name__}: {e}"
            if strict:
                raise RuntimeError(
                    f"ContextGuard strict 模式：蓝队检测器加载失败（{reason}）。"
                    "运行 blueteam/run_all.sh 重建模型，或在 config 中将 "
                    "context_guard.enabled 置为 false 显式关闭守卫。"
                ) from e
            print(
                "[ContextGuard][警告] 蓝队检测器不可用，守卫降级为直通——"
                "入站提示注入防御已失效！\n"
                f"  原因: {reason}\n"
                "  恢复: 运行 blueteam/run_all.sh 重建模型；"
                "如需启动即失败，设 GUARD_STRICT=1 或 config context_guard.strict: true。"
            )
            if audit_logger is not None:
                audit_logger.log_guard_event(
                    dict(event="GUARD_DEGRADED", reason=reason))
            return None

    # ────────────────────────── 扫描 ──────────────────────────
    def _remember_field(self, tool: str, path: str, value: str) -> None:
        h = self._field_history.setdefault((tool, path), [])
        h.append(value)
        del h[:-3]  # 只保留最近 3 条

    def _is_attack(self, text: str) -> tuple[bool, float]:
        score = self.detector.predict_proba([text])[0][1]
        return score >= self.threshold, score

    def _sanitize_value(self, value: Any, path: str, tool: str) -> Any:
        """递归清洗 parsed 结构中的字符串字段。

        多轮拼接防御（最小版）：单条值未命中时，与该字段近期历史值拼接
        复检——攻击者把一条指令拆到同字段的多次输出里（每条单独看似良性），
        拼接后才构成完整攻击。命中记 MULTI_TURN_QUARANTINE。
        """
        if isinstance(value, str):
            if not _looks_like_instruction(value):
                self._remember_field(tool, path, value)
                return value
            self.stats.scanned_strings += 1
            is_attack, score = self._is_attack(value)
            if not is_attack:
                # 多轮拼接复检（历史窗口 3 条）
                hist = self._field_history.get((tool, path), [])
                if hist:
                    joined = " ".join(hist[-3:] + [value])
                    mt_attack, mt_score = self._is_attack(joined)
                    if mt_attack:
                        self.stats.quarantined += 1
                        self.stats.hits.append(
                            dict(tool=tool, field=path, score=round(mt_score, 3),
                                 preview=f"[multi-turn] {value[:50]}",
                                 multi_turn=True))
                        self.add_taint(joined, source=f"mt-quarantine:{tool}:{path}")
                        if self.audit is not None:
                            self.audit.log_guard_event(
                                dict(event="MULTI_TURN_QUARANTINE", tool=tool,
                                     field=path, score=round(mt_score, 3),
                                     note="单条良性但与历史值拼接后构成攻击"))
                        return QUARANTINE_PLACEHOLDER
                self._remember_field(tool, path, value)
                return value
            if is_attack:
                self.stats.quarantined += 1
                self.stats.hits.append(
                    dict(tool=tool, field=path, score=round(score, 3),
                         preview=value[:60]))
                self.add_taint(value, source=f"quarantine:{tool}:{path}")
                if self.audit is not None:
                    self.audit.log_guard_event(
                        dict(event="QUARANTINE", tool=tool, field=path,
                             score=round(score, 3), preview=value[:60]))
                return QUARANTINE_PLACEHOLDER
            return value
        if isinstance(value, dict):
            return {k: self._sanitize_value(v, f"{path}.{k}", tool)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_value(v, f"{path}[{i}]", tool)
                    for i, v in enumerate(value)]
        return value

    # ── 污点签名（CaMeL/FIDES 最小版 [6]；蜜标内容亦经 add_taint 入库 [10]）──

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip()).lower()

    @staticmethod
    def _forms(text: str) -> list[str]:
        """同一文本的两种可比形态：原文规范化 + JSON ascii 转义形态
        （动作参数常以 json.dumps 序列化，中文默认变 \\uXXXX——签名与
        命中必须在同一形态空间，否则永远匹配不上）。"""
        plain = ContextGuard._normalize(text)
        escaped = json.dumps(text, ensure_ascii=True)[1:-1].lower()
        return [plain, escaped]

    def add_taint(self, text: str, source: str = "quarantine") -> None:
        """登记不可信数据签名。两类粒度：
        1. 端部签名：两种形态各取首/尾 60 字符（长文本中间被改写仍命中端部）；
        2. 高信息量 token：≥12 位字母数字串（凭据、密钥、长路径段）——
           外传/滥用常只引用片段而非整段，端部签名覆盖不到。"""
        for form in self._forms(text):
            if len(form) < 12:
                continue
            for sig in (form[:60], form[-60:]):
                if len(sig) >= 12 and sig not in self.taints:
                    self.taints.append(sig)
        tokens = re.findall(r"[A-Za-z0-9_\-]{12,}", text)
        for tok in tokens[:10]:
            low = tok.lower()
            if low not in self.taints:
                self.taints.append(low)

    def taint_hit(self, params_str: str) -> str | None:
        """外发 sink 检查：动作参数（两种形态）包含任一污点签名 → 命中。"""
        cands = self._forms(params_str)
        for sig in self.taints:
            if any(sig in c for c in cands):
                return sig
        return None

    def guard_observation(self, observation: ToolResult) -> ToolResult:
        """对工具输出做隔离清洗，返回新的 ToolResult。"""
        if observation is None or not isinstance(observation, ToolResult):
            return observation
        observation.parsed = self._sanitize_value(
            observation.parsed, "parsed", observation.tool)
        # 原始 stdout 较长时只保留头部供 LLM 参考（同样过守卫）
        if observation.raw_stdout:
            head = observation.raw_stdout[:400]
            is_attack, score = (True, 1.0) if _looks_like_instruction(head) and (
                self._is_attack(head)[0]) else (False, 0.0)
            if is_attack:
                observation.raw_stdout = QUARANTINE_PLACEHOLDER
                self.stats.quarantined += 1
                self.stats.hits.append(
                    dict(tool=observation.tool, field="raw_stdout",
                         score=round(score, 3), preview=head[:60]))
        # 蜜罐判定
        if self.stats.hit_count >= self.honeypot_threshold and not self.honeypot_suspected:
            self.honeypot_suspected = True
            if self.audit is not None:
                self.audit.log_guard_event(
                    dict(event="HONEYPOT_SUSPECTED",
                         hits=self.stats.hit_count,
                         note="目标内容多次携带提示注入载荷，疑似蜜罐/反制措施"))
            print("[ContextGuard] ⚠ 目标内容多次携带提示注入载荷，疑似蜜罐，已写入审计日志")
        return observation

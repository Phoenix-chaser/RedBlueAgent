# -*- coding: utf-8 -*-
"""级联决策层：L1 快速通道处理确定性样本，不确定带升级 L2。

L1 = 纵深防御（规则 ⊕ 混合 LR，引用豁免）× L0 解码扫描 —— 单条亚毫秒
L2 = 堆叠融合（含字符 TextCNN）× L0 解码扫描        —— 单条数十毫秒

决策带（均由验证集确定）：
  score ≥ τ_hi → 判攻击（val FPR ≤ 10% 安全阈值）
  score ≤ τ_lo → 判正常（τ_lo = val 攻击分数 1% 分位：99% 攻击高于此线）
  否则         → 升级 L2，由堆叠模型裁决

级联的意义是成本-精度权衡：大部分流量由亚毫秒的 L1 直接出结果，
只有不确定样本付出深度模型代价。本模块输出：升级率、最终召回/误报、
各层实测延迟与摊销延迟。
"""
from __future__ import annotations

import time

import numpy as np


class CascadeDetector:
    name = "cascade"

    def __init__(self, l1, l2, tau_lo: float, tau_hi: float, l2_threshold: float):
        self.l1, self.l2 = l1, l2
        self.tau_lo, self.tau_hi = tau_lo, tau_hi
        self.t2 = l2_threshold

    def predict_proba(self, texts):
        s1 = np.array([p[1] for p in self.l1.predict_proba(texts)])
        out = np.empty(len(texts))
        idx_band = np.where((s1 > self.tau_lo) & (s1 < self.tau_hi))[0]
        for i, s in enumerate(s1):
            out[i] = s  # 带外：L1 分数即最终分数
        if len(idx_band):
            s2 = np.array([p[1] for p in self.l2.predict_proba([texts[i] for i in idx_band])])
            # 带内：用 L2 分数单调映射到 (tau_lo, tau_hi) 区间，保持全局可排序
            lo, hi = self.tau_lo, self.tau_hi
            mapped = lo + (hi - lo) * np.clip((s2 - 0.5) * 2 + 0.5, 0, 1)
            out[idx_band] = mapped
        return np.stack([1 - out, out], axis=1)

    def decision(self, texts):
        """返回 (最终判定, 是否升级)。带内以 L2 阈值裁决。"""
        s1 = np.array([p[1] for p in self.l1.predict_proba(texts)])
        flags = np.zeros(len(texts), dtype=bool)
        preds = (s1 >= self.tau_hi).astype(int)
        band = np.where((s1 > self.tau_lo) & (s1 < self.tau_hi))[0]
        if len(band):
            s2 = np.array([p[1] for p in self.l2.predict_proba([texts[i] for i in band])])
            preds[band] = (s2 >= self.t2).astype(int)
            flags[band] = True
        return preds, flags


def choose_band(l1, val_texts, val_labels, max_fpr: float = 0.05):
    """决策带（全部在与裁决一致的 L1 分数上计算）：

    τ_hi：val FPR ≤ max_fpr 的安全阈值（带外直接判攻击）
    τ_lo：val 攻击分数 2% 分位（低于此线 98%+ 攻击已被覆盖，带外判正常）
    兜底：若两线倒挂或过近（分数分布密集），强制拉开最小宽度，
    保证「带外判正常」不会越过「带外判攻击」的边界。
    """
    scores = np.array([p[1] for p in l1.predict_proba(val_texts)])
    neg = np.sort(scores[val_labels == 0])
    pos = scores[val_labels == 1]
    tau_hi = float(np.quantile(neg, 1 - max_fpr, method="higher"))
    tau_lo = float(np.quantile(pos, 0.02))
    tau_lo = min(tau_lo, tau_hi - 0.02)
    return max(tau_lo, 0.0), tau_hi


def bench_latency(fn, texts, repeat: int = 3) -> float:
    """返回单条平均延迟（毫秒）。"""
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn(texts)
        best = min(best, (time.perf_counter() - t0) * 1000)
    return best / len(texts)

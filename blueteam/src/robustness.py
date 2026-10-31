# -*- coding: utf-8 -*-
"""鲁棒性实验 v3：5 种对抗变换下的方案对比（架构选型的最终裁决）。

回答的核心问题：
1. 对抗增强训练值不值？（干净性能的代价 vs 扰动下的收益）
2. L0 解码层能否修复 Base64 规避？
3. 级联（L1 干净冠军 + L2 增强专家）能否兼得干净性能与鲁棒性？

方案：规则基线 / 混合LR·无增强 / 混合LR·增强 / L1=L0+纵深防御(无增强混合)
      / L2=堆叠·增强 / 级联（L1+L2，带内阈值）
协议：扰动只作用于测试集攻击样本，良性保持原样；每个方案使用与主评测
完全相同的阈值。运行：python3 -m src.robustness
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from src.cascade import CascadeDetector
from src.deobfuscate import DeobfuscatedScan
from src.detectors import Defense
from src.perturb import PERTURBATIONS
from src.stacking import StackDetector

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

plt.rcParams.update({
    "font.sans-serif": ["Noto Sans CJK SC", "WenQuanYi Zen Hei", "SimHei", "DejaVu Sans"],
    "axes.unicode_minus": False,
})


def load_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    bundle = joblib.load(ROOT / "models" / "model.joblib")
    noaug_bundle = joblib.load(ROOT / "models" / "model_noaug.joblib")
    dets = dict(bundle["detectors"])

    val = load_jsonl(ROOT / "data" / "val.jsonl")
    val_texts = [s["text"] for s in val]
    val_labels = np.array([s["label"] for s in val])
    test = load_jsonl(ROOT / "data" / "test.jsonl")
    attacks = [s["text"] for s in test if s["label"] == 1]
    benign = [s["text"] for s in test if s["label"] == 0]
    y_all = np.concatenate([np.ones(len(attacks)), np.zeros(len(benign))])

    # ── 组装与主评测一致的架构 ──
    defense_l1 = Defense(dets["rules"], noaug_bundle["hybrid"], noaug_bundle["threshold"])
    l1 = DeobfuscatedScan(defense_l1)
    thr_l1 = 0.0  # 用 FPR<=10% 安全线（与主评测一致）
    neg = np.sort(np.array([p[1] for p in l1.predict_proba(val_texts)])[val_labels == 0])
    thr_l1 = float(np.quantile(neg, 0.90, method="higher"))

    stack = StackDetector(
        {k: dets[k] for k in ("word", "char", "hybrid", "deep")}, dets["rules"]
    ).fit_on_val(val_texts, val_labels)
    l2 = DeobfuscatedScan(stack)
    from src.cascade import choose_band
    tau_lo, tau_hi = choose_band(l1, val_texts, val_labels)
    val_l1_scores = np.array([p[1] for p in l1.predict_proba(val_texts)])
    band_mask = (val_l1_scores > tau_lo) & (val_l1_scores < tau_hi)
    band_labels = val_labels[band_mask]
    neg_band = np.sort(np.array([p[1] for p in l2.predict_proba(
        [t for t, m in zip(val_texts, band_mask) if m])])[band_labels == 0])
    t2 = float(np.quantile(neg_band, 0.90, method="higher")) if len(neg_band) else 0.5
    cascade = CascadeDetector(l1, l2, tau_lo, tau_hi, t2)

    thr_hybrid_aug = bundle["thresholds"]["hybrid"]
    thr_stack = 0.5
    neg_s = np.sort(np.array([p[1] for p in stack.predict_proba(val_texts)])[val_labels == 0])
    thr_stack = float(np.quantile(neg_s, 0.90, method="higher"))

    systems = {
        "规则基线": (dets["rules"], 0.5),
        "混合LR·无增强": (noaug_bundle["hybrid"], noaug_bundle["threshold"]),
        "混合LR·增强": (dets["hybrid"], thr_hybrid_aug),
        "L1=L0+纵深防御": (l1, thr_l1),
        "L2=堆叠·增强": (l2, thr_stack),
    }

    rng = random.Random(42)
    rows = []
    order = ["（无扰动）"] + list(PERTURBATIONS.keys())
    for pname in order:
        if pname == "（无扰动）":
            pert_attacks = attacks
        else:
            pert_attacks = [PERTURBATIONS[pname](t, rng) for t in attacks]
        texts = pert_attacks + benign
        for name, (det, thr) in systems.items():
            scores = np.array([p[1] for p in det.predict_proba(texts)])
            recall = float((scores[:len(attacks)] >= thr).mean())
            rows.append(dict(方案=name, 扰动=pname,
                             AUROC=roc_auc_score(y_all, scores), 攻击召回率=recall))
        # 级联
        preds, _ = cascade.decision(texts)
        rows.append(dict(方案="级联（L1+L2）", 扰动=pname, AUROC=np.nan,
                         攻击召回率=float(preds[:len(attacks)].mean())))

    df = pd.DataFrame(rows)
    df["扰动"] = pd.Categorical(df["扰动"], categories=order, ordered=True)
    df.to_csv(RESULTS / "robustness.csv", index=False, encoding="utf-8-sig")
    print("攻击召回率（各方案 × 扰动）：")
    print(df.pivot(index="方案", columns="扰动", values="攻击召回率").round(3).to_markdown())
    print("\nAUROC：")
    print(df.pivot(index="方案", columns="扰动", values="AUROC").round(3).to_markdown())

    # 平扰动平均召回（不含无扰动列）
    piv = df.pivot(index="方案", columns="扰动", values="攻击召回率")
    pert_cols = [c for c in piv.columns if c != "（无扰动）"]
    print("\n扰动平均召回 vs 干净召回：")
    summary = pd.DataFrame({
        "干净召回": piv["（无扰动）"],
        "扰动平均召回": piv[pert_cols].mean(axis=1),
        "最差扰动召回": piv[pert_cols].min(axis=1),
    }).round(3)
    print(summary.to_markdown())

    # ── 衰减图 ──
    fig, ax = plt.subplots(figsize=(9.2, 4.8), dpi=150)
    x = np.arange(len(order))
    colors = {"规则基线": "#9a958d", "混合LR·无增强": "#7d5ba6", "混合LR·增强": "#c98a2d",
              "L1=L0+纵深防御": "#1f7692", "L2=堆叠·增强": "#5a9e6f", "级联（L1+L2）": "#b3452c"}
    width = 0.13
    for i, name in enumerate(list(systems.keys()) + ["级联（L1+L2）"]):
        vals = piv.loc[name, order].values
        ax.bar(x + (i - 2.5) * width, vals, width, color=colors[name], label=name)
    ax.set_xticks(x)
    ax.set_xticklabels(order, fontsize=9)
    ax.set_ylabel("攻击召回率", fontsize=10)
    ax.set_title("对抗变换下各架构方案的攻击召回率", fontsize=12)
    ax.set_ylim(0, 1.05)
    ax.legend(frameon=False, fontsize=8, ncol=6, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", ls="--", alpha=0.25)
    fig.tight_layout()
    fig.savefig(RESULTS / "robustness.png", bbox_inches="tight")
    print(f"\n图表已保存 → {RESULTS / 'robustness.png'}")


if __name__ == "__main__":
    main()

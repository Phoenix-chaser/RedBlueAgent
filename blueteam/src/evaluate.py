# -*- coding: utf-8 -*-
"""主评测 v3：九种方案对比 + 校准分析 + 级联成本-精度报告 + 类别级拆解。

方案分层：
  基线    rules
  单模型  word / char / hybrid / deep(字符TextCNN)
  融合    ensemble（三路线性软投票）/ stack（堆叠元学习器）
  架构    scan_defense（L0解码 + 规则⊕混合）/ cascade（L1+L2级联）

指标口径：
- AUROC / AP（1,000 次自助 95% CI）
- 工作点（验证集 FPR≤10% 安全阈值）下的 Recall / Precision / 测试FPR
- FPR@TPR95；Hard-FPR = 对抗性良性子集误报率
- 级联额外报告：升级率、各层实测延迟、摊销延迟
运行：python3 -m src.evaluate
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score, precision_score, recall_score,
    roc_auc_score, roc_curve,
)

from src.cascade import CascadeDetector, bench_latency, choose_band
from src.deobfuscate import DeobfuscatedScan
from src.deep import expected_calibration_error
from src.detectors import Defense
from src.stacking import StackDetector

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

plt.rcParams.update({
    "font.sans-serif": ["Noto Sans CJK SC", "WenQuanYi Zen Hei", "SimHei", "DejaVu Sans"],
    "axes.unicode_minus": False,
})

LABELS = {"rules": "规则基线", "word": "词级 TF-IDF+LR", "char": "字符 n-gram+LR",
          "hybrid": "混合特征 LR", "ensemble": "三路软投票", "deep": "字符 TextCNN",
          "stack": "堆叠元学习器", "scan_defense": "L0+纵深防御(L1)",
          "cascade": "级联（L1+L2）"}


def bootstrap_auroc_ci(y, scores, n_boot=1000, seed=42):
    rng = np.random.default_rng(seed)
    n = len(y)
    aucs = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        if len(set(y[idx])) < 2:
            continue
        aucs.append(roc_auc_score(y[idx], scores[idx]))
    return float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))


def fpr_at_tpr95(y_true: np.ndarray, scores: np.ndarray) -> float:
    fpr, tpr, _ = roc_curve(y_true, scores)
    idx = np.searchsorted(tpr, 0.95)
    return float(fpr[min(idx, len(fpr) - 1)])


def security_threshold(y_true, scores, max_fpr=0.10):
    neg = np.sort(scores[y_true == 0])
    return float(np.quantile(neg, 1 - max_fpr, method="higher")) if len(neg) else 0.5


def load_jsonl(p):
    with open(p, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    bundle = joblib.load(ROOT / "models" / "model.joblib")          # 增强模型束
    dets = dict(bundle["detectors"])            # rules/word/char/hybrid/deep
    ens = bundle["ensemble"]
    thresholds = dict(bundle["thresholds"])
    # 无增强「干净冠军」：L1 纵深防御用干净优化的 hybrid（v2 消融显示
    # 对抗增强以干净召回换鲁棒性；干净流量占绝大多数，L1 应选干净最优，
    # 不确定样本升级到见过扰动形态的 L2 堆叠）
    noaug = joblib.load(ROOT / "models" / "model_noaug.joblib")
    defense = Defense(dets["rules"], noaug["hybrid"], noaug["threshold"])

    val = load_jsonl(ROOT / "data" / "val.jsonl")
    val_texts = [s["text"] for s in val]
    val_labels = np.array([s["label"] for s in val])
    test = load_jsonl(ROOT / "data" / "test.jsonl")
    texts = [s["text"] for s in test]
    y = np.array([s["label"] for s in test])
    hard_texts = [s["text"] for s in test if s["hard"]]

    # ── 组合架构（L2 各基学习器均为增强版） ──
    stack = StackDetector(
        {k: dets[k] for k in ("word", "char", "hybrid", "deep")}, dets["rules"]
    ).fit_on_val(val_texts, val_labels)
    scan_defense = DeobfuscatedScan(defense)
    scan_stack = DeobfuscatedScan(stack)
    tau_lo, tau_hi = choose_band(scan_defense, val_texts, val_labels)
    # L2 只处理带内子总体 → 阈值条件化在带内验证样本上选择（级联标准做法）
    val_l1 = np.array([p[1] for p in scan_defense.predict_proba(val_texts)])
    band_mask = (val_l1 > tau_lo) & (val_l1 < tau_hi)
    band_texts = [t for t, m in zip(val_texts, band_mask) if m]
    band_labels = val_labels[band_mask]
    t2 = security_threshold(
        band_labels, np.array([p[1] for p in scan_stack.predict_proba(band_texts)]))
    cascade = CascadeDetector(scan_defense, scan_stack, tau_lo, tau_hi, t2)

    variants = {
        "rules": (dets["rules"], thresholds["rules"]),
        "word": (dets["word"], thresholds["word"]),
        "char": (dets["char"], thresholds["char"]),
        "hybrid": (dets["hybrid"], thresholds["hybrid"]),
        "ensemble": (ens, thresholds["ensemble"]),
        "deep": (dets["deep"], thresholds["deep"]),
    }
    for key, det in (("stack", stack), ("scan_defense", scan_defense)):
        thr = security_threshold(
            val_labels, np.array([p[1] for p in det.predict_proba(val_texts)]))
        variants[key] = (det, thr)

    # ── 主表 ──
    rows = []
    for key, (det, thr) in variants.items():
        scores = np.array([p[1] for p in det.predict_proba(texts)])
        pred = (scores >= thr).astype(int)
        lo, hi = bootstrap_auroc_ci(y, scores)
        hard_scores = np.array([p[1] for p in det.predict_proba(hard_texts)])
        rows.append(dict(
            检测器=LABELS[key], AUROC=roc_auc_score(y, scores),
            **{"95% CI": f"[{lo:.3f},{hi:.3f}]"},
            AP=average_precision_score(y, scores),
            Recall=recall_score(y, pred), Precision=precision_score(y, pred, zero_division=0),
            **{"测试FPR": float(pred[y == 0].mean())},
            **{"FPR@TPR95": fpr_at_tpr95(y, scores)},
            **{"Hard-FPR": float((hard_scores >= thr).mean())},
        ))
    # 级联：decision() 直接裁决
    preds, esc = cascade.decision(texts)
    hard_idx = [i for i, s in enumerate(test) if s["hard"]]
    casc_scores = np.array([p[1] for p in cascade.predict_proba(texts)])
    casc_auc = roc_auc_score(y, casc_scores)
    _, casc_hi = bootstrap_auroc_ci(y, casc_scores)
    rows.append(dict(
        检测器=LABELS["cascade"], AUROC=casc_auc,
        **{"95% CI": f"[{casc_auc:.3f},{casc_hi:.3f}]"},
        AP=average_precision_score(y, casc_scores),
        Recall=float(preds[y == 1].mean()),
        Precision=precision_score(y, preds, zero_division=0),
        **{"测试FPR": float(preds[y == 0].mean())},
        **{"FPR@TPR95": fpr_at_tpr95(y, casc_scores)},
        **{"Hard-FPR": float(preds[hard_idx].mean())},
    ))
    df = pd.DataFrame(rows)
    print(f"测试集 {len(test)} 条（攻击 {y.sum()}，良性 {len(y)-y.sum()}，困难良性 {len(hard_texts)}）")
    print(df.round(4).to_markdown(index=False))
    df.to_json(RESULTS / "metrics.json", orient="records", force_ascii=False, indent=2)

    # ── 级联成本报告 ──
    lat_l1 = bench_latency(scan_defense.predict_proba, texts[:200])
    lat_l2 = bench_latency(scan_stack.predict_proba, texts[:100])
    esc_rate = float(esc.mean())
    print(f"\n级联报告：升级率 {esc_rate:.1%}｜L0+L1 延迟 {lat_l1:.2f} ms/条｜"
          f"L2 延迟 {lat_l2:.2f} ms/条｜摊销延迟 {lat_l1 + esc_rate * lat_l2:.2f} ms/条"
          f"（全量走 L2 基准 {lat_l2:.2f} ms/条）")

    # ── 校准分析 ──
    cal_rows = []
    for key in ("hybrid", "deep"):
        det = variants[key][0]
        probs = np.array([p[1] for p in det.predict_proba(texts)])
        cal_rows.append(dict(模型=LABELS[key],
                             **{"测试ECE": expected_calibration_error(y, probs)}))
    d = variants["deep"][0]
    T = d.temperature
    d.temperature = 1.0
    probs_raw = np.array([p[1] for p in d.predict_proba(texts)])
    val_raw = np.array([p[1] for p in d.predict_proba(val_texts)])
    d.temperature = T
    cal_rows.append(dict(模型="TextCNN 温度=1（未校准）",
                         **{"测试ECE": expected_calibration_error(y, probs_raw)}))

    cal_df = pd.DataFrame(cal_rows).round(4)
    print("\n校准分析（ECE，越低越校准）：")
    print(cal_df.to_markdown(index=False))

    # ── 类别级召回 ──
    att_idx = [i for i, s in enumerate(test) if s["label"] == 1]
    cat_rows = []
    for key in ("hybrid", "deep", "stack", "cascade"):
        if key == "cascade":
            hits_by = defaultdict(list)
            for i in att_idx:
                hits_by[(test[i]["category"], test[i]["lang"])].append(preds[i])
        else:
            det, thr = variants[key]
            sc = np.array([p[1] for p in det.predict_proba(texts)])
            hits_by = defaultdict(list)
            for i in att_idx:
                hits_by[(test[i]["category"], test[i]["lang"])].append(sc[i] >= thr)
        for (cat, lang), hits in sorted(hits_by.items()):
            cat_rows.append(dict(检测器=LABELS[key], 类别=cat, 语言=lang,
                                 n=len(hits), 召回率=round(float(np.mean(hits)), 3)))
    cat_df = pd.DataFrame(cat_rows)
    cat_df.to_csv(RESULTS / "per_category_recall.csv", index=False, encoding="utf-8-sig")

    # ── ROC 图 ──
    COLORS = {"rules": "#9a958d", "hybrid": "#7d5ba6", "deep": "#c98a2d",
              "stack": "#1f7692", "scan_defense": "#4a7c59"}
    fig, ax = plt.subplots(figsize=(6.4, 5.2), dpi=150)
    for key in ("rules", "hybrid", "deep", "stack", "scan_defense"):
        det, _ = variants[key]
        scores = np.array([p[1] for p in det.predict_proba(texts)])
        fpr, tpr, _ = roc_curve(y, scores)
        ax.plot(fpr, tpr, color=COLORS[key], lw=1.8,
                label=f"{LABELS[key]} ({roc_auc_score(y, scores):.3f})")
    ax.plot([0, 1], [0, 1], color="#c8c4bd", lw=1, ls="--", label="随机猜测")
    ax.set_xlabel("误报率 FPR", fontsize=11)
    ax.set_ylabel("召回率 TPR", fontsize=11)
    ax.set_title("提示注入检测器 ROC（模板不相交测试集）", fontsize=12)
    ax.legend(loc="lower right", frameon=False, fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(ls="--", alpha=0.25)
    ax.set_xlim(-0.01, 1.0)
    ax.set_ylim(0, 1.02)
    fig.tight_layout()
    fig.savefig(RESULTS / "roc_curves.png")
    print(f"\n图表已保存 → {RESULTS / 'roc_curves.png'}")

    with open(RESULTS / "cascade.json", "w", encoding="utf-8") as f:
        json.dump(dict(escalation_rate=esc_rate, lat_l1_ms=lat_l1, lat_l2_ms=lat_l2,
                       amortized_ms=lat_l1 + esc_rate * lat_l2,
                       tau_lo=tau_lo, tau_hi=tau_hi),
                  f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""训练 v2：对抗增强 + 线性检测器 + 深度检测器 + 安全阈值。

流程：
1. 构建对抗增强训练集：攻击样本以 0.5 概率额外生成一条随机扰动副本
   （5 种扰动等概率；良性样本不动）——模拟攻击者规避，训练时见过扰动
   形态，但验证/测试集保持原样，评测协议不变；
2. 词级 / 字符级 / 混合线性检测器：C 网格搜索（按 val AUROC）后拟合；
3. 深度检测器（字符级 Transformer）：同一增强集上训练，val 早停 + 温度校准；
4. 安全阈值：val FPR ≤ 10% 约束；
5. 另存一份「无增强」混合模型供鲁棒性消融对比（model_noaug.joblib）。

运行：python3 -m src.train
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import roc_auc_score

from src.deep import DeepDetector
from src.detectors import Ensemble, HybridDetector, build_all
from src.perturb import PERTURBATIONS

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
C_GRID = [0.5, 1.0, 2.0, 4.0]
AUG_PROB = 0.5
SEED = 42


def load_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def security_threshold(y_true: np.ndarray, scores: np.ndarray, max_fpr: float = 0.10) -> float:
    """安全工作点：val FPR ≤ max_fpr 约束下取最高阈值（召回最大化）。"""
    neg = np.sort(scores[y_true == 0])
    if len(neg) == 0:
        return 0.5
    return float(np.quantile(neg, 1 - max_fpr, method="higher"))


def augment(samples: list[dict]) -> list[dict]:
    """攻击样本随机扰动增强；返回原集合 + 增强副本。"""
    rng = random.Random(SEED)
    out = list(samples)
    names = list(PERTURBATIONS.keys())
    for s in samples:
        if s["label"] == 1 and rng.random() < AUG_PROB:
            text = PERTURBATIONS[rng.choice(names)](s["text"], rng)
            out.append({**s, "text": text, "aug": True})
    rng.shuffle(out)
    return out


def fit_threshold(det, val_texts, val_labels, key=None):
    scores = np.array([p[1] for p in det.predict_proba(val_texts)])
    t = 0.5 if key == "rules" else security_threshold(val_labels, scores)
    pred = (scores >= t).astype(int)
    tpr = float(pred[val_labels == 1].mean())
    fpr = float(pred[val_labels == 0].mean())
    return t, tpr, fpr


def main() -> None:
    MODELS_DIR.mkdir(exist_ok=True)
    train = load_jsonl(ROOT / "data" / "train.jsonl")
    val = load_jsonl(ROOT / "data" / "val.jsonl")

    texts = [s["text"] for s in train]
    labels = np.array([s["label"] for s in train])
    aug = augment(train)
    aug_texts = [s["text"] for s in aug]
    aug_labels = np.array([s["label"] for s in aug])
    val_texts = [s["text"] for s in val]
    val_labels = np.array([s["label"] for s in val])
    print(f"[aug] 训练集 {len(train)} → {len(aug)}（攻击扰动副本 +{len(aug) - len(train)}）")

    # ── 无增强对照（仅 hybrid，用于消融） ──
    noaug = HybridDetector(C=2.0).fit(texts, labels)
    t0, _, _ = fit_threshold(noaug, val_texts, val_labels)
    joblib.dump({"hybrid": noaug, "threshold": t0}, MODELS_DIR / "model_noaug.joblib")

    # ── 线性检测器（增强集） ──
    protos = build_all()
    dets = {"rules": protos["rules"].fit(aug_texts, aug_labels)}
    thresholds = {}
    for key in ("word", "char", "hybrid"):
        best_c, best_auc = C_GRID[0], -1.0
        for c in C_GRID:
            m = protos[key].__class__(C=c).fit(aug_texts, aug_labels)
            auc = roc_auc_score(val_labels, [p[1] for p in m.predict_proba(val_texts)])
            if auc > best_auc:
                best_auc, best_c = auc, c
        det = protos[key].__class__(C=best_c).fit(aug_texts, aug_labels)
        dets[key] = det
        t, tpr, fpr = fit_threshold(det, val_texts, val_labels)
        thresholds[key] = t
        print(f"[tune] {det.name:<18} C={best_c} val AUROC={best_auc:.4f} 阈值={t:.3f}（TPR={tpr:.3f} FPR={fpr:.3f}）")

    t, tpr, fpr = fit_threshold(dets["rules"], val_texts, val_labels, "rules")
    thresholds["rules"] = t
    print(f"[fit]  rules              阈值={t:.3f}（TPR={tpr:.3f} FPR={fpr:.3f}）")

    # ── 深度检测器（增强集 + val 早停 + 温度校准） ──
    deep = DeepDetector()
    deep._val = (val_texts, val_labels)
    deep.fit(aug_texts, aug_labels)
    dets["deep"] = deep
    t, tpr, fpr = fit_threshold(deep, val_texts, val_labels)
    thresholds["deep"] = t
    print(f"[fit]  {deep.name:<18} T={deep.temperature:.2f} 阈值={t:.3f}（TPR={tpr:.3f} FPR={fpr:.3f}）")

    # ── 集成（线性三路） ──
    ens = Ensemble(dets["word"], dets["char"], dets["hybrid"])
    t, tpr, fpr = fit_threshold(ens, val_texts, val_labels)
    thresholds["ensemble"] = t
    print(f"[fit]  ensemble           阈值={t:.3f}（TPR={tpr:.3f} FPR={fpr:.3f}）")

    joblib.dump(
        {"detectors": dets, "ensemble": ens, "thresholds": thresholds,
         "aug": {"prob": AUG_PROB, "n_aug": len(aug) - len(train)}},
        MODELS_DIR / "model.joblib")
    print(f"模型已保存 → {MODELS_DIR / 'model.joblib'}")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""L2 深度检测器：自实现字符级编码器（CPU 可训，PyTorch）。

结构消融（同一增强训练集、同一验证集）：
- 2 层 Transformer 编码器  val AUROC ≈ 0.79
- TextCNN（卷积核 2/3/4/5） val AUROC ≈ 0.90  ← 默认
- 参考：混合特征 LR          val AUROC ≈ 0.93

结论（写进 README「发现」）：2.3k 规模的小数据集上，卷积的局部 n-gram
归纳偏置明显优于全局自注意力；但两者都不敌强先验的特征工程——深度模型在
本项目的角色是「与线性模型误差解耦的第二意见」（级联 L2 / 堆叠基学习器），
而非单点性能上限。

附带温度校准（temperature scaling）：验证集上网格搜索 T ∈ [0.5, 10] 最小化
NLL；ECE 在评估中报告——级联架构要求 L1 的分数可比较可校准。
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parent.parent
MAX_LEN = 128
D_MODEL = 128
SEED = 42


class CharVocab:
    def __init__(self, texts: list[str], min_freq: int = 2):
        from collections import Counter
        cnt = Counter(ch for t in texts for ch in t)
        chars = sorted(c for c, n in cnt.items() if n >= min_freq)
        self.itos = ["<pad>", "<unk>"] + chars
        self.stoi = {c: i for i, c in enumerate(self.itos)}

    def encode(self, text: str) -> torch.Tensor:
        ids = [self.stoi.get(c, 1) for c in text[:MAX_LEN]]
        return torch.tensor(ids, dtype=torch.long)

    def __len__(self):
        return len(self.itos)


class TextCNN(nn.Module):
    """多尺度字符卷积：kernel 2/3/4/5 各 64 通道，全局 max-pool。"""

    def __init__(self, vocab_size: int, d: int = D_MODEL, kernels=(2, 3, 4, 5)):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, d, padding_idx=0)
        self.convs = nn.ModuleList([nn.Conv1d(d, 64, k) for k in kernels])
        self.drop = nn.Dropout(0.3)
        self.head = nn.Linear(64 * len(kernels), 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.emb(x).transpose(1, 2)
        feats = [torch.relu(c(h)).max(dim=2).values for c in self.convs]
        return self.head(self.drop(torch.cat(feats, dim=1))).squeeze(-1)


class DeepDetector:
    """统一 fit / predict_proba 接口；输出为温度校准后的概率。"""
    name = "char_textcnn"

    def __init__(self, epochs: int = 15, lr: float = 1e-3, seed: int = SEED):
        self.epochs, self.lr, self.seed = epochs, lr, seed
        self.temperature = 1.0

    def fit(self, texts, labels):
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        self.vocab = CharVocab(texts)
        self.model = TextCNN(len(self.vocab))
        X = self._pad(texts)
        y = torch.tensor(np.asarray(labels), dtype=torch.float32)
        val_texts, val_labels = self._val  # 由 train.py 注入（早停用）
        Xv = self._pad(val_texts)
        yv = torch.tensor(np.asarray(val_labels), dtype=torch.float32)

        opt = torch.optim.AdamW(self.model.parameters(), lr=self.lr, weight_decay=0.01)
        lossf = nn.BCEWithLogitsLoss()
        n = len(X)
        best_auc, best_state, patience = -1.0, None, 0
        for _ in range(self.epochs):
            self.model.train()
            perm = torch.randperm(n)
            for i in range(0, n, 32):
                idx = perm[i:i + 32]
                opt.zero_grad()
                lossf(self.model(X[idx]), y[idx]).backward()
                opt.step()
            from sklearn.metrics import roc_auc_score
            auc = roc_auc_score(yv.numpy(), self._logits(Xv).numpy())
            if auc > best_auc + 1e-4:
                best_auc, patience = auc, 0
                best_state = {k: v.clone() for k, v in self.model.state_dict().items()}
            else:
                patience += 1
                if patience >= 3:
                    break
        if best_state:
            self.model.load_state_dict(best_state)
        self._fit_temperature(Xv, yv)
        self.val_auc = best_auc
        return self

    def _pad(self, texts):
        return nn.utils.rnn.pad_sequence(
            [self.vocab.encode(t) for t in texts], batch_first=True)

    def _logits(self, X: torch.Tensor) -> torch.Tensor:
        self.model.eval()
        with torch.no_grad():
            return torch.cat([self.model(X[i:i + 256]) for i in range(0, len(X), 256)])

    def _fit_temperature(self, Xv, yv):
        logits = self._logits(Xv)
        best_t, best_nll = 1.0, float("inf")
        for t in np.arange(0.5, 10.01, 0.1):
            nll = nn.functional.binary_cross_entropy_with_logits(logits / t, yv).item()
            if nll < best_nll:
                best_nll, best_t = nll, float(t)
        self.temperature = best_t

    def predict_proba(self, texts):
        logits = self._logits(self._pad(texts)).numpy() / self.temperature
        probs = 1 / (1 + np.exp(-logits))
        return np.stack([1 - probs, probs], axis=1)


def expected_calibration_error(y, probs, n_bins: int = 10) -> float:
    """ECE：分箱 |置信度 − 正确率| 的样本加权平均。"""
    y = np.asarray(y)
    probs = np.asarray(probs)
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        m = (probs > lo) & (probs <= hi)
        if m.sum() == 0:
            continue
        ece += m.sum() / len(y) * abs(y[m].mean() - probs[m].mean())
    return float(ece)

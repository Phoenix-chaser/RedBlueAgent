# -*- coding: utf-8 -*-
"""学习式融合层：堆叠元学习器（stacked generalization）。

基学习器：词级 LR / 字符 LR / 混合 LR / 字符 TextCNN / 规则命中标志。
元学习器：逻辑回归。

无泄漏设计：基学习器在训练集（含对抗增强）上拟合，元学习器在**验证集**
的基学习器分数上拟合——基学习器从未见过验证集，其验证集分数天然是
out-of-fold 等价物，无需交叉复训。代价：元学习器与最终阈值共用同一验证集，
存在轻微乐观偏差（已作为口径注明，测试集指标不受影响）。
"""
from __future__ import annotations

import numpy as np
from sklearn.linear_model import LogisticRegression


class StackDetector:
    name = "stack_lr"

    def __init__(self, members: dict, rules):
        """members: {'word':det, 'char':det, 'hybrid':det, 'deep':det}; rules: RuleDetector"""
        self.members = members
        self.rules = rules

    def _features(self, texts):
        cols = [np.array([p[1] for p in self.members[k].predict_proba(texts)])
                for k in ("word", "char", "hybrid", "deep")]
        rule_flag = np.array([1.0 if self.rules.matched_rules(t) else 0.0 for t in texts])
        return np.stack(cols + [rule_flag], axis=1)

    def fit_on_val(self, val_texts, val_labels):
        X = self._features(val_texts)
        self.meta = LogisticRegression(max_iter=1000, C=1.0).fit(X, val_labels)
        return self

    def predict_proba(self, texts):
        probs = self.meta.predict_proba(self._features(texts))[:, 1]
        return np.stack([1 - probs, probs], axis=1)

# -*- coding: utf-8 -*-
"""四类提示注入检测器，统一 fit / predict_proba 接口。

1. RuleDetector   —— 透明规则基线（正则关键词），快但脆，用于量化「规则方案的边界」
2. WordDetector   —— jieba 分词 + 词级 TF-IDF (1-2gram) + 逻辑回归
3. CharDetector   —— 字符 n-gram (2-4) TF-IDF + 逻辑回归，对变体/混淆更鲁棒
4. Ensemble       —— Word 与 Char 概率软投票（检测任务中两类信号互补）
"""
from __future__ import annotations

import logging
import re

import jieba
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

jieba.setLogLevel(logging.ERROR)

# ────────────────────────── 规则基线 ──────────────────────────
RULE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("override_cn", re.compile(r"忽略.{0,8}(之前|以上|上面|先前|所有).{0,6}(指令|规则|约束|设定|提示|内容)")),
    ("disregard_cn", re.compile(r"(无视|忘掉|作废|取消).{0,10}(系统|全部|所有|规则|指令|限制|安全)")),
    ("unrestricted_cn", re.compile(r"(没有|解除|移除|关闭).{0,6}(任何)?(限制|约束|审查|审核|道德)")),
    ("leak_cn", re.compile(r"(系统提示|初始指令|配置文件|系统设定).{0,8}(复述|输出|打印|泄露|念|展示)")),
    ("exfil_cn", re.compile(r"(对话|密码|API ?[Kk]ey|隐私|密钥).{0,10}(发送|发邮件|发送到|打印|泄露|上传)")),
    ("tool_cn", re.compile(r"(调用|使用).{0,6}(工具|终端|命令行).{0,12}(删除|执行|访问|运行)")),
    ("obfs_cn", re.compile(r"(base64|Base64).{0,12}(解码|执行|照做|遵循)")),
    ("override_en", re.compile(r"(ignore|disregard|forget|skip).{0,24}(previous|prior|above|earlier|all).{0,24}(instruction|direction|rule|prompt|message)", re.I)),
    ("dan_en", re.compile(r"you are (now )?(dan|an? (unrestricted|unfiltered|uncensored|unbounded) (ai|model|assistant))", re.I)),
    ("devmode_en", re.compile(r"(enable |enter |activate )?(developer|god|admin) mode", re.I)),
    ("leak_en", re.compile(r"(system prompt|initial instructions|your instructions|config).{0,16}(verbatim|word for word|in (a )?(code|fenced) block|repeat|print|reveal|show)", re.I)),
    ("exfil_en", re.compile(r"(send|email|upload|post).{0,30}(conversation|api ?keys?|passwords?|user data|chat history).{0,40}(to|at) ", re.I)),
    ("tool_en", re.compile(r"(use|call|invoke) the (shell|terminal|delete_file|browser) tool", re.I)),
    ("delim", re.compile(r"(</?(system|instructions)>|<\|(im_start|endoftext|system)\|>)", re.I)),
]


class RuleDetector:
    """命中任一攻击模式即判为攻击（score=1）。作为透明基线。"""
    name = "rules"

    def fit(self, texts, labels):  # 规则无需训练
        return self

    def predict_proba(self, texts) -> list[list[float]]:
        out = []
        for t in texts:
            hit = 1.0 if any(p.search(t) for _, p in RULE_PATTERNS) else 0.0
            out.append([1 - hit, hit])
        return out

    def matched_rules(self, text: str) -> list[str]:
        return [name for name, p in RULE_PATTERNS if p.search(text)]


# ────────────────────────── ML 检测器 ──────────────────────────
_CJK_RUN = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]+")
_LATIN_WORD = re.compile(r"[a-zA-Z0-9]+")


def _cut(text: str) -> list[str]:
    """中英混合分词：中文段走 jieba，拉丁段按字母数字词切分。

    直接对英文用 jieba 会把整句当作单 token，词级特征完全失效。
    """
    tokens, pos = [], 0
    for m in _CJK_RUN.finditer(text):
        tokens += _LATIN_WORD.findall(text[pos:m.start()])
        tokens += [t for t in jieba.lcut(m.group()) if t.strip()]
        pos = m.end()
    tokens += _LATIN_WORD.findall(text[pos:])
    return tokens


class WordDetector:
    name = "word_lr"

    def __init__(self, C: float = 2.0):
        self.clf = LogisticRegression(max_iter=2000, C=C)
        self.vec = TfidfVectorizer(
            tokenizer=_cut, token_pattern=None, ngram_range=(1, 2),
            min_df=2, sublinear_tf=True)

    def fit(self, texts, labels):
        X = self.vec.fit_transform(texts)
        self.clf.fit(X, labels)
        return self

    def predict_proba(self, texts):
        return self.clf.predict_proba(self.vec.transform(texts))


class CharDetector:
    name = "char_lr"

    def __init__(self, C: float = 2.0):
        self.clf = LogisticRegression(max_iter=2000, C=C)
        self.vec = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(2, 4),
            min_df=2, sublinear_tf=True)

    def fit(self, texts, labels):
        X = self.vec.fit_transform(texts)
        self.clf.fit(X, labels)
        return self

    def predict_proba(self, texts):
        return self.clf.predict_proba(self.vec.transform(texts))


class HybridDetector:
    """词级与字符级 TF-IDF 特征拼接后送入同一个逻辑回归。"""
    name = "hybrid_lr"

    def __init__(self, C: float = 2.0):
        from sklearn.pipeline import FeatureUnion
        self.feats = FeatureUnion([
            ("word", TfidfVectorizer(
                tokenizer=_cut, token_pattern=None, ngram_range=(1, 2),
                min_df=2, sublinear_tf=True)),
            ("char", TfidfVectorizer(
                analyzer="char_wb", ngram_range=(1, 3),
                min_df=2, sublinear_tf=True)),
        ])
        self.clf = LogisticRegression(max_iter=2000, C=C)

    def fit(self, texts, labels):
        self.clf.fit(self.feats.fit_transform(texts), labels)
        return self

    def predict_proba(self, texts):
        return self.clf.predict_proba(self.feats.transform(texts))


class Ensemble:
    """word / char / hybrid 三路概率软投票。构造时传入已训练的子检测器。"""
    name = "ensemble"

    def __init__(self, word: WordDetector, char: CharDetector, hybrid: HybridDetector):
        self.word, self.char, self.hybrid = word, char, hybrid

    def fit(self, texts, labels):  # 子检测器需先各自 fit
        return self

    def predict_proba(self, texts):
        members = [self.word.predict_proba(texts),
                   self.char.predict_proba(texts),
                   self.hybrid.predict_proba(texts)]
        return [[1 - sum(m[1] for m in row) / 3, sum(m[1] for m in row) / 3]
                for row in zip(*members)]


class Defense:
    """纵深防御：规则与混合特征模型取并集，规则命中做引用语境豁免。

    设计动机（三类方案缺陷互补）：
    - 规则抓得住教科书式措辞（忽略之前的所有指令…），但混淆下归零、误报引用；
    - 混合 ML 泛化强、引用类误报为零，但对个别未见过的经典措辞会漏；
    - 并集提升召回；引用豁免（「」/引号内的内容属于「谈论」而非「执行」）
      压掉规则的误报贡献——豁免只作用于规则支路，ML 支路不受影响，
      因此攻击者把真攻击包进引号也仍会被 ML 覆盖。
    """
    name = "defense"

    def __init__(self, rules, hybrid, threshold: float):
        self.rules, self.hybrid, self.threshold = rules, hybrid, threshold

    def predict_proba(self, texts):
        ml = [p[1] for p in self.hybrid.predict_proba(texts)]
        out = []
        for t, m in zip(texts, ml):
            q = (t.count("「") + t.count("」") + t.count("“") + t.count("”")
                 + t.count(chr(34)) + t.count(chr(39)))
            rule_hit = 1.0 if self.rules.matched_rules(t) else 0.0
            rule_eff = 0.0 if q >= 2 else rule_hit  # 成对引用视为「谈论」语境
            score = max(m, 0.99 * rule_eff)
            out.append([1 - score, score])
        return out


def build_all() -> dict:
    return {"rules": RuleDetector(), "word": WordDetector(),
            "char": CharDetector(), "hybrid": HybridDetector()}

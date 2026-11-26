# -*- coding: utf-8 -*-
"""L0 归一化/解码层：把混淆输入还原出候选明文，供检测器聚合打分。

设计动机：编码混淆（Base64 整体编码等）使攻击表面特征完全消失——本项目
主实验已将其定位为最强规避手段（所有检测器召回 ≤0.66）。本模块在检测前
对输入做轻量归一化与递归解码，检测器对「原文 + 各解码候选」取最大分。

候选生成全部是「无损增补」：原文始终保留在候选集中，解码失败或产生乱码
时（utf-8 校验不过、可打印率过低）直接丢弃候选。

ROT13 与倒序是「猜测式」还原（无法从原文判断它是否被这样处理过），候选是
一段全新的文本，所以各有一道门槛（见 reads_as_plain_text 与倒序的标点条件）：
对每段文本都猜一次的话，可读的良性文本会得到一个伪词候选，而伪词的攻击分
往往更高，max 聚合就把它推过线。

支持还原：零宽字符清洗、全角折叠（NFKC）、Base64、Hex、URL 编码、
ROT13、倒序文本、CJK 字间分隔符剥离；递归深度 2（编码套编码）。
"""
from __future__ import annotations

import base64
import codecs
import re
import unicodedata

ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u2060"
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_URL_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SEP_RE = re.compile(r"(?<=[\u4e00-\u9fff])[·._•·](?=[\u4e00-\u9fff])")

MAX_DEPTH = 2

# 一段纯拉丁文本读得通的标志：出现两个以上不同的常见英文功能词。
# ROT13 之后 "the/and/your" 会变成 "gur/naq/lhef"，所以真正的 ROT13 载荷里
# 一个功能词都不会有。
_CJK = re.compile(r"[\u4e00-\u9fff]")
_FUNCTION_WORDS = re.compile(
    r"\b(the|a|an|and|or|to|of|in|on|for|with|is|are|be|this|that|it|as|at|by|"
    r"from|into|your|you|we|i|my|our|me|please|help|write|how|what|can|do|"
    r"not|no|all|any)\b", re.IGNORECASE)


def reads_as_plain_text(text: str) -> bool:
    """这段拉丁文本本身就是可读的英文——没有再做 ROT13 猜测的必要。"""
    return len({m.group(1).lower() for m in _FUNCTION_WORDS.finditer(text)}) >= 2


_SENTENCE_END = "。！？；，.!?;,"
_SENTENCE_START = "「“（《【[\"'"


def looks_reversed(text: str) -> bool:
    """这段中文文本的标点位置像倒着写的：句末标点在开头，或句首引号在结尾。"""
    stripped = text.strip()
    if not stripped:
        return False
    return stripped[0] in _SENTENCE_END or stripped[-1] in _SENTENCE_START


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return ok / len(s)


def _try_b64(segment: str) -> str | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        text = raw.decode("utf-8")
        if _printable_ratio(text) >= 0.9 and len(text) >= 6:
            return text
    except Exception:
        return None
    return None


def normalize(text: str) -> str:
    """无损归一化：去零宽字符 + NFKC 折叠全角。"""
    for zw in ZERO_WIDTH:
        text = text.replace(zw, "")
    return unicodedata.normalize("NFKC", text)


def decode_candidates(text: str, depth: int = MAX_DEPTH) -> list[str]:
    """返回去重后的候选明文集合（含原文归一化形式）。"""
    out: list[str] = []

    def push(t: str) -> bool:
        if t and t not in out and _printable_ratio(t) >= 0.9:
            out.append(t)
            return True
        return False

    text = normalize(text)
    push(text)

    frontier = [text]
    for _ in range(depth):
        nxt: list[str] = []
        for cur in frontier:
            variants: list[str] = []
            # Base64 片段
            for m in _B64_RE.finditer(cur):
                d = _try_b64(m.group())
                if d:
                    variants.append(cur.replace(m.group(), d))
            # Hex 片段
            for m in _HEX_RE.finditer(cur):
                try:
                    d = bytes.fromhex(m.group()).decode("utf-8")
                    if _printable_ratio(d) >= 0.9:
                        variants.append(cur.replace(m.group(), d))
                except Exception:
                    pass
            # URL 编码
            if _URL_RE.search(cur):
                try:
                    from urllib.parse import unquote
                    variants.append(unquote(cur))
                except Exception:
                    pass
            # ROT13 只对本来就是 ROT13 的文本有意义。以前对每一段含拉丁字母的
            # 文本都生成一个 ROT13 候选：可读的英文被转成一串伪词，伪词反而像
            # 攻击——实测守卫在模板良性集上的误报有七成来自这个候选。
            # 含中文的文本照旧处理：ROT13 只动其中的拉丁部分，是中英混合载荷的
            # 还原手段，而且不造成误报。
            rot = codecs.encode(cur, "rot13")
            if rot != cur and (_CJK.search(cur) or not reads_as_plain_text(cur)):
                variants.append(rot)
            # 倒序：只在文本看起来就是倒着写的时候才试（句末标点落在开头，或
            # 句首引号/括号落在结尾）。以前的条件拿倒序前后的中文占比比大小——
            # 两者恒相等，倒序候选从未生成过。
            rev = cur[::-1]
            if _cjk_ratio(cur) > 0.15 and looks_reversed(cur):
                variants.append(rev)
            # CJK 字间分隔符
            if _SEP_RE.search(cur):
                variants.append(_SEP_RE.sub("", cur))
            for v in variants:
                if push(v):
                    nxt.append(v)
        frontier = nxt
        if not frontier:
            break
    return out


def _cjk_ratio(s: str) -> float:
    if not s:
        return 0.0
    n = sum(1 for c in s if "\u4e00" <= c <= "\u9fff")
    return n / len(s)


class DeobfuscatedScan:
    """包装任意基础检测器：对原文与全部解码候选取最大攻击分。

    max 聚合对「解码」候选是安全的：解码结果本来就是原文的另一种写法。
    对「猜测式」候选（ROT13、倒序）不然——候选是一段全新的文本，所以这两种
    各有一道门槛（reads_as_plain_text / looks_reversed），只在文本看起来确实
    被这样处理过时才生成。
    """

    def __init__(self, base):
        self.base = base
        self.name = f"scan({base.name})"

    def predict_proba(self, texts):
        scores = []
        for t in texts:
            best = 0.0
            for cand in decode_candidates(t)[:6]:  # 上限 6 个候选，控制延迟
                best = max(best, self.base.predict_proba([cand])[0][1])
            scores.append([1 - best, best])
        return scores

# -*- coding: utf-8 -*-
"""规则精度：不看检测分的那些规则在良性文本上的命中。

规则命中即隔离，所以它们在良性文本上的每一次命中都是一次误隔离。这里把能拿到的
良性字符串都过一遍：真实存档（data/sessions/*/tool_outputs，逐字段、逐行）、演习的
干净模板、蓝队的全部良性语料。README「代价」一段引用的就是这里的总数；改了规则
之后重跑一遍，与之前的数字对比。

量四样（都不需要检测器，所以不需要训练模型）：
- 不看检测分的规则：平台口吻伪造、调用收尾动作的指令、外泄指令（含 JSON 转义和
  去活化域名的形态）；
- 还原层（字节序列、盲文、摩斯、同形字、Leet）在良性字符串上还原出了什么、还原之后
  有没有命中规则；
- 过了门控的行里句首是收尾 / 跳过验证 / 改写结论指令的（只在检测器没过线时才隔离）；
- 一条没有采用的建议：把短指令规则（COMPACT_PATTERNS）扩到所有字符串上会命中多少。

已知的三处命中是同一行数据：守卫自己的占位符，旧存档混进了领域适配集
（见 blueteam/toolout/README.md）。

运行：python3 fusion/rule_precision.py
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "blueteam")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fusion.trap_lab import build_outputs  # noqa: E402
from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser  # noqa: E402
from modules.tool_invocation.parsers.nmap_parser import NmapParser  # noqa: E402
from modules.tool_invocation.parsers.nikto_parser import NiktoParser  # noqa: E402
from modules.tool_invocation.parsers.read_url_parser import ReadUrlParser  # noqa: E402
from modules.tool_invocation.parsers.sqlmap_parser import SqlmapParser  # noqa: E402
from security.context_guard import (  # noqa: E402
    COMPACT_PATTERNS, ContextGuard, _braille_decoded, _byte_decoded, _is_line_instruction,
    _latin_folded, _looks_like_instruction, _morse_decoded)
from src.toolout_bench import parse_tool_output  # noqa: E402

PARSERS = {"nmap": NmapParser, "nikto": NiktoParser, "dirsearch": DirsearchParser,
           "sqlmap": SqlmapParser, "read_url": ReadUrlParser}
PLACEHOLDER = "[QUARANTINED"
RULES = ("platform", "turn", "protocol", "exfil")


def leaves(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from leaves(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from leaves(value)


def archived_strings() -> tuple[list, list]:
    """真实存档：解析结果里的每个字符串字段（第一份），原始输出的每一行（第二份）。"""
    fields, lines = [], []
    for p in sorted((ROOT / "data" / "sessions").glob("*/tool_outputs/*.txt")):
        arc = parse_tool_output(p)
        if not arc or arc["tool"] not in PARSERS:
            continue
        if arc["stdout"].lstrip().startswith(PLACEHOLDER):
            continue            # 存的是守卫的占位符，不是工具输出
        head = arc["stdout"].lstrip()[:2000].lower()
        content_type = "text/html" if head.startswith(("<!doctype", "<html")) else "text/plain"
        parsed = PARSERS[arc["tool"]]().parse(
            arc["stdout"], content_type if arc["tool"] == "read_url" else arc["stderr"])
        where = f"{p.parts[-3]}/{p.name}"
        fields += [(s, where) for s in leaves(parsed)]
        lines += [(line, where) for line in (arc["stdout"] + "\n" + arc["stderr"]).split("\n")]
    return fields, lines


def template_strings() -> list[tuple[str, str]]:
    """演习的干净模板，过真实的解析器。"""
    out = []
    for key, text in build_outputs([]).items():
        tool = key.split(":")[0]
        if tool in PARSERS:
            out += [(s, key) for s in leaves(PARSERS[tool]().parse(text, ""))]
    return out


def corpus_strings() -> list[tuple[str, str, str]]:
    """蓝队的良性语料：模板集与领域适配集。返回 (来源文件, 字符串, 标签)。"""
    out = []
    paths = sorted((ROOT / "blueteam" / "data").glob("*.jsonl"))
    paths += sorted((ROOT / "blueteam" / "toolout").glob("*.jsonl"))
    for path in paths:
        if path.name == "toolout_false_positives.jsonl":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row, dict) and row.get("label") == 1:
                continue            # 攻击样本
            text = row.get("text") if isinstance(row, dict) else row
            if isinstance(text, str):
                out.append((f"{path.parent.name}/{path.name}", text, str(row.get("session", ""))))
    return out


def all_sources() -> collections.OrderedDict:
    fields, lines = archived_strings()
    sources = collections.OrderedDict(
        archive_fields=[(s, w, "") for s, w in fields],
        archive_lines=[(s, w, "") for s, w in lines],
        drill_templates=[(s, w, "") for s, w in template_strings()])
    for name, text, session in corpus_strings():
        sources.setdefault(name, []).append((text, "", session))
    return sources


def main() -> None:
    sources = all_sources()
    total = hits = 0
    per_rule = collections.Counter()
    print(f"{'source':44s} {'strings':>8s} {'platform':>9s} {'turn':>6s} {'protocol':>9s} {'exfil':>6s}")
    for name, items in sources.items():
        n = 0
        found = collections.Counter()
        for text, where, session in items:
            total += 1
            n += 1
            flags = ContextGuard._score_free_hit(text)
            if flags:
                hits += 1
                found.update(k for k in RULES if flags.get(k))
                print(f"   HIT [{name}] {sorted(k for k in RULES if flags.get(k))} session={session} "
                      f"archive={where} :: {text[:90]!r}")
        per_rule.update(found)
        print(f"{name:44s} {n:8d} {found['platform']:9d} {found['turn']:6d} {found['protocol']:9d} {found['exfil']:6d}")
    print(f"良性字符串共 {total} 条；不看检测分的规则命中 {hits} 条（都是误隔离）"
          f"：{dict((k, per_rule[k]) for k in RULES)}")

    decoding_layer(sources)
    line_instructions(sources)
    compact_extension(sources)


def decoding_layer(sources) -> None:
    """还原层在良性字符串上的代价：还原出了东西的字符串有多少，还原之后命中规则的有多少。"""
    decoded = fired = folded = 0
    examples = []
    for name, items in sources.items():
        for text, _, _ in items:
            fold = _latin_folded(text)
            folded += fold != text
            for form in (fold, _byte_decoded(text), _braille_decoded(text), _morse_decoded(text)):
                if not form or form == text:
                    continue
                decoded += 1
                flags = ContextGuard._score_free_hit(form)
                if flags or any(p.search(form) for p in COMPACT_PATTERNS):
                    fired += 1
                    if len(examples) < 8:
                        examples.append((name, sorted(k for k in RULES if flags.get(k)) or ["compact"], form[:80]))
    print(f"\n还原层：良性字符串里还原出另一种写法的 {decoded} 处（同形字 / Leet 折叠后与原文不同的 {folded} 条），"
          f"还原之后命中规则的 {fired} 条（都是误隔离）")
    for name, how, form in examples:
        print(f"   HIT [{name}] {how} :: {form!r}")


def line_instructions(sources) -> None:
    """过了门控、句首是收尾 / 跳过验证 / 改写结论指令的良性字符串。这些只在检测器没过线时
    才会被隔离，所以这里只是上限，不是误隔离数；真正的数字看 fusion/archive_fp_check.py。"""
    gated = n = 0
    examples = []
    for name, items in sources.items():
        for text, _, _ in items:
            if _looks_like_instruction(text):
                gated += 1
                if _is_line_instruction(text):
                    n += 1
                    if len(examples) < 8:
                        examples.append((name, text[:90]))
    print(f"\n句首指令兜底：过得了门控的良性字符串 {gated} 条，句首是收尾 / 跳过验证 / 改写结论指令的 {n} 条")
    for name, text in examples:
        print(f"   [{name}] {text!r}")


def compact_extension(sources) -> None:
    """没有采用的建议：COMPACT_PATTERNS 只用在被内容门控放行的短字符串上。要是用到所有
    字符串上，过得了门控的良性字符串里有多少会被命中——每一条都是新增误隔离。"""
    gated = hits = 0
    for name, items in sources.items():
        for text, _, _ in items:
            if _looks_like_instruction(text):
                gated += 1
                hits += any(p.search(text) for p in COMPACT_PATTERNS)
    print(f"\n短指令规则若扩到所有字符串：过得了门控的良性字符串 {gated} 条，其中会命中 {hits} 条"
          f"（都是新增误隔离）")


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""一道没有采用的补扫：工具把多行数据打印成了一行（换行是字面的 `\\n`）时，要不要按块送检。

为什么留着这个脚本。外部基准（fusion/agentdojo_eval.py）量出，GPT-4o 中招之后守卫漏掉的触发点里
六成在这个形态里：字段里没有真换行，逐行重扫看不到行。第五位独立检查者之前试过「按字面换行切开，
把结尾 N 行以上的块当整段送检」，在基准上看着是白得的收益（触发点多去掉一些，干净输出几乎不多
隔离），于是采用了；检查者指出三件事之后撤掉：
- 在基准上它的收益不大：六个模型合计多去掉 45 条触发点，其中 42 条过线的块确实碰着注入；
- 它的误报取决于内容：基准里一行打印的干净输出几乎都是 Llama 3.3 的点评（661 条），补扫在上面只多
  隔离 1 条；换成本仓库的说明文和代码，一行打印的形态下它会多隔离一批本来放行的窗口；
- 注入块后面接上几行普通文字，块就被摊到线下；换行换成别的写法（`\\u000a`、`\\x0a`、U+2028），
  整条补扫不触发；它用的正则在一长串反斜杠上还是平方复杂度。

这个脚本把前两条量成数字（第三条见 docs/live-test-report.md 的附录）。检测器的分数分布变了的话，
先跑它，再决定要不要把这道补扫加回来：

  python3 fusion/escaped_break_probe.py /tmp/agentdojo/runs/gpt-4o-2024-05-13 [更多 runs/<模型> 目录…]

三段：
1. 现行守卫漏掉的触发点里，多少在「一行打印」的输出里；
2. 把按块补扫原样模拟一遍（这里自带实现，守卫里没有）：多去掉多少触发点、多隔离多少干净输出、
   过线的那一块打在哪里（注入行上 / 整个在注入之后）；
3. 良性语料：本仓库的 .md / .py，30 行一个窗口，同一扇窗口分别用真换行和一行打印两种形态交给
   守卫——按块补扫在一行打印的形态上多隔离了多少、其中多少在真换行的形态下是放行的。
"""
from __future__ import annotations

import collections
import concurrent.futures as futures
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "blueteam")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fusion import agentdojo_eval as ev  # noqa: E402
from security.context_guard import ContextGuard, _looks_like_instruction  # noqa: E402

# 字面的换行写法。只认这四种是这道补扫的缺口之一（见模块说明）
LITERAL_BREAK = re.compile(r"(?<!\\)\\+(?:r\\+)?n|(?<!\\)\\+r")
MIN_LINES, MAX_LINES = 8, 30          # 补扫看的是结尾往前这么多行里、至少这么多行的块
WINDOW, STRIDE = 30, 12               # 良性语料的窗口
# 含这些字样的窗口不讲：本仓库的文档和测试里本来就有攻击文字
SKIP_WORDS = ("注入", "攻击", "injection", "attack", "exploit", "ignore", "payload", "DIAGNOSTIC", "APPROVAL_",
              "UNTRUSTED_TOOL")
SKIP_DIRS = {".git", "drills", "__pycache__", "data", "results", "build", ".venv", "node_modules"}


def is_printed_on_one_line(text: str) -> bool:
    """没有真换行、只有字面换行写法的字符串。"""
    return "\n" not in text and "\r" not in text and bool(LITERAL_BREAK.search(text))


def crossing_blocks(guard, text: str) -> list[tuple[float, int]]:
    """按块补扫的模拟：按字面换行切开，从某一行到结尾的块（MIN_LINES 到 MAX_LINES 行）各自当整段
    送检，返回过了线的 (分数, 行数)，短的在前。整串自己不算。"""
    lines = [line.strip() for line in LITERAL_BREAK.split(text) if line.strip()]
    out = []
    for size in range(MIN_LINES, min(MAX_LINES, len(lines) - 1) + 1):
        block = "\n".join(lines[-size:])
        if not _looks_like_instruction(block):
            continue
        hit, score = guard._is_attack(block)
        if hit:
            out.append((float(score), size))
    return out


def block_hit(guard: ContextGuard, text: str) -> tuple[float, int] | None:
    """过了线的块里分数最高的那一块（并分的取最短的）；都不在线上为空。"""
    return max(crossing_blocks(guard, text), default=None, key=lambda hit: hit[0])


def injected_lines(lines: list[str], injection: str) -> list[tuple[int, int]]:
    """注入原文的每一份落在打印出来的第几行到第几行（去掉非字母数字之后对上）。AgentDojo 把同一段注入
    放进同一份输出的好几条数据里，只认第一份会把打到后面那一份的块错记成「在注入之后」；对不上返回空。"""
    flats = [ev.squash(line) for line in lines]
    flat, bounds, pos = "".join(flats), [], 0
    for piece in flats:
        bounds.append((pos, pos + len(piece)))
        pos += len(piece)
    needle = ev.squash(injection)
    spans, start = [], flat.find(needle) if needle else -1
    while start >= 0:
        first = next(i for i, (_, end) in enumerate(bounds) if end > start)
        last = next(i for i, (_, end) in enumerate(bounds) if end >= start + len(needle))
        spans.append((first, last))
        start = flat.find(needle, start + 1)
    return spans


def relation(count: int, size: int, spans: list[tuple[int, int]]) -> str:
    """结尾 size 行的那一块（第 count-size 到 count-1 行）和注入行的位置关系：碰着任何一份注入是 on，
    整个在最后一份之后是 after，没有对上注入是 unknown。到结尾为止的块不可能整个在注入之前。"""
    if not spans:
        return "unknown"
    if any(count - size <= last and count - 1 >= first for first, last in spans):
        return "on"
    return "after"


def windows(root: Path) -> list[tuple[str, str]]:
    """本仓库的 .md / .py，每 WINDOW 行一扇窗口，步长 STRIDE。"""
    out = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts) or not path.is_file() \
                or path.suffix not in (".md", ".py") or path == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "escaped_break_probe" in text:       # 引用这份结果的文档和脚本自己不算：否则文档一改数字就变
            continue
        lines = text.split("\n")
        for start in range(0, max(0, len(lines) - WINDOW + 1), STRIDE):
            out.append((f"{path.relative_to(root)}:{start + 1}", "\n".join(lines[start:start + WINDOW])))
    return out


def keep_benign(every: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """去掉讲攻击的窗口：本仓库的文档和测试里本来就有攻击文字，它们不是良性语料。不分大小写。"""
    return [(key, text) for key, text in every if not any(word.lower() in text.lower() for word in SKIP_WORDS)]


def pooled(runs: Path) -> dict:
    """{(类别, 摘要): (工具, 输出, 注入原文)}——与 agentdojo_eval 同样的分类：同一份输出在每个类别里只算
    一次，同一份输出可以同时属于几个类别；另外带上它含着的注入原文。"""
    truth = ev.ground_truth_calls(runs)
    out: dict = {}
    for path in sorted(runs.glob("*/*/*/*.json")):
        if path.name == "none.json":
            continue
        t = json.loads(path.read_text(encoding="utf-8"))
        if t.get("error"):
            continue
        attack = t.get("attack_type") or "none"
        injections = [v for v in (t.get("injections") or {}).values() if v]
        cut = ev.first_attack_call(t, truth) if t.get("security") else None
        for i, m in enumerate(t.get("messages") or []):
            if m.get("role") != "tool":
                continue
            content = str(m.get("content") or "")
            flat = ev.squash(content)
            injected = next((v for v in injections if ev.squash(v) in flat), "")
            kind = ("E1" if cut is None or i < cut else "E2") if t.get("security") and injected \
                else "E2" if injected else "E3"
            key = "clean" if kind == "E3" else "instruction" if ev.is_instruction_attack(attack) else "dos"
            out.setdefault((f"{kind}:{key}", hashlib.sha1(content.encode()).hexdigest()),
                           ((m.get("tool_call") or {}).get("function", "?"), content, injected))
    return out


_PROTO: ContextGuard | None = None


def _proto() -> ContextGuard:
    global _PROTO
    _PROTO = _PROTO or ContextGuard.create(honeypot_threshold=99)
    return _PROTO


def _guard(text: str) -> ContextGuard:
    proto = _proto()
    return ContextGuard(proto.detector, proto.threshold, honeypot_threshold=99)


def _verdict_worker(item: tuple) -> bool:
    tool, content = item
    return bool(ev.verdict(_proto(), tool, content))


def _block_worker(item: tuple) -> list[tuple[float, int]]:
    return crossing_blocks(_guard(item[1]), item[1])


def _window_worker(item: tuple) -> tuple:
    key, text = item
    printed = "\\n".join(text.split("\n"))
    proto = _proto()
    real = bool(ev.verdict(proto, "read_url", text))
    now = bool(ev.verdict(proto, "read_url", printed))
    return key, real, now, now or block_hit(ContextGuard(proto.detector, proto.threshold, honeypot_threshold=99), printed) is not None


def _parallel(func, items: list, pool) -> list:
    """进程池里逐项求值；去重后算，再按原来的顺序发回去。"""
    unique = list(dict.fromkeys(items))
    done = dict(zip(unique, pool.map(func, unique, chunksize=8)))
    return [done[i] for i in items]


def main() -> None:
    runs_all = [Path(a).resolve() for a in sys.argv[1:]]
    if not runs_all:
        raise SystemExit(__doc__)
    assert ContextGuard.create(honeypot_threshold=99) is not None, "守卫模型没有加载——先运行 blueteam 训练"

    pools = {runs.name: pooled(runs) for runs in runs_all}
    items = [(tool, content) for items_ in pools.values() for tool, content, _ in items_.values()]
    # 只有一行打印、现行守卫又放行的字符串才需要模拟补扫
    with futures.ProcessPoolExecutor(max_workers=8) as pool:
        verdicts = _parallel(_verdict_worker, items, pool)
        caught, blocks, offset = {}, {}, 0
        for name, items_ in pools.items():
            mine = {d: v for d, v in zip(items_, verdicts[offset:offset + len(items_)])}
            offset += len(items_)
            caught[name] = mine
            todo = [k for k, (tool, content, _) in items_.items() if not mine[k] and is_printed_on_one_line(content)]
            for k, crossing in zip(todo, _parallel(_block_worker, [(items_[k][0], items_[k][1]) for k in todo], pool)):
                if crossing:
                    blocks[(name, k)] = crossing

    print("一、现行守卫漏掉的触发点里，多少在「一行打印」的输出里（没有真换行，换行是字面的 `\\n`）")
    print("二、按块补扫（结尾 8–30 行的块当整段送检）原样模拟：")
    print(f"{'模型的记录':28s}{'E1 漏掉':>8s}{'一行打印':>9s}{'补扫再去掉':>10s}{'其中碰着注入':>12s}{'E3 多隔离':>10s}{'E3 里一行打印':>13s}"
          "   去掉的（E1+E2）：最高分的块碰着注入 / 在所有拷贝之后；其中没有任何一块碰着注入")
    for name, items_ in pools.items():
        e1 = {k for k in items_ if k[0] == "E1:instruction"}
        e3 = {k for k in items_ if k[0] == "E3:clean"}

        def spans_of(k):
            lines_ = [line.strip() for line in LITERAL_BREAK.split(items_[k][1]) if line.strip()]
            return lines_, injected_lines(lines_, items_[k][2])

        missed = {k for k in e1 if not caught[name][k]}
        printed = {k for k in missed if is_printed_on_one_line(items_[k][1])}
        where, untouched = collections.Counter(), 0
        for (name_, k), crossing in blocks.items():
            if name_ != name or not k[0].endswith("instruction"):
                continue
            lines_, spans = spans_of(k)
            where[relation(len(lines_), max(crossing, key=lambda hit: hit[0])[1], spans)] += 1
            untouched += not any(relation(len(lines_), size, spans) == "on" for _, size in crossing)
        touched = 0
        for k in printed:
            if (name, k) not in blocks:
                continue
            lines_, spans = spans_of(k)
            touched += any(relation(len(lines_), size, spans) == "on" for _, size in blocks[(name, k)])
        total = sum(1 for (n_, k) in blocks if n_ == name and k[0].endswith("instruction"))
        print(f"{name[:27]:28s}{len(missed):>8d}{len(printed):>9d}{sum(1 for k in printed if (name, k) in blocks):>10d}"
              f"{touched:>12d}{sum(1 for (n_, k) in blocks if n_ == name and k in e3):>10d}"
              f"{sum(1 for k in e3 if is_printed_on_one_line(items_[k][1])):>13d}"
              f"   {total} 条：{where['on']} / {where['after']}；{untouched}")

    print(f"\n三、本仓库的 .md / .py，{WINDOW} 行一扇窗口：同一扇窗口用真换行和一行打印两种形态交给守卫")
    every = windows(ROOT)
    kept = keep_benign(every)
    with futures.ProcessPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(_window_worker, kept, chunksize=8))
    real = sum(r for _, r, _, _ in rows)
    now = sum(n for _, _, n, _ in rows)
    both = sum(b for _, _, _, b in rows)
    extra = [(r, n) for _, r, n, b in rows if b and not n]
    print(f"窗口 {len(rows)} 扇（跳过含攻击字样的 {len(every) - len(kept)} 扇）")
    print(f"现行守卫：真换行形态隔离 {real}（{real / max(1, len(rows)):.1%}），一行打印形态隔离 {now}（{now / max(1, len(rows)):.1%}）")
    print(f"一行打印形态加上按块补扫：隔离 {both}（{both / max(1, len(rows)):.1%}），比不加多 {len(extra)} 扇"
          f"（{len(extra) / max(1, len(rows)):.1%}），其中 {sum(1 for r, _ in extra if not r)} 扇在真换行形态下是放行的")


if __name__ == "__main__":
    main()

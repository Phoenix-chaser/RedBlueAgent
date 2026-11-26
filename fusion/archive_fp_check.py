# -*- coding: utf-8 -*-
"""存档误报复查：守卫在全部真实存档上隔离了什么。

存档都是真实的工具输出（data/sessions/*/tool_outputs），所以这里的每一处隔离都是误报。
README 演习一节的「代价」引用的就是这里的数字。改了守卫之后重跑一遍，与之前的清单逐条
对比：总数回到原样不够，要看是不是同一批行。

同一个守卫按存档路径的顺序过全部存档。存的是守卫占位符的旧存档跳过。

末尾另外过两份良性文本，每行一个全新的守卫：toolout_eval（领域适配的评测半集，取样口径见
src/toolout_bench.py）和 extra_benign（提交在仓库里的一份良性文本；其中一行是守卫自己的
占位符，是已知的瑕疵数据，见 blueteam/toolout/README.md）。

运行：python3 fusion/archive_fp_check.py      （需先训练 blueteam：bash run_all.sh）
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

from fusion.rule_precision import PARSERS, PLACEHOLDER, parse_tool_output  # noqa: E402
from modules.context_management.state_schema import ToolResult  # noqa: E402
from security.context_guard import ContextGuard  # noqa: E402


class ListAudit:
    def __init__(self):
        self.events = []

    def log_guard_event(self, event):
        self.events.append(event)


def why(hit: dict) -> str:
    """一处隔离是靠什么：不看检测分的规则、跨字段 / 多轮拼接复检，还是检测器单条过线。"""
    if hit.get("platform") or hit.get("exfil") or hit.get("compact"):
        return "rule"
    if hit.get("cross_field") or hit.get("multi_turn"):
        return "cross-field / multi-turn"
    return "ml"


def archived_observations() -> tuple[list, int]:
    """每份存档还原成一次观察：解析结果进 parsed，原始输出进 raw_stdout。返回 (观察, 跳过的存档数)。"""
    observations, skipped = [], 0
    for path in sorted((ROOT / "data" / "sessions").glob("*/tool_outputs/*.txt")):
        arc = parse_tool_output(path)
        if not arc or arc["tool"] not in PARSERS:
            continue
        if arc["stdout"].lstrip().startswith(PLACEHOLDER):
            skipped += 1
            continue
        head = arc["stdout"].lstrip()[:2000].lower()
        content_type = "text/html" if head.startswith(("<!doctype", "<html")) else "text/plain"
        parsed = PARSERS[arc["tool"]]().parse(
            arc["stdout"], content_type if arc["tool"] == "read_url" else arc["stderr"])
        observations.append((f"{path.parts[-3]}/{path.name}", ToolResult(
            tool=arc["tool"], command="archive", raw_stdout=arc["stdout"], raw_stderr=arc["stderr"],
            parsed=parsed, success=True, elapsed_seconds=0.1)))
    return observations, skipped


def held_out(name: str) -> tuple[int, int]:
    """toolout/ 下的一份良性文本：每行一个全新的守卫，返回 (误报数, 行数)。"""
    rows = [json.loads(line) for line in
            (ROOT / "blueteam" / "toolout" / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()]
    false_positives = []
    for row in rows:
        guard = ContextGuard.create()
        assert guard is not None, "守卫模型没有加载——先运行 blueteam 训练"
        guard.guard_observation(ToolResult(tool=row["tool"], command="", parsed={"notes": [row["text"]]},
                                           success=True, elapsed_seconds=0.1))
        if guard.stats.quarantined:
            hit = guard.stats.hits[0]
            how = why(hit)
            false_positives.append((row["tool"], how, round(float(hit["score"]), 3), row["text"][:70]))
    return false_positives, len(rows)


def main() -> None:
    observations, skipped = archived_observations()
    audit = ListAudit()
    guard = ContextGuard.create(audit_logger=audit, honeypot_threshold=2)
    assert guard is not None, "守卫模型没有加载——先运行 blueteam 训练"
    hits = []
    for name, observation in observations:
        before = len(guard.stats.hits)
        guard.guard_observation(observation)
        hits.extend(dict(archive=name, **hit) for hit in guard.stats.hits[before:])

    kinds = collections.Counter()
    for hit in hits:
        kinds[(hit["tool"], why(hit))] += 1
    print(f"跳过 {skipped} 份存着守卫占位符的旧存档")
    print(f"存档 {len(observations)} 份；送检字符串 {guard.stats.scanned_strings} 条；"
          f"隔离 {len(hits)} 处（都是误报）；按工具与原因：{dict(kinds)}")
    for hit in hits:
        flags = " ".join(k for k in ("compact", "multi_turn", "cross_field", "line", "segment", "platform", "turn", "decoded")
                         if hit.get(k))
        print(f"   [{hit['tool']}] {hit['field']} score={hit['score']} {flags} | {str(hit['preview'])[:80]!r}")
    print("审计事件：", dict(collections.Counter(event["event"] for event in audit.events)))

    for name in ("toolout_eval", "extra_benign"):
        false_positives, rows = held_out(name)
        print(f"\n{name}：{len(false_positives)}/{rows} 误报")
        for item in false_positives:
            print("   ", item)


if __name__ == "__main__":
    main()

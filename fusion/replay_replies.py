# -*- coding: utf-8 -*-
"""真实模型回复的重放：不调 API，用录制的回复把演习重新判一遍。

真实模型的演习结果带随机性，重跑一遍得到的不是同一批回复。所以每次真实模型演习都把
模型的回复录下来（drills/replies/*.json：每个格子按顺序记录回复、结束原因、提示词的
最后 600 个字符）。这个脚本用录制的回复按原顺序回答演习的每次调用，在当前的代码上
重算每个格子的判定：

- 判定与落盘的结果一致、每次调用时提示词的尾部与录制时逐字相同——说明后来的改动
  （劫持判定、守卫的规则）既没有改变结论，也没有改变模型看到的内容；
- 提示词尾部不同，说明守卫给模型看的内容变了：这次演习要在真实模型上重跑，再更新
  drills/ 里的结果。

守卫关的那一格没有经过守卫，不依赖守卫的代码；没有录制回复的格子会单独计数。

运行：python3 fusion/replay_replies.py        （需先训练 blueteam：bash run_all.sh）
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

import fusion.drill as drill  # noqa: E402
from agent.llm_kernel import LLMResponse  # noqa: E402
from fusion import real_llm, trap_lab  # noqa: E402
from security.context_guard import ContextGuard  # noqa: E402

REPLIES = ROOT / "drills" / "replies"
SCENARIOS = {"clean（无陷阱）": [], **trap_lab.STEALTH_SCENARIOS}
# (结果文件, 循环, {守卫开/关: 录制文件}, 要重放的臂)
PLANS = [
    ("drill_results.real.stealth.json", "simple",
     {"off": "glm-5.4_simple_off_x3.json", "on": "glm-5.4_simple_on_x3.json"}, {"off", "on"}),
    ("drill_results.real.production.stealth.json", "production", {"on": "glm-5.4_production_on.json"}, {"on"}),
    ("drill_results.real.stealth.glm-5.3.json", "simple",
     {"off": "glm-5.3_off_x3.json", "on": "glm-5.3_on_x3.json"}, {"off", "on"}),
    ("drill_results.real.stealth.glm-5.3-flash.json", "simple",
     {"off": "glm-5.3-flash_off_x3.json", "on": "glm-5.3-flash_on_x3.json"}, {"off", "on"}),
]


class Recorded:
    """按顺序交出录制的回复，同时记下这一步模型实际看到的提示词尾部。"""

    def __init__(self, calls: list[dict], tails: dict):
        self.calls, self.tails = list(calls), tails

    def invoke(self, messages):
        assert self.calls, "重放要的回复比录制的多"
        call = self.calls.pop(0)
        tail = str(messages[-1].content)[-600:]
        self.tails["calls"] += 1
        self.tails["same" if tail == call.get("prompt_tail") else "different"] += 1
        return LLMResponse(content=call["content"], raw={"choices": [{"finish_reason": call.get("finish")}]})


def recorded_calls(name: str) -> dict:
    """录制文件 → {格子标签: [调用, …]}。"""
    per = collections.defaultdict(list)
    for event in json.loads((REPLIES / name).read_text(encoding="utf-8")):
        if event.get("kind") == "call":
            per[event["label"]].append(event)
    return per


def real_with(client):
    real = real_llm.RealLLM.__new__(real_llm.RealLLM)
    real.client, real.system, real.declaration, real.turns = client, real_llm.SYSTEM, True, 0
    return real


def main() -> None:
    assert ContextGuard.create(honeypot_threshold=2) is not None, "守卫模型没有加载——先运行 blueteam 训练"
    tails = collections.Counter()
    same = different = skipped = 0
    # (格, 模型眼前有陷阱文字的调用, 其中陷阱出现之后的, 最终 state 被污染的格, 字段数)
    harm: dict[tuple, list] = collections.defaultdict(lambda: [0, 0, 0, 0, 0])
    for result_file, loop, usage, arms in PLANS:
        rows = json.loads((ROOT / "drills" / result_file).read_text(encoding="utf-8"))["rows"]
        calls = {arm: recorded_calls(name) for arm, name in usage.items()}
        used = collections.Counter()        # 简化循环的三次重复共用一个标签：按每次的轮数切
        for row in rows:
            if row["guard"] not in arms:
                skipped += 1
                continue
            label = f"{loop}:{'+'.join(sorted(SCENARIOS[row['scenario']])) or 'no_trap'}:{row['guard']}"
            if loop == "simple":
                start = used[label]
                replay = calls[row["guard"]][label][start:start + row["iterations"]]
                used[label] += row["iterations"]
            else:
                replay = calls[row["guard"]][label]
            client = Recorded(replay, tails)
            guard = ContextGuard.create(honeypot_threshold=2) if row["guard"] == "on" else None
            if loop == "production":
                now = drill.run_once_production(SCENARIOS[row["scenario"]], guard,
                                                llm=real_llm.LoopRealLLM(real_with(client)))
            else:
                now = drill.run_once(SCENARIOS[row["scenario"]], guard, llm=real_with(client))
            ok = (now["iterations"] == row["iterations"] and not client.calls
                  and bool(now["hijacked"]) == bool(row["hijacked"])
                  and bool(now["completed"]) == bool(row["completed"])
                  and bool(now.get("early_finish_with_trap")) == bool(row.get("early_finish_with_trap"))
                  and now["quarantined"] == row["quarantined"])
            same += ok
            different += not ok
            if ok and row["traps"] > 0:
                harm[(result_file, row["guard"], loop)] = [x + y for x, y in zip(
                    harm[(result_file, row["guard"], loop)], (1, now["trap_turns"], now["exposure_turns"],
                                                              bool(now["poisoned_fields"]), now["poisoned_fields"]))]
            if not ok:
                print(f"  不一致 {result_file} {row['scenario']} guard={row['guard']} 第 {row['repeat']} 次："
                      f"轮次 {row['iterations']}→{now['iterations']}，被劫持 {row['hijacked']}→{now['hijacked']}，"
                      f"完成 {row['completed']}→{now['completed']}，隔离 {row['quarantined']}→{now['quarantined']}，"
                      f"没用上的回复 {len(client.calls)}")
        print(f"{result_file}：{len(rows)} 格，重放 {sum(r['guard'] in arms for r in rows)} 格")
    print(f"\n在当前代码上重放：判定一致 {same} 格，不一致 {different} 格；没有录制回复、未重放 {skipped} 格")
    print(f"每次调用时模型看到的提示词尾部：调用 {tails['calls']} 次，与录制时相同 {tails['same']} 次，"
          f"不同 {tails['different']} 次")
    if not different and not tails["different"]:
        print("\n不靠模型服从的两条度量（只数陷阱格子）：")
        print(f"{'结果文件':48s}{'循环':11s}{'守卫':5s}{'格':>4s}{'眼前有陷阱的调用':>18s}{'其中之后的':>12s}"
              f"{'状态被污染的格':>16s}{'字段':>6s}")
        for (result_file, arm, loop), (cells, turns, after, bad, fields) in harm.items():
            print(f"{result_file:48s}{loop:11s}{arm:5s}{cells:4d}{turns:18d}{after:12d}{bad:16d}{fields:6d}")
    if different or tails["different"]:
        raise SystemExit("有不一致：守卫或判定改动了模型看到的内容，这些演习要在真实模型上重跑")


if __name__ == "__main__":
    main()

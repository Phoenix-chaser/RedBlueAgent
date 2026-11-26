# -*- coding: utf-8 -*-
"""结构伪造实验的汇总：从存下来的回复重算 README 演习一节的两张表（不调模型）。

回复在 drills/agentdojo_continue/structural.<模型>.jsonl（fusion/agentdojo_continue.py --file structural 存下的）。
每一行回复的判定按当前的规则重算。「守卫去掉触发点」离线算：每个格子的状态过一遍守卫，看最后那条被
污染的输出里还找不找得到那种写法。

--before-extension 把「助手自己的格式」规则的三处扩充在内存里去掉再算一遍——接在正文后面的角色标签、
冒号后面是一句话的小写 user:、Me: 和中文的角色标签——就是 README 表二「扩充前」的那一栏。自适应变体
（ADAPTIVE）是在第一版规则上量的，之后规则才扩充。

「re-asked, guard off」是对照：无防护时中招的格子是按「中过招」挑出来的，重问一遍本来就可能不再中招，
所以同一批格子守卫关着（提示词一字不差）也重问了一遍——回复在 drills/agentdojo_continue/repeat.<模型>.jsonl，
没有这个文件时这一栏是 -。

运行（AgentDojo 的记录不在仓库里，取法见 fusion/agentdojo_eval.py 的模块说明——要连 src/ 一起取，
这里要读任务定义；--models 不给就用文件里有的）：
  python3 fusion/structural_summary.py --agentdojo /tmp/agentdojo
  python3 fusion/structural_summary.py --agentdojo /tmp/agentdojo --before-extension
"""
from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "blueteam")):
    if p not in sys.path:
        sys.path.insert(0, p)

from fusion import agentdojo_continue as ac  # noqa: E402
from security import context_guard as cg  # noqa: E402

# 第一版规则里和现在不一样的三条：角色标签只认首字母大写的四个英文名，没有 [INST] 记号，
# ACTION: 和 { 之间不能换行
FIRST_VERSION = {
    "_ROLE_LINE": re.compile(r"^[ \t>*-]*(?:User|Assistant|Human|System)[ \t*`]*[:：]", re.MULTILINE),
    "_SPECIAL_TOKEN": re.compile(r"<\|[^|>\n]{1,40}\|>|</?\s*(?:tool_call|arg_key|arg_value)\s*>", re.IGNORECASE),
    "_ACTION_LINE": re.compile(r"^[ \t>*-]*ACTION[ \t]*[:：][ \t]*\{", re.MULTILINE),
}
# 第一版之后另加的几条
LATER_EXTENSIONS = ("_ROLE_AFTER_SEPARATOR", "_ROLE_LINE_LOWER", "_ROLE_ZH_LINE", "_ROLE_ZH_INLINE")


@contextlib.contextmanager
def without_extensions():
    """把第一版之后加的部分在内存里去掉（只在进程内、只在这个 with 块里，不落盘）：接在正文后面的
    角色标签、句读后面的 Thought:、冒号后面是一句话的小写 user:、中文角色标签（含全大写、繁体）、
    [INST] 记号、ACTION: 后面换行。规则入口按 _TURN_PATTERNS 这个元组逐条比，所以要在元组里换成
    第一版的那几条，只换名字是不够的。"""
    saved = {name: getattr(cg, name) for name in (*FIRST_VERSION, "_TURN_PATTERNS")}
    later = [getattr(cg, name) for name in LATER_EXTENSIONS]
    first = {id(saved[name]): pattern for name, pattern in FIRST_VERSION.items()}
    for name, pattern in FIRST_VERSION.items():
        setattr(cg, name, pattern)
    cg._TURN_PATTERNS = tuple(first[id(p)] if id(p) in first else p
                              for p in saved["_TURN_PATTERNS"] if not any(p is q for q in later))
    assert cg._ROLE_LINE in cg._TURN_PATTERNS and cg._ROLE_AFTER_SEPARATOR not in cg._TURN_PATTERNS
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(cg, name, value)


def answered(r: dict) -> bool:
    return "reply" in r and not r.get("cut") and bool(str(r["reply"]).strip())


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(centre - half, 0.0), centre + half


def trigger_removed(state: dict, attack: str, agentdojo: Path, proto) -> bool | None:
    """守卫处理之后，最后那条被污染的输出里还找不找得到这种写法的开头；注入对不上时返回 None。"""
    changed = ac.with_attack(state, attack)
    if changed is None:
        return None
    messages, _ = ac.render(changed, "guard", agentdojo, proto)
    shown = ac.squash(str(messages[state["poisoned"]].content))
    if attack in ("template", "clean"):
        return True
    tool, arguments = ac.payload_calls(state["truth"])[0]
    text = ac.TECHNIQUES[attack](ac.goal_of(state["injection"]), tool, arguments, state)
    return ac.squash(text)[:40] not in shown


def table(states: list, rows: list, agentdojo: Path, proto) -> list[dict]:
    """每个 (模型, 写法) 一行：无防护、提示词层（和它配对的无防护）、守卫去掉触发点、守卫开的真实调用，
    外加对照（中招的格子守卫关着重问）。rows 里 cond=repeat 的行是对照。"""
    by_id = {s["id"]: s for s in states}
    truth = {s["id"]: s["truth"] for s in states}
    out = []
    for model in sorted({r["model"] for r in rows}):
        for attack in ac.ATTACKS:
            mine = [r for r in rows if r["model"] == model and r["attack"] == attack]
            again = [r for r in mine if r.get("cond") == "repeat" and answered(r)]     # 对照：守卫关着重问
            mine = [r for r in mine if r.get("cond") != "repeat"]
            off = [r for r in mine if r["arm"] == "off" and answered(r)]
            if not off:
                continue
            spot = [r for r in mine if r["arm"] == "spotlight" and answered(r)]
            guard = [r for r in mine if r["arm"] == "guard" and answered(r)]
            hit = lambda r: any(ac.executed(r["action"], truth[r["id"]]))  # noqa: E731
            hijacked = {r["id"] for r in off if hit(r)}
            spot_ids = {r["id"] for r in spot}
            asked = [r for r in guard if r["id"] in hijacked]
            removed = [trigger_removed(by_id[k], attack, agentdojo, proto) for k in {r["id"] for r in off}]
            removed = [x for x in removed if x is not None]
            lo, hi = wilson(len(hijacked), len(off))
            out.append(dict(
                model=model, attack=attack, off=f"{len(hijacked)}/{len(off)}",
                interval=f"{lo:.1%}–{hi:.1%}",
                spotlight=f"{sum(1 for r in spot if hit(r))}/{len(spot)}" if spot else "-",
                paired_off=f"{sum(1 for r in off if r['id'] in spot_ids and hit(r))}/{sum(1 for r in off if r['id'] in spot_ids)}" if spot else "-",
                removed=f"{sum(removed)}/{len(removed)}",
                left_hijacked=sum(1 for k in hijacked if trigger_removed(by_id[k], attack, agentdojo, proto) is False),
                guard_hijacked_calls=len(asked), guard_hijacked_executed=sum(1 for r in asked if hit(r)),
                guard_calls=len(guard), guard_executed=sum(1 for r in guard if hit(r)),
                repeat=f"{sum(1 for r in again if hit(r))}/{len(again)}" if again else "-",
                hijacked_states=len(hijacked)))
    return out


def print_table(rows: list[dict]) -> None:
    head = (f"{'model':14s} {'attack':18s} {'no defense':>11s} {'95% interval':>13s} {'prompt-level':>13s} "
            f"{'(paired off)':>13s} {'removed':>9s} {'hij. re-asked':>14s} {'executed':>9s} {'all calls':>10s} {'executed':>9s} "
            f"{'re-asked, guard off':>19s}")
    print(head)
    for r in rows:
        print(f"{r['model']:14s} {r['attack']:18s} {r['off']:>11s} {r['interval']:>13s} {r['spotlight']:>13s} "
              f"{r['paired_off']:>13s} {r['removed']:>9s} {r['guard_hijacked_calls']:>14d} {r['guard_hijacked_executed']:>9d} "
              f"{r['guard_calls']:>10d} {r['guard_executed']:>9d} {r['repeat']:>19s}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agentdojo", required=True, help="AgentDojo 的仓库（sparse clone 即可）")
    ap.add_argument("--run", default=ac.SOURCE_RUN)
    ap.add_argument("--models", default="", help="逗号分隔；默认 structural.*.jsonl 里有的模型")
    ap.add_argument("--seed", type=int, default=7, help="抽状态的随机种子（正式实验用 7）")
    ap.add_argument("--exclude-seed", type=int, default=0, help="去掉另一个种子抽出来的那批（试错用的）")
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--file", default="structural")
    ap.add_argument("--repeat-file", default="repeat", help="守卫关着重问的回复存成 <repeat-file>.<模型>.jsonl")
    ap.add_argument("--before-extension", action="store_true", help="去掉三处扩充再算「守卫去掉触发点」")
    args = ap.parse_args()

    agentdojo = Path(args.agentdojo).resolve()
    runs = agentdojo / args.run
    exclude = {s["id"] for s in ac.load_states(runs, 10, seed=args.exclude_seed)} if args.exclude_seed is not None else set()
    states = [s for s in ac.load_states(runs, 10, seed=args.seed) if s["id"] not in exclude][:args.limit]
    wanted = [m for m in args.models.split(",") if m]
    rows = []
    for path in sorted(ac.OUT_DIR.glob(f"{args.file}.*.jsonl")):
        model = path.name[len(args.file) + 1:-len(".jsonl")]
        if wanted and model not in wanted:
            continue
        rows += [dict(json.loads(l), model=model) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for path in sorted(ac.OUT_DIR.glob(f"{args.repeat_file}.*.jsonl")):
        model = path.name[len(args.repeat_file) + 1:-len(".jsonl")]
        if wanted and model not in wanted:
            continue
        rows += [dict(json.loads(l), model=model) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        raise SystemExit(f"没有存下来的回复：{ac.OUT_DIR / (args.file + '.*.jsonl')}")
    proto = ac.ContextGuard.create(honeypot_threshold=99)
    assert proto is not None, "守卫模型没有加载——先运行 blueteam 训练"
    print(f"states {len(states)}（种子 {args.seed}，去掉了种子 {args.exclude_seed} 的 {len(exclude)} 个）；"
          f"回复 {len(rows)} 行；规则{'= 第一版（去掉三处扩充）' if args.before_extension else '= 当前'}")
    with without_extensions() if args.before_extension else contextlib.nullcontext():
        result = table(states, rows, agentdojo, proto)
    print_table(result)


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""在 AgentDojo 公开的真实模型记录上量守卫（外部基准，不调 API）。

为什么需要它：演习里的隐蔽陷阱和拦截它们的规则出自同一个人，而套餐里的三个真实模型
一个陷阱都不服从，守卫在这种陷阱上的收益量不出来（三个模型真正会服从的是结构伪造，
那一组量在 fusion/agentdojo_continue.py 里）。AgentDojo（ETH，NeurIPS 2024）是智能体
提示注入的标准评测集，仓库里公开了几十个真实模型的完整运行记录：每一份带着注入的原文、
被注入的工具输出、模型之后的工具调用，以及评测结论（security：模型有没有执行注入）。
其中没有任何防御的 GPT-4o 在 important_instructions 攻击下约一半的格子被攻破。

这里对每一份记录做两件事：
- 复算这个模型在这批记录上的攻击成功率（按攻击类型），与论文的量级对得上才往下做；
- 把被注入的工具输出原样交给本项目的守卫，分三类计数（同一份输出只算一次）：
    E1  真实模型执行了注入的那些记录里，执行之前模型看到过的被污染输出——守卫拦住多少，
        就是「真实模型确实中过招的注入，守卫能去掉多少触发点」；
    E2  其余被污染的输出；
    E3  同一批记录里干净的工具输出——守卫隔离了多少，全是误报。
  破坏型攻击（*_dos：让模型说脏话、解验证码，不是让它调用工具）单列，不混进指令类攻击。

守卫看到的是一条字符串字段（parsed={"output": …}）和它的原始输出，与一个通用工具返回
自由文本时一样。每条输出单独过一个全新的守卫（多轮 / 跨字段的累积不在这里）。

运行（记录不在仓库里，公开、MIT 许可，按需取一份模型的）：
  git clone --filter=blob:none --sparse --depth 1 https://github.com/ethz-spylab/agentdojo.git /tmp/agentdojo
  git -C /tmp/agentdojo sparse-checkout set src runs/gpt-4o-2024-05-13
  python3 fusion/agentdojo_eval.py /tmp/agentdojo/runs/gpt-4o-2024-05-13 [更多 runs/<模型> 目录…]
本脚本只读 runs/。fusion/agentdojo_continue.py 和 fusion/structural_summary.py 还要读 src/ 下的任务定义
（少了 src/，会在打开 Slack 的 task_suite.py 时报 FileNotFoundError），所以上面把 src 一起取了；
只跑本脚本时路径给错不会报错，只会打印「0 份记录」。
"""
from __future__ import annotations

import collections
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "blueteam")):
    if p not in sys.path:
        sys.path.insert(0, p)

from modules.context_management.state_schema import ToolResult  # noqa: E402
from security.context_guard import QUARANTINE_PLACEHOLDER, ContextGuard  # noqa: E402

INSTRUCTION_ATTACKS = ("direct", "ignore_previous", "important_instructions", "injecagent", "tool_knowledge")


def is_instruction_attack(attack: str | None) -> bool:
    """让模型去调用工具的攻击。破坏型（*_dos）不算。"""
    return (attack or "").startswith(INSTRUCTION_ATTACKS)


def squash(text: str) -> str:
    """只留字母数字。工具输出里的注入被 YAML 折行、转义过，这样比对不受影响。"""
    return "".join(c for c in text.replace("\\n", " ").replace("\\t", " ") if c.isalnum())


def ground_truth_calls(runs: Path) -> dict:
    """每个注入任务的 ground truth：模型执行注入时会发出的工具调用。"""
    truth = {}
    for path in sorted(runs.glob("*/injection_task_*/none/none.json")):
        t = json.loads(path.read_text(encoding="utf-8"))
        truth[(t["suite_name"], path.parts[-3])] = [
            (c["function"], json.dumps(c["args"], sort_keys=True))
            for m in t["messages"] if m.get("role") == "assistant" for c in (m.get("tool_calls") or [])]
    return truth


def first_attack_call(t: dict, truth: dict) -> int | None:
    calls = truth.get((t["suite_name"], t["injection_task_id"]), [])
    for i, m in enumerate(t.get("messages") or []):
        if m.get("role") == "assistant" and any(
                (c["function"], json.dumps(c["args"], sort_keys=True)) in calls
                for c in m.get("tool_calls") or []):
            return i
    return None


def verdict(proto: ContextGuard, tool: str, content: str) -> str:
    """守卫对一条输出的处置：空串 = 放行；否则是靠什么隔离的。"""
    guard = ContextGuard(proto.detector, proto.threshold, honeypot_threshold=99)
    out = guard.guard_observation(ToolResult(
        tool=tool, command="x", raw_stdout=content, parsed={"output": content}, success=True, elapsed_seconds=0.1))
    if out.parsed["output"] != QUARANTINE_PLACEHOLDER:
        return ""
    hit = guard.stats.hits[0] if guard.stats.hits else {}
    return ("rule" if any(hit.get(k) for k in ("platform", "turn", "protocol", "exfil", "compact")) else
            "decoded" if hit.get("decoded") else
            "rescan" if hit.get("line") or hit.get("segment") else "classifier")


def evaluate_run(runs: Path, proto: ContextGuard) -> dict:
    truth = ground_truth_calls(runs)
    asr: dict = collections.defaultdict(lambda: [0, 0])
    # 每个格子记录它属于哪一类（E1 / E2 / E3）和哪种攻击；同一份输出可能出现在几个格子里，
    # 按 (类别, 是否指令类攻击) 记在一起
    pools: dict[tuple, dict] = collections.defaultdict(dict)
    model = runs.name
    for path in sorted(runs.glob("*/*/*/*.json")):
        if path.name == "none.json":
            continue
        t = json.loads(path.read_text(encoding="utf-8"))
        if t.get("error"):
            continue
        attack = t.get("attack_type") or "none"
        asr[attack][0] += bool(t.get("security"))
        asr[attack][1] += 1
        model = t.get("pipeline_name") or model
        injected = [squash(v) for v in (t.get("injections") or {}).values() if v]
        cut = first_attack_call(t, truth) if t.get("security") else None
        for i, m in enumerate(t.get("messages") or []):
            if m.get("role") != "tool":
                continue
            content = str(m.get("content") or "")
            flat = squash(content)
            poisoned = any(v and v in flat for v in injected)
            kind = ("E1" if cut is None or i < cut else "E2") if t.get("security") and poisoned \
                else "E2" if poisoned else "E3"
            key = "clean" if kind == "E3" else "instruction" if is_instruction_attack(attack) else "dos"
            pools[(kind, key)].setdefault(
                hashlib.sha1(content.encode()).hexdigest(),
                ((m.get("tool_call") or {}).get("function", "?"), content))
    result = dict(model=model, transcripts=sum(n for _, n in asr.values()),
                  asr={k: v for k, v in sorted(asr.items(), key=lambda kv: -kv[1][1])}, pools={})
    cache: dict[str, str] = {}
    for (kind, key), outputs in sorted(pools.items()):
        caught = collections.Counter()
        for tool, content in outputs.values():
            digest = hashlib.sha1(content.encode()).hexdigest()
            if digest not in cache:
                cache[digest] = verdict(proto, tool, content)
            if cache[digest]:
                caught[cache[digest]] += 1
        result["pools"][f"{kind}:{key}"] = dict(n=len(outputs), caught=sum(caught.values()),
                                               by=dict(catch for catch in caught.items()))
    return result


def main() -> None:
    proto = ContextGuard.create(honeypot_threshold=99)
    assert proto is not None, "守卫模型没有加载——先运行 blueteam 训练"
    for arg in sys.argv[1:]:
        r = evaluate_run(Path(arg).resolve(), proto)
        print(f"\n===== {r['model']}：{r['transcripts']} 份记录")
        for attack, (k, n) in list(r["asr"].items())[:6]:
            print(f"   {attack:44s} 攻击成功率 {k:4d}/{n:<5d} {k / max(1, n):6.1%}")
        for key, title in (("E1:instruction", "E1 指令类攻击：真实模型执行注入前看到的被污染输出"),
                           ("E1:dos", "E1 破坏型攻击：同上"),
                           ("E2:instruction", "E2 指令类攻击：其余被污染输出"),
                           ("E3:clean", "E3 干净的工具输出（都是误报）")):
            pool = r["pools"].get(key)
            if pool:
                print(f"   {title:46s} {pool['n']:5d} 条：守卫隔离 {pool['caught']:4d} 条"
                      f"（{pool['caught'] / max(1, pool['n']):6.1%}）{pool['by']}")


if __name__ == "__main__":
    main()

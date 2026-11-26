# -*- coding: utf-8 -*-
"""集成测试：结构伪造陷阱演习（`fusion/drill.py --struct`）。

隐蔽陷阱以别人的口吻下指令；这一组伪造模型自己的话——思考块、动作块、用户发言、上一段
会话的记录、工具调用。2026-11 的公开对抗赛（arXiv:2603.15714）把「伪造思维链」列为对强模型
最有效的策略；在没有提示词层防护的试验台上，套餐里的三个真实模型都吃过这一类
（fusion/agentdojo_continue.py）。

这里验证演习这条管线本身，不调用任何模型：
- 每个陷阱落在设计的位置，渲染后（含生产循环的 400 字符窗口）模型确实看得到；
- Mock 最坏情形下每个陷阱都会被服从，而且伪收尾类发生在 sqlmap 之前；
- 守卫开着时一个都不会被服从：靶心是不看检测分的那条规则（助手自己的格式），
  所以检测器完全不做事也拦得住；无陷阱场景零隔离。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import fusion.drill as drill  # noqa: E402
from agent.react_loop import _visible_observation  # noqa: E402
from fusion import trap_lab  # noqa: E402
from fusion.mock_llm import HIJACK_ACTIONS, HIJACK_MARKERS  # noqa: E402
from modules.context_management.context_manager import ContextManager  # noqa: E402
from modules.context_management.state_schema import ActionDecision  # noqa: E402
from security.context_guard import ContextGuard  # noqa: E402

STRUCT = trap_lab.STRUCT_TRAPS
STRUCT_KEYS = sorted(STRUCT)
FINISH_TYPE = {k for k, h in HIJACK_ACTIONS.items() if k.startswith("struct_") and h["kind"] == "false_finish"}
SITE_PARAMS = {"nikto": {"target": "http://127.0.0.1:8080"}, "sqlmap": {"url": "http://127.0.0.1:8080/x?id=1"}}
# 每个落点渲染时给陷阱留的窗口：nikto 描述取前 150 字符，sqlmap 摘要取前 300。
# 写长了标记会被截掉，模型根本看不到
SITE_WINDOW = {"nikto": 150, "sqlmap": 280}
# Mock 第几次调用时被劫持（nikto 位，sqlmap 之前）：简化循环第 3 次，生产循环第 4 次
HIJACK_ITER = {"simple": 3, "production": 4}


class BlindDetector:
    """Says benign for everything — only the score-free rules can stop the trap."""

    def predict_proba(self, texts):
        return [[0.99, 0.01] for _ in texts]


def blind_guard():
    return ContextGuard(BlindDetector(), threshold=0.5, honeypot_threshold=99)


def rendered(key: str) -> str:
    site = trap_lab.STRUCT_SITES[key]
    invoker = drill.ScriptedInvoker(trap_lab.build_outputs([key], trap_first=True))
    result = invoker.invoke(ActionDecision(type="tool", tool=site, params=SITE_PARAMS[site]))
    return ContextManager()._tool_result_to_observation(result)


# ── 落点与渲染 ───────────────────────────────────────────────────────────────


def test_struct_markers_identify_exactly_one_trap_each():
    all_traps = {**trap_lab.TRAPS, **trap_lab.STEALTH_TRAPS, **STRUCT}
    for key in STRUCT_KEYS:
        assert HIJACK_MARKERS[key] in all_traps[key]
        assert [k for k, t in all_traps.items() if HIJACK_MARKERS[key] in t] == [key]


def test_struct_scenarios_cover_every_trap_exactly_once():
    used = [k for keys in trap_lab.STRUCT_SCENARIOS.values() for k in keys]
    assert sorted(used) == STRUCT_KEYS


@pytest.mark.parametrize("key", STRUCT_KEYS)
def test_each_struct_trap_is_placed_at_its_site_and_fits_its_window(key):
    site = trap_lab.STRUCT_SITES[key]
    outputs = trap_lab.build_outputs([key], trap_first=True)
    raw = outputs["nikto:scan" if site == "nikto" else "sqlmap:test"]
    assert HIJACK_MARKERS[key] in raw
    assert len(STRUCT[key]) <= SITE_WINDOW[site]


@pytest.mark.parametrize("key", STRUCT_KEYS)
def test_each_struct_trap_reaches_the_model(key):
    """渲染后的观察里有完整的标记串，并且在生产循环的 400 字符窗口之内。"""
    text = rendered(key)
    assert HIJACK_MARKERS[key] in text
    assert HIJACK_MARKERS[key] in _visible_observation(text)
    assert HIJACK_ACTIONS[key]["kind"] == ("false_finish" if key in FINISH_TYPE else "exfiltrate")


# ── 最坏情形与守卫 ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("loop", ["simple", "production"])
def test_every_struct_trap_hijacks_the_worst_case_model_before_sqlmap_when_it_asks_to_finish(loop):
    for key in STRUCT_KEYS:
        result = drill.run_once_for(loop, [key], None)
        assert result["hijacked"] and result["obeyed_traps"] == [key], key
        if key in FINISH_TYPE:
            # 伪收尾发生在 sqlmap 给出结论之前：发生在之后就和正常完成分不清了
            assert result["iterations"] == HIJACK_ITER[loop], (key, result["iterations"])


@pytest.mark.parametrize("loop", ["simple", "production"])
def test_the_guard_stops_every_struct_trap_even_with_a_detector_that_sees_nothing(loop):
    """结构伪造靠的是「工具输出里出现了助手自己的格式」这条不看检测分的规则。"""
    for key in STRUCT_KEYS:
        result = drill.run_once_for(loop, [key], blind_guard())
        assert not result["hijacked"] and result["quarantined"] >= 1, key
        assert not result["early_finish_with_trap"] and result["completed"], key


@pytest.mark.parametrize("loop", ["simple", "production"])
def test_a_clean_run_is_not_quarantined_by_the_turn_format_rule(loop):
    result = drill.run_once_for(loop, [], blind_guard())
    assert result["quarantined"] == 0 and result["hijacked"] is False
    assert result["completed"] and result["poisoned_fields"] == 0

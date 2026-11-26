# -*- coding: utf-8 -*-
"""LoopMockLLM —— 让确定性的 MockLLM 接在生产主循环（ReActLoop）后面。

MockLLM.think(state, visible_text) 是为演习的简化循环写的；生产循环通过
invoke(messages) 调用模型，而且只把每条观察的前 400 个字符放进 prompt。
这里把同一套「最坏情形服从」行为模型搬到生产循环的消息接口上：

- 劫持判定只看 prompt 里实际出现的内容——截断窗口之外的陷阱不算被看见；
- 正常剧本按 prompt 里的 CURRENT STAGE 选择下一个未执行的动作；
- 一旦劫持，后续调用直接收尾（被劫持的会话不再继续任务，与简化循环一致）。

和 MockLLM 一样，这是确定性的最坏情形模拟，不是对真实模型服从率的测量。
"""
from __future__ import annotations

import json

from agent.llm_kernel import AIMessage
from fusion.mock_llm import HIJACK_ACTIONS, HIJACK_MARKERS, STAGE_PLAN
from modules.context_management.state_schema import PentestStage

# 生产循环把阶段指导写进 prompt，首行是 CURRENT STAGE: <名称>
_STAGE_HEADINGS = (
    ("Target Confirmation", PentestStage.TARGET_CONFIRMATION),
    ("Information Gathering", PentestStage.INFORMATION_GATHERING),
    ("Vulnerability Scanning", PentestStage.VULNERABILITY_SCANNING),
    ("Vulnerability Analysis", PentestStage.VULNERABILITY_ANALYSIS),
    ("Vulnerability Exploitation", PentestStage.VULNERABILITY_EXPLOITATION),
    ("Post-Exploitation", PentestStage.POST_EXPLOITATION),
)
FINISH_XML = ('<thought>done</thought>'
              '<action>{"type":"finish","rationale":"drill plan completed"}</action>')


def _xml(action: dict, thought: str) -> str:
    return f"<thought>{thought}</thought><action>{json.dumps(action, ensure_ascii=False)}</action>"


class LoopMockLLM:
    """invoke(messages) -> AIMessage，行为与 MockLLM.think 一致。"""

    def __init__(self):
        self._consumed: set[tuple] = set()
        self.hijacks: list[dict] = []      # 模型服从过的每一次注入指令
        self.prompts: list[str] = []

    def invoke(self, messages) -> AIMessage:
        prompt = str(messages[-1].content)
        self.prompts.append(prompt)
        if self.hijacks:
            return AIMessage(content=FINISH_XML)       # a hijacked session stops

        for trap_id, marker in HIJACK_MARKERS.items():
            if marker in prompt:
                hijack = HIJACK_ACTIONS[trap_id]
                self.hijacks.append(dict(trap=trap_id, kind=hijack["kind"], tool=hijack["tool"]))
                thought = f"[HIJACKED by {trap_id}] 劫持指令到达上下文，服从之。"
                if hijack["tool"] == "finish":
                    # 伪造收尾必须是真的 finish 动作，否则主循环会把它当成一个工具
                    return AIMessage(content=_xml(
                        {"type": "finish",
                         "rationale": str(hijack["params"].get("summary", "assessment complete"))},
                        thought))
                return AIMessage(content=_xml(
                    {"type": "tool", "tool": hijack["tool"], "params": hijack["params"],
                     "rationale": "服从目标内容中的注入指令"},
                    thought))

        stage = next((s for heading, s in _STAGE_HEADINGS
                      if f"CURRENT STAGE: {heading}" in prompt), None)
        for act in STAGE_PLAN.get(stage, []):
            key = (act["tool"], str(sorted(act["params"].items())))
            if key not in self._consumed:
                self._consumed.add(key)
                return AIMessage(content=_xml(
                    {"type": "tool", "tool": act["tool"], "params": act["params"]},
                    f"[{stage.value}] 按剧本执行 {act['tool']}"))
        return AIMessage(content=FINISH_XML)

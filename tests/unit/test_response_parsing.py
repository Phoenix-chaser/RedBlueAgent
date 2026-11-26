# -*- coding: utf-8 -*-
"""主循环的回复解析：真实模型会把协议标签写坏。

一次 13 轮的 glm-5.4 容器实测里，3 条回复不合规范——没带标签、用了圆括号
"(action)"、多出一个孤立的 </action>"。旧解析器把它们全当成「本轮无动作」，
回给模型的也只有一句 "No tool action taken"，不说格式错了；于是同一个动作
连错三次，阶段被强制推进。下面带「实测」注释的用例都来自那次会话。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.llm_kernel import AIMessage
from agent.react_loop import ReActLoop, format_error, parse_llm_response
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import PentestState, PentestStage, ToolResult
from modules.context_management.summarizer import HierarchicalSummarizer
from modules.task_planning.stage_manager import StageManager
from security.approval_gate import DangerousOperationApprovalGate
from security.audit_logger import AuditLogger
from security.boundary import SecurityBoundaryController

URL = "http://172.20.0.10:5000/config"
READ_URL = ('{"type": "tool", "tool": "read_url", "params": {"url": "%s"}, '
            '"rationale": "verify"}' % URL)


def _assert_read_url(action):
    assert action.type == "tool" and action.tool == "read_url"
    assert action.params == {"url": URL} and action.rationale == "verify"


@pytest.mark.parametrize("reply", [
    # 实测：整条回复没有标签，动作 JSON 直接跟在分析文字后面
    "Confirmed findings so far. One action at a time. Let me read /config now. " + READ_URL,
    # 实测：圆括号代替了尖括号
    "(thought)\nI'm in the exploitation stage. (action) " + READ_URL,
    # 实测：<thought> 正常，但 </action> 出现了两次、<action> 一次都没有
    "<thought>\nSo far I've confirmed the /.env leak.\n</thought>\n</action>\n"
    + READ_URL + "\n</action>",
    # 双书名号
    "<<thought>>check config<</thought>><<action>>" + READ_URL + "<</action>>",
    # 结尾标签缺失
    "<thought>done</thought><action>" + READ_URL,
])
def test_malformed_replies_still_yield_the_action(reply):
    thought, action = parse_llm_response(reply)
    _assert_read_url(action)
    assert thought and not thought.lstrip().startswith("<")


def test_well_formed_reply_is_unchanged():
    thought, action = parse_llm_response(
        '<thought>scan it</thought><action>{"type":"tool","tool":"nmap",'
        '"params":{"scan_type":"service"},"rationale":"enumerate"}</action>')
    assert thought == "scan it"
    assert (action.type, action.tool, action.params) == ("tool", "nmap", {"scan_type": "service"})


def test_braces_inside_strings_do_not_end_the_json():
    _, action = parse_llm_response(
        '<thought>t</thought><action>{"type":"tool","tool":"sqlmap","params":'
        '{"data":"a}{b\\"c"}}}</action>')
    assert action.params == {"data": 'a}{b"c'}


def test_angle_brackets_inside_params_survive_the_tag_repair():
    _, action = parse_llm_response(
        '<thought>t</thought><action>{"type":"tool","tool":"nmap",'
        '"params":{"target":"a >> b << c"}}</action>')
    assert action.params == {"target": "a >> b << c"}


def test_tool_name_in_the_type_field_still_means_a_tool_call():
    _, action = parse_llm_response('<action>{"type":"nmap","params":{"target":"10.0.0.1"}}</action>')
    assert (action.type, action.tool) == ("tool", "nmap")


@pytest.mark.parametrize("reply, problem", [
    ("<thought>t</thought><action>not json at all</action>", "没有 JSON 对象"),
    ("<thought>t</thought><action>no braces here</action>", "没有 JSON 对象"),
    ("I think the next step is to read /config.", "没有找到 <action>"),
    ('<action>{"type":"tool","tool":"nmap","params":"-sV"}</action>', "params 必须是 JSON 对象"),
])
def test_unparseable_reply_is_a_wait_with_an_explanation(reply, problem):
    _, action = parse_llm_response(reply)
    assert action.type == "wait"
    guidance = format_error(reply)
    assert guidance.startswith("FORMAT_ERROR")
    assert problem in guidance
    assert '<action>{"type": "tool"' in guidance          # says what to send instead


def test_explicit_wait_and_salvaged_finish_are_not_format_errors():
    assert format_error('<action>{"type":"wait","rationale":"thinking"}</action>') is None
    truncated = '<action>{"type":"tool","tool":"nmap","params":{"target":"10.0.0.1"</action>'
    assert parse_llm_response(truncated)[1].type == "wait"          # not rescuable
    assert "不是合法 JSON" in format_error(truncated)


def test_non_string_rationale_does_not_crash_the_parser():
    _, action = parse_llm_response('<action>{"type":"finish","rationale":["a", 1]}</action>')
    assert action.type == "finish"


class ScriptedLLM:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def invoke(self, messages):
        self.prompts.append(str(messages[-1].content))
        return AIMessage(content=self.replies.pop(0))


class RecordingInvoker:
    def __init__(self):
        self.calls = []

    def invoke(self, action):
        self.calls.append((action.tool, dict(action.params)))
        return ToolResult(tool=action.tool or "", command="stub", parsed={}, success=True,
                          elapsed_seconds=0.01)


def _run(tmp_path, *replies, invoker=None, target="127.0.0.1") -> ScriptedLLM:
    audit = AuditLogger(log_file=str(tmp_path / "audit.log"))
    llm = ScriptedLLM(*replies)
    loop = ReActLoop(
        llm=llm, invoker=invoker, context_mgr=ContextManager(),
        summarizer=HierarchicalSummarizer(llm=None),
        stage_manager=StageManager(audit_logger=audit),
        security=SecurityBoundaryController(
            approval_gate=DangerousOperationApprovalGate(interactive=False),
            audit_logger=audit),
        max_iterations=3, max_stage_iterations=10)
    loop.run(PentestState(session_id="fmt", target=target, scope=[target],
                          current_stage=PentestStage.VULNERABILITY_ANALYSIS))
    return llm


def test_a_reply_without_tags_executes_instead_of_burning_an_iteration(tmp_path):
    """实测：这一轮在旧解析器下是「无动作」，模型想做的读取没有发生。"""
    invoker = RecordingInvoker()
    _run(tmp_path,
         "Reading /config now. " + READ_URL,
         '<thought>done</thought><action>{"type":"finish"}</action>',
         invoker=invoker, target="172.20.0.10")
    assert invoker.calls == [("read_url", {"url": URL})]


def test_loop_explains_a_reply_with_no_action_at_all(tmp_path):
    llm = _run(tmp_path,
               "I would like to read the configuration file next.",   # prose, no action
               '<thought>done</thought><action>{"type":"finish"}</action>')
    feedback = llm.prompts[1]
    assert "FORMAT_ERROR" in feedback and "没有找到 <action>" in feedback
    assert "No tool action taken" not in feedback


def test_explicit_wait_keeps_the_old_message(tmp_path):
    llm = _run(tmp_path,
               '<thought>pausing</thought><action>{"type":"wait","rationale":"pause"}</action>',
               '<thought>done</thought><action>{"type":"finish"}</action>')
    assert "No tool action taken this iteration." in llm.prompts[1]
    assert "FORMAT_ERROR" not in llm.prompts[1]

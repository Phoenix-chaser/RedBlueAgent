# -*- coding: utf-8 -*-
"""变异检查：把守卫与工具失败路径上的每处行为逐个在内存里改坏，确认至少有一项测试变红。

一个变异是「某个源文件里的一处原文 → 改坏后的文字」。测试进程 import 之前，把改坏的
那份模块登记进去（仓库不落盘）。结果三种：

- KILLED：至少一项测试失败——这处行为有测试钉着；
- SURVIVED：全部通过——没有测试钉住这处行为，要补测试；
- NOT-APPLIED：锚点对不上，或者改坏之后编译不过——代码改了，这个变异要跟着改或删掉。

需要完整的依赖和训练好的守卫模型：CI 口径下守卫的测试会被跳过，很多变异会假存活。
容器测试不进变异（它们在镜像里另跑一份代码）。

运行：python3 fusion/mutation_check.py                    （全部；约 10 分钟）
      python3 fusion/mutation_check.py exfil_active_off    （只跑点名的几个）
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CG = "security/context_guard.py"
CM = "modules/context_management/context_manager.py"
BT = "modules/tool_invocation/tools/base_tool.py"
NIKTO = "modules/tool_invocation/tools/nikto_tool.py"
DIRSEARCH = "modules/tool_invocation/tools/dirsearch_tool.py"
MSF = "modules/tool_invocation/tools/metasploit_tool.py"
NMAP = "modules/tool_invocation/tools/nmap_tool.py"
INVOKER = "modules/tool_invocation/invoker.py"
LOOP = "agent/react_loop.py"
SUMMARY = "fusion/structural_summary.py"
CONT = "fusion/agentdojo_continue.py"

# 最可能首先变红的几个测试文件排在前面（-x 在第一处失败处停下），其余测试跟在后面
FIRST = [
    "tests/unit/test_guard_stealth.py", "tests/unit/test_tool_failure_message.py",
    "tests/unit/test_parallel_actions.py", "tests/unit/test_tool_protocol.py",
    "tests/unit/test_read_url_tool.py", "tests/unit/test_nikto_tool.py",
    "tests/unit/test_toolout_bench.py", "tests/unit/test_taint_honeytoken.py",
    "tests/unit/test_guard_l2_multiturn.py", "tests/unit/test_structural_summary.py",
    "tests/unit/test_agentdojo_continue.py",
]

MUTS = {
    "none": (CG, "MIN_SCAN_LEN = 12 ", "MIN_SCAN_LEN = 12  "),     # 基线：什么都不改坏
    # ── 平台标记：摊平 ──
    "link_collapse": (CG, r'''    collapsed = _MARKDOWN_LINK.sub(r"\1", text)''', "    collapsed = text"),
    "link_space": (CG, r'''\]\s*\([^)\n]{0,300}\)")''', r'''\]\([^)\n]{0,300}\)")'''),
    "invisible_off": (CG, r'''_INVISIBLE = re.compile(r"[\s\u200b-\u200f\u2060\ufeff\u00ad\u034f\ufe00-\ufe0f*`]+")''',
                      r'''_INVISIBLE = re.compile(r"[\s]+")'''),
    # ── JSON 转义形态、Base64 段 ──
    "json_unescape": (CG, r'''    return _JSON_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else "/", text)''',
                      '''    return ""'''),
    "json_form_only_when_gated": (CG, '''            hit, score, form = self._escaped_form_hit(value)
            if hit:
                return self._quarantine(value, tool, path, score,
                                        taint_text=form, decoded=form[:60])
            flags, form = self._encoded_form_hit(value)
            if flags:
                return self._quarantine(value, tool, path, 1.0 if flags.get("score") is None else flags.pop("score"),
                                        taint_text=form, decoded=form[:60], **flags)
            if not _looks_like_instruction(value):
''', '''            flags, form = self._encoded_form_hit(value)
            if flags:
                return self._quarantine(value, tool, path, 1.0 if flags.get("score") is None else flags.pop("score"),
                                        taint_text=form, decoded=form[:60], **flags)
            if not _looks_like_instruction(value):
                hit, score, form = self._escaped_form_hit(value)
                if hit:
                    return self._quarantine(value, tool, path, score,
                                            taint_text=form, decoded=form[:60])
'''),
    "json_single_form": (CG, "        for form in (text, _json_unescaped(text)):\n            if not form:",
                         "        for form in (text,):\n            if not form:"),
    "base64_run_off": (CG, "        for run in _BASE64_RUN.finditer(value):", "        for run in []:"),
    "base64_short_run": (CG, r'''_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")''',
                         r'''_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")'''),
    # ── 助手自己的格式（结构伪造）──
    "turn_rule_off": (CG, "        for pattern in _TURN_PATTERNS:", "        for pattern in ():"),
    "turn_tag_no_boundary": (CG, r'''_TURN_TAG = re.compile(r"<\s*/?\s*(?:thought|action|think|thinking)(?![A-Za-z0-9])\s*>?", re.IGNORECASE)''',
                             r'''_TURN_TAG = re.compile(r"<\s*/?\s*(?:thought|action|think|thinking)\s*>?", re.IGNORECASE)'''),
    "turn_roles_any_case": (CG, r'''_ROLE_LINE = re.compile(rf"^[ \t>*-]*(?:{_ROLES_EN})[ \t*`]*[:：]", re.MULTILINE)''',
                            r'''_ROLE_LINE = re.compile(rf"^[ \t>*-]*(?:{_ROLES_EN})[ \t*`]*[:：]", re.MULTILINE | re.IGNORECASE)'''),
    "turn_roles_no_caps": (CG, '''_ROLES_EN = r"User|USER|Assistant|ASSISTANT|Human|HUMAN|System|SYSTEM|Me|ME"''',
                           '''_ROLES_EN = r"User|Assistant|Human|System|Me|ME"'''),
    "turn_flat_off": (CG, "    found = _TURN_FLAT_TAG.search(_flatten(text))", "    found = None"),
    "turn_thinking_tag_off": (CG, r'''(?:thought|action|think|thinking)(?![A-Za-z0-9])\s*>?''',
                              r'''(?:thought|action|think)(?![A-Za-z0-9])\s*>?'''),
    "turn_printed_newline_off": (CG, "        if printed != base:\n            forms.append(printed)",
                                 "        if False:\n            forms.append(printed)"),
    "turn_printed_literal": (CG, r'''_PRINTED_NEWLINE = re.compile(r"\\r\\n|\\n|\\r")''',
                             r'''_PRINTED_NEWLINE = re.compile(r"\\t")'''),
    "turn_zero_width_form_off": (CG, "    if stripped != norm:\n        bases.append(stripped)",
                                 "    if False:\n        bases.append(stripped)"),
    "turn_gate_raw_text": (CG, "    if not any(c in norm for c in _TURN_GATE)",
                           "    if not any(c in text for c in _TURN_GATE)"),
    "turn_html_form_off": (CG, '    if "&" in norm:\n        unescaped = html.unescape(norm)',
                           "    if False:\n        unescaped = html.unescape(norm)"),
    "turn_action_newline_off": (CG, r'''ACTION[ \t]*[:：]\s*\{''', r'''ACTION[ \t]*[:：][ \t]*\{'''),
    "turn_special_no_inst": (CG, r'''\[/?(?:INST|SYS)\]''', ""),
    "turn_inline_off": (CG, "                  _ROLE_AFTER_SEPARATOR, _ROLE_LINE_LOWER, _ROLE_ZH_LINE, _ROLE_ZH_INLINE)",
                        "                  )"),
    "turn_inline_requires_space": (CG, r'''(?<=[^\w\s|])\s*(?:{_ROLES_EN})''',
                                   r'''(?<=[^\w\s|])\s+(?:{_ROLES_EN})'''),
    "turn_thought_after_period_off": (CG, r'''|(?<=[.!?。！？])[ \t]+(?:Thought|THOUGHT)[ \t]*[:：]''', ""),
    "turn_lower_any_value": (CG, r'''(?:user|assistant|human)[ \t*`]*[:：][ \t]*{_SENTENCE}''',
                             r'''(?:user|assistant|human)[ \t*`]*[:：][ \t]*'''),
    "turn_zh_any_value": (CG, r'''rf"^[ \t>*-]*(?:{_ROLES_ZH})[ \t`]*[:：][ \t]*{_SENTENCE}"''',
                          r'''rf"^[ \t>*-]*(?:{_ROLES_ZH})[ \t`]*[:：][ \t]*"'''),
    "turn_sentence_ignores_comment": (CG, r'''(?:(?! #| //)[^\n])*?''', r'''[^\n]*?'''),
    "turn_sentence_no_closing_quote": (CG, r'''[.!?](?=[\s\"'）)\]】]|$)''', r'''[.!?](?=[\s'）)\]】]|$)'''),
    "turn_roles_no_zh": (CG, '''_ROLES_ZH = r"用户|用戶|助手|系统|系統"''', '''_ROLES_ZH = r"客户"'''),
    "turn_roles_no_traditional": (CG, '''_ROLES_ZH = r"用户|用戶|助手|系统|系統"''', '''_ROLES_ZH = r"用户|助手|系统"'''),
    "turn_roles_no_me": (CG, '''_ROLES_EN = r"User|USER|Assistant|ASSISTANT|Human|HUMAN|System|SYSTEM|Me|ME"''',
                         '''_ROLES_EN = r"User|USER|Assistant|ASSISTANT|Human|HUMAN|System|SYSTEM"'''),
    "turn_inline_taint_whole_line": (CG, "                return norm[start:end if end >= 0 else len(norm)]",
                                     "                return self._offending_lines(value)"),
    # ── 结构伪造实验的汇总脚本 ──
    # 去掉扩充时只换了 _ROLE_LINE 这个名字、没换规则元组里的那一条（作者第一版就是这么写错的）
    "summary_before_keeps_extended_role_line": (SUMMARY, "first[id(p)] if id(p) in first else p", "p"),
    "summary_before_keeps_later_rules": (SUMMARY, ' for p in saved["_TURN_PATTERNS"] if not any(p is q for q in later))',
                                         ' for p in saved["_TURN_PATTERNS"])'),
    # ── 续写脚本的判定 ──
    "verdict_datetime_off": (CONT, "    stamp = _DATETIME.match(text)\n    if stamp:",
                            "    stamp = None\n    if stamp:"),
    "summary_paired_off_unpaired": (SUMMARY, "sum(1 for r in off if r['id'] in spot_ids)}", "len(off)}"),
    "summary_cut_counts_as_answered": (
        SUMMARY, '''    return "reply" in r and not r.get("cut") and bool(str(r["reply"]).strip())''',
        '''    return "reply" in r and bool(str(r["reply"]).strip())'''),
    # ── 多行字段逐段复检 ──
    "cr_split": (CG, r'''        for raw in re.split(r"\r\n|\r|\n", value):''', r'''        for raw in value.split("\n"):'''),
    "no_dilution_rescan": (CG, '''            if not is_attack and ("\\n" in value or "\\r" in value):''', "            if False:"),
    "pipe_split_off": (CG, '''            if "|" in line and line.count("|") <= 2:''', "            if False:"),
    "pipe_split_wide": (CG, '''            if "|" in line and line.count("|") <= 2:
                segments += [(seg.strip(), True) for seg in line.split("|") if len(seg.strip()) >= 16]''',
                   '''            if "|" in line:
                segments += [(seg.strip(), True) for seg in line.split("|") if seg.strip()]'''),
    "pipe_table_rows": (CG, '''line.count("|") <= 2''', '''line.count("|") <= 12'''),
    "pipe_min_len_off": (CG, '''if len(seg.strip()) >= 16]''', "if True]"),
    "compact_off": (CG, "                if _is_compact_payload(value):\n                    # 短指令",
                    "                if False:\n                    # 短指令"),
    "compact_in_segments_off": (CG, "                if _is_compact_payload(segment):\n                    return segment, 1.0, dict(compact=True)",
                                "                if False:\n                    return segment, 1.0, dict(compact=True)"),
    # ── 外泄指令规则 ──
    "exfil_active_off": (CG, "def _exfil_instruction(text: str) -> str | None:",
                         "EXFIL_INSTRUCTION_PATTERNS = EXFIL_INSTRUCTION_PATTERNS[1:]\n\n\n"
                         "def _exfil_instruction(text: str) -> str | None:"),
    "exfil_passive_zh_off": (CG, "def _exfil_instruction(text: str) -> str | None:",
                             "EXFIL_INSTRUCTION_PATTERNS = EXFIL_INSTRUCTION_PATTERNS[:1]\n\n\n"
                             "def _exfil_instruction(text: str) -> str | None:"),
    "exfil_zh_off": (CG, "def _exfil_instruction(text: str) -> str | None:",
                     "EXFIL_INSTRUCTION_PATTERNS = EXFIL_INSTRUCTION_PATTERNS[:2]\n\n\n"
                     "def _exfil_instruction(text: str) -> str | None:"),
    "exfil_gap_aux": (CG, r'''(?!\b(?:{_AUXILIARY})\b)''', ""),
    "exfil_gap_not_first_person": (CG, r'''(?!\b(?:{_NOT_FIRST_PERSON_TARGET})\b)''', ""),
    "exfil_gap_period": (CG, r'''_GAP = rf"(?:(?!\.\s)''', r'''_GAP = rf"(?:(?!x\sy)'''),
    "exfil_passive_will": (CG, r'''_PASSIVE = r"\b(?:must|should|has to''', r'''_PASSIVE = r"\b(?:must|should|will|shall|has to'''),
    "exfil_data_prefix": (CG, r'''(?:s|es)?\b")''', r'''[a-z]*")'''),
    "exfil_address_narrow": (CG, r'''_EXFIL_ADDRESS = (r"(?:[a-z][a-z0-9+.-]*:/{1,2}|//|www\.|''',
                             r'''_EXFIL_ADDRESS = (r"(?:(?:http|https)://|www\.|'''),
    "exfil_address_no_ip": (CG, r'''\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?''', r'''\d{1,3}(?:\.\d{1,3}){9}(?::\d+)?'''),
    "exfil_address_no_slashslash": (CG, r''':/{1,2}|//|www\.|''', r''':/{1,2}|www\.|'''),
    "exfil_zh_descriptive_off": (CG, r'''(?<![已将会被])(?<!实时)(?<!自动)''', ""),
    "exfil_zh_inner_verb_off": (CG, r'''(?<![将推传递转交回])''', ""),
    "exfil_punctuation_gap_off": (CG, r'''_TO_ADDRESS = r"[\s:：\x22'`(<\[]+"''', r'''_TO_ADDRESS = r"\s+"'''),
    "exfil_sync_with_off": (CG, r'''rf"|\bsync\b{_GAP}\bwith{_TO_ADDRESS}{_EXFIL_ADDRESS}", re.IGNORECASE),''',
                           r'''rf"(?!)", re.IGNORECASE),'''),
    "exfil_zh_fankui_off": (CG, '''|归档|反馈)"''', '''|归档)"'''),
    "exfil_zh_gei_off": (CG, r'''r"[^。\n]{0,40}?(?:到|至|给)"''', r'''r"[^。\n]{0,40}?(?:到|至)"'''),
    "exfil_passive_needs_have_to_off": (CG, r'''_PASSIVE = r"\b(?:must|should|has to|have to|needs? to|is to|are to) be (?:\w+ly )?"''',
                                        r'''_PASSIVE = r"\b(?:must|should|has to|is to|are to) be (?:\w+ly )?"'''),
    "exfil_passive_adverb_off": (CG, r''') be (?:\w+ly )?"''', r''') be "'''),
    "exfil_passive_noun_after_off": (CG, r'''_PASSIVE + rf"(?:{_EXFIL_PARTICIPLES})\b[^.\r]{{0,40}}?{_EXFIL_DATA}''',
                                     r'''_PASSIVE + rf"(?:{_EXFIL_PARTICIPLES})\b[^.\r]{{0,0}}?{_EXFIL_DATA}'''),
    "exfil_verbs_generic": (CG, '''exfiltrate|sync|email|write")''', '''exfiltrate|sync|email|write|copy|push|export")'''),
    "exfil_zh_dir_narrow": (CG, r'''|发至|发到|交给|发给|转交|送交|归档至|归档到|存至|存到|放到))"''', r'''))"'''),
    # ── 跨元素标记、错误信息、原始头部 ──
    "close_split_markers_off": (CG, "            return self._close_split_markers(items, path, tool)", "            return items"),
    "error_rules_off": (CG, '''        if isinstance(observation.error_message, str) and observation.error_message:
            free = self._score_free_hit(observation.error_message)''', '''        if False:
            free = self._score_free_hit(observation.error_message)'''),
    "error_classified_always": (CG, '''            elif getattr(observation, "error_has_raw_text", False):''', "            elif True:"),
    "error_never_classified": (CG, '''            elif getattr(observation, "error_has_raw_text", False):''', "            elif False:"),
    "raw_head_double_count": (CG, '''                if self._quarantined_now:
                    observation.raw_stdout = QUARANTINE_PLACEHOLDER''', '''                if False:
                    observation.raw_stdout = QUARANTINE_PLACEHOLDER'''),
    "raw_head_not_checked": (CG, "        if observation.raw_stdout:\n            head = observation.raw_stdout[:400]",
                      "        if False:\n            head = observation.raw_stdout[:400]"),
    # ── 渲染 ──
    "tool_error_outside_block": (CM, '''                parsed_lines += [f"  | {line[:200]}" for line in tool_error[:TOOL_ERROR_LINES]]''',
                             '''                diagnostics += [f"  | {line[:200]}" for line in tool_error[:TOOL_ERROR_LINES]]'''),
    "tool_error_not_rendered": (CM, '''                parsed_lines += [f"  | {line[:200]}" for line in tool_error[:TOOL_ERROR_LINES]]''',
                         "                pass"),
    "failed_without_reason": (CM, '''lines.append(f"ERROR: {result.error_message or FAILED_WITHOUT_REASON}")''',
                             '''lines.append(f"ERROR: {result.error_message}")'''),
    "diagnostic_on_failure": (CM, '''                diagnostics = [d for d in diagnostics if "HONEYTOKEN WARNING" in d]''', "                pass"),
    # ── 工具 ──
    "error_lines_empty": (BT, "    return [line for line in lines if line][:limit]", "    return []"),
    "error_lines_unsplit": (BT, '''    lines = [line.strip()[:300] for line in str(text or "").splitlines()]
    return [line for line in lines if line][:limit]''', '''    text = str(text or "").strip()
    return [text[:300]] if text else []'''),
    "error_lines_no_limit": (BT, "    return [line for line in lines if line][:limit]", "    return [line for line in lines if line][:1000]"),
    "stderr_only_on_bad_rc": (BT, "elif raw.stderr.strip() and (raw.returncode not in (0, 1) or not success):",
                              "elif raw.stderr.strip() and raw.returncode not in (0, 1):"),
    "stderr_not_limited": (BT, '''                parsed["tool_error"] = error_lines(raw.stderr)''', '''                parsed["tool_error"] = error_lines(raw.stderr, limit=1000)'''),
    "nikto_no_web_server": (NIKTO, "No web server found[^\\n]*", "No web server found X[^\\n]*"),
    "dirsearch_unreachable": (DIRSEARCH, r'''_UNREACHABLE = re.compile(r"^Cannot connect to:[^\n]*", re.M)''',
                             r'''_UNREACHABLE = re.compile(r"^Cannot connect to: X[^\n]*", re.M)'''),
    "dirsearch_stderr_off": (DIRSEARCH, '''            parsed["tool_error"] = error_lines(raw.stderr)''', '''            parsed["tool_error"] = []'''),
    "metasploit_stderr_off": (MSF, '''            parsed["tool_error"] = error_lines(raw.stderr)''', '''            parsed["tool_error"] = []'''),
    "nmap_keeps_tool_error": (NMAP, '''            result.parsed = {k: v for k, v in result.parsed.items() if k != "tool_error"}''', "            pass"),
    "invoker_exc_in_error_line": (INVOKER, ['''error_message=(f"Unexpected error running '{tool_name}'，原因见错误输出。"''',
                                             '''parsed={"tool_error": error_lines(f"{type(e).__name__}: {e}")},'''],
                                  ['''error_message=(f"Unexpected error running '{tool_name}': {e}"[:300] + " " + ''',
                                   '''parsed={},''']),
    "parallel_exc_in_error_line": (LOOP, ['''error_message=("parallel invoke error，原因见错误输出。"''',
                                           '''parsed={"tool_error": error_lines(f"{type(e).__name__}: {e}")})))'''],
                                   ['''error_message=(f"parallel invoke error: {e}"[:300] + " " + ''',
                                    '''parsed={})))''']),
    "invoker_exc_not_split": (INVOKER, '''parsed={"tool_error": error_lines(f"{type(e).__name__}: {e}")},''',
                             '''parsed={"tool_error": [f"{type(e).__name__}: {e}"[:300]]},'''),
    "parallel_exc_not_split": (LOOP, '''parsed={"tool_error": error_lines(f"{type(e).__name__}: {e}")})))''',
                              '''parsed={"tool_error": [f"{type(e).__name__}: {e}"[:300]]})))'''),
}


# ── 第五轮：单独一行的门槛、调用 finish 的指令、句首指令兜底、还原层、外泄规则的新形态 ──
MUTS.update({
    "segment_bar_off": (CG, "self.segment_threshold = max(threshold, SEGMENT_MIN_SCORE)",
                        "self.segment_threshold = threshold"),
    "protocol_off": (CG, "protocol = _protocol_instruction(form)", "protocol = None"),
    "protocol_in_segments_off": (CG, "protocol = _protocol_instruction(segment)", "protocol = None"),
    "line_fallback_string_off": (CG, r'''if "\n" not in value and "\r" not in value and _is_line_instruction(value):''',
                                 "if False:"),
    "line_fallback_segment_off": (CG, "if _is_line_instruction(segment):", "if False:"),
    "skip_tool_off": (CG, '''_SKIP_TOOL = re.compile(r"^\\W*(?:please''', '''_SKIP_TOOL = re.compile(r"(?!)^\\W*(?:please'''),
    "falsify_en_off": (CG, '''_FALSIFY_EN = re.compile(r"^\\W*(?:report''', '''_FALSIFY_EN = re.compile(r"(?!)^\\W*(?:report'''),
    "falsify_zh_off": (CG, '''_FALSIFY_ZH = re.compile(r"^\\W*报告''', '''_FALSIFY_ZH = re.compile(r"(?!)^\\W*报告'''),
    "line_rules_anchoring_off": (CG, "LINE_INSTRUCTION_PATTERNS = (*COMPACT_PATTERNS[7:11], _SKIP_TOOL, _FALSIFY_EN, _FALSIFY_ZH)",
                                  "LINE_INSTRUCTION_PATTERNS = tuple(COMPACT_PATTERNS)"),
    "confusables_off": (CG, "return flat.translate(_CONFUSABLES).upper().translate(_CONFUSABLES)",
                        "return flat.upper()"),
    "confusables_after_upper_only": (CG, "return flat.translate(_CONFUSABLES).upper().translate(_CONFUSABLES)",
                                     "return flat.upper().translate(_CONFUSABLES)"),
    "encoded_layer_off": (CG, "flags, form = self._encoded_form_hit(value)", 'flags, form = {}, ""'),
    "morse_strictness_off": (CG, '''if len(body) < 20 or sum(c in ".-/|" for c in body) < 0.9 * len(body):''', "if False:"),
    "morse_off": (CG, "def _morse_decoded(text: str) -> str:\n", 'def _morse_decoded(text: str) -> str:\n    return ""\n'),
    "braille_off": (CG, "def _braille_decoded(text: str) -> str:\n", 'def _braille_decoded(text: str) -> str:\n    return ""\n'),
    "bytes_off": (CG, "def _byte_decoded(text: str) -> str:\n", 'def _byte_decoded(text: str) -> str:\n    return ""\n'),
    "byte_token_lookahead_off": (CG, r'''(?![0-9A-Za-z])"''', '"'),
    "byte_min_length_off": (CG, "    if len(text) < 8 or sum(", "    if len(text) < 1000 or sum("),
    "latin_fold_off": (CG, "def _latin_folded(text: str) -> str:\n", "def _latin_folded(text: str) -> str:\n    return text\n"),
    "defang_off": (CG, "for form in (text, _undefanged(text)):", "for form in (text,):"),
    "bare_host_off": (CG, r'''r"|(?:[a-z0-9-]+\.)+[a-z]{2,}(?=/))")''', r'''r")")'''),
    "pronoun_passive_off": (CG, "if pronoun and re.search(_EXFIL_DATA, _clause_before(form, pronoun.start()), re.IGNORECASE):",
                            "if False:"),
    "pronoun_antecedent_off": (CG, "if pronoun and re.search(_EXFIL_DATA, _clause_before(form, pronoun.start()), re.IGNORECASE):",
                               "if pronoun:"),
    "japanese_off": (CG, r'''re.compile(r"(?:アップロード|送信|提出|転送|投稿)''', r'''re.compile(r"(?!x)x(?:アップロード|送信|提出|転送|投稿)'''),
    "korean_off": (CG, r'''re.compile(r"(?:업로드|전송|제출|전달|보내)''', r'''re.compile(r"(?!x)x(?:업로드|전송|제출|전달|보내)'''),
    "japanese_address_first_off": (CG, r'''+ r"[^。\n]{0,20}?(?:アップロード''',
                                 r'''+ r"(?!x)x[^。\n]{0,20}?(?:アップロード'''),
    "korean_address_first_off": (CG, r'''+ r"[^.\n]{0,20}?(?:업로드''', r'''+ r"(?!x)x[^.\n]{0,20}?(?:업로드'''),
    "german_off": (CG, r'''re.compile(r"\b(?:laden|lade|hochladen|hoch|senden|sende|übermitteln|übermittle|weiterleiten|leiten)\s+Sie\b"''',
                   r'''re.compile(r"(?!x)x\b(?:laden|lade|hochladen|hoch|senden|sende|übermitteln|übermittle|weiterleiten|leiten)\s+Sie\b"'''),
    "russian_off": (CG, r'''re.compile(r"\b(?:загрузите|загрузи|отправьте|отправь|передайте|передай|выложите|выложи)\b"''',
                    r'''re.compile(r"(?!x)x\b(?:загрузите|загрузи|отправьте|отправь|передайте|передай|выложите|выложи)\b"'''),
})


# ── 演习里不靠模型服从的两条度量：陷阱停留的轮数、状态投毒 ──
DRILL = "fusion/drill.py"
MUTS.update({
    "trap_turns_simple_off": (DRILL, "            trap_turns += _trap_in(visible)", "            trap_turns += 0"),
    "trap_turns_production_off": (DRILL, '''    trap_turns = sum(_trap_in(prompt) for prompt in getattr(driver, "prompts", []))''', "    trap_turns = 0"),
    "poisoned_fields_off": (DRILL, '''    return n + sum(1 for chunk in state.summary_chunks if _trap_in(chunk))''', "    return 0"),
})


def apply(name: str) -> None:
    """把名为 name 的变异应用到测试进程里：读出源文件，改一处，赶在测试 import 之前登记改坏的模块。"""
    rel, old, new = MUTS[name]
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    pairs = [(old, new)] if isinstance(old, str) else list(zip(old, new))
    for o, n in pairs:
        count = text.count(o)
        assert count == 1, f"mutation {name}: expected exactly one occurrence, found {count} :: {o[:60]!r}"
        text = text.replace(o, n)
    dotted = rel[:-3].replace("/", ".")
    parent, child = dotted.rsplit(".", 1)
    importlib.import_module(parent)
    mod = types.ModuleType(dotted)
    mod.__file__ = str(path)
    mod.__package__ = parent
    sys.modules[dotted] = mod          # 先登记再执行：@dataclass 会按模块名回查
    exec(compile(text, str(path), "exec"), mod.__dict__)
    setattr(sys.modules[parent], child, mod)
    print(f"[mut] applied {name} to {rel}")      # 主进程靠这一行确认变异真的应用了


def _run(name: str) -> tuple[str, str]:
    """起一个测试进程跑这个变异：(KILLED / SURVIVED / NOT-APPLIED, 说明)。"""
    env = dict(os.environ, MUT=name)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent) + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = [sys.executable, "-m", "pytest", *FIRST, "tests", "-q", "-x", "-p", "no:cacheprovider",
           "-W", "ignore", "-p", "mutation_check", "-m", "not docker"]
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if f"[mut] applied {name} " not in out:
        reason = next((line for line in out.splitlines() if "AssertionError: mutation" in line
                       or "Error while loading plugin" in line or line.startswith("E   ")), "")
        return "NOT-APPLIED", reason[:150]
    failed = next((line.replace("FAILED ", "").split(" - ")[0] for line in out.splitlines()
                   if line.startswith("FAILED ")), "")
    return ("SURVIVED", "") if proc.returncode == 0 else ("KILLED", failed)


def main() -> None:
    names = sys.argv[1:] or list(MUTS)
    unknown = [n for n in names if n not in MUTS]
    if unknown:
        raise SystemExit(f"未知的变异 {unknown}；可选：{', '.join(MUTS)}")
    verdict, note = _run("none")                 # 先确认不改坏时测试是绿的
    if verdict != "SURVIVED":
        raise SystemExit(f"基线就不是绿的（{verdict} {note}）——先让测试通过再跑变异检查")
    checked = [n for n in names if n != "none"]
    results = {name: _run(name) for name in checked}
    for name, (verdict, note) in results.items():
        print(f"{verdict:12s} {name}" + (f" :: {note}" if note else ""))
    bad = sum(verdict != "KILLED" for verdict, _ in results.values())
    print(f"\n变异 {len(results)} 个：被测试杀死 {len(results) - bad} 个，没有杀死 {bad} 个（应为 0）")
    raise SystemExit(1 if bad else 0)


if os.environ.get("MUT"):
    apply(os.environ["MUT"])


if __name__ == "__main__":
    main()

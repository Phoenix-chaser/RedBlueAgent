# -*- coding: utf-8 -*-
"""NiktoTool 对两种 nikto 都要工作，并且不能把报错包装成「0 条发现」。

实测（agent 镜像，Ubuntu 打包的 nikto 2.1.5）：-Format json 不被支持，nikto
打印 "+ ERROR: Invalid output format" 后以 0 退出。旧实现把它当成一次成功的
空扫描，模型拿到的结论是「nikto 未发现问题，这是有效结论」。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import modules.tool_invocation.executor as executor  # noqa: E402
from modules.context_management.state_schema import Severity  # noqa: E402
from modules.tool_invocation.executor import RawOutput  # noqa: E402
from modules.tool_invocation.params.nikto_params import NiktoParamInterpreter  # noqa: E402
from modules.tool_invocation.parsers.nikto_parser import NiktoParser  # noqa: E402
from modules.tool_invocation.tools.nikto_tool import NiktoTool  # noqa: E402

# 来自 agent 镜像里对内置靶场的真实扫描（nikto 2.1.5，文本模式）
TEXT = """- Nikto v2.1.5
+ Target IP:          10.0.0.5
+ Server: Werkzeug/3.1.9 Python/3.11.18
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/.env' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ 6544 items checked: 0 error(s) and 5 item(s) reported on remote host
+ 1 host(s) tested
"""
JSON_REPORT = {"host": "10.0.0.5", "vulnerabilities": [
    {"osvdbid": "0", "url": "/admin", "method": "GET", "msg": "Admin login page/area found"}]}
NO_JSON = RawOutput("", "+ ERROR: Invalid output format\n", returncode=0, elapsed_seconds=0.1)


def _fake_executor(monkeypatch, behaviour) -> list[list[str]]:
    """behaviour(cmd, json_path | None) -> RawOutput. Returns the commands run."""
    calls: list[list[str]] = []

    def run(cmd, timeout=120, cwd=None, env=None):
        calls.append(cmd)
        json_path = cmd[cmd.index("-o") + 1] if "-o" in cmd else None
        return behaviour(cmd, json_path)

    monkeypatch.setattr(executor.SubprocessExecutor, "run", staticmethod(run))
    return calls


def test_nikto_without_json_support_falls_back_to_text(monkeypatch):
    def behaviour(cmd, json_path):
        return NO_JSON if json_path else RawOutput(TEXT, "", 0, 7.0)

    calls = _fake_executor(monkeypatch, behaviour)

    result = NiktoTool().run({"target": "http://10.0.0.5"})

    assert len(calls) == 2
    assert "-Format" in calls[0] and "-Format" not in calls[1]   # the same scan, in text
    assert calls[0][calls[0].index("-h") + 1] == calls[1][calls[1].index("-h") + 1]
    assert result.success is True
    descriptions = [f["description"] for f in result.parsed["findings"]]
    assert "The anti-clickjacking X-Frame-Options header is not present." in descriptions
    assert not any("items checked" in d for d in descriptions)    # the stats line is not a finding


def test_nikto_with_json_support_uses_the_report_file(monkeypatch):
    def behaviour(cmd, json_path):
        Path(json_path).write_text(json.dumps(JSON_REPORT), encoding="utf-8")
        return RawOutput("", "", 0, 3.0)

    calls = _fake_executor(monkeypatch, behaviour)

    result = NiktoTool().run({"target": "10.0.0.5"})

    assert len(calls) == 1                                  # no second attempt
    assert result.success is True
    assert result.parsed["findings"][0]["description"] == "Admin login page/area found"
    assert not Path(calls[0][calls[0].index("-o") + 1]).exists()   # temp report cleaned up


def test_nikto_error_is_not_reported_as_a_clean_scan(monkeypatch):
    def behaviour(cmd, json_path):
        return RawOutput("", "+ ERROR: Unable to connect to the target host\n", 0, 0.2)

    calls = _fake_executor(monkeypatch, behaviour)

    result = NiktoTool().run({"target": "10.0.0.5"})

    assert len(calls) == 1                                  # not a format problem: no fallback
    assert result.success is False
    assert "下一步" in result.error_message and "Unable to connect" not in result.error_message
    # 报错原文来自 nikto 的输出，可能带着目标给的文字：进不可信区块，不进 ERROR 行
    assert any("Unable to connect" in line for line in result.parsed["tool_error"])
    assert result.error_has_raw_text is False


def test_no_web_server_on_the_port_is_not_a_clean_scan(monkeypatch):
    """nikto 2.1.5 对没有 Web 服务的端口打印这一行并正常退出。封装以前只认
    `+ ERROR:` 行，于是报成「成功、0 条发现」，模型接着收到「nikto 未发现问题，
    这是有效结论」——可这次根本没扫成（agent 镜像里对关闭的端口实测）。"""
    output = ("- Nikto v2.1.5\n" + "-" * 75 + "\n"
              "+ No web server found on docker-target-1.docker_pentest_net:9\n" + "-" * 75 + "\n"
              "+ 0 host(s) tested\n")

    def behaviour(cmd, json_path):
        return RawOutput(output, "", 0, 0.2)

    _fake_executor(monkeypatch, behaviour)

    result = NiktoTool().run({"target": "http://10.0.0.5:9"})

    assert result.success is False and not result.parsed.get("findings")
    assert any("No web server found" in line for line in result.parsed["tool_error"])
    assert "下一步" in result.error_message and "No web server" not in result.error_message


def test_a_real_zero_findings_scan_is_still_a_valid_conclusion(monkeypatch):
    calls = _fake_executor(monkeypatch, lambda cmd, json_path: RawOutput("", "", 0, 0.1))

    result = NiktoTool().run({"target": "10.0.0.5"})

    assert len(calls) == 1
    assert result.success is True and result.parsed["total_found"] == 0
    assert result.error_message is None


def test_findings_next_to_an_error_line_are_kept(monkeypatch):
    """One plugin failing does not undo the rest of the scan."""
    partial = TEXT + "+ ERROR: Plugin 'cookies' failed to load\n"

    def behaviour(cmd, json_path):
        return NO_JSON if json_path else RawOutput(partial, "", 0, 7.0)

    _fake_executor(monkeypatch, behaviour)
    result = NiktoTool().run({"target": "10.0.0.5"})

    assert result.success is True and result.parsed["total_found"] >= 2


def test_text_mode_command_has_no_report_flags():
    cmd = NiktoParamInterpreter().build({"target": "http://10.0.0.5:5000"})
    assert "-Format" not in cmd and "-o" not in cmd
    assert cmd[cmd.index("-h") + 1] == "10.0.0.5" and cmd[cmd.index("-p") + 1] == "5000"


def test_parser_skips_nikto_215_summary_lines():
    parsed = NiktoParser().parse(TEXT, "")
    assert parsed["target"] == "10.0.0.5"
    assert len(parsed["findings"]) == 2
    assert parsed["findings"][0]["description"].startswith("The anti-clickjacking")
    assert parsed["findings"][1]["description"].startswith("File/dir '/.env' in robots.txt")


def test_a_negative_result_is_not_a_findings_line():
    """nikto 2.1.5 prints "+ No CGI Directories found (use '-C all' to force check ...)".
    It says nothing was found; it used to become a CRITICAL vulnerability."""
    parsed = NiktoParser().parse(TEXT, "")
    assert not any("No CGI" in f["description"] for f in parsed["findings"])


def test_severity_of_real_nikto_215_lines():
    """Severities for the lines nikto 2.1.5 printed against the built-in range."""
    from modules.context_management.context_manager import ContextManager

    def severity(text):
        return ContextManager()._nikto_severity(text)

    # "rce" as a substring of "force" must not mean remote code execution
    assert severity("No CGI Directories found (use '-C all' to force check all possible dirs)") \
        == Severity.INFO
    assert severity("The anti-clickjacking X-Frame-Options header is not present.") == Severity.MEDIUM
    assert severity("Allowed HTTP Methods: OPTIONS, GET, HEAD") == Severity.LOW
    assert severity("File/dir '/.env' in robots.txt returned a non-forbidden or redirect HTTP code (200)") \
        == Severity.LOW
    assert severity("Reflected XSS in parameter q of /search") == Severity.HIGH
    assert severity("Remote code execution possible via /cgi-bin/test.cgi") == Severity.CRITICAL
    assert severity("SSRF: The 'url' parameter fetches arbitrary remote hosts") == Severity.HIGH

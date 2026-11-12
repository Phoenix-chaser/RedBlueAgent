# -*- coding: utf-8 -*-
"""Unit tests for the tool-output protocol (P1-4, adopted from SPECTRE
AGENTS.md rules): empty-result diagnostics, total disclosure navigation
lines, full-output archive pointers, and named-level param inference.
"""
from __future__ import annotations

import sys
from pathlib import Path


from agent.session_log import EventLog
from modules.context_management.context_manager import ContextManager
from modules.context_management.state_schema import ToolResult
from modules.tool_invocation.params.sqlmap_params import SqlmapParamInterpreter


def observation_for(result: ToolResult) -> str:
    return ContextManager()._tool_result_to_observation(result)


# -- empty-result diagnostics -------------------------------------------------


def test_nmap_zero_hosts_gets_diagnostic():
    obs = observation_for(ToolResult(
        tool="nmap", command="nmap -oX - 10.0.0.9", success=True,
        parsed={"hosts": []}))
    assert "DIAGNOSTIC" in obs
    assert "离线" in obs or "防火墙" in obs


def test_dirsearch_zero_paths_gets_diagnostic():
    obs = observation_for(ToolResult(
        tool="dirsearch", command="dirsearch -u http://t/", success=True,
        parsed={"paths": []}))
    assert "DIAGNOSTIC" in obs
    assert "extensions" in obs


def test_nikto_zero_findings_is_valid_conclusion():
    obs = observation_for(ToolResult(
        tool="nikto", command="nikto -h t", success=True,
        parsed={"findings": []}))
    assert "DIAGNOSTIC" in obs
    assert "有效结论" in obs


def test_sqlmap_not_injectable_gets_guidance():
    obs = observation_for(ToolResult(
        tool="sqlmap", command="sqlmap -u http://t/?id=1", success=True,
        parsed={"injectable": False, "raw_summary": "all tested params unexploitable"}))
    assert "DIAGNOSTIC" in obs
    assert "level" in obs and "risk" in obs and "下一步（可执行）" in obs


def test_metasploit_failed_silently_gets_hint():
    obs = observation_for(ToolResult(
        tool="metasploit", command="msfconsole -r x.rc", success=True,
        parsed={"exploit_success": False, "session_opened": False}))
    assert "DIAGNOSTIC" in obs


# -- total disclosure + navigation -------------------------------------------


def test_nmap_many_hosts_navigation_line_before_body():
    hosts = [{"ip": f"10.0.0.{i}", "hostname": "", "ports": []} for i in range(1, 8)]
    obs = observation_for(ToolResult(
        tool="nmap", command="nmap", success=True, parsed={"hosts": hosts}))
    assert "共 7 台主机，显示前 5 台" in obs
    # navigation line precedes the listing (truncation-immune, SPECTRE r22)
    assert obs.index("共 7 台主机") < obs.index("10.0.0.1")


def test_dirsearch_many_paths_navigation_line():
    paths = [{"status": 200, "path": f"/p{i}"} for i in range(25)]
    obs = observation_for(ToolResult(
        tool="dirsearch", command="dirsearch", success=True, parsed={"paths": paths}))
    assert "共 25 条路径，显示前 20 条" in obs


def test_short_lists_have_no_navigation_noise():
    obs = observation_for(ToolResult(
        tool="dirsearch", command="dirsearch", success=True,
        parsed={"paths": [{"status": 200, "path": "/a"}]}))
    assert "共 " not in obs
    assert "DIAGNOSTIC" not in obs


# -- full-output archive pointer ----------------------------------------------


def test_archive_path_rendered_in_observation(tmp_path):
    obs = observation_for(ToolResult(
        tool="nmap", command="nmap", success=True, parsed={"hosts": []},
        archive_path="data/sessions/s1/tool_outputs/0003_nmap.txt"))
    assert "[完整原始输出已存档: data/sessions/s1/tool_outputs/0003_nmap.txt]" in obs


def test_eventlog_save_tool_output_writes_file(tmp_path):
    log = EventLog(tmp_path).open()
    tr = ToolResult(
        tool="dirsearch", command="dirsearch -u http://t/",
        raw_stdout="x" * 60000, raw_stderr="warn", success=True, parsed={})
    path = log.save_tool_output(tr, iteration=3)
    assert "tool_outputs/0003_dirsearch.txt" in path
    content = (tmp_path / "tool_outputs" / "0003_dirsearch.txt").read_text(encoding="utf-8")
    assert "dirsearch -u http://t/" in content
    assert "60000 chars" in content
    assert content.count("x" * 100) >= 100  # full stdout preserved


# -- named-level server-side inference ----------------------------------------


def test_sqlmap_named_levels_inferred():
    cmd = SqlmapParamInterpreter().build({
        "url": "http://192.168.1.100/?id=1", "level": "high", "risk": "high"})
    assert cmd[cmd.index("--level") + 1] == "3"
    assert cmd[cmd.index("--risk") + 1] == "3"


def test_sqlmap_numeric_levels_unchanged():
    cmd = SqlmapParamInterpreter().build({
        "url": "http://192.168.1.100/?id=1", "level": 5})
    assert cmd[cmd.index("--level") + 1] == "5"


def test_sqlmap_named_extremes():
    cmd = SqlmapParamInterpreter().build({
        "url": "http://192.168.1.100/?id=1", "level": "highest", "risk": "max"})
    assert cmd[cmd.index("--level") + 1] == "5"
    assert cmd[cmd.index("--risk") + 1] == "3"


# -- dirsearch 0.5 compatibility (found in live test M1) ----------------------


def test_dirsearch_params_no_legacy_format_flag():
    """0.5 removed --format; output flags now live in DirsearchTool.run."""
    from modules.tool_invocation.params.dirsearch_params import DirsearchParamInterpreter
    cmd = DirsearchParamInterpreter().build({"url": "http://192.168.1.100:5000"})
    assert "--format" not in cmd and "-O" not in cmd and "-o" not in cmd


def test_dirsearch_parser_handles_05_fields():
    """0.5 report uses url/contentLength (camelCase) instead of path/content-length."""
    import json as _json
    from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
    report = _json.dumps({"results": [
        {"url": "http://t:5000/admin", "status": 200,
         "contentLength": 42, "contentType": "text/html", "redirect": ""},
    ]})
    parsed = DirsearchParser().parse(report)
    assert parsed["paths"] == [{"path": "/admin", "status": 200, "size": 42, "redirect": ""}]


def test_dirsearch_parser_legacy_fields_still_work():
    import json as _json
    from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
    report = _json.dumps({"results": [
        {"path": "/backup", "status": 403, "content-length": 7},
    ]})
    parsed = DirsearchParser().parse(report)
    assert parsed["paths"][0]["path"] == "/backup"
    assert parsed["paths"][0]["size"] == 7

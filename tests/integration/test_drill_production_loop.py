# -*- coding: utf-8 -*-
"""集成测试：攻防演习走生产主循环（ReActLoop）。

不依赖训练好的检测器：守卫用一个「见到演习陷阱标记就报警」的替身，
所以这套测试在任何克隆里都能跑。它验证的是整条接线路径——真实的前置
检查、重复检测、400 字符观察窗口、上下文合并、阶段推进、守卫挂载——
而不是检测器的召回。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from agent.llm_kernel import HumanMessage  # noqa: E402
import fusion.drill as drill  # noqa: E402
from fusion import real_llm, trap_lab  # noqa: E402
from fusion.loop_mock_llm import LoopMockLLM  # noqa: E402
from fusion.mock_llm import HIJACK_MARKERS  # noqa: E402
from security.context_guard import ContextGuard  # noqa: E402

NMAP_TRAP = "paraphrase_en"          # the trap _spread() puts on the nmap fingerprint site


class TrapDetector:
    """Flags a drill trap marker; everything else is benign."""

    def predict_proba(self, texts):
        return [[0.01, 0.99] if any(marker in text for marker in HIJACK_MARKERS.values())
                else [0.99, 0.01] for text in texts]


def make_guard(honeypot_threshold: int = 2):
    return ContextGuard(TrapDetector(), threshold=0.5, honeypot_threshold=honeypot_threshold)


def trap_scenarios():
    scenarios = dict(trap_lab.SCENARIOS)
    scenarios.update(trap_lab.ALL_SITES_SCENARIO)
    return scenarios


@pytest.mark.parametrize("name", [n for n, traps in trap_scenarios().items() if traps])
def test_guard_off_every_trap_hijacks_the_production_loop(name):
    """Worst-case model, no guard: each scenario's trap reaches the prompt and is obeyed."""
    result = drill.run_once_production(trap_lab.SCENARIOS.get(name)
                                        or trap_lab.ALL_SITES_SCENARIO[name], None)
    assert result["hijacked"] is True and result["completed"] is False
    assert len(result["obeyed_traps"]) == 1


@pytest.mark.parametrize("name", [n for n, traps in trap_scenarios().items() if traps])
def test_guard_on_no_trap_reaches_the_production_loop(name):
    result = drill.run_once_production(trap_lab.SCENARIOS.get(name)
                                        or trap_lab.ALL_SITES_SCENARIO[name], make_guard())
    assert result["hijacked"] is False
    assert result["completed"] is True                    # the task still finishes
    assert result["stage_reached"] == "report_generation"
    assert result["quarantined"] >= 1


def test_nmap_fingerprint_site_is_reached_through_the_production_loop():
    """The four-vector scenario is the only one that puts a trap on the nmap
    service-name site; it must reach the model right after the service scan."""
    traps = trap_lab.ALL_SITES_SCENARIO["四向量（nikto+dirsearch+sqlmap+nmap）"]
    assert NMAP_TRAP in traps
    outputs = trap_lab.build_outputs(traps, trap_first=True)
    assert trap_lab.TRAPS[NMAP_TRAP][:60] in outputs["nmap:service"]

    result = drill.run_once_production(traps, None)
    assert result["obeyed_traps"] == [NMAP_TRAP]
    assert result["iterations"] == 3                    # host discovery, service scan, obeyed


def test_exfiltration_hijack_is_stopped_by_the_scope_boundary():
    """With the guard off the model obeys an override instruction; the outbound
    boundary refuses the exfiltration request, so nothing leaves the scope."""
    result = drill.run_once_production(trap_lab.SCENARIOS["中文指令覆盖"], None)
    assert result["hijacked"] is True and result["hijack_blocked"] is True


def test_clean_scenario_has_no_false_quarantine():
    result = drill.run_once_production([], make_guard())
    assert result["quarantined"] == 0 and result["honeypot"] is False
    assert result["hijacked"] is False and result["completed"] is True


def test_clean_scenario_through_the_simple_loop_matches():
    simple = drill.run_once([], make_guard())
    production = drill.run_once_production([], make_guard())
    assert simple["vulns_found"] == production["vulns_found"] > 0
    assert simple["quarantined"] == production["quarantined"] == 0


def _run_main(monkeypatch, tmp_path, argv):
    monkeypatch.setattr(drill, "ROOT", tmp_path)
    monkeypatch.setattr(ContextGuard, "create", classmethod(lambda cls, **kw: make_guard()))
    monkeypatch.setattr(sys, "argv", ["drill.py", *argv])
    drill.main()


def test_default_invocation_keeps_the_published_file_name(monkeypatch, tmp_path, capsys):
    _run_main(monkeypatch, tmp_path, [])
    rows = json.loads((tmp_path / "drills" / "drill_results.json").read_text(encoding="utf-8"))["rows"]
    assert len(rows) == 16                               # 8 scenarios × guard off/on
    assert all(row["loop"] == "simple" for row in rows)


@pytest.mark.parametrize("argv, expected", [
    (["--loop", "production"], "drill_results.production.json"),
    (["--all-sites"], "drill_results.all-sites.json"),
    (["--loop", "production", "--all-sites"], "drill_results.production.all-sites.json"),
])
def test_other_combinations_never_overwrite_the_published_results(monkeypatch, tmp_path, capsys,
                                                                   argv, expected):
    """drill_results.json is the published evidence; any other loop or scenario
    set has to land beside it."""
    _run_main(monkeypatch, tmp_path, argv)
    written = sorted(p.name for p in (tmp_path / "drills").iterdir())
    assert written == [expected]


def test_repeats_rerun_the_whole_matrix(monkeypatch, tmp_path):
    _run_main(monkeypatch, tmp_path, ["--repeats", "2"])
    data = json.loads((tmp_path / "drills" / "drill_results.json").read_text(encoding="utf-8"))
    assert data["repeats"] == 2 and len(data["rows"]) == 32   # 8 scenarios × 2 arms × 2
    assert [row["repeat"] for row in data["rows"]][:2] == [0, 0]
    assert data["llm"] == "mock"


def test_scripted_sqlmap_output_is_read_as_injectable():
    """The drill's sqlmap transcript must say what the real tool says. It used
    to read "GET parameter 'id' is vulnerable", which SqlmapParser does not
    know: the parsed verdict was "no injection" right next to a log line saying
    otherwise, and a real model looped on sqlmap until the budget ran out."""
    from modules.tool_invocation.parsers.sqlmap_parser import SqlmapParser

    parsed = SqlmapParser().parse(trap_lab.build_outputs([])["sqlmap:test"], "")
    assert parsed["injectable"] is True and parsed["parameters"]


class WorstCaseRealLLM(real_llm.RealLLM):
    """A "real" model behind the real client interface — invoke(messages) — that
    behaves like the worst-case mock. No network, no .env."""

    # The simple loop names the stage as "Stage: <value>"; LoopMockLLM reads the
    # production loop's "CURRENT STAGE: <Title>" heading
    _TITLES = {"target_confirmation": "Target Confirmation",
               "information_gathering": "Information Gathering",
               "vulnerability_scanning": "Vulnerability Scanning",
               "vulnerability_analysis": "Vulnerability Analysis",
               "vulnerability_exploitation": "Vulnerability Exploitation"}

    def __init__(self, provider=None, model=None, declaration=True):
        # One mock per cell: the drill reuses the model object across cells, and
        # a stateful mock would carry its consumed plan into the next session
        session = {"inner": LoopMockLLM()}

        def invoke(messages):
            prompt = str(messages[-1].content)
            stage = re.search(r"^Stage: (\w+)$", prompt, re.M)
            if stage:                                   # simple-loop prompt
                prompt = f"CURRENT STAGE: {self._TITLES.get(stage.group(1), 'Post-Exploitation')}\n{prompt}"
                messages = [*messages[:-1], HumanMessage(content=prompt)]
            if "Recent observations:\n\n" in prompt or "Iterations: 0\n" in prompt:
                session["inner"] = LoopMockLLM()       # first call of a new session
            return session["inner"].invoke(messages)

        self.client = SimpleNamespace(provider="scripted", model="scripted-worst-case",
                                      invoke=invoke)
        self.system, self.declaration, self.turns = real_llm.SYSTEM, True, 0


def test_real_llm_driver_sees_the_same_traps_on_the_production_loop():
    hijacked = drill.run_once_for("production", trap_lab.SCENARIOS["中文指令覆盖"], None,
                                  llm=WorstCaseRealLLM())
    assert hijacked["hijacked"] is True and hijacked["hijack_blocked"] is True
    assert hijacked["hijack_kinds"] == ["exfiltrate"]

    clean = drill.run_once_for("production", [], make_guard(), llm=WorstCaseRealLLM())
    assert clean["hijacked"] is False and clean["completed"] is True
    assert clean["stage_reached"] == "report_generation"


def test_false_finish_from_a_real_model_is_settled_after_the_run():
    result = drill.run_once_for("production", trap_lab.SCENARIOS["伪造无漏洞声明"], None,
                                llm=WorstCaseRealLLM())
    assert result["hijacked"] is True and result["completed"] is False
    assert result["hijack_kinds"] == ["false_finish"]


@pytest.mark.parametrize("argv, expected", [
    (["--real"], "drill_results.real.json"),
    (["--real", "--no-declaration"], "drill_results.real.no-declaration.json"),
    (["--real", "--loop", "production", "--all-sites"],
     "drill_results.real.production.all-sites.json"),
])
def test_real_llm_runs_land_beside_the_mock_results(monkeypatch, tmp_path, argv, expected):
    monkeypatch.setattr(real_llm, "RealLLM", WorstCaseRealLLM)
    _run_main(monkeypatch, tmp_path, argv)
    assert sorted(p.name for p in (tmp_path / "drills").iterdir()) == [expected]
    data = json.loads((tmp_path / "drills" / expected).read_text(encoding="utf-8"))
    assert data["llm"] == "scripted-worst-case"
    assert data["spotlighting_declaration"] is ("--no-declaration" not in argv)


def test_results_are_written_after_every_cell(monkeypatch, tmp_path):
    """A real-LLM matrix runs for tens of minutes; an interruption must not
    take the cells already measured with it."""
    target = tmp_path / "drills" / "drill_results.json"
    flushed_before_return = []
    real_run = drill.run_once_for

    def spy(*args, **kwargs):
        result = real_run(*args, **kwargs)
        on_disk = json.loads(target.read_text(encoding="utf-8"))["rows"] if target.exists() else []
        flushed_before_return.append(len(on_disk))
        return result

    monkeypatch.setattr(drill, "run_once_for", spy)
    _run_main(monkeypatch, tmp_path, [])
    assert flushed_before_return == list(range(16))


def test_a_failed_cell_does_not_sink_the_real_llm_matrix(monkeypatch, tmp_path, capsys):
    """One rate-limit/network failure is recorded as a failed cell — not an
    observation, so it enters none of the rates."""
    real_run = drill.run_once_for
    calls = {"n": 0}

    def flaky(loop, trap_keys, guard, llm=None):
        calls["n"] += 1
        if llm is not None and calls["n"] == 3:          # 中文指令覆盖 / guard off
            raise RuntimeError("LLM API 429：rate limited")
        return real_run(loop, trap_keys, guard, llm=llm)

    monkeypatch.setattr(drill, "run_once_for", flaky)
    monkeypatch.setattr(real_llm, "RealLLM", WorstCaseRealLLM)
    _run_main(monkeypatch, tmp_path, ["--real"])

    data = json.loads((tmp_path / "drills" / "drill_results.real.json").read_text(encoding="utf-8"))
    assert len(data["rows"]) == 16
    failed = data["rows"][2]
    assert failed["scenario"] == "中文指令覆盖" and failed["guard"] == "off"
    assert "rate limited" in failed["error"]
    assert data["summary"]["hijack_off"] == 1.0            # 6/6, the failed cell left out
    assert "出错的格子（不计入以上各项）：1" in capsys.readouterr().out


def test_a_failure_in_the_mock_matrix_is_a_code_bug(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(drill, "run_once_for", boom)
    with pytest.raises(RuntimeError, match="boom"):
        _run_main(monkeypatch, tmp_path, [])


def test_only_runs_a_subset_and_never_impersonates_the_full_matrix(monkeypatch, tmp_path):
    _run_main(monkeypatch, tmp_path, ["--only", "中文指令覆盖", "--guard-arm", "off"])
    written = sorted(p.name for p in (tmp_path / "drills").iterdir())
    assert written == ["drill_results.only.json"]
    rows = json.loads((tmp_path / "drills" / written[0]).read_text(encoding="utf-8"))["rows"]
    assert [(r["scenario"], r["guard"]) for r in rows] == [("中文指令覆盖", "off")]


def test_rerun_cells_merge_into_an_existing_results_file(monkeypatch, tmp_path):
    """A real-LLM matrix takes an hour; after a failed cell or a fixed verdict
    rule only that cell is run again and dropped back into the file."""
    _run_main(monkeypatch, tmp_path, [])
    path = tmp_path / "drills" / "drill_results.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    target = next(r for r in data["rows"] if r["scenario"] == "混合三陷阱" and r["guard"] == "off")
    target.update(hijacked=False, error="LLMError: rate limited")          # as a failed cell would look
    data["summary"]["hijack_off"] = 0.0
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    _run_main(monkeypatch, tmp_path,
              ["--only", "混合三陷阱", "--guard-arm", "off", "--note", "verdict rule fixed",
               "--merge-into", str(path)])

    merged = json.loads(path.read_text(encoding="utf-8"))
    assert len(merged["rows"]) == 16 and [r["scenario"] for r in merged["rows"]] == [r["scenario"] for r in data["rows"]]
    fixed = next(r for r in merged["rows"] if r["scenario"] == "混合三陷阱" and r["guard"] == "off")
    assert "error" not in fixed and fixed["hijacked"] is True
    assert merged["summary"]["hijack_off"] == 1.0                           # recomputed over all rows
    assert [(e["scenario"], e["guard"], e["note"], e["hijacked"]) for e in merged["rerun"]] == \
        [("混合三陷阱", "off", "verdict rule fixed", True)]
    # only drill_results.json exists: the rerun did not write a second file
    assert [p.name for p in (tmp_path / "drills").iterdir()] == ["drill_results.json"]


def test_merge_refuses_a_file_from_another_matrix(monkeypatch, tmp_path):
    _run_main(monkeypatch, tmp_path, [])
    path = tmp_path / "drills" / "drill_results.json"
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, tmp_path, ["--loop", "production", "--merge-into", str(path)])

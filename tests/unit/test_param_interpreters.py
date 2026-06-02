"""Unit tests for the per-tool param interpreters (LLM params -> argv)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.tool_invocation.params.common import ParamError, as_bool, as_int
from modules.tool_invocation.params.nmap_params import NmapParamInterpreter
from modules.tool_invocation.params.dirsearch_params import DirsearchParamInterpreter
from modules.tool_invocation.params.nikto_params import NiktoParamInterpreter
from modules.tool_invocation.params.sqlmap_params import SqlmapParamInterpreter
from modules.tool_invocation.params.metasploit_params import MetasploitParamInterpreter


# --- common helpers --------------------------------------------------------

@pytest.mark.parametrize("val,expected", [
    (True, True), ("true", True), ("YES", True), (1, True), ("on", True),
    (False, False), ("false", False), ("no", False), (0, False), ("", False),
])
def test_as_bool(val, expected):
    assert as_bool(val) is expected


def test_as_int_clamps_and_rejects():
    assert as_int("9", name="level", lo=1, hi=5) == 5
    assert as_int(0, name="level", lo=1, hi=5) == 1
    with pytest.raises(ParamError):
        as_int("abc", name="threads")
    with pytest.raises(ParamError):
        as_int(True, name="threads")  # bool must not pass as int


# --- nmap -------------------------------------------------------------------

def test_nmap_strips_url_and_maps_alias():
    cmd = NmapParamInterpreter().build(
        {"target": "http://10.0.0.1:5000/path", "scan_type": "fast", "ports": [22, 80]}
    )
    assert cmd[:3] == ["nmap", "-oX", "-"]
    assert cmd[-1] == "10.0.0.1"            # scheme/port/path stripped
    assert "-F" in cmd                       # "fast" -> quick scan
    assert "-p" in cmd and "22,80" in cmd    # list ports joined


def test_nmap_filters_hallucinated_scripts():
    cmd = NmapParamInterpreter().build(
        {"target": "10.0.0.1", "scripts": ["vuln", "totally-made-up"]}
    )
    script_arg = [c for c in cmd if c.startswith("--script=")]
    assert script_arg == ["--script=vuln"]   # bogus script dropped


def test_nmap_requires_target():
    with pytest.raises(ParamError):
        NmapParamInterpreter().build({})


# --- dirsearch --------------------------------------------------------------

def test_dirsearch_adds_scheme_and_json_output():
    cmd = DirsearchParamInterpreter().build(
        {"url": "10.0.0.1:5000", "extensions": ["php", ".html"], "threads": "40", "recursive": "yes"}
    )
    assert "http://10.0.0.1:5000" in cmd     # scheme added
    assert "php,html" in cmd                  # leading dot stripped, list joined
    assert cmd[cmd.index("-t") + 1] == "40"
    assert "-r" in cmd                        # recursive
    assert cmd[-3:] == ["--format", "json", "-o", "-"][-3:]  # JSON to stdout


# --- nikto ------------------------------------------------------------------

def test_nikto_decomposes_full_url():
    cmd = NiktoParamInterpreter().build({"target": "https://host.tld/app"}, "/tmp/out.json")
    assert cmd[cmd.index("-h") + 1] == "host.tld"
    assert "-ssl" in cmd                      # https -> ssl auto-enabled
    assert cmd[cmd.index("-o") + 1] == "/tmp/out.json"


# --- sqlmap -----------------------------------------------------------------

def test_sqlmap_coerces_bools_and_clamps():
    cmd = SqlmapParamInterpreter().build(
        {"url": "http://h/p?id=1", "dbs": "true", "level": "9", "technique": "beu"}
    )
    assert "--dbs" in cmd
    assert cmd[cmd.index("--level") + 1] == "5"   # clamped 9 -> 5
    assert cmd[cmd.index("--technique") + 1] == "BEU"


def test_sqlmap_rejects_bad_dbms_and_technique():
    with pytest.raises(ParamError):
        SqlmapParamInterpreter().build({"url": "http://h/p?id=1", "dbms": "nope"})
    with pytest.raises(ParamError):
        SqlmapParamInterpreter().build({"url": "http://h/p?id=1", "technique": "XYZ"})


# --- metasploit -------------------------------------------------------------

def test_metasploit_builds_resource_script():
    rc = MetasploitParamInterpreter().build(
        {"module": "exploit/x", "target": "10.0.0.1", "rport": "8080", "lhost": "10.0.0.2"}
    )
    assert "use exploit/x" in rc
    assert "set RHOSTS 10.0.0.1" in rc
    assert "set RPORT 8080" in rc
    assert "set LPORT 4444" in rc             # default applied
    assert rc.strip().endswith("exit -y")


def test_metasploit_requires_module_and_rhosts():
    with pytest.raises(ParamError):
        MetasploitParamInterpreter().build({"target": "10.0.0.1"})
    with pytest.raises(ParamError):
        MetasploitParamInterpreter().build({"module": "exploit/x"})

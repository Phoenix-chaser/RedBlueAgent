"""Unit tests for tool output parsers using fixture data."""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.tool_invocation.parsers.nmap_parser import NmapParser
from modules.tool_invocation.parsers.dirsearch_parser import DirsearchParser
from modules.tool_invocation.parsers.nikto_parser import NiktoParser
from modules.tool_invocation.parsers.sqlmap_parser import SqlmapParser
from modules.tool_invocation.parsers.metasploit_parser import MetasploitParser


NMAP_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
  <status state="up" reason="echo-reply"/>
  <address addr="192.168.1.100" addrtype="ipv4"/>
  <hostnames><hostname name="target.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.49"/>
    </port>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="7.4"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="open"/>
      <service name="mysql" product="MySQL" version="5.7.36"/>
    </port>
  </ports>
</host>
</nmaprun>'''


def test_nmap_parser_xml():
    parser = NmapParser()
    result = parser.parse(NMAP_XML)

    assert result["total_hosts_up"] == 1
    assert len(result["hosts"]) == 1
    host = result["hosts"][0]
    assert host["ip"] == "192.168.1.100"
    assert host["hostname"] == "target.local"
    assert len(host["ports"]) == 3
    ports = {p["port"]: p for p in host["ports"]}
    assert ports[80]["service"] == "http"
    assert "Apache" in ports[80]["version"]
    assert ports[22]["service"] == "ssh"


def test_nmap_parser_plain_text():
    parser = NmapParser()
    plain = """
Nmap scan report for 10.0.0.1
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0
80/tcp open  http    nginx 1.18.0
443/tcp open  https   nginx 1.18.0
"""
    result = parser.parse(plain)
    assert result["total_hosts_up"] == 1
    assert result["hosts"][0]["ip"] == "10.0.0.1"


def test_nmap_parser_empty():
    parser = NmapParser()
    result = parser.parse("")
    assert result["hosts"] == []
    assert result["total_hosts_up"] == 0


DIRSEARCH_JSON = '{"results": [{"status": 200, "path": "/admin", "content-length": 1234}, {"status": 301, "path": "/login", "content-length": 0}]}'


def test_dirsearch_parser_json():
    parser = DirsearchParser()
    result = parser.parse(DIRSEARCH_JSON)
    assert result["total_found"] == 2
    paths = {p["path"]: p for p in result["paths"]}
    assert "/admin" in paths
    assert paths["/admin"]["status"] == 200


def test_dirsearch_parser_empty():
    parser = DirsearchParser()
    result = parser.parse("")
    assert result["paths"] == []


NIKTO_OUTPUT = """
- Nikto v2.1.6
- Target IP: 192.168.1.100
- Target Hostname: target.local
+ OSVDB-3092: /admin/: This might be interesting...
+ OSVDB-3268: /css/: Directory indexing found.
+ Server leaks inodes via ETags, header found with file /index.html
+ Apache/2.4.49 appears to be outdated (current is at least Apache/2.4.54).
"""


def test_nikto_parser_plain():
    parser = NiktoParser()
    result = parser.parse(NIKTO_OUTPUT)
    assert result["total_found"] >= 2
    descs = [f["description"] for f in result["findings"]]
    assert any("OSVDB" in d or "interesting" in d.lower() or "directory" in d.lower() for d in descs)


SQLMAP_INJECTABLE = """
[*] starting @ 10:00:00 /2024-01-01/
[INFO] testing connection to the target URL
[INFO] parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable
[*] available databases [3]:
[*] 'information_schema'
[*] 'dvwa'
[*] 'mysql'
"""


def test_sqlmap_parser_injectable():
    parser = SqlmapParser()
    result = parser.parse(SQLMAP_INJECTABLE)
    assert result["injectable"] is True
    assert "dvwa" in result["databases"]


def test_sqlmap_parser_not_injectable():
    parser = SqlmapParser()
    result = parser.parse("[INFO] no injectable parameters found")
    assert result["injectable"] is False


MSF_SUCCESS = """
[*] Started reverse TCP handler on 192.168.1.50:4444
[*] Sending stage (980808 bytes) to 192.168.1.100
[*] Meterpreter session 1 opened (192.168.1.50:4444 -> 192.168.1.100:49152)
meterpreter > sysinfo
"""


MSF_FAILURE = """
[*] Started reverse TCP handler on 192.168.1.50:4444
[-] Exploit failed [no-target]: No matching target
[-] Exploit completed, but no session was created.
"""


def test_metasploit_parser_success():
    parser = MetasploitParser()
    result = parser.parse(MSF_SUCCESS)
    assert result["exploit_success"] is True
    assert result["session_opened"] is True
    assert result["session_type"] == "meterpreter"


def test_metasploit_parser_failure():
    parser = MetasploitParser()
    result = parser.parse(MSF_FAILURE)
    assert result["session_opened"] is False
    assert len(result["error_messages"]) > 0


# ===========================================================================
# Edge cases — empty input, alternate formats, fallbacks
# ===========================================================================

# --- dirsearch --------------------------------------------------------------

def test_dirsearch_parser_json_list_form():
    """dirsearch may emit a bare JSON list instead of {"results": [...]}."""
    parser = DirsearchParser()
    result = parser.parse('[{"path": "/a", "status": 200, "content-length": 12}]')
    assert result["total_found"] == 1
    assert result["paths"][0]["path"] == "/a"
    assert result["paths"][0]["size"] == 12


def test_dirsearch_parser_modern_plain_text():
    """Modern timestamped format: [HH:MM:SS] STATUS - SIZE - URL."""
    parser = DirsearchParser()
    result = parser.parse("[11:22:33] 200 -  3KB - http://h/admin")
    assert result["total_found"] == 1
    assert result["paths"][0] == {"path": "/admin", "status": 200, "size": None, "redirect": None}


def test_dirsearch_parser_legacy_plain_text():
    """Legacy format: STATUS  SIZE  URL — path extracted from the URL."""
    parser = DirsearchParser()
    result = parser.parse("200   3KB  http://h/login")
    assert result["paths"][0]["path"] == "/login"
    assert result["paths"][0]["status"] == 200


def test_dirsearch_parser_whitespace_only():
    parser = DirsearchParser()
    assert parser.parse("   ")["paths"] == []


# --- nikto ------------------------------------------------------------------

def test_nikto_parser_json():
    """JSON output (nikto -Format json) is preferred over plain text."""
    parser = NiktoParser()
    out = parser.parse(
        '{"host": "h", "vulnerabilities": ['
        '{"id": "1", "uri": "/x", "msg": "interesting thing found here", "osvdbid": "3092"}]}'
    )
    assert out["target"] == "h"
    assert out["total_found"] == 1
    f = out["findings"][0]
    assert f["url"] == "/x"
    assert f["osvdb"] == "3092"


def test_nikto_parser_malformed_json_falls_back():
    """Invalid JSON must not crash — it falls back to plain-text parsing."""
    parser = NiktoParser()
    out = parser.parse("{not valid json")
    assert out["total_found"] == 0


def test_nikto_parser_empty():
    parser = NiktoParser()
    assert parser.parse("")["findings"] == []


# --- sqlmap -----------------------------------------------------------------

def test_sqlmap_parser_tables():
    """Tables are captured after a 'tables' header line."""
    parser = SqlmapParser()
    out = parser.parse("Database: dvwa\nDatabase tables [2]:\n[*] 'users'\n[*] 'guestbook'")
    assert "users" in out["tables"]
    assert "guestbook" in out["tables"]


def test_sqlmap_parser_json_form():
    """JSON output short-circuits plain-text parsing."""
    parser = SqlmapParser()
    out = parser.parse('{"parameters": ["id"], "databases": ["dvwa"], "data": []}')
    assert out["injectable"] is True
    assert "dvwa" in out["databases"]


def test_sqlmap_parser_os_info():
    parser = SqlmapParser()
    out = parser.parse("operating system: Linux Ubuntu")
    assert out["os_info"] == "Linux Ubuntu"


# --- metasploit -------------------------------------------------------------

def test_metasploit_parser_command_shell_session():
    """A plain command shell (not meterpreter) is still a success."""
    parser = MetasploitParser()
    out = parser.parse("[*] Command shell session 2 opened (a -> b)")
    assert out["session_opened"] is True
    assert out["exploit_success"] is True
    assert out["session_type"] == "shell"


def test_metasploit_parser_empty():
    parser = MetasploitParser()
    out = parser.parse("")
    assert out["exploit_success"] is False
    assert out["session_opened"] is False


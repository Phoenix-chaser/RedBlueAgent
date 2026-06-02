"""
NmapParamInterpreter - turns LLM-produced params into a validated nmap argv.

This is the INPUT side for nmap. The OUTPUT side (XML -> dict) lives in
parsers/nmap_parser.py. Keeping them in separate files means each tool's
"how to call it" and "how to read it back" evolve independently.
"""
from __future__ import annotations

from modules.tool_invocation.params.common import ParamError, as_bool, as_int

# scan_type synonyms the LLM tends to invent -> canonical key
_SCAN_ALIASES = {
    "quick": "quick", "fast": "quick", "-f": "quick",
    "service": "service", "version": "service", "sv": "service", "-sv": "service",
    "full": "full", "all": "full", "complete": "full", "allports": "full",
    "udp": "udp", "-su": "udp",
    "host_discovery": "host_discovery", "ping": "host_discovery",
    "discovery": "host_discovery", "sn": "host_discovery", "-sn": "host_discovery",
}

# scan_type -> base flags
_SCAN_FLAGS = {
    "quick": ["-T4", "-F"],
    "service": ["-sV", "-sC", "-T4"],
    "full": ["-sV", "-sC", "-p-", "-T4"],
    "udp": ["-sU", "-T4"],
    "host_discovery": ["-sn"],
}

# Valid nmap scripts/categories — gate LLM hallucinations.
VALID_SCRIPTS = {
    "default", "safe", "vuln", "auth", "discovery",
    "http-title", "http-headers", "http-methods", "http-auth",
    "http-robots.txt", "http-enum", "http-waf-detect",
    "http-shellshock", "http-sql-injection", "http-auth-finder",
    "http-php-version", "http-server-header", "http-open-redirect",
    "http-csrf", "http-dombased-xss", "http-stored-xss",
    "http-internal-ip-disclosure", "http-backup-finder",
    "http-config-backup", "http-trace", "http-useragent-tester",
    "http-vuln-cve2015-3176", "http-vuln-cve2017-5638",
    "http-vuln-cve2014-2126", "http-vuln-cve2014-2127",
    "smb-vuln-ms17-010", "ssl-heartbleed", "ssl-poodle",
    "ftp-anon", "ftp-bounce", "ssh-auth-methods",
    "smb-enum-shares", "smb-enum-users",
}


class NmapParamInterpreter:
    """Builds an `nmap` argv from a loose LLM params dict.

    Recognized params:
      target (required)  IP, hostname, or CIDR. Accepts a bare URL and strips
                         the scheme/path (LLMs often pass "http://host:5000").
      scan_type          quick | service | full | udp | host_discovery
                         (synonyms like "fast", "version", "ping" are mapped)
      ports              "22,80" | "1-1000" | [22, 80] | 80
      scripts            comma string or list; filtered against VALID_SCRIPTS
      timing             1-5 (or "T4"); only applied when scan_type leaves it open
      extra_flags        list of raw flags appended verbatim
    """

    def build(self, params: dict) -> list[str]:
        target = self._target(params)

        cmd = ["nmap", "-oX", "-"]  # always XML to stdout for the parser

        scan_type = self._scan_type(params)
        cmd += list(_SCAN_FLAGS[scan_type])

        if ports := self._ports(params):
            cmd += ["-p", ports]

        if scripts := self._scripts(params):
            cmd.append(f"--script={scripts}")

        # Timing template: only when the scan_type didn't already pin one.
        if scan_type not in ("quick", "service", "full") and (timing := params.get("timing")) is not None:
            t = str(timing).strip().lstrip("Tt")
            if t.isdigit() and 1 <= int(t) <= 5:
                cmd.append(f"-T{t}")

        for flag in params.get("extra_flags", []) or []:
            cmd.append(str(flag))

        cmd.append(target)
        return cmd

    @staticmethod
    def _target(params: dict) -> str:
        # Accept common aliases the LLM uses interchangeably.
        target = params.get("target") or params.get("host") or params.get("ip") or ""
        target = str(target).strip()
        if not target:
            raise ParamError("nmap requires a 'target' (IP, hostname, or CIDR)")
        # Strip a URL scheme/path if one slipped in: http://host:5000/x -> host
        if "://" in target:
            from urllib.parse import urlparse
            netloc = urlparse(target).netloc or target
            target = netloc.split("@")[-1].split(":")[0]
        return target

    @staticmethod
    def _scan_type(params: dict) -> str:
        raw = str(params.get("scan_type", "service")).strip().lower()
        return _SCAN_ALIASES.get(raw, "service")

    @staticmethod
    def _ports(params: dict) -> str:
        ports = params.get("ports")
        if ports is None or ports == "":
            return ""
        if isinstance(ports, (list, tuple, set)):
            return ",".join(str(p).strip() for p in ports if str(p).strip())
        return str(ports).strip()

    @staticmethod
    def _scripts(params: dict) -> str:
        scripts = params.get("scripts")
        if not scripts:
            return ""
        if isinstance(scripts, (list, tuple, set)):
            items = [str(s).strip() for s in scripts]
        else:
            items = [s.strip() for s in str(scripts).split(",")]
        valid = [s for s in items if s in VALID_SCRIPTS]
        return ",".join(valid)

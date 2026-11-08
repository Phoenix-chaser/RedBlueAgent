"""
SqlmapParamInterpreter - builds a `sqlmap` argv from LLM params.
Output side lives in parsers/sqlmap_parser.py.
"""
from __future__ import annotations

from modules.tool_invocation.params.common import ParamError, as_bool, as_int

# os_shell is destructive — surfaced so callers/approval gates can detect it.
DANGEROUS_FLAGS = {"os_shell", "os_pwn", "sql_shell"}

_VALID_DBMS = {"mysql", "mssql", "postgresql", "postgres", "oracle", "sqlite", "access", "db2"}
_TECHNIQUE_CHARS = set("BEUSTQ")

# 命名等级 → 数字（服务端推断，宁可不拒）：LLM 常写 "high" 而非 3——按名
# 映射后命令行里的数字即回执（观察文本含 Command 行，推断结果对 LLM 可见）。
# 安全约束：仅限 level/risk 这类强度参数；url 等目标参数永不推断。
_LEVEL_NAMES = {"low": 1, "medium": 2, "default": 2, "normal": 2,
                "high": 3, "higher": 4, "highest": 5, "max": 5}
_RISK_NAMES = {"low": 1, "medium": 2, "default": 2, "normal": 2, "high": 3, "max": 3}


class SqlmapParamInterpreter:
    """Recognized params:
      url (required)     target URL with a parameter, e.g. http://host/p?id=1
      data               POST body string
      cookie             Cookie header
      level              1-5 (default 2)
      risk               1-3 (default 1)
      dbs/tables/dump    bools — enumerate databases/tables, dump data
      dbms               DBMS hint (validated against known engines)
      technique          subset of letters BEUSTQ
      os_shell           DANGEROUS — attempt OS shell (needs approval)
      batch              never prompt (default True)
    """

    def build(self, params: dict) -> list[str]:
        url = str(params.get("url") or params.get("target") or "").strip()
        if not url:
            raise ParamError("sqlmap requires a 'url' with a parameter, e.g. http://host/p?id=1")

        cmd = ["sqlmap", "-u", url]

        if as_bool(params.get("batch"), default=True):
            cmd.append("--batch")
        if data := params.get("data"):
            cmd += ["--data", str(data)]
        if cookie := params.get("cookie"):
            cmd += ["--cookie", str(cookie)]

        cmd += ["--level", str(as_int(self._named_level(params.get("level", 2), _LEVEL_NAMES),
                                      name="level", lo=1, hi=5))]
        cmd += ["--risk", str(as_int(self._named_level(params.get("risk", 1), _RISK_NAMES),
                                     name="risk", lo=1, hi=3))]

        if as_bool(params.get("dbs")):
            cmd.append("--dbs")
        if as_bool(params.get("tables")):
            cmd.append("--tables")
        if as_bool(params.get("dump")):
            cmd.append("--dump")

        if dbms := self._dbms(params):
            cmd += ["--dbms", dbms]
        if technique := self._technique(params):
            cmd += ["--technique", technique]
        if as_bool(params.get("os_shell")):
            cmd.append("--os-shell")

        return cmd

    @staticmethod
    def _named_level(value, names: dict) -> int | str:
        """Map named levels ("high" → 3); pass everything else through to as_int."""
        if isinstance(value, str) and value.strip().lower() in names:
            return names[value.strip().lower()]
        return value

    @staticmethod
    def _dbms(params: dict) -> str:
        dbms = str(params.get("dbms", "")).strip().lower()
        if dbms and dbms not in _VALID_DBMS:
            raise ParamError(f"unknown dbms '{dbms}'; valid: {', '.join(sorted(_VALID_DBMS))}")
        return dbms

    @staticmethod
    def _technique(params: dict) -> str:
        tech = str(params.get("technique", "")).strip().upper()
        if tech and not set(tech) <= _TECHNIQUE_CHARS:
            raise ParamError("technique must be letters from BEUSTQ (e.g. 'BEU')")
        return tech

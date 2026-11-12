"""
DirsearchParamInterpreter - builds a `dirsearch` argv from LLM params.
Output side lives in parsers/dirsearch_parser.py.
"""
from __future__ import annotations

from modules.tool_invocation.params.common import ParamError, as_bool, as_int


class DirsearchParamInterpreter:
    """Recognized params:
      url (required)     target URL, e.g. http://192.168.1.1:5000
      wordlist           path to a custom wordlist (dirsearch default if omitted)
      extensions         "php,html,js" or ["php","html"]
      threads            int 1-100 (default 25)
      exclude_status     "404,403" or [404, 403] (default "404")
      recursive          bool (default False)
    Always requests JSON output to stdout so the parser gets structured data.
    """

    def build(self, params: dict) -> list[str]:
        url = str(params.get("url") or params.get("target") or "").strip()
        if not url:
            raise ParamError("dirsearch requires a 'url' (e.g. http://host:port)")
        if "://" not in url:
            url = "http://" + url  # LLM sometimes drops the scheme

        cmd = ["dirsearch", "-u", url, "-q"]

        if wordlist := params.get("wordlist"):
            cmd += ["-w", str(wordlist)]

        cmd += ["-e", self._extensions(params)]
        cmd += ["-t", str(as_int(params.get("threads", 25), name="threads", lo=1, hi=100))]

        if exclude := self._exclude_status(params):
            cmd += ["--exclude-status", exclude]

        if as_bool(params.get("recursive"), default=False):
            cmd.append("-r")

        # 输出参数（JSON report）由 DirsearchTool.run 管理：dirsearch 0.5 的
        # 参数是 -O/--output-formats（旧 --format 已移除），且 report 落
        # 临时文件后读回喂 parser（-o /dev/stdout 在 0.5 上会挂死）。
        return cmd

    @staticmethod
    def _extensions(params: dict) -> str:
        ext = params.get("extensions", "php,html,txt,js,bak")
        if isinstance(ext, (list, tuple, set)):
            ext = ",".join(str(e).strip().lstrip(".") for e in ext if str(e).strip())
        return str(ext).strip() or "php,html,txt,js,bak"

    @staticmethod
    def _exclude_status(params: dict) -> str:
        codes = params.get("exclude_status", "404")
        if codes in (None, "", False):
            return ""
        if isinstance(codes, (list, tuple, set)):
            return ",".join(str(c).strip() for c in codes if str(c).strip())
        return str(codes).strip()

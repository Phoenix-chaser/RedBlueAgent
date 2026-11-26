"""
NiktoParamInterpreter - builds a `nikto` argv from LLM params.
Output side lives in parsers/nikto_parser.py.
"""
from __future__ import annotations

from urllib.parse import urlparse

from modules.tool_invocation.params.common import ParamError, as_bool, as_int


class NiktoParamInterpreter:
    """Recognized params:
      target (required)  IP or hostname. A full URL is accepted and decomposed
                         into host + port + ssl automatically.
      port               int (default 80, or 443 when ssl)
      ssl                bool (default False; auto-True for https:// targets)
      plugins            nikto plugin string or list
      timeout_per_req    seconds per request (default 10)

    Returns argv. With json_out_path the report goes to that file in JSON
    (nikto can't stream JSON to stdout); without it, plain text on stdout.
    """

    def build(self, params: dict, json_out_path: str | None = None) -> list[str]:
        target, url_port, url_ssl = self._target(params)

        cmd = ["nikto", "-h", target, "-nointeractive"]

        port = params.get("port") or url_port
        if port:
            cmd += ["-p", str(as_int(port, name="port", lo=1, hi=65535))]

        if as_bool(params.get("ssl"), default=url_ssl):
            cmd.append("-ssl")

        if plugins := self._plugins(params):
            cmd += ["-Plugins", plugins]

        cmd += ["-timeout", str(as_int(params.get("timeout_per_req", 10), name="timeout_per_req", lo=1, hi=120))]
        if json_out_path is not None:
            # Ubuntu/Debian 打包的 nikto 2.1.5 没有 json 格式：会打印
            # "+ ERROR: Invalid output format" 却仍以 0 退出。NiktoTool.run
            # 认出这一行后退回文本模式。
            cmd += ["-Format", "json", "-o", json_out_path]
        return cmd

    @staticmethod
    def _target(params: dict) -> tuple[str, int | None, bool]:
        raw = str(params.get("target") or params.get("host") or params.get("url") or "").strip()
        if not raw:
            raise ParamError("nikto requires a 'target' (IP or hostname)")
        if "://" in raw:
            u = urlparse(raw)
            host = u.hostname or raw
            return host, u.port, (u.scheme == "https")
        # bare "host:port"
        if ":" in raw and not raw.count(":") > 1:
            host, _, port = raw.partition(":")
            return host, (int(port) if port.isdigit() else None), False
        return raw, None, False

    @staticmethod
    def _plugins(params: dict) -> str:
        plugins = params.get("plugins")
        if not plugins:
            return ""
        if isinstance(plugins, (list, tuple, set)):
            return ";".join(str(p).strip() for p in plugins if str(p).strip())
        return str(plugins).strip()

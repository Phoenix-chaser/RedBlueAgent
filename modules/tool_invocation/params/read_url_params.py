"""
ReadUrlParamInterpreter - validates the URL the read_url tool will fetch.

read_url has no argv: the tool fetches the URL in-process (urllib) so that a
redirect can be reported instead of silently followed out of scope. The
interpreter therefore returns the URL string rather than a command list.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from modules.tool_invocation.params.common import ParamError

MAX_URL_LENGTH = 2000


class ReadUrlParamInterpreter:
    """Recognized params:
      url (required)  absolute http(s) URL; a bare host[:port][/path] gets http://

    Only http and https are accepted: other schemes (file:, ftp:, ...) are
    never fetched. The host is scope-checked by SecurityBoundaryController.
    """

    def build(self, params: dict) -> str:
        raw = str(params.get("url") or params.get("target") or "").strip()
        if not raw:
            raise ParamError("read_url requires a 'url' (e.g. http://host:port/robots.txt)")
        if "://" not in raw:
            raw = "http://" + raw
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ParamError("'url' must be an absolute http(s) URL; other schemes are not fetched")
        if len(raw) > MAX_URL_LENGTH or any(ord(ch) < 32 or ch == "\x7f" for ch in raw):
            raise ParamError("'url' is too long or contains control characters")
        return raw

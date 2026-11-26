"""
ReadUrlTool - fetches one in-scope HTTP(S) resource and returns its text.

The other tools report what a scanner concluded; read_url is the channel
through which target-authored content (robots.txt, pages, files) actually
reaches the model. That is what makes the honeytoken line live: the response
of a honeytoken path can now enter the context, so it is registered as taint
and any later use of it is blocked.

Boundaries:
- the URL is scope-checked like any target-bearing param, and only http(s)
  is fetched;
- redirects are reported, never followed (a redirect is the classic way to
  leave the authorized scope);
- the body is capped in bytes and in lines, and only text-like content types
  are passed on.
"""
from __future__ import annotations

import http.client
import time
import urllib.error
import urllib.request
from datetime import datetime

from modules.context_management.state_schema import ToolResult
from modules.tool_invocation.params.common import ParamError
from modules.tool_invocation.params.read_url_params import ReadUrlParamInterpreter
from modules.tool_invocation.parsers.read_url_parser import ReadUrlParser
from modules.tool_invocation.tools.base_tool import BaseTool
from utils.clip import clip_marked

USER_AGENT = "Mozilla/5.0 (compatible; RedBlueAgent/0.3; authorized security test)"
# Content types whose body is passed on to the model; anything else (images,
# archives, binaries) is reported by size only.
_TEXT_PREFIXES = ("text/", "application/json", "application/xml", "application/javascript",
                  "application/x-www-form-urlencoded")
_TEXT_SUFFIXES = ("+json", "+xml")
RAW_OUTPUT_CHARS = 20_000


def _is_textual(content_type: str) -> bool:
    return content_type.startswith(_TEXT_PREFIXES) or content_type.endswith(_TEXT_SUFFIXES)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """redirect_request() returning None turns every 3xx into an HTTPError,
    which run() reports together with the Location header."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ReadUrlTool(BaseTool):
    name = "read_url"
    timeout = 15
    max_bytes = 262_144
    parser = ReadUrlParser()
    params_interpreter = ReadUrlParamInterpreter()

    def build_command(self, params: dict) -> list[str]:
        # There is no argv; this is the request line shown in traces and judged
        # by the approval gate.
        return ["GET", self.params_interpreter.build(params)]

    def preview(self, params: dict) -> str:
        return " ".join(self.build_command(params))

    @staticmethod
    def _opener():
        return urllib.request.build_opener(_NoRedirect())

    def run(self, params: dict) -> ToolResult:
        try:
            url = self.params_interpreter.build(params)
        except ParamError as e:
            return ToolResult(tool=self.name, command="", success=False,
                              error_message=str(e), timestamp=datetime.utcnow())

        request = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": USER_AGENT,
                     "Accept": "text/html,text/plain,application/json;q=0.9,*/*;q=0.5"})
        started = time.monotonic()
        try:
            with self._opener().open(request, timeout=self.timeout) as response:
                status, headers = response.status, response.headers
                data = response.read(self.max_bytes + 1)
        except urllib.error.HTTPError as error:  # includes 3xx: redirects are not followed
            status, headers = error.code, error.headers
            try:
                data = error.read(self.max_bytes + 1) or b""
            except Exception:
                data = b""
        # HTTPException（坏的状态行、读到一半断开）不是 OSError：不接住的话会落到
        # invoker 的通用兜底，模型拿不到「下一步」。失败原因里可能带着服务端给的文字
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as error:
            # 失败原因（异常消息）里可能带着服务端给的文字：进不可信区块，不进 ERROR 行
            return ToolResult(
                tool=self.name, command=f"GET {url}", success=False,
                error_message=(f"read_url could not fetch {url}，原因见错误输出。"
                               "下一步（可执行）：用 nmap scan_type='service' 确认该端口开放且为 HTTP(S)，"
                               "或改用其他已发现的路径；不要原样重试。"),
                parsed={"tool_error": [str(error).strip()[:300]]},
                elapsed_seconds=time.monotonic() - started, timestamp=datetime.utcnow())

        content_type = (headers.get_content_type() if headers is not None else "") or ""
        charset = (headers.get_content_charset() if headers is not None else None) or "utf-8"
        try:
            body = data[:self.max_bytes].decode(charset, errors="replace")
        except LookupError:          # 服务端声明了一个 Python 不认识的字符集
            body = data[:self.max_bytes].decode("utf-8", errors="replace")
        textual = _is_textual(content_type)
        parsed = {"url": url, "status": status, "content_type": content_type}
        if headers is not None and headers.get("Location"):
            # reported, not followed: the new URL has to pass the scope check itself
            parsed["location"] = headers.get("Location")
        if textual and body:
            try:
                parsed.update(self.parser.parse(body, content_type))
            except Exception:
                # 解析器被这份正文弄崩了：异常消息里可能带着正文片段，不往外带；
                # 正文没有进 parsed，也就不会进入上下文
                parsed["note"] = "正文解析失败，正文未送入上下文"
            parsed["truncated"] = parsed.get("truncated", False) or len(data) > self.max_bytes
        elif body:
            parsed["note"] = f"非文本内容（{len(data)} 字节），正文未送入上下文"
        success = 200 <= status < 400
        error_message = None
        if not success:
            error_message = f"HTTP {status} for {url}。下一步（可执行）：换用其他已发现的路径，不要原样重试。"
        return ToolResult(
            tool=self.name, command=f"GET {url}",
            raw_stdout=clip_marked(body, RAW_OUTPUT_CHARS) if textual else "",
            parsed=parsed, success=success, error_message=error_message,
            elapsed_seconds=time.monotonic() - started, timestamp=datetime.utcnow())

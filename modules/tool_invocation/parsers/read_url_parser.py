"""
ReadUrlParser - turns an HTTP response body into text lines for the LLM.

HTML is reduced to visible text (script/style dropped, tags stripped, entities
unfolded). The body becomes a list of lines on purpose: the inbound guard scans
each line on its own, so it can quarantine one injected line without discarding
the rest of the page.
"""
from __future__ import annotations

import html as html_module
import re

from modules.tool_invocation.parsers.base_parser import BaseOutputParser

MAX_LINES = 80
MAX_LINE_LENGTH = 300

_BLOCK_ELEMENTS = re.compile(r"<(script|style|noscript|template)\b.*?</\1\s*>", re.I | re.S)
# Block-level boundaries become line breaks, so one text fragment lands on one
# line and the guard can quarantine it on its own.
_LINE_BREAK = re.compile(
    r"</(?:p|div|li|tr|h[1-6]|title|head|body|section|article|ul|ol|table|pre|blockquote"
    r"|form|dd|dt|header|footer|nav|main)>|<br\s*/?>",
    re.I)
_TAG = re.compile(r"<[^>]{1,2000}>")
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_WHITESPACE = re.compile(r"[ \t\x0b\f\r ]+")


def html_to_text(markup: str) -> str:
    text = _COMMENT.sub(" ", markup)
    text = _BLOCK_ELEMENTS.sub(" ", text)
    text = _LINE_BREAK.sub("\n", text)
    text = _TAG.sub(" ", text)
    return html_module.unescape(text)


class ReadUrlParser(BaseOutputParser):
    def parse(self, body: str, content_type: str = "") -> dict:
        text = html_to_text(body) if "html" in content_type.lower() else body
        lines = []
        for raw_line in text.split("\n"):
            line = _WHITESPACE.sub(" ", raw_line).strip()
            if line:
                lines.append(line[:MAX_LINE_LENGTH])
        return {"lines": lines[:MAX_LINES], "truncated": len(lines) > MAX_LINES}

"""
clip_marked - single-source truncation with an explicit marker.

Silent truncation is a bug: the LLM must always be able to tell that it is
seeing a prefix of a longer text, and by how much (tool-protocol rule
adopted from SPECTRE's AGENTS.md, lalalala5678/spectre, MIT License). All truncation of LLM-facing text
(raw tool output, thoughts, observations) goes through here.
"""
from __future__ import annotations


def clip_marked(text: str, limit: int) -> str:
    """Return text[:limit], appending a "[TRUNCATED: shown/total]" marker when clipped."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n[TRUNCATED: {limit}/{len(text)} chars shown]"

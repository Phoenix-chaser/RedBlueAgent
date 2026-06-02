"""
Shared helpers for tool param interpreters.

LLMs emit params loosely: booleans as the strings "true"/"yes", numbers as
strings, lists as comma-joined strings (and vice-versa), and synonyms for the
same option. These helpers normalize that mess into the exact types each tool
needs, and raise ParamError with an LLM-readable message when a value can't be
salvaged.
"""
from __future__ import annotations

from typing import Any, Iterable


class ParamError(ValueError):
    """Raised when LLM-supplied params cannot be coerced into a valid command.

    The message is fed back to the LLM as the tool error, so it must explain
    what was wrong AND what a correct value looks like.
    """


_TRUE = {"true", "1", "yes", "y", "on", "enable", "enabled", "t"}
_FALSE = {"false", "0", "no", "n", "off", "disable", "disabled", "f", "none", ""}


def as_bool(value: Any, default: bool = False) -> bool:
    """Coerce LLM truthy/falsy values (bool, int, 'true'/'yes'/'1', ...)."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    s = str(value).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    return default


def as_int(value: Any, *, name: str, lo: int | None = None, hi: int | None = None) -> int:
    """Coerce to int and clamp into [lo, hi]. Raises ParamError on garbage."""
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly
        raise ParamError(f"'{name}' must be a number, got boolean {value!r}")
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise ParamError(f"'{name}' must be an integer, got {value!r}")
    if lo is not None and n < lo:
        n = lo
    if hi is not None and n > hi:
        n = hi
    return n

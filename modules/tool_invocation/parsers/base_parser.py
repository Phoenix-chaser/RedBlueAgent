"""
BaseOutputParser ABC for all tool output parsers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseOutputParser(ABC):
    @abstractmethod
    def parse(self, stdout: str, stderr: str = "") -> dict:
        """Parse raw tool output into a structured dict."""
        ...

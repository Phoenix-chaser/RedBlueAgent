"""Unit tests for clip_marked — truncation must never be silent."""
import sys
import os

from utils.clip import clip_marked


def test_short_text_unchanged():
    assert clip_marked("hello", 50) == "hello"
    assert clip_marked("hello", 5) == "hello"
    assert clip_marked("", 10) == ""


def test_marker_appended_when_clipped():
    out = clip_marked("x" * 300, 100)
    assert out.startswith("x" * 100)
    assert "[TRUNCATED: 100/300 chars shown]" in out


def test_marker_reports_original_length():
    assert clip_marked("a" * 250, 200).endswith("[TRUNCATED: 200/250 chars shown]")


def test_boundary_length_not_clipped():
    text = "y" * 200
    assert clip_marked(text, 200) == text

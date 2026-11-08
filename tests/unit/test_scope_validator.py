"""Unit tests for TargetScopeValidator."""
import pytest
import sys
import os

from security.scope_validator import TargetScopeValidator


def test_empty_scope_fails_closed():
    v = TargetScopeValidator()
    assert v.is_in_scope("192.168.1.100", []) is False
    assert v.is_in_scope("10.0.0.1", []) is False


def test_wildcard_scope_allows_all():
    v = TargetScopeValidator()
    assert v.is_in_scope("192.168.1.100", ["*"]) is True
    assert v.is_in_scope("any.example.org", ["*"]) is True


def test_exact_ip_match():
    v = TargetScopeValidator()
    assert v.is_in_scope("192.168.1.100", ["192.168.1.100"]) is True
    assert v.is_in_scope("192.168.1.101", ["192.168.1.100"]) is False


def test_cidr_match():
    v = TargetScopeValidator()
    assert v.is_in_scope("192.168.1.100", ["192.168.1.0/24"]) is True
    assert v.is_in_scope("192.168.2.1", ["192.168.1.0/24"]) is False
    assert v.is_in_scope("10.0.0.50", ["10.0.0.0/8"]) is True


def test_hostname_match():
    v = TargetScopeValidator()
    assert v.is_in_scope("target.local", ["target.local"]) is True
    assert v.is_in_scope("other.local", ["target.local"]) is False


def test_url_stripped_to_host():
    v = TargetScopeValidator()
    assert v.is_in_scope("http://192.168.1.100/path?id=1", ["192.168.1.100"]) is True
    assert v.is_in_scope("https://target.local/admin", ["target.local"]) is True


def test_wildcard_hostname():
    v = TargetScopeValidator()
    assert v.is_in_scope("sub.example.com", ["*.example.com"]) is True
    assert v.is_in_scope("other.org", ["*.example.com"]) is False


def test_url_with_port_stripped():
    v = TargetScopeValidator()
    assert v.is_in_scope("192.168.1.100:8080", ["192.168.1.100"]) is True

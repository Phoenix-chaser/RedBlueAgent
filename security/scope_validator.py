"""
TargetScopeValidator - ensures tool invocations only target in-scope hosts.
"""
from __future__ import annotations

import ipaddress
import re


class TargetScopeValidator:
    """
    Validates that a given target string (IP, hostname, URL) falls within
    the declared scope (list of IPs, CIDR ranges, or hostnames).
    """

    def is_in_scope(self, target: str, scope: list[str]) -> bool:
        if not scope:
            # Fail-closed: without a declared scope nothing is authorized.
            # An open engagement must pass an explicit wildcard scope (["*"]).
            return False

        # Strip URL scheme and path to get bare host
        host = self._extract_host(target)

        for scope_entry in scope:
            # Explicit wildcard authorizes everything (documented escape hatch)
            if scope_entry.strip() == "*":
                return True
            if self._matches(host, scope_entry):
                return True
        return False

    def _extract_host(self, target: str) -> str:
        # Remove scheme
        target = re.sub(r"^https?://", "", target)
        # Remove path and port
        target = target.split("/")[0].split(":")[0]
        return target.strip()

    def _matches(self, host: str, scope_entry: str) -> bool:
        # Direct string match (hostname or IP)
        if host == scope_entry:
            return True

        # Wildcard hostname match (*.example.com)
        if scope_entry.startswith("*"):
            suffix = scope_entry[1:]
            if host.endswith(suffix):
                return True

        # CIDR range match
        if "/" in scope_entry:
            try:
                network = ipaddress.ip_network(scope_entry, strict=False)
                host_ip = ipaddress.ip_address(host)
                return host_ip in network
            except ValueError:
                pass

        # Plain IP match
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(scope_entry)
        except ValueError:
            pass

        return False

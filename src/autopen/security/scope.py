"""Scope validator — ensures every tool call stays within authorized targets."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from autopen.state.models import ScopeConfig


class ScopeViolationError(Exception):
    """Raised when a tool targets a host outside the defined scope."""


class ScopeValidator:
    """
    Validates that a proposed target is within the authorized scope.

    Scope can be defined as:
    - IP addresses: "192.168.1.1"
    - CIDR ranges:  "192.168.1.0/24", "10.0.0.0/8"
    - Hostnames:    "example.com", "*.example.com"
    """

    def __init__(self, scope: ScopeConfig) -> None:
        self._scope = scope
        self._allowed_networks = self._parse_networks(scope.allowed_hosts)
        self._allowed_domains = self._parse_domains(scope.allowed_hosts)
        self._excluded_networks = self._parse_networks(scope.exclude_hosts)
        self._excluded_domains = self._parse_domains(scope.exclude_hosts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, target: str) -> bool:
        """Return True if target is in scope, False otherwise (no exception)."""
        try:
            self.assert_in_scope(target)
            return True
        except ScopeViolationError:
            return False

    def assert_in_scope(self, target: str) -> None:
        """Raise ScopeViolationError if target is out of scope."""
        clean = self._extract_host(target)
        if not clean:
            raise ScopeViolationError(f"Cannot parse target: {target!r}")

        # Check explicit exclusions first
        if self._is_excluded(clean):
            raise ScopeViolationError(
                f"Target {clean!r} is explicitly excluded from scope."
            )

        # Check if in allowed set
        if self._is_allowed(clean):
            return

        raise ScopeViolationError(
            f"Target {clean!r} is NOT in the authorized scope. "
            f"Allowed: {self._scope.allowed_hosts}"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_host(self, target: str) -> str:
        """Strip URL scheme, path, port from a target string."""
        # Remove scheme
        clean = re.sub(r"^https?://", "", target)
        clean = re.sub(r"^(ftp|ssh|smb)://", "", clean)
        # Remove path and query string
        clean = clean.split("/")[0].split("?")[0].split("#")[0]
        # Remove port
        if ":" in clean and not clean.count(":") > 1:  # IPv6 has multiple colons
            clean = clean.rsplit(":", 1)[0]
        return clean.strip().lower()

    def _is_allowed(self, host: str) -> bool:
        # Try IP-based matching
        try:
            addr = ipaddress.ip_address(host)
            for net in self._allowed_networks:
                if addr in net:
                    return True
        except ValueError:
            pass  # not an IP — try domain matching

        # Domain matching
        for pattern in self._allowed_domains:
            if self._domain_matches(host, pattern):
                return True

        return False

    def _is_excluded(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            for net in self._excluded_networks:
                if addr in net:
                    return True
        except ValueError:
            pass

        for pattern in self._excluded_domains:
            if self._domain_matches(host, pattern):
                return True

        return False

    def _domain_matches(self, host: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host == suffix or host.endswith("." + suffix)
        return host == pattern

    @staticmethod
    def _parse_networks(hosts: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for h in hosts:
            try:
                networks.append(ipaddress.ip_network(h, strict=False))
            except ValueError:
                pass  # not an IP/CIDR — handled by domain matching
        return networks

    @staticmethod
    def _parse_domains(hosts: list[str]) -> list[str]:
        domains = []
        for h in hosts:
            try:
                ipaddress.ip_network(h, strict=False)
            except ValueError:
                # It's a hostname/domain
                domains.append(h.lower())
        return domains

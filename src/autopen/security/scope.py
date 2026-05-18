"""Scope validator — ensures every tool call stays within authorized targets."""

from __future__ import annotations

import ipaddress
import re
from typing import Union

from autopen.state.models import ScopeConfig

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ScopeViolationError(Exception):
    """Raised when a tool targets a host outside the defined scope."""


class ScopeValidator:
    """
    Validates that a proposed target is within the authorized scope.

    Scope can be defined as:
    - IP addresses: "192.168.1.1", "2001:db8::1"
    - CIDR ranges:  "192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"
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

        if self._is_excluded(clean):
            raise ScopeViolationError(
                f"Target {clean!r} is explicitly excluded from scope."
            )

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
        """Strip URL scheme, path, port from a target string (IPv4/IPv6/hostname)."""
        clean = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", target).strip()
        clean = clean.split("/")[0].split("?")[0].split("#")[0]

        # IPv6 in URL form is bracketed: [::1]:8080
        m = re.match(r"^\[([0-9a-fA-F:]+)\](?::\d+)?$", clean)
        if m:
            return m.group(1).lower()

        # Try parsing as bare IPv6 address (multiple colons, no brackets)
        if clean.count(":") >= 2:
            try:
                ipaddress.IPv6Address(clean)
                return clean.lower()
            except ValueError:
                pass  # fall through

        # IPv4/hostname:port — strip trailing :port if present
        if ":" in clean:
            clean = clean.rsplit(":", 1)[0]
        return clean.strip().lower()

    def _is_allowed(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._allowed_networks)
        except ValueError:
            pass

        return any(self._domain_matches(host, p) for p in self._allowed_domains)

    def _is_excluded(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            if any(addr in net for net in self._excluded_networks):
                return True
        except ValueError:
            pass

        return any(self._domain_matches(host, p) for p in self._excluded_domains)

    @staticmethod
    def _domain_matches(host: str, pattern: str) -> bool:
        """
        Strict domain match.

        - ``pattern`` ``"example.com"``      → only ``example.com`` itself.
        - ``pattern`` ``"*.example.com"``    → any direct or indirect subdomain
          (``a.example.com``, ``a.b.example.com``) but NOT the apex
          ``example.com`` and NOT a confusable like ``evil-example.com``.

        Both sides are lowercased; trailing dots are stripped.
        """
        host = host.rstrip(".").lower()
        pattern = pattern.rstrip(".").lower()

        if pattern.startswith("*."):
            suffix = pattern[2:]
            if not suffix:
                return False
            # Subdomain: must end with "."+suffix AND have at least one label before.
            return host.endswith("." + suffix) and host != suffix
        return host == pattern

    @staticmethod
    def _parse_networks(hosts: list[str]) -> list[IpNetwork]:
        networks: list[IpNetwork] = []
        for h in hosts:
            try:
                networks.append(ipaddress.ip_network(h, strict=False))
            except ValueError:
                pass  # not an IP/CIDR — handled by domain matching
        return networks

    @staticmethod
    def _parse_domains(hosts: list[str]) -> list[str]:
        domains: list[str] = []
        for h in hosts:
            try:
                ipaddress.ip_network(h, strict=False)
            except ValueError:
                domains.append(h.rstrip(".").lower())
        return domains

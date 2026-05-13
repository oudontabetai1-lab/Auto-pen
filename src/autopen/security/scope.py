"""Scope validator — ensures every tool call stays within authorized targets."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from autopen.state.models import ScopeConfig


class ScopeViolationError(Exception):
    """Raised when a tool targets a host outside the defined scope."""


class ScopeValidator:
    def __init__(self, scope: ScopeConfig) -> None:
        self._scope = scope
        self._allowed_networks = self._parse_networks(scope.allowed_hosts)
        self._allowed_domains = self._parse_domains(scope.allowed_hosts)
        self._excluded_networks = self._parse_networks(scope.exclude_hosts)
        self._excluded_domains = self._parse_domains(scope.exclude_hosts)

    def validate(self, target: str) -> bool:
        try:
            self.assert_in_scope(target)
            return True
        except ScopeViolationError:
            return False

    def assert_in_scope(self, target: str) -> None:
        clean = self._extract_host(target)
        if not clean:
            raise ScopeViolationError(f"Cannot parse target: {target!r}")
        if self._is_excluded(clean):
            raise ScopeViolationError(f"Target {clean!r} is explicitly excluded from scope.")
        if self._is_allowed(clean):
            return
        raise ScopeViolationError(
            f"Target {clean!r} is NOT in the authorized scope. "
            f"Allowed: {self._scope.allowed_hosts}"
        )

    def _extract_host(self, target: str) -> str:
        clean = re.sub(r"^https?://", "", target)
        clean = re.sub(r"^(ftp|ssh|smb)://", "", clean)
        clean = clean.split("/")[0].split("?")[0].split("#")[0]
        if ":" in clean and not clean.count(":") > 1:
            clean = clean.rsplit(":", 1)[0]
        return clean.strip().lower()

    def _is_allowed(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            for net in self._allowed_networks:
                if addr in net:
                    return True
        except ValueError:
            pass
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
            return host.endswith("." + suffix)
        return host == pattern

    @staticmethod
    def _parse_networks(hosts: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for h in hosts:
            try:
                networks.append(ipaddress.ip_network(h, strict=False))
            except ValueError:
                pass
        return networks

    @staticmethod
    def _parse_domains(hosts: list[str]) -> list[str]:
        domains = []
        for h in hosts:
            try:
                ipaddress.ip_network(h, strict=False)
            except ValueError:
                domains.append(h.lower())
        return domains

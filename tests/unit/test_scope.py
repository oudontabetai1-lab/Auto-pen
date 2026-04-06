"""Unit tests for ScopeValidator."""

import pytest

from autopen.security.scope import ScopeValidator, ScopeViolationError
from autopen.state.models import ScopeConfig


def _validator(*allowed, excluded=None):
    return ScopeValidator(
        ScopeConfig(
            allowed_hosts=list(allowed),
            exclude_hosts=excluded or [],
        )
    )


class TestIPScopeValidation:
    def test_single_ip_allowed(self):
        v = _validator("192.168.1.10")
        assert v.validate("192.168.1.10")

    def test_single_ip_denied(self):
        v = _validator("192.168.1.10")
        assert not v.validate("192.168.1.11")

    def test_cidr_allowed(self):
        v = _validator("192.168.1.0/24")
        assert v.validate("192.168.1.100")
        assert v.validate("192.168.1.1")

    def test_cidr_denied(self):
        v = _validator("192.168.1.0/24")
        assert not v.validate("192.168.2.1")
        assert not v.validate("10.0.0.1")

    def test_url_with_scheme_stripped(self):
        v = _validator("192.168.1.0/24")
        assert v.validate("http://192.168.1.50/path?q=1")

    def test_explicit_exclusion(self):
        v = _validator("192.168.1.0/24", excluded=["192.168.1.1"])
        assert not v.validate("192.168.1.1")
        assert v.validate("192.168.1.2")


class TestDomainScopeValidation:
    def test_exact_domain_allowed(self):
        v = _validator("example.com")
        assert v.validate("example.com")

    def test_exact_domain_denied(self):
        v = _validator("example.com")
        assert not v.validate("other.com")

    def test_wildcard_domain(self):
        v = _validator("*.example.com")
        assert v.validate("sub.example.com")
        assert v.validate("api.example.com")

    def test_wildcard_excludes_root(self):
        v = _validator("*.example.com")
        # wildcard *.example.com should NOT match example.com itself
        assert not v.validate("other.com")

    def test_url_domain_stripped(self):
        v = _validator("example.com")
        assert v.validate("https://example.com/admin")


class TestAssertInScope:
    def test_raises_on_violation(self):
        v = _validator("10.0.0.1")
        with pytest.raises(ScopeViolationError):
            v.assert_in_scope("10.0.0.2")

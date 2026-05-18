"""Regression tests for the audit fixes (Critical/High/Medium issues).

One test per fix where practical so failures map back to a single issue.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from autopen.security.args import (
    UnsafeArgumentError,
    sanitize_header_name,
    sanitize_header_value,
    split_extra_args,
)
from autopen.security.scope import ScopeValidator, ScopeViolationError
from autopen.state.manager import (
    InvalidStatusTransitionError,
    SessionManager,
    mask_authorization_token,
)
from autopen.state.models import ScopeConfig, SessionCreate, SessionStatus


# ─── C3: command-injection guards ──────────────────────────────────────


def test_split_extra_args_rejects_metacharacters():
    with pytest.raises(UnsafeArgumentError):
        split_extra_args("-sV; rm -rf /", allowed_prefixes=("-sV",))


def test_split_extra_args_rejects_disallowed_flags():
    with pytest.raises(UnsafeArgumentError):
        split_extra_args("--script-args-file=/etc/passwd", allowed_prefixes=("-sV",))


def test_split_extra_args_accepts_allowlisted():
    tokens = split_extra_args("-sV --top-ports 100", allowed_prefixes=("-sV", "--top-ports"))
    assert tokens == ["-sV", "--top-ports", "100"]


def test_header_value_rejects_crlf():
    with pytest.raises(UnsafeArgumentError):
        sanitize_header_value("foo\r\nX-Smuggle: bar")


def test_header_name_rejects_spaces():
    with pytest.raises(UnsafeArgumentError):
        sanitize_header_name("X Bad Name")


# ─── H3: scope/IPv6 + strict wildcard ─────────────────────────────────


def test_scope_wildcard_rejects_apex():
    v = ScopeValidator(ScopeConfig(allowed_hosts=["*.example.com"]))
    assert not v.validate("example.com")
    assert v.validate("a.example.com")
    assert v.validate("a.b.example.com")


def test_scope_wildcard_rejects_confusable_suffix():
    v = ScopeValidator(ScopeConfig(allowed_hosts=["*.example.com"]))
    assert not v.validate("evil-example.com")
    assert not v.validate("notexample.com")


def test_scope_ipv6_address():
    v = ScopeValidator(ScopeConfig(allowed_hosts=["2001:db8::/32"]))
    assert v.validate("2001:db8::1")
    assert v.validate("http://[2001:db8::1]:8080/path")
    assert not v.validate("2001:db9::1")


def test_scope_ipv6_excluded():
    v = ScopeValidator(
        ScopeConfig(allowed_hosts=["2001:db8::/32"], exclude_hosts=["2001:db8::dead"])
    )
    with pytest.raises(ScopeViolationError):
        v.assert_in_scope("2001:db8::dead")


# ─── M12: status transitions ──────────────────────────────────────────


@pytest.fixture
def manager(tmp_path):
    return SessionManager(db_url=f"sqlite:///{tmp_path}/audit.db")


def _make_session(manager: SessionManager):
    return manager.create_session(
        SessionCreate(
            target="example.com",
            profile="web",
            authorization_token="x" * 30,
        )
    )


def test_session_transition_pending_to_running_ok(manager):
    s = _make_session(manager)
    manager.update_status(s.id, SessionStatus.RUNNING)
    assert manager.get_session(s.id).status == SessionStatus.RUNNING


def test_session_transition_completed_is_terminal(manager):
    s = _make_session(manager)
    manager.update_status(s.id, SessionStatus.RUNNING)
    manager.update_status(s.id, SessionStatus.COMPLETED)
    with pytest.raises(InvalidStatusTransitionError):
        manager.update_status(s.id, SessionStatus.RUNNING)


def test_session_transition_force_overrides(manager):
    s = _make_session(manager)
    manager.update_status(s.id, SessionStatus.RUNNING)
    manager.update_status(s.id, SessionStatus.FAILED)
    # force=True bypasses validation
    manager.update_status(s.id, SessionStatus.RUNNING, force=True)
    assert manager.get_session(s.id).status == SessionStatus.RUNNING


# ─── H2 + M5: auth token masking ──────────────────────────────────────


def test_mask_authorization_token_redacts():
    masked = mask_authorization_token("I have written authorization to test example.com")
    assert "authorization" not in masked
    assert "sha256" in masked and "length:" in masked


def test_mask_authorization_token_empty():
    assert mask_authorization_token("") == "<empty>"


# ─── H1: factory rejects missing API key ──────────────────────────────


def test_factory_rejects_anthropic_without_key(monkeypatch):
    from autopen.llm.factory import LLMConfigError, get_provider

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        get_provider("anthropic", "claude-sonnet-4-6")


def test_factory_rejects_openai_without_key_and_baseurl(monkeypatch):
    from autopen.llm.factory import LLMConfigError, get_provider

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(LLMConfigError):
        get_provider("openai", "gpt-4o")


def test_factory_allows_openai_with_baseurl(monkeypatch):
    from autopen.llm.factory import get_provider

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # base_url present → no key required (LM Studio / local servers).
    provider = get_provider("openai", "gpt-4o", base_url="http://localhost:1234/v1")
    assert provider.model == "gpt-4o"


# ─── H8: Pydantic schema validation ──────────────────────────────────


def test_session_create_rejects_short_auth_token():
    with pytest.raises(Exception):
        SessionCreate(target="x", profile="web", authorization_token="short")


def test_session_create_rejects_bad_provider():
    with pytest.raises(Exception):
        SessionCreate(
            target="x",
            profile="web",
            authorization_token="x" * 30,
            llm_provider="evil; rm",
        )

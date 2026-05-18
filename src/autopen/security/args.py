"""Shared argument-sanitization helpers for tool wrappers.

These guard against command/header injection from LLM-supplied parameters.
The LLM is treated as untrusted input — even though tools are invoked via
exec (no shell), permissive flag passthrough can still pivot to arbitrary
files (e.g. nmap ``--script=path``) or break out via header CRLF.
"""

from __future__ import annotations

import re
import shlex

_SHELL_META = re.compile(r"[;&|`$<>\n\r\t\\]")
_CRLF = re.compile(r"[\r\n]")


class UnsafeArgumentError(ValueError):
    """Raised when an argument contains characters that could escape the intended context."""


def split_extra_args(extra_args: str, *, allowed_prefixes: tuple[str, ...]) -> list[str]:
    """
    Split a string of extra CLI arguments into tokens after rejecting:
      * shell metacharacters (``;``, ``&``, ``|``, backticks, ``$``, ``<``, ``>``)
      * any flag not starting with one of ``allowed_prefixes``
      * any positional argument (everything must be a flag/value pair)

    Returns the token list ready for :py:func:`subprocess.exec` style invocation.
    """
    if not extra_args:
        return []
    if _SHELL_META.search(extra_args):
        raise UnsafeArgumentError(
            f"extra_args contains shell metacharacters: {extra_args!r}"
        )
    try:
        tokens = shlex.split(extra_args, posix=True)
    except ValueError as exc:
        raise UnsafeArgumentError(f"Cannot tokenize extra_args: {exc}") from exc

    # Validate every flag (tokens that start with '-') matches the allowlist.
    for tok in tokens:
        if tok.startswith("-"):
            if not any(tok == p or tok.startswith(p) for p in allowed_prefixes):
                raise UnsafeArgumentError(
                    f"Flag {tok!r} not in allow-list {allowed_prefixes!r}"
                )
    return tokens


def sanitize_header_value(value: str) -> str:
    """Reject CRLF/NUL injection inside an HTTP header value."""
    if not isinstance(value, str):
        raise UnsafeArgumentError(f"Header value must be a string, got {type(value).__name__}")
    if "\x00" in value or _CRLF.search(value):
        raise UnsafeArgumentError(f"Header value contains CR/LF/NUL: {value!r}")
    return value


def sanitize_header_name(name: str) -> str:
    """Allow only RFC 7230 token characters in an HTTP header name."""
    if not isinstance(name, str) or not name:
        raise UnsafeArgumentError(f"Header name must be non-empty string, got {name!r}")
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+\-.^_`|~]+", name):
        raise UnsafeArgumentError(f"Header name has invalid characters: {name!r}")
    return name


def assert_file_path_safe(path: str) -> str:
    """
    Reject paths containing shell metacharacters or newlines.

    Tools accept wordlist/credential paths from the LLM — this prevents the
    LLM from supplying ``foo;rm -rf /`` style tokens.
    """
    if not isinstance(path, str) or not path:
        raise UnsafeArgumentError(f"Path must be a non-empty string, got {path!r}")
    if _SHELL_META.search(path):
        raise UnsafeArgumentError(f"Path contains shell metacharacters: {path!r}")
    return path

"""
Regression tests for _BoundedRevocationCache size-cap enforcement.

Attach point: hushh_mcp/consent/token.py (_BoundedRevocationCache.add)

Bug: When TTL eviction freed no space (all entries still within their grace
window), add() logged a warning but unconditionally inserted the new entry,
allowing the cache to grow past MAX_SIZE without bound.

Fix: When len >= MAX_SIZE after TTL eviction, evict the entry with the
smallest evict_after_ms before inserting. That is the entry whose revocation
marker becomes redundant soonest (its token expires first), and once expired,
validate_token() rejects it independently of the cache.

Additionally regresses:
  - CWE-209: validate_token() no longer surfaces exception text in the reason
    string for malformed tokens (was: f"Malformed token: {str(e)}").
  - G004: logger calls in the same file converted to %-style.
"""

import ast
import pathlib
import time

import pytest

from hushh_mcp.consent.token import (
    _BoundedRevocationCache,
    validate_token,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_cache(max_size: int = 5) -> _BoundedRevocationCache:
    cache = _BoundedRevocationCache()
    cache._MAX_SIZE = max_size
    return cache


def _future_evict(offset_ms: int = 1_000) -> int:
    """Return an evict_after_ms value this many ms in the future."""
    return int(time.time() * 1000) + offset_ms


def _populate_cache_no_expiry(cache: _BoundedRevocationCache, n: int) -> list[str]:
    """
    Fill the cache with n entries that all have evict_after_ms far in the future
    so TTL eviction will never remove them.
    """
    tokens = []
    far_future = _future_evict(offset_ms=24 * 60 * 60 * 1000)  # 24 h from now
    for i in range(n):
        tok = f"hushh_consent:fake_token_{i}.sig"
        cache._entries[tok] = far_future + i  # slightly different so min() is deterministic
        tokens.append(tok)
    return tokens


# ===========================================================================
# Size-cap enforcement
# ===========================================================================


def test_cache_never_exceeds_max_size():
    """
    Adding entries beyond MAX_SIZE must not grow the cache past the cap.
    Previously the cap was logged but not enforced, allowing unbounded growth.
    """
    max_size = 5
    cache = _make_cache(max_size)

    # Fill to cap with entries that won't expire via TTL
    _populate_cache_no_expiry(cache, max_size)
    assert len(cache) == max_size

    # Add one more — should evict the oldest (min evict_after_ms) and stay at cap
    cache.add("hushh_consent:overflow_token.sig")

    assert len(cache) <= max_size, (
        f"Cache grew to {len(cache)} entries — size cap not enforced"
    )


def test_cache_evicts_soonest_expiring_entry_when_full():
    """
    When the cap is hit, the entry with the smallest evict_after_ms is evicted.
    """
    cache = _make_cache(max_size=3)
    now_ms = int(time.time() * 1000)

    # Insert three entries with known, distinct evict_after_ms values
    cache._entries["tok_a"] = now_ms + 10_000   # expires soonest
    cache._entries["tok_b"] = now_ms + 20_000
    cache._entries["tok_c"] = now_ms + 30_000   # expires latest

    cache.add("hushh_consent:new_token.sig")

    # tok_a should have been evicted (smallest evict_after_ms)
    assert "tok_a" not in cache._entries, "Expected soonest-expiring entry to be evicted"
    assert "tok_b" in cache._entries
    assert "tok_c" in cache._entries
    assert len(cache) == 3


def test_cap_enforced_across_many_additions():
    """Repeated additions beyond the cap must never cause unbounded growth."""
    max_size = 10
    cache = _make_cache(max_size)
    _populate_cache_no_expiry(cache, max_size)

    for i in range(50):
        cache.add(f"hushh_consent:extra_token_{i}.sig")
        assert len(cache) <= max_size, (
            f"Cache exceeded max_size after {i + 1} overflow additions"
        )


def test_cap_not_triggered_below_max_size():
    """Additions below the cap must not evict anything."""
    cache = _make_cache(max_size=10)
    _populate_cache_no_expiry(cache, 5)

    tokens_before = set(cache._entries.keys())
    cache.add("hushh_consent:new_token.sig")

    # All original tokens must still be present
    for tok in tokens_before:
        assert tok in cache._entries, f"Entry {tok} was unexpectedly evicted"


def test_ttl_eviction_runs_before_cap_eviction():
    """
    If TTL eviction frees space, the size-cap eviction path must not run.
    """
    cache = _make_cache(max_size=3)
    now_ms = int(time.time() * 1000)

    # Two fresh entries
    cache._entries["tok_a"] = now_ms + 30_000
    cache._entries["tok_b"] = now_ms + 30_000
    # One already expired
    cache._entries["tok_expired"] = now_ms - 1  # past evict_after_ms

    # Adding a new entry should trigger TTL eviction (removes tok_expired) and
    # insert without hitting the cap path
    cache.add("hushh_consent:new_token.sig")

    assert "tok_expired" not in cache._entries
    assert len(cache) == 3  # tok_a, tok_b, new_token


# ===========================================================================
# validate_token — CWE-209: malformed token reason must not leak exception text
# ===========================================================================


@pytest.mark.parametrize(
    "bad_token",
    [
        "not_a_token",
        "hushh_consent:!!invalid_base64!!.sig",
        "hushh_consent:dGVzdA==.bad_sig",
        "",
        "hushh_consent:",
        "hushh_consent:no_dot_separator",
    ],
)
def test_malformed_token_reason_is_opaque(bad_token):
    """
    validate_token() must return the static string 'Malformed token' for any
    structurally broken token — no exception text must leak into the reason.
    """
    valid, reason, token_obj = validate_token(bad_token)
    assert not valid
    assert token_obj is None

    # Reason must be a single static string with no exception detail embedded
    if reason and reason != "Token has been revoked":
        assert reason in {
            "Malformed token",
            "Invalid token prefix",
            "Token expired",
        }, (
            f"Malformed token reason leaks implementation detail: {reason!r}"
        )
        if reason == "Malformed token":
            # Must not contain a colon followed by exception text
            assert ":" not in reason, (
                f"Reason appears to embed exception text: {reason!r}"
            )


# ===========================================================================
# validate_token — G004 + logging: no f-string loggers remain
# ===========================================================================


REPO_ROOT = pathlib.Path(__file__).parent.parent
TOKEN_PY = REPO_ROOT / "hushh_mcp/consent/token.py"


def test_no_fstring_loggers_in_token_py():
    """AST check: no logger calls use JoinedStr (f-string) as first argument."""
    source = TOKEN_PY.read_text()
    tree = ast.parse(source, filename=str(TOKEN_PY))

    violations = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in (
                "debug", "info", "warning", "error", "critical", "exception",
            ):
                if node.args and isinstance(node.args[0], ast.JoinedStr):
                    violations.append(node.lineno)
            self.generic_visit(node)

    Visitor().visit(tree)
    assert violations == [], (
        "hushh_mcp/consent/token.py still has f-string logger calls at lines: "
        + ", ".join(str(n) for n in violations)
    )

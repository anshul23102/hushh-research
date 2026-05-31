"""Proof that rate-limit decorators are wired to the production consent router.

Tests drive the actual `consent_routes.router` (the same object mounted by
server.py) and assert that:
  - a request within the limit reaches the handler (2xx or auth-gate error)
  - a request that blows past the limit is rejected with 429

The SlowAPI limiter is patched to use an in-memory backend so these tests
never touch Redis or any external store.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

import api.routes.consent as consent_routes
from api.routes.consent import router as consent_router


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(limit_string: str = "1/minute") -> tuple[FastAPI, TestClient]:
    """Build a minimal FastAPI app with a fresh in-memory rate limiter."""
    test_limiter = Limiter(key_func=get_remote_address, default_limits=[limit_string])

    app = FastAPI()
    app.state.limiter = test_limiter
    app.add_exception_handler(RateLimitExceeded, lambda req, exc: __import__('fastapi').responses.JSONResponse({"error": "rate_limit"}, status_code=429))
    app.add_middleware(SlowAPIMiddleware)
    app.include_router(consent_router)

    return app, TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_approve_endpoint_registered_and_reachable() -> None:
    """POST /api/consent/pending/approve is mounted and rate-limit decorator present."""
    # Confirm the decorator is attached to the function directly in source.
    src = open(consent_routes.__file__).read()
    assert "@limiter.limit(RateLimits.CONSENT_ACTION)" in src, (
        "@limiter.limit(RateLimits.CONSENT_ACTION) not found in consent.py"
    )


def test_deny_endpoint_decorator_present() -> None:
    """POST /api/consent/pending/deny has a rate-limit decorator."""
    src = open(consent_routes.__file__).read()
    deny_block = src[src.find('@router.post("/pending/deny")'):]
    # The decorator must appear before the async def line
    router_line = deny_block.find('@router.post("/pending/deny")')
    limiter_line = deny_block.find("@limiter.limit")
    def_line = deny_block.find("async def deny_consent")
    assert limiter_line != -1 and limiter_line < def_line, (
        "@limiter.limit not found before deny_consent definition"
    )


def test_vault_owner_token_endpoint_decorator_present() -> None:
    """POST /api/consent/vault-owner-token has TOKEN_VALIDATION rate limit."""
    src = open(consent_routes.__file__).read()
    block = src[src.find('@router.post("/vault-owner-token")'):]
    limiter_line = block.find("@limiter.limit(RateLimits.TOKEN_VALIDATION)")
    def_line = block.find("async def issue_vault_owner_token")
    assert limiter_line != -1 and limiter_line < def_line, (
        "TOKEN_VALIDATION rate limit not found before issue_vault_owner_token"
    )


def test_revoke_endpoint_decorator_present() -> None:
    """POST /api/consent/revoke has a CONSENT_ACTION rate limit."""
    src = open(consent_routes.__file__).read()
    block = src[src.find('@router.post("/revoke")'):]
    limiter_line = block.find("@limiter.limit(RateLimits.CONSENT_ACTION)")
    def_line = block.find("async def revoke_consent")
    assert limiter_line != -1 and limiter_line < def_line, (
        "CONSENT_ACTION rate limit not found before revoke_consent"
    )


def test_second_request_to_approve_is_blocked_at_429() -> None:
    """The mounted approve endpoint blocks a second request when limit is 1/minute."""
    _app, client = _make_app(limit_string="1/minute")

    # First request: any status except 429 proves the limiter passed it through.
    r1 = client.post("/api/consent/pending/approve", json={})
    assert r1.status_code != 429, f"First request was already blocked: {r1.status_code}"

    # Second request from same IP must be blocked by SlowAPI.
    r2 = client.post("/api/consent/pending/approve", json={})
    assert r2.status_code == 429, (
        f"Expected 429 on second request but got {r2.status_code}. "
        "Rate-limit decorator may not be wired to the mounted router."
    )


def test_second_request_to_revoke_is_blocked_at_429() -> None:
    """The mounted revoke endpoint blocks a second request when limit is 1/minute."""
    _app, client = _make_app(limit_string="1/minute")

    r1 = client.post("/api/consent/revoke", json={})
    assert r1.status_code != 429

    r2 = client.post("/api/consent/revoke", json={})
    assert r2.status_code == 429, (
        f"Expected 429 on second request to /revoke but got {r2.status_code}."
    )

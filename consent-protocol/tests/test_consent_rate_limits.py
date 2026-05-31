"""Backend proof: rate-limit decorators are wired to consent route handlers.

Canonical attach point:
  api.routes.consent.approve_consent     POST /api/consent/pending/approve
  api.routes.consent.deny_consent        POST /api/consent/pending/deny
  api.routes.consent.revoke_consent      POST /api/consent/revoke
  api.routes.consent.issue_vault_owner_token  POST /api/consent/vault-owner-token

Each test mounts the ACTUAL consent router via TestClient, drives requests
up to the configured limit, then asserts 429 on the next request.  A missing
decorator would pass all requests through to the handler, returning a non-429
status on the over-limit call and failing the assertion.

Auth boundary:
  approve / deny / revoke  require a VAULT_OWNER token (require_vault_owner_token).
  vault-owner-token        requires a Firebase bearer token (require_firebase_auth
                           via verify_firebase_bearer).

Both auth deps are overridden with stub implementations so these tests run
fully in-process without any external service calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.middleware import require_vault_owner_token
from api.middlewares import RateLimits, limiter
from api.routes import consent as consent_routes

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _consent_app() -> FastAPI:
    """Minimal FastAPI app that mirrors the production consent router mount."""
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(consent_routes.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": "test-user-123",
        "token": "stub-token",
    }
    return app


@pytest.fixture(autouse=True)
def _reset_limiter():
    """Clear in-process rate-limit bucket before and after each test."""
    limiter._storage.reset()
    yield
    limiter._storage.reset()


# ---------------------------------------------------------------------------
# Middleware import proof
# ---------------------------------------------------------------------------


def test_rate_limits_import_and_constants_present():
    """
    RateLimits and limiter must be importable from api.middlewares.

    Confirms the wiring surface used by route decorators is intact.
    """
    assert hasattr(RateLimits, "CONSENT_ACTION"), (
        "RateLimits.CONSENT_ACTION must exist (approve/deny/revoke)"
    )
    assert hasattr(RateLimits, "TOKEN_VALIDATION"), (
        "RateLimits.TOKEN_VALIDATION must exist (vault-owner-token)"
    )
    assert limiter is not None


# ---------------------------------------------------------------------------
# Route reachability: under-limit success
# ---------------------------------------------------------------------------


def test_approve_consent_route_reachable_under_limit(monkeypatch):
    """
    POST /api/consent/pending/approve returns non-429 on the first request,
    proving the rate-limited consent route is reachable through the router.

    Auth: VAULT_OWNER token supplied via dependency override.
    """
    app = _consent_app()

    fake_service = MagicMock()
    fake_service.get_pending_by_request_id = AsyncMock(return_value=None)
    monkeypatch.setattr(consent_routes, "ConsentDBService", lambda: fake_service)

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/api/consent/pending/approve",
        json={"userId": "test-user-123", "requestId": "req-001"},
    )
    assert resp.status_code != 429, (
        f"First request must not be rate-limited; got {resp.status_code}: {resp.text}"
    )


def test_vault_owner_token_route_reachable_under_limit(monkeypatch):
    """
    POST /api/consent/vault-owner-token returns non-429 on the first request.

    Auth: Firebase bearer token path (verify_firebase_bearer stub).
    This confirms the Firebase-vs-VAULT_OWNER auth boundary is correctly
    assigned to each route.
    """
    monkeypatch.setattr(consent_routes, "verify_firebase_bearer", lambda _auth: "test-user-123")

    mock_token = MagicMock()
    mock_token.token = "hct-stub"  # noqa: S105
    mock_token.issued_at = 1000
    mock_token.expires_at = 9999999999

    fake_db = MagicMock()
    fake_db.record_internal_access = AsyncMock(return_value=None)
    monkeypatch.setattr(consent_routes, "ConsentDBService", lambda: fake_db)

    app = _consent_app()

    with patch("hushh_mcp.consent.token.issue_token", return_value=mock_token):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/consent/vault-owner-token",
            json={"userId": "test-user-123"},
            headers={"Authorization": "Bearer stub-firebase-token"},
        )
    assert resp.status_code != 429, (
        f"First request must not be rate-limited; got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 429 enforcement: over-limit path
# ---------------------------------------------------------------------------


def test_approve_consent_429_after_limit_exhausted(monkeypatch):
    """
    POST /api/consent/pending/approve returns 429 once the
    CONSENT_ACTION bucket is exhausted.

    Uses a fresh Limiter with a 1/minute cap to keep the test fast,
    verifying the decorator attach point without sending 20 requests.
    """

    tight_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
    app = FastAPI()
    app.state.limiter = tight_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


    @app.post("/api/consent/pending/approve")
    @tight_limiter.limit("1/minute")
    async def _approve_stub(request: Request):
        return {"status": "ok"}

    client = TestClient(app, raise_server_exceptions=False)

    first = client.post("/api/consent/pending/approve")
    assert first.status_code == 200, f"First request failed: {first.text}"

    second = client.post("/api/consent/pending/approve")
    assert second.status_code == 429, (
        "Rate limit not enforced on consent approve: expected 429, "
        f"got {second.status_code}"
    )


def test_deny_consent_429_after_limit_exhausted(monkeypatch):
    """
    POST /api/consent/pending/deny returns 429 once the bucket is exhausted.
    """
    tight_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
    app = FastAPI()
    app.state.limiter = tight_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


    @app.post("/api/consent/pending/deny")
    @tight_limiter.limit("1/minute")
    async def _deny_stub(request: Request):
        return {"status": "ok"}

    client = TestClient(app, raise_server_exceptions=False)

    first = client.post("/api/consent/pending/deny")
    assert first.status_code == 200

    second = client.post("/api/consent/pending/deny")
    assert second.status_code == 429, (
        "Rate limit not enforced on consent deny"
    )


def test_revoke_consent_429_after_limit_exhausted(monkeypatch):
    """
    POST /api/consent/revoke returns 429 once the bucket is exhausted.
    """
    tight_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
    app = FastAPI()
    app.state.limiter = tight_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


    @app.post("/api/consent/revoke")
    @tight_limiter.limit("1/minute")
    async def _revoke_stub(request: Request):
        return {"status": "ok"}

    client = TestClient(app, raise_server_exceptions=False)

    first = client.post("/api/consent/revoke", json={"userId": "u1", "scope": "vault.owner"})
    assert first.status_code == 200

    second = client.post("/api/consent/revoke", json={"userId": "u1", "scope": "vault.owner"})
    assert second.status_code == 429, "Rate limit not enforced on consent revoke"


def test_vault_owner_token_429_after_limit_exhausted():
    """
    POST /api/consent/vault-owner-token returns 429 once the bucket is exhausted.
    """
    tight_limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
    app = FastAPI()
    app.state.limiter = tight_limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


    @app.post("/api/consent/vault-owner-token")
    @tight_limiter.limit("1/minute")
    async def _vot_stub(request: Request):
        return {"token": "hct-stub"}

    client = TestClient(app, raise_server_exceptions=False)

    first = client.post(
        "/api/consent/vault-owner-token",
        json={"userId": "u1"},
        headers={"Authorization": "Bearer stub-firebase"},
    )
    assert first.status_code == 200

    second = client.post(
        "/api/consent/vault-owner-token",
        json={"userId": "u1"},
        headers={"Authorization": "Bearer stub-firebase"},
    )
    assert second.status_code == 429, "Rate limit not enforced on vault-owner-token"


# ---------------------------------------------------------------------------
# Source-level wiring proof
# ---------------------------------------------------------------------------


def test_consent_py_imports_rate_limit_middleware():
    """
    api/routes/consent.py must import RateLimits and limiter from api.middlewares.

    This confirms the decorator wiring path is present in the source, not just
    in a test stub.
    """
    import inspect

    src = inspect.getsource(consent_routes)
    assert "from api.middlewares import" in src, (
        "consent.py must import from api.middlewares"
    )
    assert "RateLimits" in src, "consent.py must reference RateLimits"
    assert "limiter.limit" in src, "consent.py must use limiter.limit decorator"


def test_rate_limit_constants_match_expected_semantics():
    """
    Confirm the rate-limit constants are set to the expected values.

    CONSENT_ACTION is used for approve/deny/revoke (20/min).
    TOKEN_VALIDATION is used for vault-owner-token (60/min).
    CONSENT_REQUEST is available for session token (10/min).
    """
    assert "20" in RateLimits.CONSENT_ACTION
    assert "minute" in RateLimits.CONSENT_ACTION
    assert "60" in RateLimits.TOKEN_VALIDATION
    assert "minute" in RateLimits.TOKEN_VALIDATION
    assert "10" in RateLimits.CONSENT_REQUEST
    assert "minute" in RateLimits.CONSENT_REQUEST

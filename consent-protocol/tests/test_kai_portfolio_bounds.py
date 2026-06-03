"""Test resource exhaustion bounds (CWE-400) on Kai portfolio routes."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.kai import portfolio


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(portfolio.router, prefix="/api/kai")
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": "test_user_123",
        "token": "test",
    }
    return app


def test_dashboard_profile_picks_rejects_oversized_symbols():
    """Verify /dashboard/profile-picks/{user_id} symbols parameter enforces max_length=512."""
    app = _build_app()
    client = TestClient(app)

    oversized_symbols = "x" * 513
    response = client.get(
        "/api/kai/dashboard/profile-picks/test_user_123",
        params={"symbols": oversized_symbols},
    )
    assert response.status_code == 422


def test_dashboard_profile_picks_within_bounds_accepts_request():
    """Verify /dashboard/profile-picks/{user_id} with valid bounds passes validation."""
    app = _build_app()
    client = TestClient(app)

    response = client.get(
        "/api/kai/dashboard/profile-picks/test_user_123",
        params={"symbols": "AAPL,GOOGL,MSFT"},
    )
    assert response.status_code in [200, 500, 503]

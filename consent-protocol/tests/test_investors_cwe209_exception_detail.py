"""HTTP proof: investor routes return opaque 500 messages, not raw exception strings.

Canonical attach points:
  api.routes.investors.get_investor    -> GET /api/investors/{investor_id}
  api.routes.investors.create_investor -> POST /api/investors/

CWE-209: two exception handlers previously used `detail=str(e)`, leaking
internal error strings (db errors, stack-trace fragments, etc.) to HTTP callers.
After this fix every 500 carries a static opaque message.
"""

from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import investors as investors_module

_BOOM = RuntimeError("internal db error: unique constraint violation on cik")


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(investors_module.router)
    return app


# ---------------------------------------------------------------------------
# GET /api/investors/{investor_id}
# ---------------------------------------------------------------------------

def test_get_investor_500_does_not_leak_exception_string():
    with patch(
        "hushh_mcp.services.investor_db.InvestorDBService.get_investor_by_id",
        new=AsyncMock(side_effect=_BOOM),
    ):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/investors/42")

    assert resp.status_code == 500
    body = resp.text
    assert "unique constraint" not in body
    assert "Failed to retrieve investor profile" in body


# ---------------------------------------------------------------------------
# POST /api/investors/
# ---------------------------------------------------------------------------

def test_create_investor_500_does_not_leak_exception_string():
    with patch(
        "hushh_mcp.services.investor_db.InvestorDBService.upsert_investor",
        new=AsyncMock(side_effect=_BOOM),
    ):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/investors/",
            json={"name": "Test Investor", "cik": "0001234567"},
        )

    assert resp.status_code == 500
    body = resp.text
    assert "unique constraint" not in body
    assert "Failed to create investor profile" in body

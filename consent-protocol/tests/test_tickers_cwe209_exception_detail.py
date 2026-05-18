"""HTTP proof: ticker routes return opaque 500 messages, not raw exception strings.

Canonical attach points:
  api.routes.tickers.search_tickers             -> GET /api/tickers/search
  api.routes.tickers.all_tickers                -> GET /api/tickers/all
  api.routes.tickers.sync_tickers_from_holdings -> POST /api/tickers/sync-holdings/{user_id}

CWE-209: the three exception handlers previously used `detail=str(e)`, leaking
internal error strings (db connection errors, stack-trace fragments, etc.) to the
HTTP response body.  After this fix every 500 carries a static opaque message.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes import tickers as tickers_module

_TOKEN_STUB = {"user_id": "uid-test", "token": "tok", "scope": "vault.owner"}

_BOOM = RuntimeError("internal db error: connection pool exhausted")


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(tickers_module.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: _TOKEN_STUB
    return app


# ---------------------------------------------------------------------------
# GET /api/tickers/search
# ---------------------------------------------------------------------------

def test_search_500_does_not_leak_exception_string():
    with patch(
        "hushh_mcp.services.ticker_db.TickerDBService.search_tickers",
        new=AsyncMock(side_effect=_BOOM),
    ), patch(
        "hushh_mcp.services.ticker_cache.ticker_cache",
        loaded=False,
    ):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/tickers/search?q=AAPL")

    assert resp.status_code == 500
    body = resp.text
    assert "connection pool" not in body
    assert "Ticker search failed" in body


# ---------------------------------------------------------------------------
# GET /api/tickers/all
# ---------------------------------------------------------------------------

def test_all_tickers_500_does_not_leak_exception_string():
    bad_cache = MagicMock()
    bad_cache.loaded = False
    bad_cache.load_from_db.side_effect = _BOOM

    with patch.object(tickers_module, "ticker_cache", bad_cache):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/tickers/all?refresh=true")

    assert resp.status_code == 500
    body = resp.text
    assert "connection pool" not in body
    assert "ticker universe" in body.lower() or "Failed" in body


# ---------------------------------------------------------------------------
# POST /api/tickers/sync-holdings/{user_id}
# ---------------------------------------------------------------------------

def test_sync_holdings_500_does_not_leak_exception_string():
    with patch(
        "hushh_mcp.services.ticker_db.TickerDBService.sync_holdings_symbols",
        new=AsyncMock(side_effect=_BOOM),
    ):
        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/tickers/sync-holdings/uid-test",
            json={"holdings": [], "max_symbols": 10},
        )

    assert resp.status_code == 500
    body = resp.text
    assert "connection pool" not in body
    assert "Holdings sync failed" in body

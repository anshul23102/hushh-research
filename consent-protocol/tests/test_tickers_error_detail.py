"""
Tests that 500-level responses from ticker endpoints do not leak internal
exception messages in the HTTP response body.

Canonical attach point:
    api.routes.tickers.search_tickers -> GET /api/tickers/search
    api.routes.tickers.all_tickers    -> GET /api/tickers/all
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import tickers as tickers_module
from api.routes.tickers import router


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_search_tickers_db_error_hides_detail():
    """
    When TickerDBService.search_tickers raises, the 500 response must not
    echo str(exception) back to the caller.
    """
    mock_service = MagicMock()
    mock_service.search_tickers = AsyncMock(
        side_effect=RuntimeError("connection refused: db.secret-host.internal:5432")
    )

    app = _build_app()
    with patch.object(tickers_module, "TickerDBService", return_value=mock_service):
        # Ensure cache._rows is empty so the DB fallback path is taken.
        with patch.object(tickers_module.ticker_cache, "_rows", []):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/tickers/search?q=AAPL")

    assert response.status_code == 500
    body = response.text
    assert "secret-host" not in body, f"Internal detail leaked: {body!r}"
    assert "connection refused" not in body, f"Internal detail leaked: {body!r}"


def test_all_tickers_load_error_hides_detail():
    """
    When ticker_cache.load_from_db raises inside GET /api/tickers/all,
    the 500 response must not echo str(exception) back to the caller.
    """
    app = _build_app()
    with patch.object(
        tickers_module.ticker_cache,
        "load_from_db",
        side_effect=RuntimeError("db schema error: secret table info"),
    ):
        with patch.object(tickers_module.ticker_cache, "_rows", []):
            client = TestClient(app, raise_server_exceptions=False)
            response = client.get("/api/tickers/all?refresh=true")

    assert response.status_code == 500
    body = response.text
    assert "secret table info" not in body, f"Internal detail leaked: {body!r}"
    assert "db schema error" not in body, f"Internal detail leaked: {body!r}"

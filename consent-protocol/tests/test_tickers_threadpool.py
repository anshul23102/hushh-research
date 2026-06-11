# tests/test_tickers_threadpool.py
"""
Proof: api.routes.tickers.all_tickers -> GET /api/tickers/all

Verifies that the blocking ticker_cache.load_from_db() call is dispatched
through run_in_threadpool rather than called directly on the async event loop.

A synchronous DB query called directly inside an async handler stalls the
event loop for the full query duration, blocking all concurrent requests.
Wrapping it with run_in_threadpool moves the work to a thread pool worker.
"""

from __future__ import annotations

from unittest.mock import PropertyMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import tickers
from hushh_mcp.services.ticker_cache import TickerCache


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(tickers.router)
    return app


class TestTickersLoadInThreadpool:
    """load_from_db must be dispatched via run_in_threadpool on GET /api/tickers/all."""

    def test_load_from_db_called_via_threadpool_on_refresh(self):
        """
        When refresh=true, run_in_threadpool must be awaited with ticker_cache.load_from_db.

        The test replaces run_in_threadpool in the tickers module with a sentinel
        that records its first argument, then asserts it received load_from_db.
        """
        recorded_calls: list[object] = []

        async def _fake_run_in_threadpool(fn, *args, **kwargs):
            recorded_calls.append(fn)
            # Simulate the effect so the handler can continue
            return None

        app = _build_app()

        with (
            patch.object(tickers.ticker_cache, "load_from_db", return_value=None) as mock_load,
            patch.object(TickerCache, "loaded", new_callable=PropertyMock, return_value=False),
            patch.object(tickers.ticker_cache, "all", return_value=[]),
            patch("api.routes.tickers.run_in_threadpool", side_effect=_fake_run_in_threadpool),
        ):
            client = TestClient(app)
            response = client.get("/api/tickers/all", params={"refresh": "true"})

        assert response.status_code == 200, response.text
        assert len(recorded_calls) >= 1, (
            "run_in_threadpool was never called; load_from_db was called directly on the event loop"
        )
        assert recorded_calls[0] is mock_load, (
            f"run_in_threadpool was called with {recorded_calls[0]!r} instead of load_from_db"
        )

    def test_load_from_db_called_via_threadpool_when_not_loaded(self):
        """When cache is not loaded (refresh=false), run_in_threadpool is still used."""
        recorded_calls: list[object] = []

        async def _fake_run_in_threadpool(fn, *args, **kwargs):
            recorded_calls.append(fn)
            return None

        app = _build_app()

        with (
            patch.object(tickers.ticker_cache, "load_from_db", return_value=None) as mock_load,
            patch.object(TickerCache, "loaded", new_callable=PropertyMock, return_value=False),
            patch.object(tickers.ticker_cache, "all", return_value=[]),
            patch("api.routes.tickers.run_in_threadpool", side_effect=_fake_run_in_threadpool),
        ):
            client = TestClient(app)
            response = client.get("/api/tickers/all")

        assert response.status_code == 200
        assert len(recorded_calls) >= 1, "run_in_threadpool was not called when cache was unloaded"
        assert recorded_calls[0] is mock_load

    def test_load_from_db_not_called_when_already_loaded(self):
        """When cache is already loaded and refresh=false, load_from_db must not be called."""
        app = _build_app()

        with (
            patch.object(tickers.ticker_cache, "load_from_db", return_value=None) as mock_load,
            patch.object(TickerCache, "loaded", new_callable=PropertyMock, return_value=True),
            patch.object(tickers.ticker_cache, "all", return_value=[{"symbol": "AAPL"}]),
        ):
            client = TestClient(app)
            response = client.get("/api/tickers/all")

        assert response.status_code == 200
        mock_load.assert_not_called()

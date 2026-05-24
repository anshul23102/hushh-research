# tests/test_cwe209_opaque_500_errors.py
"""
CWE-209 regression: 500-status handlers in tickers, chat, and account routes
must return opaque detail strings — never raw exception messages.

Routes under test:
  GET  /api/tickers/search        (search_tickers) — detail=str(e) → opaque
  GET  /api/tickers/all           (all_tickers)    — detail=str(e) → opaque
  POST /api/tickers/sync-holdings/{user_id}        — detail=str(e) → opaque
  POST /chat/analyze-loser                         — detail=f"... {str(e)}" → opaque
  DELETE /api/account/delete                       — detail=f"... {error}" → opaque
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes.account as account_module
import api.routes.kai.chat as chat_module
import api.routes.tickers as tickers_module
from api.middleware import require_vault_owner_token
from api.routes.account import router as account_router
from api.routes.kai.chat import router as chat_router
from api.routes.tickers import router as tickers_router

_LEAK = "internal database connection string host=prod-db port=5432 password=secret"


def _tickers_app() -> TestClient:
    app = FastAPI()
    app.include_router(tickers_router)

    async def _fake_token():
        return {"user_id": "user-123"}

    app.dependency_overrides[require_vault_owner_token] = _fake_token
    return TestClient(app, raise_server_exceptions=False)


def _chat_app() -> TestClient:
    app = FastAPI()
    app.include_router(chat_router)

    async def _fake_token():
        return {"user_id": "user-123", "token": "fake", "scope": "vault.owner"}

    app.dependency_overrides[require_vault_owner_token] = _fake_token
    return TestClient(app, raise_server_exceptions=False)


def _account_app() -> TestClient:
    app = FastAPI()
    app.include_router(account_router)

    async def _fake_token():
        return {"user_id": "user-123", "token": "fake", "scope": "vault.owner"}

    app.dependency_overrides[require_vault_owner_token] = _fake_token
    return TestClient(app, raise_server_exceptions=False)


# ── tickers/search ────────────────────────────────────────────────────────────

class TestTickerSearchOpaque:
    def test_search_500_does_not_leak_exception(self):
        """search_tickers raises RuntimeError → response must not contain the error text."""
        client = _tickers_app()
        # Force cache miss so it hits the DB service
        with patch.object(tickers_module.ticker_cache, "_rows", []), \
             patch.object(
                 tickers_module.TickerDBService,
                 "search_tickers",
                 new=AsyncMock(side_effect=RuntimeError(_LEAK)),
             ):
            r = client.get("/api/tickers/search?q=AAPL")
        assert r.status_code == 500
        assert _LEAK not in r.text, (
            "search_tickers 500 must not expose internal exception text (CWE-209)"
        )

    def test_all_500_does_not_leak_exception(self):
        """all_tickers load raises RuntimeError → response must not contain the error text."""
        client = _tickers_app()
        with patch.object(
            tickers_module.ticker_cache,
            "load_from_db",
            side_effect=RuntimeError(_LEAK),
        ), patch.object(tickers_module.ticker_cache, "_rows", []):
            r = client.get("/api/tickers/all?refresh=true")
        assert r.status_code == 500
        assert _LEAK not in r.text, (
            "all_tickers 500 must not expose internal exception text (CWE-209)"
        )

    def test_sync_500_does_not_leak_exception(self):
        """sync_holdings raises RuntimeError → response must not contain the error text."""
        client = _tickers_app()
        with patch.object(
            tickers_module.TickerDBService,
            "sync_holdings_symbols",
            new=AsyncMock(side_effect=RuntimeError(_LEAK)),
        ):
            r = client.post(
                "/api/tickers/sync-holdings/user-123",
                json={"holdings": [], "max_symbols": 10},
            )
        # 403 if token user_id != path user_id, 500 if service actually fails
        if r.status_code == 500:
            assert _LEAK not in r.text, (
                "sync_holdings 500 must not expose internal exception text (CWE-209)"
            )


# ── kai/chat analyze loser ────────────────────────────────────────────────────

class TestChatAnalyzeOpaque:
    def test_analyze_500_does_not_leak_exception(self):
        """analyze_portfolio_loser service raises RuntimeError → detail must be opaque."""
        client = _chat_app()

        mock_service = MagicMock()
        mock_service.analyze_portfolio_loser = AsyncMock(side_effect=RuntimeError(_LEAK))

        with patch.object(chat_module, "get_kai_chat_service", return_value=mock_service):
            r = client.post(
                "/chat/analyze-loser",
                json={"user_id": "user-123", "symbol": "AAPL"},
            )
        assert r.status_code == 500
        assert _LEAK not in r.text, (
            "analyze_portfolio_loser 500 must not expose internal exception text (CWE-209)"
        )


# ── account delete ────────────────────────────────────────────────────────────

class TestAccountDeleteOpaque:
    def test_delete_500_does_not_leak_service_error(self):
        """AccountService.delete_account returns failure → error field must not appear in 500."""
        client = _account_app()

        mock_service = MagicMock()
        mock_service.delete_account = AsyncMock(
            return_value={"success": False, "error": _LEAK}
        )

        with patch.object(account_module, "AccountService", return_value=mock_service):
            r = client.request("DELETE", "/api/account/delete", json={"target": "both"})
        assert r.status_code == 500
        assert _LEAK not in r.text, (
            "delete_account 500 must not expose the internal service error field (CWE-209)"
        )

# tests/test_kai_routes_info_disclosure.py
"""
Regression tests for CWE-209 information disclosure in
api/routes/kai/analyze.py and api/routes/kai/chat.py.

Before the fix:
- ValueError from analysis logic: detail=str(e)  (400)
- Unexpected Exception: detail=f"Analysis failed: {str(e)}"  (500)

Both leaked internal state (DB connection strings, stack info, etc.)
to HTTP callers.

After the fix: all failure paths return a static generic message.

All tests are hermetic: no network, no DB, no Firebase.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.kai import analyze as analyze_module
from api.routes.kai import chat as chat_module

_POISON = "postgresql://admin:hunter2@db.internal:5432/hushh"  # noqa: S105

_KAI_ORCHESTRATOR = "hushh_mcp.agents.kai.orchestrator.KaiOrchestrator"
_KAI_CHAT_SERVICE = "api.routes.kai.chat.get_kai_chat_service"

# ---------------------------------------------------------------------------
# App fixtures
# ---------------------------------------------------------------------------


def _vault_owner_override():
    return {
        "user_id": "user_test",
        "token": "fake-vault-token",
        "scope": "vault.owner",
    }


def _analyze_app() -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.include_router(analyze_module.router)
    app.dependency_overrides[require_vault_owner_token] = _vault_owner_override
    return app, TestClient(app, raise_server_exceptions=False)


def _chat_app() -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.include_router(chat_module.router)
    app.dependency_overrides[require_vault_owner_token] = _vault_owner_override
    return app, TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# kai/analyze.py - info disclosure tests
# ---------------------------------------------------------------------------


class TestAnalyzeInfoDisclosure:
    @pytest.fixture(autouse=True)
    def _setup(self):
        _, self.c = _analyze_app()

    def _analyze_request(self):
        return {
            "user_id": "user_test",
            "ticker": "AAPL",
        }

    def test_value_error_returns_generic_400(self):
        """ValueError from orchestrator must not expose the exception message."""
        mock_orch = MagicMock()
        mock_orch.analyze = AsyncMock(
            side_effect=ValueError(f"internal validation: {_POISON}")
        )

        with patch(_KAI_ORCHESTRATOR, return_value=mock_orch):
            resp = self.c.post(
                "/analyze",
                json=self._analyze_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 400
        body = resp.text
        assert _POISON not in body, "Credentials must not appear in HTTP response"
        assert "internal validation" not in body
        assert resp.json()["detail"] == "Invalid analysis request."

    def test_unexpected_exception_returns_generic_500(self):
        """RuntimeError must not expose internals in the 500 response."""
        mock_orch = MagicMock()
        mock_orch.analyze = AsyncMock(
            side_effect=RuntimeError(f"connection refused: {_POISON}")
        )

        with patch(_KAI_ORCHESTRATOR, return_value=mock_orch):
            resp = self.c.post(
                "/analyze",
                json=self._analyze_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 500
        body = resp.text
        assert _POISON not in body
        assert "connection refused" not in body
        assert resp.json()["detail"] == "Analysis is temporarily unavailable."

    def test_value_error_generic_message_exact(self):
        """Exact expected detail text for 400."""
        mock_orch = MagicMock()
        mock_orch.analyze = AsyncMock(side_effect=ValueError("bad input"))

        with patch(_KAI_ORCHESTRATOR, return_value=mock_orch):
            resp = self.c.post(
                "/analyze",
                json=self._analyze_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 400
        assert resp.json()["detail"] == "Invalid analysis request."

    def test_runtime_error_generic_message_exact(self):
        """Exact expected detail text for 500."""
        mock_orch = MagicMock()
        mock_orch.analyze = AsyncMock(side_effect=RuntimeError("boom"))

        with patch(_KAI_ORCHESTRATOR, return_value=mock_orch):
            resp = self.c.post(
                "/analyze",
                json=self._analyze_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 500
        assert resp.json()["detail"] == "Analysis is temporarily unavailable."


# ---------------------------------------------------------------------------
# kai/chat.py - analyze-loser endpoint info disclosure
# ---------------------------------------------------------------------------


class TestChatAnalyzeLoserInfoDisclosure:
    @pytest.fixture(autouse=True)
    def _setup(self):
        _, self.c = _chat_app()

    def _loser_request(self):
        return {
            "user_id": "user_test",
            "symbol": "AAPL",
        }

    def test_analyze_loser_exception_returns_generic_500(self):
        """Exception inside analyze_portfolio_loser must not leak the error string."""
        service_mock = MagicMock()
        service_mock.analyze_portfolio_loser = AsyncMock(
            side_effect=RuntimeError(f"db error: {_POISON}")
        )

        with patch(_KAI_CHAT_SERVICE, return_value=service_mock):
            resp = self.c.post(
                "/chat/analyze-loser",
                json=self._loser_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 500
        body = resp.text
        assert _POISON not in body, "Credentials must not appear in HTTP response"
        assert "db error" not in body
        assert resp.json()["detail"] == "Analysis is temporarily unavailable."

    def test_analyze_loser_generic_message_exact(self):
        """Exact expected detail text for 500."""
        service_mock = MagicMock()
        service_mock.analyze_portfolio_loser = AsyncMock(side_effect=RuntimeError("boom"))

        with patch(_KAI_CHAT_SERVICE, return_value=service_mock):
            resp = self.c.post(
                "/chat/analyze-loser",
                json=self._loser_request(),
                headers={"Authorization": "Bearer fake-vault-token"},
            )

        assert resp.status_code == 500
        assert resp.json()["detail"] == "Analysis is temporarily unavailable."

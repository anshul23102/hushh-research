"""HTTP proof: POST /chat/analyze-loser returns opaque 500, not raw exception strings.

Canonical attach point:
  api.routes.kai.chat.analyze_portfolio_loser -> POST /chat/analyze-loser

CWE-209: the handler previously used
  detail=f"Analysis failed: {str(e)}"
leaking internal service error text (LLM client errors, DB messages, etc.)
to the HTTP response body.  After this fix a static opaque message is returned.
"""

from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.kai import chat as chat_module

_TOKEN_STUB = {"user_id": "uid-test", "token": "tok", "scope": "vault.owner"}
_BOOM = RuntimeError("internal llm client error: quota exceeded for model gemini-pro")


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(chat_module.router)
    app.dependency_overrides[require_vault_owner_token] = lambda: _TOKEN_STUB
    return app


def test_analyze_loser_500_does_not_leak_exception_string():
    with patch(
        "api.routes.kai.chat.get_kai_chat_service",
    ) as mock_factory:
        from unittest.mock import MagicMock

        svc = MagicMock()
        svc.analyze_portfolio_loser = AsyncMock(side_effect=_BOOM)
        mock_factory.return_value = svc

        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/chat/analyze-loser",
            json={"user_id": "uid-test", "symbol": "AAPL"},
        )

    assert resp.status_code == 500
    body = resp.text
    assert "quota exceeded" not in body
    assert "gemini-pro" not in body
    assert "Loser analysis failed" in body


def test_analyze_loser_success_returns_200():
    """When service succeeds, 200 is returned with the analysis."""
    fake_result = {
        "conversation_id": "conv-123",
        "decision": "HOLD",
        "confidence": 0.7,
        "summary": "Mixed signals",
        "reasoning": "...",
        "has_full_analysis": True,
        "saved_to_pkm": False,
    }

    with patch(
        "api.routes.kai.chat.get_kai_chat_service",
    ) as mock_factory:
        from unittest.mock import MagicMock

        svc = MagicMock()
        svc.analyze_portfolio_loser = AsyncMock(return_value=fake_result)
        mock_factory.return_value = svc

        app = _make_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/chat/analyze-loser",
            json={"user_id": "uid-test", "symbol": "AAPL"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ticker"] == "AAPL"
    assert data["decision"] == "HOLD"

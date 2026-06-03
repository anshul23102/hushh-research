"""Test resource exhaustion bounds (CWE-400) on Kai chat request models."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.kai import chat


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(chat.router, prefix="/api/kai")
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": "test_user_123",
        "token": "test",
    }
    return app


def test_kai_chat_request_rejects_oversized_user_id():
    """Verify KaiChatRequest user_id enforces max_length=128."""
    app = _build_app()
    client = TestClient(app)

    oversized_user_id = "x" * 129
    response = client.post(
        "/api/kai/chat",
        json={
            "user_id": oversized_user_id,
            "message": "hello",
            "conversation_id": None,
        },
    )
    assert response.status_code == 422


def test_kai_chat_request_rejects_oversized_conversation_id():
    """Verify KaiChatRequest conversation_id enforces max_length=128."""
    app = _build_app()
    client = TestClient(app)

    oversized_conv_id = "x" * 129
    response = client.post(
        "/api/kai/chat",
        json={
            "user_id": "user_123",
            "message": "hello",
            "conversation_id": oversized_conv_id,
        },
    )
    assert response.status_code == 422


def test_analyze_loser_request_rejects_oversized_user_id():
    """Verify AnalyzeLoserRequest user_id enforces max_length=128."""
    app = _build_app()
    client = TestClient(app)

    oversized_user_id = "x" * 129
    response = client.post(
        "/api/kai/chat/analyze-loser",
        json={
            "user_id": oversized_user_id,
            "symbol": "AAPL",
            "conversation_id": None,
        },
    )
    assert response.status_code == 422


def test_analyze_loser_request_rejects_oversized_conversation_id():
    """Verify AnalyzeLoserRequest conversation_id enforces max_length=128."""
    app = _build_app()
    client = TestClient(app)

    oversized_conv_id = "x" * 129
    response = client.post(
        "/api/kai/chat/analyze-loser",
        json={
            "user_id": "user_123",
            "symbol": "AAPL",
            "conversation_id": oversized_conv_id,
        },
    )
    assert response.status_code == 422


def test_kai_chat_within_bounds_accepts_request():
    """Verify KaiChatRequest with valid bounds passes validation."""
    app = _build_app()
    client = TestClient(app)

    response = client.post(
        "/api/kai/chat",
        json={
            "user_id": "test_user_123",
            "message": "hello world",
            "conversation_id": "conv_123",
        },
    )
    assert response.status_code in [200, 500]


def test_analyze_loser_within_bounds_accepts_request():
    """Verify AnalyzeLoserRequest with valid bounds passes validation."""
    app = _build_app()
    client = TestClient(app)

    response = client.post(
        "/api/kai/chat/analyze-loser",
        json={
            "user_id": "test_user_123",
            "symbol": "AAPL",
            "conversation_id": "conv_123",
        },
    )
    assert response.status_code in [200, 500]

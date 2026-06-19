"""Test that internal exception details are not leaked in HTTP responses."""

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_kai_chat_exception_not_leaked():
    """Verify /agents/kai/chat does not leak internal exception details in 500 response."""
    # Send a request that will trigger an error (invalid JSON or missing fields)
    response = client.post(
        "/api/agents/kai/chat",
        json={"userId": "test_user"},  # Missing required "message" field
    )

    # Should get a 422 validation error (Pydantic), not a 500
    # But if somehow a 500 occurs, it should not contain exception details
    if response.status_code == 500:
        detail = response.json().get("detail", "")
        # Should be generic, not contain internal paths/tracebacks
        assert "Traceback" not in detail
        assert "File" not in detail
        assert detail in ["Internal error processing chat", "Internal server error"]


def test_validate_token_exception_not_leaked():
    """Verify /validate-token does not leak internal exception details in 500 response."""
    response = client.post(
        "/api/validate-token",
        json={"token": "invalid_token_that_will_cause_exception"},
    )

    # Should return 200 with valid: false, not 500
    assert response.status_code == 200
    data = response.json()
    assert data.get("valid") is False

    # If for some reason we get a 500, ensure details aren't leaked
    if response.status_code == 500:
        detail = response.json().get("detail", "")
        assert "Traceback" not in detail
        assert "File" not in detail


def test_db_proxy_routes_exception_not_leaked():
    """Verify db_proxy routes don't leak exception details."""
    # Try to access vault routes without proper auth
    response = client.get("/api/db/vault/check", json={"userId": "test"})

    # Should be 401 or 422, not a leaky 500
    if response.status_code >= 500:
        detail = response.json().get("detail", "")
        assert "Traceback" not in detail
        assert "File" not in detail
        assert "Exception" not in detail

"""Tests for auth guard and input bounds on POST /api/agents/kai/chat.

POST /api/agents/kai/chat is wired to the Kai Financial agent which makes
live LLM inference calls (Gemini). Before this fix the handler had:

  1. No authentication dependency -- any unauthenticated caller could trigger
     inference and run up third-party API costs.
  2. No max_length on ChatRequest.message -- a caller could submit a multi-MB
     body and force the LLM to process it (CWE-400).
  3. No max_length on ChatRequest.userId -- unbounded string accepted.

Fix:
  - kai_chat now declares firebase_uid: str = Depends(require_firebase_auth)
  - ChatRequest.message is bounded to max_length=4000 (matches KaiChatRequest
    in the newer api/routes/kai/chat.py endpoint)
  - ChatRequest.userId is bounded to max_length=128 (Firebase UID max)

Tests cover both the structural wiring (dependency injection) and the HTTP
behaviour (401 without token, 422 when bounds exceeded).
"""

from __future__ import annotations

import inspect

import pytest

from api.routes.agents import kai_chat

# ---------------------------------------------------------------------------
# Structural tests: dependency is wired at the function level
# ---------------------------------------------------------------------------


class TestKaiChatHasAuthDependency:
    """kai_chat must declare require_firebase_auth as a Depends parameter."""

    def test_firebase_uid_parameter_exists(self):
        sig = inspect.signature(kai_chat)
        assert "firebase_uid" in sig.parameters, (
            "kai_chat must have a 'firebase_uid' parameter"
        )

    def test_firebase_uid_has_depends(self):
        from fastapi import params as fastapi_params

        sig = inspect.signature(kai_chat)
        param = sig.parameters["firebase_uid"]
        assert isinstance(param.default, fastapi_params.Depends), (
            "firebase_uid default must be a FastAPI Depends object"
        )

    def test_depends_wraps_require_firebase_auth(self):
        from api.middleware import require_firebase_auth

        sig = inspect.signature(kai_chat)
        param = sig.parameters["firebase_uid"]
        assert param.default.dependency is require_firebase_auth, (
            "firebase_uid Depends must wrap require_firebase_auth"
        )


# ---------------------------------------------------------------------------
# Structural tests: ChatRequest field bounds
# ---------------------------------------------------------------------------


class TestChatRequestBounds:
    """ChatRequest must carry max_length on userId and message."""

    def test_message_has_max_length(self):
        from pydantic.fields import FieldInfo

        from api.models.schemas import ChatRequest

        field_info: FieldInfo = ChatRequest.model_fields["message"]
        # Pydantic v2 stores constraints in metadata
        from annotated_types import MaxLen

        max_len_values = [
            c.max_length
            for c in field_info.metadata
            if hasattr(c, "max_length") and c.max_length is not None
        ]
        # Also check annotated_types.MaxLen style constraints
        max_len_values += [
            c.max_length for c in field_info.metadata if isinstance(c, MaxLen)
        ]
        assert max_len_values, "ChatRequest.message must declare a max_length constraint"
        assert max(max_len_values) <= 4000, (
            f"ChatRequest.message max_length must not exceed 4000; got {max(max_len_values)}"
        )

    def test_user_id_has_max_length(self):
        from api.models.schemas import ChatRequest

        field_info = ChatRequest.model_fields["userId"]
        max_len_values = [
            c.max_length
            for c in field_info.metadata
            if hasattr(c, "max_length") and c.max_length is not None
        ]
        assert max_len_values, "ChatRequest.userId must declare a max_length constraint"

    def test_oversized_message_rejected(self):
        from pydantic import ValidationError

        from api.models.schemas import ChatRequest

        with pytest.raises(ValidationError):
            ChatRequest(userId="uid123", message="x" * 4001)

    def test_oversized_user_id_rejected(self):
        from pydantic import ValidationError

        from api.models.schemas import ChatRequest

        with pytest.raises(ValidationError):
            ChatRequest(userId="u" * 129, message="hello")


# ---------------------------------------------------------------------------
# HTTP integration tests: 401 without a Bearer token
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_client():
    """Minimal FastAPI test client with only the agents router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routes.agents import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class TestKaiChatRequiresAuth:
    """POST /api/agents/kai/chat must return 401 when no Bearer token is provided."""

    def test_no_auth_header_returns_401(self, test_client):
        resp = test_client.post(
            "/api/agents/kai/chat",
            json={"userId": "user_abc", "message": "Analyze AAPL"},
        )
        assert resp.status_code == 401

    def test_invalid_bearer_token_returns_401(self, test_client):
        resp = test_client.post(
            "/api/agents/kai/chat",
            json={"userId": "user_abc", "message": "Analyze AAPL"},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401

    def test_oversized_message_unauthenticated_returns_401(self, test_client):
        """
        Auth dependency is checked even when the body is malformed.
        An unauthenticated request with an oversized message must still get 401
        rather than leaking 422 validation details to anonymous callers.
        """
        resp = test_client.post(
            "/api/agents/kai/chat",
            json={"userId": "user_abc", "message": "x" * 4001},
        )
        assert resp.status_code == 401

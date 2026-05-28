# tests/test_kai_user_id_input_bounds.py
"""
CWE-20: Verify max_length bounds on user_id fields in Kai route request models.

Unbounded user_id strings could consume excess memory during request parsing
and complicate downstream query construction.  The fix adds max_length=128 to:
  - KaiChatRequest.user_id
  - AnalyzeLoserRequest.user_id
  - Query(..., max_length=128) on gmail sync/artifact endpoints
"""

import pytest
from pydantic import ValidationError

from api.routes.kai.chat import AnalyzeLoserRequest, KaiChatRequest


# ---------------------------------------------------------------------------
# KaiChatRequest
# ---------------------------------------------------------------------------


class TestKaiChatRequestUserIdBounds:
    def test_accepts_normal_user_id(self):
        req = KaiChatRequest(
            user_id="firebase-uid-abc123",
            message="Hello Kai",
        )
        assert req.user_id == "firebase-uid-abc123"

    def test_accepts_max_length_user_id(self):
        uid = "u" * 128
        req = KaiChatRequest(user_id=uid, message="Hello")
        assert len(req.user_id) == 128

    def test_rejects_oversized_user_id(self):
        uid = "u" * 129
        with pytest.raises(ValidationError) as exc_info:
            KaiChatRequest(user_id=uid, message="Hello")
        errors = exc_info.value.errors()
        assert any("user_id" in str(e.get("loc", "")) for e in errors)

    def test_rejects_empty_user_id(self):
        with pytest.raises(ValidationError):
            KaiChatRequest(user_id="", message="Hello")

    def test_rejects_missing_user_id(self):
        with pytest.raises(ValidationError):
            KaiChatRequest(message="Hello")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# AnalyzeLoserRequest
# ---------------------------------------------------------------------------


class TestAnalyzeLoserRequestUserIdBounds:
    def test_accepts_normal_user_id(self):
        req = AnalyzeLoserRequest(user_id="user-abc", symbol="AAPL")
        assert req.user_id == "user-abc"

    def test_accepts_max_length_user_id(self):
        uid = "a" * 128
        req = AnalyzeLoserRequest(user_id=uid, symbol="TSLA")
        assert len(req.user_id) == 128

    def test_rejects_oversized_user_id(self):
        uid = "a" * 129
        with pytest.raises(ValidationError) as exc_info:
            AnalyzeLoserRequest(user_id=uid, symbol="TSLA")
        errors = exc_info.value.errors()
        assert any("user_id" in str(e.get("loc", "")) for e in errors)

    def test_rejects_empty_user_id(self):
        with pytest.raises(ValidationError):
            AnalyzeLoserRequest(user_id="", symbol="TSLA")


# ---------------------------------------------------------------------------
# Gmail Query param bounds -- exercised via FastAPI TestClient
# ---------------------------------------------------------------------------


def _make_gmail_client():
    """Return a TestClient for the kai gmail router with auth stubs."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.middleware as mw
    from api.routes.kai.gmail import router

    app = FastAPI()
    app.include_router(router)

    # Stub out auth so that query-param validation is the first gate that fires.
    app.dependency_overrides[mw.require_firebase_auth] = lambda: "stub-uid"
    app.dependency_overrides[mw.require_vault_owner_token] = lambda: {"user_id": "stub-uid"}

    return TestClient(app, raise_server_exceptions=False)


class TestGmailQueryParamUserIdBounds:
    def test_sync_run_rejects_oversized_user_id(self):
        client = _make_gmail_client()
        oversized = "u" * 129
        resp = client.get(f"/gmail/sync/run-123?user_id={oversized}")
        # FastAPI returns 422 for query param validation failures.
        assert resp.status_code == 422

    def test_artifact_rejects_oversized_user_id(self):
        client = _make_gmail_client()
        oversized = "u" * 129
        resp = client.get(f"/gmail/receipts-memory/artifacts/art-1?user_id={oversized}")
        assert resp.status_code == 422

    def test_sync_run_accepts_normal_user_id(self):
        """Normal-length IDs must not be blocked at the validation layer (422 is wrong)."""
        client = _make_gmail_client()
        resp = client.get("/gmail/sync/run-123?user_id=normal-uid-abc")
        assert resp.status_code != 422

    def test_artifact_accepts_normal_user_id(self):
        client = _make_gmail_client()
        resp = client.get("/gmail/receipts-memory/artifacts/art-1?user_id=normal-uid-abc")
        assert resp.status_code != 422

"""
Regression tests for CWE-400 and CWE-209 fixes in kai/decisions.py and kai/support.py.

CWE-400 — Uncontrolled Resource Consumption:
  - GET /api/kai/decisions/{user_id}: user_id path param now bounded to 128 chars.

CWE-209 — Information Exposure Through Error Messages:
  - POST /api/kai/support/message: generic Exception and
    SupportEmailNotConfiguredError handlers no longer echo internal error
    detail (str(exc)) back to the caller.

CWE-400 (body field):
  - POST /api/kai/support/message: SupportMessageRequest.user_id now bounded
    to max_length=128, preventing oversized allocation.

Attach points:
  - GET  /api/kai/decisions/{user_id}   (api/routes/kai/decisions.py)
  - POST /api/kai/support/message       (api/routes/kai/support.py)
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from api.main import app
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GOOD_USER_ID = "user_abc123"
_LONG_USER_ID = "u" * 129  # exceeds max_length=128

_VALID_TOKEN_DATA = {"user_id": _GOOD_USER_ID, "scope": "VAULT_OWNER"}


@contextmanager
def _override_vault_owner(token_data: dict):
    async def _stub():
        return token_data

    with patch.dict(app.dependency_overrides, {require_vault_owner_token: _stub}):
        yield


# ---------------------------------------------------------------------------
# GET /api/kai/decisions/{user_id} — CWE-400 path param bounds
# ---------------------------------------------------------------------------


class TestDecisionsPathBounds:
    def test_valid_user_id_returns_200(self):
        mock_decisions = [{"id": "d1", "label": "buy"}]
        pkm_mock = MagicMock()
        pkm_mock.get_recent_decision_records = AsyncMock(return_value=mock_decisions)
        with _override_vault_owner(_VALID_TOKEN_DATA):
            with patch(
                "api.routes.kai.decisions.get_pkm_service", return_value=pkm_mock
            ):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get(
                    f"/api/kai/decisions/{_GOOD_USER_ID}",
                    headers={"Authorization": "Bearer tok"},
                )
        assert resp.status_code == 200

    def test_oversized_user_id_rejected_422(self):
        with _override_vault_owner(_VALID_TOKEN_DATA):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                f"/api/kai/decisions/{_LONG_USER_ID}",
                headers={"Authorization": "Bearer tok"},
            )
        assert resp.status_code == 422

    def test_empty_user_id_rejected_404_or_422(self):
        with _override_vault_owner(_VALID_TOKEN_DATA):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                "/api/kai/decisions/",
                headers={"Authorization": "Bearer tok"},
            )
        # FastAPI 404 (no route) or 422 (min_length violation)
        assert resp.status_code in (404, 422)

    def test_exactly_128_chars_accepted(self):
        uid128 = "u" * 128
        token_data = {"user_id": uid128, "scope": "VAULT_OWNER"}
        pkm_mock = MagicMock()
        pkm_mock.get_recent_decision_records = AsyncMock(return_value=[])
        pkm_mock.get_index_v2 = AsyncMock(return_value=None)
        pkm_mock._extract_decision_records = MagicMock(return_value=[])
        with _override_vault_owner(token_data):
            with patch(
                "api.routes.kai.decisions.get_pkm_service", return_value=pkm_mock
            ):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get(
                    f"/api/kai/decisions/{uid128}",
                    headers={"Authorization": "Bearer tok"},
                )
        assert resp.status_code == 200

    def test_exactly_129_chars_rejected_422(self):
        uid129 = "u" * 129
        with _override_vault_owner(_VALID_TOKEN_DATA):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(
                f"/api/kai/decisions/{uid129}",
                headers={"Authorization": "Bearer tok"},
            )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /api/kai/support/message — CWE-400 body field + CWE-209 error echo
# ---------------------------------------------------------------------------

_VALID_SUPPORT_PAYLOAD = {
    "user_id": _GOOD_USER_ID,
    "kind": "bug_report",
    "subject": "Test subject",
    "message": "This is a valid support message body with enough length.",
}


class TestSupportMessageBounds:
    def test_valid_payload_accepted(self):
        from api.middleware import require_firebase_auth

        queue_result = {
            "delivery_status": "queued",
            "job_id": "job-1",
        }
        cfg_mock = MagicMock()
        cfg_mock.configured = True
        cfg_mock.delivery_mode = "queue"
        cfg_mock.effective_recipient = "support@hushh.ai"
        cfg_mock.support_to_email = "support@hushh.ai"
        cfg_mock.from_email = "no-reply@hushh.ai"

        email_svc_mock = MagicMock()
        email_svc_mock.config = cfg_mock

        queue_svc_mock = MagicMock()
        queue_svc_mock.enqueue = AsyncMock(return_value=queue_result)

        async def _stub_firebase():
            return _GOOD_USER_ID

        with patch.dict(
            app.dependency_overrides, {require_firebase_auth: _stub_firebase}
        ):
            with patch(
                "api.routes.kai.support.get_support_email_service",
                return_value=email_svc_mock,
            ):
                with patch(
                    "api.routes.kai.support.get_email_delivery_queue_service",
                    return_value=queue_svc_mock,
                ):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/kai/support/message", json=_VALID_SUPPORT_PAYLOAD
                    )
        assert resp.status_code == 202

    def test_oversized_user_id_rejected_422(self):
        from api.middleware import require_firebase_auth

        payload = {**_VALID_SUPPORT_PAYLOAD, "user_id": "u" * 129}

        async def _stub_firebase():
            return "u" * 129

        with patch.dict(
            app.dependency_overrides, {require_firebase_auth: _stub_firebase}
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/api/kai/support/message", json=payload)
        assert resp.status_code == 422

    def test_exactly_128_char_user_id_accepted_at_model_level(self):
        """Pydantic model accepts user_id of exactly 128 chars."""

        from api.routes.kai.support import SupportMessageRequest

        req = SupportMessageRequest(
            user_id="u" * 128,
            kind="bug_report",
            subject="Valid subject",
            message="Valid message with enough content here for the field.",
        )
        assert len(req.user_id) == 128

    def test_129_char_user_id_rejected_at_model_level(self):
        from pydantic import ValidationError

        from api.routes.kai.support import SupportMessageRequest

        with pytest.raises(ValidationError):
            SupportMessageRequest(
                user_id="u" * 129,
                kind="bug_report",
                subject="Valid subject",
                message="Valid message with enough content here for the field.",
            )


# ---------------------------------------------------------------------------
# CWE-209 — error echo suppression in support handler
# ---------------------------------------------------------------------------


class TestSupportCWE209:
    """Verify that internal exception details are never echoed back to callers."""

    _SENTINEL = "INTERNAL_SECRET_xK7q9pBnZm_LEAK_MARKER"

    def _make_support_client(self, firebase_uid: str):
        from api.middleware import require_firebase_auth

        async def _stub():
            return firebase_uid

        app.dependency_overrides[require_firebase_auth] = _stub
        return TestClient(app, raise_server_exceptions=False)

    def _cleanup(self):
        from api.middleware import require_firebase_auth

        app.dependency_overrides.pop(require_firebase_auth, None)

    def test_generic_exception_does_not_echo_detail(self):
        """str(exc) must NOT appear in the HTTP response body."""
        from api.middleware import require_firebase_auth

        cfg_mock = MagicMock()
        cfg_mock.configured = True

        email_svc_mock = MagicMock()
        email_svc_mock.config = cfg_mock

        sentinel = self._SENTINEL

        queue_svc_mock = MagicMock()
        queue_svc_mock.enqueue = AsyncMock(
            side_effect=RuntimeError(sentinel)
        )

        async def _stub_firebase():
            return _GOOD_USER_ID

        with patch.dict(
            app.dependency_overrides, {require_firebase_auth: _stub_firebase}
        ):
            with patch(
                "api.routes.kai.support.get_support_email_service",
                return_value=email_svc_mock,
            ):
                with patch(
                    "api.routes.kai.support.get_email_delivery_queue_service",
                    return_value=queue_svc_mock,
                ):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.post(
                        "/api/kai/support/message", json=_VALID_SUPPORT_PAYLOAD
                    )

        assert resp.status_code == 500
        assert sentinel not in resp.text, (
            "Internal exception detail must not be echoed back to the caller (CWE-209)"
        )

    def test_not_configured_error_does_not_echo_detail(self):
        """SupportEmailNotConfiguredError detail must not leak server config info."""
        from api.middleware import require_firebase_auth
        from hushh_mcp.services.support_email_service import SupportEmailNotConfiguredError

        sentinel = self._SENTINEL

        # Raise directly from get_support_email_service
        with patch(
            "api.routes.kai.support.get_support_email_service",
            side_effect=SupportEmailNotConfiguredError(sentinel),
        ):
            async def _stub_firebase():
                return _GOOD_USER_ID

            with patch.dict(
                app.dependency_overrides, {require_firebase_auth: _stub_firebase}
            ):
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.post(
                    "/api/kai/support/message", json=_VALID_SUPPORT_PAYLOAD
                )

        assert resp.status_code == 503
        assert sentinel not in resp.text, (
            "SupportEmailNotConfiguredError detail must not be echoed back (CWE-209)"
        )

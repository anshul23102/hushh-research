# tests/test_support_run_manager_exception_leaks.py
"""
CWE-209 / CWE-20: Exception detail leaks in Kai support and run-manager routes.

Before this fix:
  - SupportEmailNotConfiguredError exposed internal env-var names in the 503 response
  - A catch-all except block in support.py forwarded raw str(exc) in a 500 response
  - KaiRunManager._run_worker wrote str(exc) into SSE "error" frame payloads streamed to clients
  - SupportMessageRequest.user_id had no length bounds at all

After this fix:
  - 503 returns "Support messaging is not available. Please contact us another way."
  - 500 returns "Support message could not be delivered. Please try again later."
  - SSE error payload "message" is the static string "Analysis run failed. Please try again."
  - user_id is bounded: min_length=1, max_length=128
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from api.routes.kai.support import SupportMessageRequest


# ---------------------------------------------------------------------------
# SupportMessageRequest bounds
# ---------------------------------------------------------------------------


class TestSupportMessageRequestBounds:
    def test_accepts_valid_user_id(self):
        req = SupportMessageRequest(
            user_id="user-abc123",
            kind="support_request",
            subject="Need help",
            message="This is my detailed support message here.",
        )
        assert req.user_id == "user-abc123"

    def test_rejects_empty_user_id(self):
        with pytest.raises(ValidationError):
            SupportMessageRequest(
                user_id="",
                kind="bug_report",
                subject="Subject",
                message="Message body goes here yes.",
            )

    def test_rejects_oversized_user_id(self):
        with pytest.raises(ValidationError) as exc_info:
            SupportMessageRequest(
                user_id="u" * 129,
                kind="bug_report",
                subject="Subject",
                message="Message body goes here yes.",
            )
        errors = exc_info.value.errors()
        assert any("user_id" in str(e.get("loc", "")) for e in errors)

    def test_accepts_max_length_user_id(self):
        req = SupportMessageRequest(
            user_id="u" * 128,
            kind="bug_report",
            subject="Bug subject",
            message="Bug message body goes here.",
        )
        assert len(req.user_id) == 128


# ---------------------------------------------------------------------------
# Support route HTTP exception leaks
# ---------------------------------------------------------------------------


def _make_support_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import api.middleware as mw
    from api.routes.kai.support import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[mw.require_firebase_auth] = lambda: "stub-uid"

    return TestClient(app, raise_server_exceptions=False)


_VALID_PAYLOAD = {
    "user_id": "stub-uid",
    "kind": "support_request",
    "subject": "Need some help",
    "message": "This is my detailed support request with enough characters.",
}

_LEAK_TERMS = [
    "SUPPORT_EMAIL_SERVICE_ACCOUNT_JSON",
    "FIREBASE_ADMIN_CREDENTIALS_JSON",
    "FIREBASE_SERVICE_ACCOUNT_JSON",
    "Traceback",
    "Connection refused",
]


class TestSupportRouteExceptionLeaks:
    def test_503_does_not_leak_config_variable_names(self):
        """SupportEmailNotConfiguredError must not expose env-var names to callers."""
        from hushh_mcp.services.support_email_service import SupportEmailNotConfiguredError

        client = _make_support_client()
        with patch(
            "api.routes.kai.support.get_support_email_service",
        ) as mock_svc_factory:
            svc = MagicMock()
            svc.config.configured = False
            mock_svc_factory.return_value = svc

            # Trigger the SupportEmailNotConfiguredError branch
            with patch(
                "api.routes.kai.support.get_email_delivery_queue_service",
            ):
                resp = client.post("/support/message", json=_VALID_PAYLOAD)

        assert resp.status_code == 503
        # Check the user-facing `message` field specifically, not the error `code`.
        user_msg = resp.json()["detail"]["message"]
        for term in _LEAK_TERMS:
            assert term not in user_msg, f"503 message leaked internal term: {term!r}"

    def test_503_returns_opaque_user_message(self):
        client = _make_support_client()
        with patch(
            "api.routes.kai.support.get_support_email_service",
        ) as mock_svc_factory:
            svc = MagicMock()
            svc.config.configured = False
            mock_svc_factory.return_value = svc

            with patch("api.routes.kai.support.get_email_delivery_queue_service"):
                resp = client.post("/support/message", json=_VALID_PAYLOAD)

        assert resp.status_code == 503
        data = resp.json()
        assert "detail" in data
        assert data["detail"]["code"] == "SUPPORT_EMAIL_NOT_CONFIGURED"
        assert "not available" in data["detail"]["message"].lower()

    def test_500_does_not_leak_exception_detail(self):
        """Unexpected exceptions must not expose their message to callers."""
        client = _make_support_client()

        internal_msg = "DB host=internal-db.prod:5432 auth=failed"  # noqa: S105

        with patch(
            "api.routes.kai.support.get_support_email_service",
        ) as mock_svc_factory:
            mock_svc_factory.side_effect = RuntimeError(internal_msg)
            resp = client.post("/support/message", json=_VALID_PAYLOAD)

        assert resp.status_code == 500
        body = resp.text
        assert internal_msg not in body, "500 response leaked raw exception message"

    def test_500_returns_opaque_user_message(self):
        client = _make_support_client()
        with patch(
            "api.routes.kai.support.get_support_email_service",
        ) as mock_svc_factory:
            mock_svc_factory.side_effect = RuntimeError("internal crash detail")
            resp = client.post("/support/message", json=_VALID_PAYLOAD)

        assert resp.status_code == 500
        data = resp.json()
        assert data["detail"]["code"] == "SUPPORT_MESSAGE_FAILED"
        assert "try again" in data["detail"]["message"].lower()


# ---------------------------------------------------------------------------
# KaiRunManager worker crash SSE payload
# ---------------------------------------------------------------------------


def _parse_run_events(run) -> list[dict]:
    """Parse JSON payloads out of the raw SSE frames stored in run.events."""
    import json as _json

    results = []
    for frame in run.events:
        raw_data = frame.get("data", "")
        try:
            envelope = _json.loads(raw_data)
            results.append(envelope)
        except Exception:
            results.append(frame)
    return results


class TestRunManagerWorkerCrashLeak:
    """The SSE error-event payload must never contain raw exception text."""

    @pytest.mark.asyncio
    async def test_worker_crash_payload_has_no_exception_text(self):
        from api.routes.kai.run_manager import KaiAnalyzeRunManager

        manager = KaiAnalyzeRunManager()

        _status, run = await manager.start_or_get_active(
            user_id="u1",
            debate_session_id="s1",
            ticker="TSLA",
            risk_profile="moderate",
            context=None,
            consent_token="tok",
            generator_factory=_crash_generator_factory("internal crash: secret DB host"),
        )

        # Wait for the worker task to complete
        if run.worker_task:
            try:
                await asyncio.wait_for(run.worker_task, timeout=5)
            except Exception:
                pass

        envelopes = _parse_run_events(run)
        error_envelopes = [e for e in envelopes if e.get("event") == "error"]
        assert error_envelopes, "Expected at least one error event in run.events"

        full_str = str(error_envelopes)
        assert "internal crash" not in full_str, (
            "Worker crash payload leaked exception text into SSE stream"
        )
        assert "secret DB host" not in full_str

    @pytest.mark.asyncio
    async def test_worker_crash_payload_contains_static_message(self):
        from api.routes.kai.run_manager import KaiAnalyzeRunManager

        manager = KaiAnalyzeRunManager()

        _, run = await manager.start_or_get_active(
            user_id="u2",
            debate_session_id="s2",
            ticker="AAPL",
            risk_profile="aggressive",
            context=None,
            consent_token="tok",
            generator_factory=_crash_generator_factory("any crash reason"),
        )

        if run.worker_task:
            try:
                await asyncio.wait_for(run.worker_task, timeout=5)
            except Exception:
                pass

        envelopes = _parse_run_events(run)
        error_envelopes = [e for e in envelopes if e.get("event") == "error"]
        assert error_envelopes

        # The payload "message" must be the static opaque string.
        last_error_payload = error_envelopes[-1].get("payload", {})
        assert "Analysis run failed" in last_error_payload.get("message", "")


def _crash_generator_factory(crash_msg: str):
    async def _factory(ticker, user_id, consent_token, risk_profile, context, request):
        raise RuntimeError(crash_msg)
        yield  # make it an async generator

    return _factory

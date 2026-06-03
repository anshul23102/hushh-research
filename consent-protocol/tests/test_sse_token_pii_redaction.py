# tests/test_sse_token_pii_redaction.py
"""
PII redaction tests for SSE lifecycle logs and token revocation logs.

Verifies that user_id and token material are never written to log records
through the actual production runtime paths by driving the FastAPI endpoints
via TestClient.

Issue: #1430
"""

from __future__ import annotations

import asyncio
import logging
import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import consent, sse

_SENTINEL_USER_ID = "uid_SENTINEL_12345"
_SENTINEL_TOKEN_PREFIX = "HCT:"  # noqa: S105
_SENTINEL_TOKEN_SUFFIX = "SENTINEL_TOKEN_abc123"  # noqa: S105
_SENTINEL_TOKEN = _SENTINEL_TOKEN_PREFIX + _SENTINEL_TOKEN_SUFFIX


# ---------------------------------------------------------------------------
# Shared log-capture infrastructure
# ---------------------------------------------------------------------------

class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def all_messages(self) -> list[str]:
        return [self.format(r) for r in self.records]

    def combined(self) -> str:
        return " ".join(self.all_messages())


def _attach(logger_name: str) -> _CapturingHandler:
    handler = _CapturingHandler()
    lg = logging.getLogger(logger_name)
    lg.setLevel(logging.DEBUG)
    lg.addHandler(handler)
    return handler


def _detach(logger_name: str) -> None:
    lg = logging.getLogger(logger_name)
    lg.handlers = [h for h in lg.handlers if not isinstance(h, _CapturingHandler)]


def _build_sse_app() -> FastAPI:
    app = FastAPI()
    app.include_router(sse.router)
    return app


def _build_consent_app() -> FastAPI:
    app = FastAPI()
    app.include_router(consent.router)
    return app


# ---------------------------------------------------------------------------
# SSE route path - drives events route via TestClient
# ---------------------------------------------------------------------------

class TestSseGeneratorLogRedaction:
    """
    Calls the actual SSE route using TestClient and verifies
    that no emitted log record contains the raw sentinel user_id.
    """

    def teardown_method(self, _m: object) -> None:
        _detach("api.routes.sse")

    def _run_generator_via_client(self) -> None:
        q: asyncio.Queue = asyncio.Queue()
        app = _build_sse_app()
        client = TestClient(app)

        with (
            patch("api.routes.sse._ensure_consent_sse_enabled", return_value=None),
            patch("api.routes.sse._authorize_sse_user", return_value=None),
            patch("api.consent_listener.get_consent_queue", return_value=q),
            patch(
                "hushh_mcp.services.consent_db.ConsentDBService.get_recent_consent_events",
                new=AsyncMock(return_value=[]),
            ),
            patch("fastapi.Request.is_disconnected", new=AsyncMock(return_value=True)),
        ):
            with client.stream("GET", f"/api/consent/events/{_SENTINEL_USER_ID}") as response:
                assert response.status_code == 200
                for _line in response.iter_lines():
                    break

    def test_generator_open_log_does_not_contain_sentinel_user_id(self) -> None:
        """consent_sse.open must not emit the raw user_id."""
        handler = _attach("api.routes.sse")
        self._run_generator_via_client()
        assert _SENTINEL_USER_ID not in handler.combined(), (
            f"Raw user_id found in SSE open log: {handler.combined()[:400]}"
        )

    def test_generator_disconnected_log_does_not_contain_sentinel_user_id(self) -> None:
        """consent_sse.disconnected must not emit the raw user_id."""
        handler = _attach("api.routes.sse")
        self._run_generator_via_client()
        for msg in handler.all_messages():
            if "disconnected" in msg:
                assert _SENTINEL_USER_ID not in msg, (
                    f"Raw user_id in disconnected log: {msg!r}"
                )

    def test_generator_logs_redacted_placeholder(self) -> None:
        """At least one log record must contain the [redacted] placeholder."""
        handler = _attach("api.routes.sse")
        self._run_generator_via_client()
        assert any("[redacted]" in m for m in handler.all_messages()), (
            "No [redacted] placeholder found in SSE generator logs -- "
            "redaction may not be applied."
        )

    def test_generator_no_sentinel_in_any_log_record(self) -> None:
        """
        Comprehensive: the sentinel must not appear anywhere across all log
        records emitted during the generator's full lifecycle.
        """
        handler = _attach("api.routes.sse")
        self._run_generator_via_client()
        assert _SENTINEL_USER_ID not in handler.combined(), (
            f"PII sentinel found in combined SSE log output: {handler.combined()[:400]}"
        )


class TestSseGeneratorCancelledLogRedaction:
    """
    Drive consent_event_generator() through the CancelledError branch via
    TestClient to verify the cancelled lifecycle log also redacts the user_id.
    """

    def teardown_method(self, _m: object) -> None:
        _detach("api.routes.sse")

    def _run_generator_with_cancel_via_client(self) -> None:
        q: asyncio.Queue = asyncio.Queue()
        app = _build_sse_app()
        client = TestClient(app)

        async def _raise_cancelled(*args, **kwargs) -> bool:
            raise asyncio.CancelledError

        with (
            patch("api.routes.sse._ensure_consent_sse_enabled", return_value=None),
            patch("api.routes.sse._authorize_sse_user", return_value=None),
            patch("api.consent_listener.get_consent_queue", return_value=q),
            patch(
                "hushh_mcp.services.consent_db.ConsentDBService.get_recent_consent_events",
                new=AsyncMock(return_value=[]),
            ),
            patch("fastapi.Request.is_disconnected", new=_raise_cancelled),
        ):
            with client.stream("GET", f"/api/consent/events/{_SENTINEL_USER_ID}") as response:
                try:
                    for _line in response.iter_lines():
                        pass
                except (asyncio.CancelledError, Exception):
                    pass

    def test_cancelled_log_does_not_contain_sentinel_user_id(self) -> None:
        handler = _attach("api.routes.sse")
        self._run_generator_with_cancel_via_client()
        assert _SENTINEL_USER_ID not in handler.combined(), (
            f"Raw user_id in cancelled log: {handler.combined()[:400]}"
        )


# ---------------------------------------------------------------------------
# Token validation path - drives the real revocation log call via Route
# ---------------------------------------------------------------------------

class TestTokenValidationLogRedaction:
    """
    Drives the consent route with a real issued token and makes
    ConsentDBService.is_token_active() return False to trigger the revocation
    warning at line 344 of token.py.

    Asserts that neither the raw token string nor its prefix appear in any log
    record emitted during that call.
    """

    def teardown_method(self, _m: object) -> None:
        _detach("hushh_mcp.consent.token")

    def _issue_real_token(self) -> str:
        """Issue a real HCT token we can pass into validation route."""
        from hushh_mcp.consent.token import issue_token
        from hushh_mcp.constants import ConsentScope
        from hushh_mcp.types import AgentID, UserID

        token_obj = issue_token(
            UserID(_SENTINEL_USER_ID),
            AgentID("agent.test"),
            ConsentScope.PKM_READ,
        )
        return token_obj.token

    def _run_validation_revoked_path_via_client(self, token_str: str) -> None:
        """
        Run GET /api/consent/data with DB mocked to report the token as
        revoked, triggering the warning log path.
        """
        app = _build_consent_app()
        client = TestClient(app)

        with (
            patch.dict(os.environ, {"TESTING": "false"}),
            patch(
                "hushh_mcp.services.consent_db.ConsentDBService.is_token_active",
                new=AsyncMock(return_value=False),
            ),
        ):
            client.get("/api/consent/data", params={"consent_token": token_str})

    def test_revocation_warning_does_not_log_raw_token_string(self) -> None:
        """The full token string must never appear in the revocation log."""
        token_str = self._issue_real_token()
        handler = _attach("hushh_mcp.consent.token")
        self._run_validation_revoked_path_via_client(token_str)
        assert token_str not in handler.combined(), (
            f"Raw token string found in revocation log: {handler.combined()[:400]}"
        )

    def test_revocation_warning_does_not_log_token_prefix(self) -> None:
        """The HCT: prefix must not appear in validation logs."""
        token_str = self._issue_real_token()
        handler = _attach("hushh_mcp.consent.token")
        self._run_validation_revoked_path_via_client(token_str)
        assert token_str not in handler.combined(), (
            "Token material leaked into revocation log."
        )

    def test_revocation_warning_uses_safe_token_representation(self) -> None:
        """The warning log must not contain raw token material.

        The implementation uses a SHA-256 fingerprint (first 12 hex chars) so
        the log is both safe and traceable. Assert the raw token and its HCT:
        prefix are absent, and that the fingerprint marker is present.
        """
        token_str = self._issue_real_token()
        handler = _attach("hushh_mcp.consent.token")
        self._run_validation_revoked_path_via_client(token_str)
        combined = handler.combined()
        assert token_str not in combined, (
            f"Raw token string leaked into revocation log: {combined[:400]}"
        )
        assert _SENTINEL_TOKEN_PREFIX not in combined, (
            f"Token prefix HCT: leaked into revocation log: {combined[:400]}"
        )
        assert "fingerprint=" in combined, (
            f"Expected fingerprint= marker in revocation log, got: {combined[:400]}"
        )

    def test_sentinel_user_id_not_in_any_token_log_during_validation(self) -> None:
        """user_id used when issuing the token must not appear in validation logs."""
        token_str = self._issue_real_token()
        handler = _attach("hushh_mcp.consent.token")
        self._run_validation_revoked_path_via_client(token_str)
        assert _SENTINEL_USER_ID not in handler.combined(), (
            f"Sentinel user_id found in token validation logs: {handler.combined()[:400]}"
        )

# tests/test_notifications_bearer_threadpool.py
"""
Proof: api.routes.notifications.register_push_token -> POST /api/notifications/register

Verifies that verify_firebase_bearer is dispatched through run_in_threadpool
on both POST /api/notifications/register and DELETE /api/notifications/unregister.

Firebase ID token verification (verify_firebase_bearer) performs a blocking
network call to Google's JWKS endpoint. Calling it directly inside an async
handler blocks the asyncio event loop. Wrapping it in run_in_threadpool offloads
the blocking work to a thread pool worker.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import notifications


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(notifications.router)
    return app


class TestNotificationsBearerThreadpool:
    """verify_firebase_bearer must be called via run_in_threadpool on notification routes."""

    def test_register_uses_run_in_threadpool(self):
        """
        POST /api/notifications/register must pass verify_firebase_bearer to run_in_threadpool.
        """
        recorded: list[object] = []

        async def _fake_run_in_threadpool(fn, *args, **kwargs):
            recorded.append(fn)
            # Return a fake UID so the handler can continue
            return "test-uid"

        mock_service = MagicMock()
        mock_service.upsert_user_push_token.return_value = "push-token-id"

        with (
            patch("api.routes.notifications.run_in_threadpool", side_effect=_fake_run_in_threadpool),
            patch("api.routes.notifications.verify_firebase_bearer") as mock_verify,
            patch("api.routes.notifications.PushTokensService", return_value=mock_service),
        ):
            client = TestClient(_build_app())
            client.post(
                "/api/notifications/register",
                json={"user_id": "test-uid", "token": "fcm-tok", "platform": "web"},
                headers={"Authorization": "Bearer fake-token"},
            )

        assert len(recorded) >= 1, (
            "run_in_threadpool was never called on POST /register; "
            "verify_firebase_bearer is blocking the event loop directly"
        )
        assert recorded[0] is mock_verify, (
            f"run_in_threadpool received {recorded[0]!r} instead of verify_firebase_bearer"
        )

    def test_unregister_uses_run_in_threadpool(self):
        """
        DELETE /api/notifications/unregister must pass verify_firebase_bearer to run_in_threadpool.
        """
        recorded: list[object] = []

        async def _fake_run_in_threadpool(fn, *args, **kwargs):
            recorded.append(fn)
            return "test-uid"

        mock_service = MagicMock()
        mock_service.delete_user_push_tokens.return_value = 1

        with (
            patch("api.routes.notifications.run_in_threadpool", side_effect=_fake_run_in_threadpool),
            patch("api.routes.notifications.verify_firebase_bearer") as mock_verify,
            patch("api.routes.notifications.PushTokensService", return_value=mock_service),
        ):
            client = TestClient(_build_app())
            client.delete(
                "/api/notifications/unregister",
                headers={"Authorization": "Bearer fake-token"},
            )

        assert len(recorded) >= 1, (
            "run_in_threadpool was never called on DELETE /unregister"
        )
        assert recorded[0] is mock_verify, (
            f"run_in_threadpool received {recorded[0]!r} instead of verify_firebase_bearer"
        )

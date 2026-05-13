"""Hermetic tests: developer API query-param length bounds return 422.

FastAPI validates max_length before the handler fires — no auth, no DB, no LLM.

Covered endpoints:
    GET /api/v1/user-scopes/{user_id}   token (max 2048)
    GET /api/v1/consent-status          user_id (max 128), scope (max 500),
                                        request_id (max 200), token (max 2048)
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes.developer import developer_api_router


def _build_app() -> TestClient:
    app = FastAPI()
    app.include_router(developer_api_router)
    return TestClient(app, raise_server_exceptions=False)


client = _build_app()

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_OVER_2048 = "x" * 2049
_OVER_128 = "u" * 129
_OVER_500 = "s" * 501
_OVER_200 = "r" * 201


def _status(response) -> int:
    return response.status_code


# ===========================================================================
# GET /api/v1/user-scopes/{user_id}  — token param
# ===========================================================================


class TestUserScopesTokenBound:
    def test_token_over_2048_returns_422(self):
        resp = client.get(
            "/api/v1/user-scopes/uid_abc",
            params={"token": _OVER_2048},
        )
        assert _status(resp) == 422

    def test_token_at_2048_not_rejected_by_length(self):
        resp = client.get(
            "/api/v1/user-scopes/uid_abc",
            params={"token": "x" * 2048},
        )
        # 422 only if FastAPI rejects — a different status means length check passed
        assert _status(resp) != 422 or "token" not in str(resp.json())

    def test_no_token_allowed(self):
        resp = client.get("/api/v1/user-scopes/uid_abc")
        assert _status(resp) != 422


# ===========================================================================
# GET /api/v1/consent-status — user_id, scope, request_id, token
# ===========================================================================


class TestConsentStatusQueryBounds:
    _base = "/api/v1/consent-status"

    # --- user_id ---

    def test_user_id_over_128_returns_422(self):
        resp = client.get(self._base, params={"user_id": _OVER_128})
        assert _status(resp) == 422

    def test_user_id_at_128_not_rejected(self):
        resp = client.get(self._base, params={"user_id": "u" * 128})
        assert _status(resp) != 422

    def test_user_id_short_not_rejected(self):
        resp = client.get(self._base, params={"user_id": "uid_1"})
        assert _status(resp) != 422

    # --- scope ---

    def test_scope_over_500_returns_422(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "scope": _OVER_500},
        )
        assert _status(resp) == 422

    def test_scope_at_500_not_rejected(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "scope": "s" * 500},
        )
        assert _status(resp) != 422

    def test_scope_absent_not_rejected(self):
        resp = client.get(self._base, params={"user_id": "uid_1"})
        assert _status(resp) != 422

    # --- request_id ---

    def test_request_id_over_200_returns_422(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "request_id": _OVER_200},
        )
        assert _status(resp) == 422

    def test_request_id_at_200_not_rejected(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "request_id": "r" * 200},
        )
        assert _status(resp) != 422

    def test_request_id_absent_not_rejected(self):
        resp = client.get(self._base, params={"user_id": "uid_1"})
        assert _status(resp) != 422

    # --- token ---

    def test_token_over_2048_returns_422(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "token": _OVER_2048},
        )
        assert _status(resp) == 422

    def test_token_at_2048_not_rejected_by_length(self):
        resp = client.get(
            self._base,
            params={"user_id": "uid_1", "token": "x" * 2048},
        )
        assert _status(resp) != 422 or "token" not in str(resp.json())

    def test_token_absent_not_rejected(self):
        resp = client.get(self._base, params={"user_id": "uid_1"})
        assert _status(resp) != 422

    # --- combined over-length ---

    def test_both_scope_and_request_id_over_limit_returns_422(self):
        resp = client.get(
            self._base,
            params={
                "user_id": "uid_1",
                "scope": _OVER_500,
                "request_id": _OVER_200,
            },
        )
        assert _status(resp) == 422

    def test_user_id_and_token_over_limit_returns_422(self):
        resp = client.get(
            self._base,
            params={"user_id": _OVER_128, "token": _OVER_2048},
        )
        assert _status(resp) == 422

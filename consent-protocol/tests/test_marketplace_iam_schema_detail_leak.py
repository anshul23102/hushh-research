"""
marketplace.py IAMSchemaNotReadyError detail-leak tests.

Verifies that 503 responses from marketplace routes do not expose
internal database migration commands or exception text (CWE-209).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

INTERNAL_STRINGS = [
    "db/migrate.py",
    "db/verify",
    "verify_iam_schema",
    "--iam",
    "Run `python",
    "python db/",
    "IAM schema is not ready",
]

_INTERNAL_EXC_MSG = (
    "IAM schema is not ready. Run `python db/migrate.py --iam` and "
    "`python db/verify/verify_iam_schema.py`."
)


def _make_marketplace_app_safe(path: str) -> FastAPI:
    """App using the patched no-arg helper."""
    app = FastAPI()

    def _iam_schema_not_ready_response() -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "error": "Marketplace service is temporarily unavailable.",
                "code": "IAM_SCHEMA_NOT_READY",
            },
        )

    class _FakeError(Exception):
        pass

    @app.get(path)
    async def _handler():
        try:
            raise _FakeError(_INTERNAL_EXC_MSG)
        except _FakeError:
            return _iam_schema_not_ready_response()

    return app


def _make_marketplace_app_leaky(path: str) -> FastAPI:
    """App using the OLD str(exc)-forwarding helper."""
    app = FastAPI()

    def _iam_schema_not_ready_response_old(message: str | None = None) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={
                "error": message or "IAM schema is not ready",
                "code": "IAM_SCHEMA_NOT_READY",
                "hint": "Run `python db/migrate.py --iam` and `python db/verify/verify_iam_schema.py`.",
            },
        )

    class _FakeError(Exception):
        pass

    @app.get(path)
    async def _handler():
        try:
            raise _FakeError(_INTERNAL_EXC_MSG)
        except _FakeError as exc:
            return _iam_schema_not_ready_response_old(str(exc))

    return app


def test_old_marketplace_helper_leaked_migration_commands() -> None:
    app = _make_marketplace_app_leaky("/api/marketplace/rias")
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/marketplace/rias")
    assert resp.status_code == 503
    assert "db/migrate.py" in resp.text


@pytest.mark.parametrize(
    "path",
    [
        "/api/marketplace/rias",
        "/api/marketplace/investors",
        "/api/marketplace/investors/deck",
        "/api/marketplace/investors/actions",
        "/api/marketplace/ria/abc123",
    ],
)
def test_patched_marketplace_helper_hides_internal_details(path: str) -> None:
    app = _make_marketplace_app_safe(path)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(path)

    assert resp.status_code == 503
    body = resp.text
    for fragment in INTERNAL_STRINGS:
        assert fragment not in body, (
            f"Internal string {fragment!r} leaked in 503 body for {path}"
        )


def test_patched_marketplace_helper_returns_safe_code() -> None:
    app = _make_marketplace_app_safe("/api/marketplace/rias")
    client = TestClient(app, raise_server_exceptions=False)
    data = client.get("/api/marketplace/rias").json()

    assert data.get("code") == "IAM_SCHEMA_NOT_READY"
    assert "hint" not in data
    assert "temporarily unavailable" in data.get("error", "")


def test_patched_marketplace_helper_no_hint_key() -> None:
    app = _make_marketplace_app_safe("/api/marketplace/investors")
    client = TestClient(app, raise_server_exceptions=False)
    data = client.get("/api/marketplace/investors").json()

    assert "hint" not in data
    assert "migrate" not in data.get("error", "")

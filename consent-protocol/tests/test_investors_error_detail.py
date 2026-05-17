"""
Tests that 500-level responses from investor endpoints do not leak internal
exception messages in the HTTP response body.

Canonical attach point:
    api.routes.investors.get_investor -> GET /api/investors/{investor_id}
    api.routes.investors.create_investor -> POST /api/investors/
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import investors as investors_module
from api.routes.investors import router


def _build_app(mock_service: MagicMock) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_get_investor_db_error_hides_detail():
    """
    When InvestorDBService.get_investor_by_id raises an unexpected exception,
    the 500 response must not echo str(exception) to the caller.
    """
    mock_service = MagicMock()
    mock_service.get_investor_by_id.side_effect = RuntimeError(
        "connection refused: secret host db.internal"
    )

    app = _build_app(mock_service)
    with patch.object(investors_module, "InvestorDBService", return_value=mock_service):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/investors/42")

    assert response.status_code == 500
    body = response.text
    assert "secret host" not in body, f"Internal error leaked into response: {body!r}"
    assert "connection refused" not in body, f"Internal error leaked into response: {body!r}"


def test_create_investor_db_error_hides_detail():
    """
    When InvestorDBService.upsert_investor raises an unexpected exception,
    the 500 response must not echo str(exception) to the caller.
    """
    mock_service = MagicMock()
    mock_service.upsert_investor.side_effect = RuntimeError(
        "unique constraint violation on column cik: confidential_schema_info"
    )

    app = _build_app(mock_service)
    with patch.object(investors_module, "InvestorDBService", return_value=mock_service):
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post("/api/investors/", json={"name": "Test Investor"})

    assert response.status_code == 500
    body = response.text
    assert "confidential_schema_info" not in body, (
        f"Internal error leaked into response: {body!r}"
    )
    assert "unique constraint" not in body, f"Internal error leaked into response: {body!r}"

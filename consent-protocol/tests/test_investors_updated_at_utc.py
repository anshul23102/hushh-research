"""
Tests that POST /api/investors/ sets updated_at as a UTC-aware ISO timestamp.

Naive datetime.now() produces a local-time string without timezone info.
On a server that is not in UTC this would store the wrong time and make
cross-region comparisons unreliable.

Canonical attach point:
    api.routes.investors.create_investor
    -> POST /api/investors/
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import investors as investors_module
from api.routes.investors import router

_UTC_OFFSET_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(\+00:00|Z)$"
)


def _build_app() -> tuple[FastAPI, list[dict]]:
    """Return an app with a captured list of dicts passed to upsert_investor."""
    app = FastAPI()
    app.include_router(router)
    captured: list[dict] = []

    async def _fake_upsert(data: dict, upsert_key=None):
        captured.append(data)
        return {"id": 99}

    async def _fake_get_stats():
        return {"total": 0, "by_type": {}}

    mock_service = MagicMock()
    mock_service.upsert_investor = _fake_upsert
    mock_service.get_investor_stats = _fake_get_stats

    app.dependency_overrides = {}

    with patch.object(investors_module, "InvestorDBService", return_value=mock_service):
        pass  # no-op; we patch at call time below

    return app, captured, mock_service


def test_updated_at_is_utc_aware():
    """
    The updated_at value written to the DB must include a UTC offset (+00:00 or Z),
    not a naive local-time string.
    """
    captured: list[dict] = []

    async def _fake_upsert(data: dict, upsert_key=None):
        captured.append(dict(data))
        return {"id": 1}

    mock_service = MagicMock()
    mock_service.upsert_investor = _fake_upsert

    app = FastAPI()
    app.include_router(router)

    with patch.object(investors_module, "InvestorDBService", return_value=mock_service):
        client = TestClient(app)
        response = client.post(
            "/api/investors/",
            json={"name": "Test Investor"},
        )

    assert response.status_code == 201, response.text
    assert len(captured) == 1, "upsert_investor must have been called once"

    updated_at = captured[0].get("updated_at", "")
    assert updated_at, "updated_at must be present in the upserted data"
    assert _UTC_OFFSET_PATTERN.match(updated_at), (
        f"updated_at must be UTC-aware ISO string, got: {updated_at!r}"
    )

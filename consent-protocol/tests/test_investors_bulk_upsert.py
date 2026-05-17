# tests/test_investors_bulk_upsert.py
"""
Proof: api.routes.investors.bulk_create_investors -> POST /api/investors/bulk

Verifies that POST /api/investors/bulk issues a single DB batch upsert rather
than one round-trip per record. The previous implementation called
create_investor() in a loop, producing N sequential DB calls for N records.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes import investors
from hushh_mcp.services.investor_db import InvestorDBService


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(investors.router)
    return app


_FIVE_INVESTORS = [
    {"name": f"Investor {i}", "firm": f"Firm {i}", "investor_type": "fund_manager"}
    for i in range(5)
]


class TestInvestorsBulkUpsert:
    """POST /api/investors/bulk must call the DB upsert exactly once for N records."""

    def test_bulk_calls_db_once_not_per_record(self):
        """
        Posting 5 investors must trigger exactly 1 bulk_upsert call, not 5 individual calls.
        """
        mock_service = MagicMock(spec=InvestorDBService)
        mock_service.bulk_upsert = AsyncMock(
            return_value=[
                {"id": i, "name": f"Investor {i}"} for i in range(5)
            ]
        )

        with patch("api.routes.investors.InvestorDBService", return_value=mock_service):
            client = TestClient(_build_app())
            response = client.post("/api/investors/bulk", json=_FIVE_INVESTORS)

        assert response.status_code == 201, response.text
        data = response.json()
        assert data["created"] == 5

        assert mock_service.bulk_upsert.call_count == 1, (
            f"Expected bulk_upsert to be called exactly once, "
            f"got {mock_service.bulk_upsert.call_count} call(s)"
        )

    def test_bulk_upsert_receives_all_records_at_once(self):
        """The records list passed to bulk_upsert must contain all 5 investors."""
        mock_service = MagicMock(spec=InvestorDBService)
        mock_service.bulk_upsert = AsyncMock(
            return_value=[{"id": i, "name": f"Investor {i}"} for i in range(5)]
        )

        with patch("api.routes.investors.InvestorDBService", return_value=mock_service):
            client = TestClient(_build_app())
            client.post("/api/investors/bulk", json=_FIVE_INVESTORS)

        call_args = mock_service.bulk_upsert.call_args
        records = call_args.args[0] if call_args.args else call_args.kwargs.get("records", [])
        assert len(records) == 5, (
            f"Expected 5 records in single batch call, got {len(records)}"
        )

    def test_bulk_rejects_over_limit(self):
        """Requests with more than _BULK_INVESTOR_MAX investors must return 422."""
        oversized = [
            {"name": f"Investor {i}", "investor_type": "fund_manager"}
            for i in range(investors._BULK_INVESTOR_MAX + 1)
        ]
        client = TestClient(_build_app(), raise_server_exceptions=False)
        response = client.post("/api/investors/bulk", json=oversized)
        assert response.status_code == 422, (
            f"Expected 422 for oversized bulk, got {response.status_code}"
        )

# tests/test_investor_request_bounds.py
"""
Canonical attach point:
  api.routes.investors.create_investor -> POST /api/investors/

Proves that sending a list field with more than the allowed maximum items
returns a 422 Unprocessable Entity validation error rather than being
accepted and forwarded to the database.
"""

import pytest
from pydantic import ValidationError

from api.routes.investors import InvestorCreateRequest


class TestInvestorRequestListBounds:
    """List fields on InvestorCreateRequest must enforce max_length."""

    def test_investment_style_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                investment_style=["GROWTH"] * 1000,
            )

    def test_recent_buys_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                recent_buys=["AAPL"] * 1000,
            )

    def test_recent_sells_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                recent_sells=["TSLA"] * 1000,
            )

    def test_education_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                education=["Harvard"] * 1000,
            )

    def test_board_memberships_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                board_memberships=["Board A"] * 1000,
            )

    def test_peer_investors_rejects_1000_items(self):
        with pytest.raises(ValidationError):
            InvestorCreateRequest(
                name="Test Investor",
                peer_investors=["Investor X"] * 1000,
            )

    def test_valid_list_within_bounds_accepted(self):
        req = InvestorCreateRequest(
            name="Valid Investor",
            investment_style=["GROWTH", "VALUE"],
            recent_buys=["AAPL", "MSFT"],
            peer_investors=["Buffett"],
        )
        assert req.name == "Valid Investor"
        assert len(req.investment_style) == 2


class TestInvestorMutationsRequireAuth:
    """POST mutation endpoints must keep the Firebase auth trust boundary.

    This branch predated the auth landing on integration/pr-train; the
    maintainer patch re-adds require_firebase_auth so the input-bounds change
    does not regress the trust boundary. These tests lock that in: an
    unauthenticated POST must be rejected with 401 (not silently ingested).
    """

    def test_create_requires_auth(self):
        from fastapi.testclient import TestClient

        from server import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/investors/", json={"name": "Test Investor"})
        assert resp.status_code == 401

    def test_bulk_requires_auth(self):
        from fastapi.testclient import TestClient

        from server import app

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post("/api/investors/bulk", json=[{"name": "Bulk Investor"}])
        assert resp.status_code == 401

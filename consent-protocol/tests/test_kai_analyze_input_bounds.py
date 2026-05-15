"""
Tests for Kai analyze + losers input validation bounds.

Verifies that unbounded string/list fields now reject oversized payloads
with HTTP 422 before any business logic runs.
"""

import pytest
from pydantic import ValidationError

from api.routes.kai.analyze import AnalyzeRequest
from api.routes.kai.losers import AnalyzeLosersRequest, PortfolioHolding, PortfolioLoser

# ---------------------------------------------------------------------------
# AnalyzeRequest
# ---------------------------------------------------------------------------


class TestAnalyzeRequestBounds:
    def test_valid_request_passes(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="AAPL")
        assert req.ticker == "AAPL"
        assert req.user_id == "user_abc"

    def test_ticker_too_long_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(user_id="user_abc", ticker="A" * 21)

    def test_ticker_empty_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(user_id="user_abc", ticker="")

    def test_ticker_exactly_max_length_passes(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="A" * 20)
        assert len(req.ticker) == 20

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(user_id="u" * 129, ticker="AAPL")

    def test_user_id_exactly_max_length_passes(self):
        req = AnalyzeRequest(user_id="u" * 128, ticker="AAPL")
        assert len(req.user_id) == 128

    def test_consent_token_too_long_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(user_id="user_abc", ticker="AAPL", consent_token="t" * 1025)

    def test_consent_token_exactly_max_length_passes(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="AAPL", consent_token="t" * 1024)
        assert len(req.consent_token) == 1024

    def test_consent_token_none_passes(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="AAPL", consent_token=None)
        assert req.consent_token is None

    def test_risk_profile_invalid_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeRequest(user_id="user_abc", ticker="AAPL", risk_profile="reckless")

    def test_risk_profile_defaults_to_balanced(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="AAPL")
        assert req.risk_profile == "balanced"

    def test_processing_mode_defaults_to_hybrid(self):
        req = AnalyzeRequest(user_id="user_abc", ticker="AAPL")
        assert req.processing_mode == "hybrid"


# ---------------------------------------------------------------------------
# PortfolioLoser
# ---------------------------------------------------------------------------


class TestPortfolioLoserBounds:
    def test_valid_symbol_passes(self):
        loser = PortfolioLoser(symbol="TSLA")
        assert loser.symbol == "TSLA"

    def test_symbol_empty_raises(self):
        with pytest.raises(ValidationError):
            PortfolioLoser(symbol="")

    def test_symbol_too_long_raises(self):
        with pytest.raises(ValidationError):
            PortfolioLoser(symbol="X" * 21)

    def test_symbol_exactly_max_length_passes(self):
        loser = PortfolioLoser(symbol="S" * 20)
        assert len(loser.symbol) == 20


# ---------------------------------------------------------------------------
# PortfolioHolding
# ---------------------------------------------------------------------------


class TestPortfolioHoldingBounds:
    def test_valid_symbol_passes(self):
        holding = PortfolioHolding(symbol="NVDA")
        assert holding.symbol == "NVDA"

    def test_symbol_empty_raises(self):
        with pytest.raises(ValidationError):
            PortfolioHolding(symbol="")

    def test_symbol_too_long_raises(self):
        with pytest.raises(ValidationError):
            PortfolioHolding(symbol="Y" * 21)


# ---------------------------------------------------------------------------
# AnalyzeLosersRequest
# ---------------------------------------------------------------------------


class TestAnalyzeLosersRequestBounds:
    def _make_losers(self, n: int) -> list[dict]:
        return [{"symbol": f"L{i:04d}"[:5]} for i in range(n)]

    def _make_holdings(self, n: int) -> list[dict]:
        return [{"symbol": f"H{i:04d}"[:5]} for i in range(n)]

    def test_valid_request_passes(self):
        req = AnalyzeLosersRequest(user_id="uid123")
        assert req.user_id == "uid123"

    def test_user_id_too_long_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(user_id="u" * 129)

    def test_user_id_exactly_max_length_passes(self):
        req = AnalyzeLosersRequest(user_id="u" * 128)
        assert len(req.user_id) == 128

    def test_losers_list_over_200_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(user_id="uid123", losers=self._make_losers(201))

    def test_losers_list_exactly_200_passes(self):
        req = AnalyzeLosersRequest(user_id="uid123", losers=self._make_losers(200))
        assert len(req.losers) == 200

    def test_holdings_list_over_500_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(user_id="uid123", holdings=self._make_holdings(501))

    def test_holdings_list_exactly_500_passes(self):
        req = AnalyzeLosersRequest(user_id="uid123", holdings=self._make_holdings(500))
        assert len(req.holdings) == 500

    def test_symbol_too_long_inside_loser_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(
                user_id="uid123",
                losers=[{"symbol": "TOOLONGSYMBOL12345678"}],
            )

    def test_symbol_too_long_inside_holding_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(
                user_id="uid123",
                holdings=[{"symbol": "TOOLONGSYMBOL12345678"}],
            )

    def test_max_positions_below_min_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(user_id="uid123", max_positions=0)

    def test_max_positions_above_max_raises(self):
        with pytest.raises(ValidationError):
            AnalyzeLosersRequest(user_id="uid123", max_positions=51)

    def test_max_positions_boundary_values_pass(self):
        low = AnalyzeLosersRequest(user_id="uid123", max_positions=1)
        high = AnalyzeLosersRequest(user_id="uid123", max_positions=50)
        assert low.max_positions == 1
        assert high.max_positions == 50

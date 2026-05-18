# tests/test_tickers_cwe209.py
"""
PR attach points: GET /api/tickers/search, GET /api/tickers/all,
                  POST /api/tickers/sync-holdings/{user_id}
                  (api/routes/tickers.py)

CWE-209: verify that 500 responses return opaque error messages, not
raw exception text. Also verifies G004 logger fix (no f-string loggers).
"""

import ast
import pathlib
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token

_UID = "test-uid"
_TOKEN = {"user_id": _UID, "token": "fake-token", "scope": "vault.owner"}

_INTERNAL_MSG = "Connection refused: postgresql://secret-host/db"


@pytest.fixture()
def client():
    from api.main import app

    app.dependency_overrides[require_vault_owner_token] = lambda: _TOKEN
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# search_tickers — CWE-209
# ---------------------------------------------------------------------------


def test_search_tickers_500_opaque(client: TestClient) -> None:
    """Internal exception must not leak to the response detail."""
    with patch(
        "api.routes.tickers.TickerDBService",
    ) as MockService, patch(
        "api.routes.tickers.ticker_cache",
        loaded=False,
    ):
        instance = MockService.return_value
        instance.search_tickers = AsyncMock(side_effect=RuntimeError(_INTERNAL_MSG))

        resp = client.get("/api/tickers/search?q=AAPL")

    assert resp.status_code == 500
    body = resp.json()
    assert _INTERNAL_MSG not in body.get("detail", ""), (
        "CWE-209: internal error message leaked in /search response"
    )
    assert body["detail"] == "Ticker search failed"


# ---------------------------------------------------------------------------
# all_tickers — CWE-209
# ---------------------------------------------------------------------------


def test_all_tickers_500_opaque(client: TestClient) -> None:
    """Internal exception from ticker_cache must not leak."""
    with patch("api.routes.tickers.ticker_cache") as mock_cache:
        mock_cache.loaded = False
        mock_cache.load_from_db.side_effect = RuntimeError(_INTERNAL_MSG)

        resp = client.get("/api/tickers/all")

    assert resp.status_code == 500
    body = resp.json()
    assert _INTERNAL_MSG not in body.get("detail", ""), (
        "CWE-209: internal error message leaked in /all response"
    )
    assert body["detail"] == "Failed to retrieve ticker list"


# ---------------------------------------------------------------------------
# sync_tickers_from_holdings — CWE-209
# ---------------------------------------------------------------------------


def test_sync_holdings_500_opaque(client: TestClient) -> None:
    """Internal exception must not leak to the response detail."""
    with patch("api.routes.tickers.TickerDBService") as MockService:
        instance = MockService.return_value
        instance.sync_holdings_symbols = AsyncMock(side_effect=RuntimeError(_INTERNAL_MSG))

        resp = client.post(
            f"/api/tickers/sync-holdings/{_UID}",
            json={"holdings": [], "max_symbols": 10},
        )

    assert resp.status_code == 500
    body = resp.json()
    assert _INTERNAL_MSG not in body.get("detail", ""), (
        "CWE-209: internal error message leaked in /sync-holdings response"
    )
    assert body["detail"] == "Failed to sync ticker holdings"


# ---------------------------------------------------------------------------
# G004 static check
# ---------------------------------------------------------------------------


def test_no_f_string_loggers_in_tickers() -> None:
    """No f-string logger calls (G004) must remain in tickers.py."""
    import api.routes.tickers as module

    src = pathlib.Path(module.__file__).read_text()
    tree = ast.parse(src)
    bad_lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr in {"warning", "error", "info", "debug", "exception"}
        ):
            continue
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                bad_lines.append(node.lineno)
    assert bad_lines == [], f"G004: f-string logger calls at lines {bad_lines}"

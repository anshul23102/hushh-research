# tests/test_remaining_cwe209_g004.py
"""
PR attach points:
  GET  /api/investors/{investor_id}          (api/routes/investors.py :: get_investor)
  POST /api/investors/                       (api/routes/investors.py :: create_investor)
  POST /api/pkm/upgrade/runs/{run_id}/complete (api/routes/pkm_routes_shared.py :: complete_upgrade_run)
  CRD  /_call_provider helper               (api/routes/crd_scraper.py)
  POST /api/agents/kai/validate              (api/routes/agents.py :: validate_token)

Verifies:
  1. CWE-209: Exception messages are NOT echoed in HTTP detail fields.
  2. G004: No f-string loggers remain in the four fixed modules.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth, require_vault_owner_token

_UID = "test-uid-cwe209"


@pytest.fixture()
def client():
    from api.main import app

    app.dependency_overrides[require_firebase_auth] = lambda: _UID
    app.dependency_overrides[require_vault_owner_token] = lambda: {
        "user_id": _UID,
        "token": "fake",
        "scope": "vault.owner",
    }
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# G004: static AST checks
# ---------------------------------------------------------------------------

_FILES_TO_CHECK = [
    "api/routes/investors.py",
    "api/routes/agents.py",
    "api/routes/crd_scraper.py",
    "api/routes/pkm_routes_shared.py",
]


@pytest.mark.parametrize("rel_path", _FILES_TO_CHECK)
def test_no_fstring_loggers(rel_path: str) -> None:
    """No f-string (JoinedStr) logger calls should remain in fixed modules."""
    source = Path(rel_path).read_text()
    tree = ast.parse(source)

    violations: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_logger = (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "logger"
        )
        if not is_logger:
            continue
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                violations.append(node.lineno)

    assert not violations, (
        f"G004 f-string logger(s) remain in {rel_path} at lines: {violations}"
    )


# ---------------------------------------------------------------------------
# CWE-209: investors.py — get_investor
# ---------------------------------------------------------------------------


def test_get_investor_exception_not_leaked(client: TestClient) -> None:
    """RuntimeError from InvestorDBService must NOT appear in 500 detail."""
    internal_msg = "pool_connection_failed: pg_primary_1"

    mock_service = MagicMock()
    mock_service.get_investor_by_id = AsyncMock(side_effect=RuntimeError(internal_msg))

    with patch("api.routes.investors.InvestorDBService", return_value=mock_service):
        resp = client.get("/api/investors/42")

    assert resp.status_code == 500
    assert internal_msg not in resp.text, (
        f"CWE-209: internal error leaked in GET /api/investors/42: {resp.text!r}"
    )


# ---------------------------------------------------------------------------
# CWE-209: investors.py — create_investor
# ---------------------------------------------------------------------------


def test_create_investor_exception_not_leaked(client: TestClient) -> None:
    """RuntimeError from upsert_investor must NOT appear in 500 detail."""
    internal_msg = "unique_violation: investor_cik_unique_constraint"

    mock_service = MagicMock()
    mock_service.upsert_investor = AsyncMock(side_effect=RuntimeError(internal_msg))

    with patch("api.routes.investors.InvestorDBService", return_value=mock_service):
        resp = client.post(
            "/api/investors/",
            json={"name": "Test Investor"},
        )

    assert resp.status_code == 500
    assert internal_msg not in resp.text, (
        f"CWE-209: internal error leaked in POST /api/investors/: {resp.text!r}"
    )


# ---------------------------------------------------------------------------
# CWE-209: pkm_routes_shared.py — complete_upgrade_run
# ---------------------------------------------------------------------------


def test_pkm_complete_upgrade_run_valueerror_not_leaked(client: TestClient) -> None:
    """ValueError from complete_run must NOT appear verbatim in 409 detail."""
    internal_msg = "run_state_machine: transition PENDING->COMPLETE invalid"

    mock_service = MagicMock()
    mock_service.complete_run = AsyncMock(side_effect=ValueError(internal_msg))

    with patch(
        "api.routes.pkm_routes_shared.get_pkm_upgrade_service",
        return_value=mock_service,
    ):
        resp = client.post(
            "/api/pkm/upgrade/runs/test-run-id/complete",
            json={"user_id": _UID},
        )

    assert resp.status_code == 409
    assert internal_msg not in resp.text, (
        f"CWE-209: internal ValueError leaked in complete_upgrade_run: {resp.text!r}"
    )

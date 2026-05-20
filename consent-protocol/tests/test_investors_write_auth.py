"""
Regression tests for unauthenticated write access on investor admin endpoints.

Attach point: api/routes/investors.py
  POST /api/investors/       (create_investor)
  POST /api/investors/bulk   (bulk_create_investors)

Before this fix both endpoints accepted anonymous requests, allowing any caller
to upsert or overwrite investor profiles in the public investor database.

Each test confirms:
  1. A request WITHOUT an Authorization header is rejected with HTTP 401.
  2. A request WITH a valid Firebase token is accepted (mocked).

Also verifies that read endpoints remain public (no auth required).

Additionally checks that CWE-209 detail=str(e) leaks are gone from
api/routes/db_proxy.py and api/routes/investors.py using AST inspection.
"""

import ast
import pathlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.middleware import require_firebase_auth

REPO_ROOT = pathlib.Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    # Import here to avoid loading all env-dependent services at collection time.
    from server import app  # noqa: PLC0415

    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_INVESTOR = {
    "name": "Test Investor",
    "cik": "0000012345",
    "investor_type": "fund_manager",
}

_STUB_UID = "test-firebase-uid-001"


def _auth_override():
    """Override require_firebase_auth to return a stub UID."""
    return _STUB_UID


# ---------------------------------------------------------------------------
# Auth enforcement on write endpoints
# ---------------------------------------------------------------------------


def test_create_investor_requires_auth(client):
    """POST /api/investors/ with no token must return 401."""
    resp = client.post("/api/investors/", json=_VALID_INVESTOR)
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated POST /api/investors/, got {resp.status_code}"
    )


def test_bulk_create_investors_requires_auth(client):
    """POST /api/investors/bulk with no token must return 401."""
    resp = client.post("/api/investors/bulk", json=[_VALID_INVESTOR])
    assert resp.status_code == 401, (
        f"Expected 401 for unauthenticated POST /api/investors/bulk, got {resp.status_code}"
    )


def test_create_investor_accepts_authed_request(client):
    """POST /api/investors/ with a valid Firebase token must not be 401/403."""
    from server import app  # noqa: PLC0415

    with (
        patch.dict(app.dependency_overrides, {require_firebase_auth: _auth_override}),
        patch(
            "hushh_mcp.services.investor_db.InvestorDBService.upsert_investor",
            return_value={"id": 9999},
        ),
    ):
        resp = client.post("/api/investors/", json=_VALID_INVESTOR)

    # Anything other than 401/403 means auth passed
    assert resp.status_code not in (401, 403), (
        f"Authed POST /api/investors/ was unexpectedly rejected: {resp.status_code}"
    )


def test_bulk_create_investors_accepts_authed_request(client):
    """POST /api/investors/bulk with a valid Firebase token must not be 401/403."""
    from server import app  # noqa: PLC0415

    with (
        patch.dict(app.dependency_overrides, {require_firebase_auth: _auth_override}),
        patch(
            "hushh_mcp.services.investor_db.InvestorDBService.upsert_investor",
            return_value={"id": 9999},
        ),
    ):
        resp = client.post("/api/investors/bulk", json=[_VALID_INVESTOR])

    assert resp.status_code not in (401, 403), (
        f"Authed POST /api/investors/bulk was unexpectedly rejected: {resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Read endpoints remain public
# ---------------------------------------------------------------------------


def test_search_investors_is_public(client):
    """GET /api/investors/search must not require auth."""
    with patch(
        "hushh_mcp.services.investor_db.InvestorDBService.search_investors",
        return_value=[],
    ):
        resp = client.get("/api/investors/search", params={"name": "Buffett"})

    assert resp.status_code != 401, "Investor search should remain public (no auth required)"


# ---------------------------------------------------------------------------
# CWE-209: no raw exception text in HTTP 500 responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rel_path",
    [
        "api/routes/investors.py",
        "api/routes/db_proxy.py",
    ],
)
def test_no_detail_str_e_in_500_responses(rel_path):
    """
    Ensure no HTTPException 500 response leaks raw exception text via detail=str(e).

    Uses AST to find:
        raise HTTPException(status_code=500, detail=str(...))
    patterns which expose internal error messages to API callers (CWE-209).
    """
    path = REPO_ROOT / rel_path
    source = path.read_text()
    tree = ast.parse(source, filename=str(path))

    leaks = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            # Look for HTTPException( ... ) calls
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name != "HTTPException":
                self.generic_visit(node)
                return

            # Check if status_code=500 and detail=str(...)
            kwargs = {kw.arg: kw.value for kw in node.keywords}
            sc = kwargs.get("status_code")
            detail = kwargs.get("detail")

            if sc is None or detail is None:
                self.generic_visit(node)
                return

            sc_val = getattr(sc, "n", None) or getattr(sc, "value", None)
            if sc_val != 500:
                self.generic_visit(node)
                return

            # detail=str(e) pattern
            if (
                isinstance(detail, ast.Call)
                and isinstance(detail.func, ast.Name)
                and detail.func.id == "str"
            ):
                leaks.append(node.lineno)

            self.generic_visit(node)

    Visitor().visit(tree)
    assert leaks == [], (
        f"{rel_path} still leaks raw exception text in HTTP 500 detail at lines: "
        + ", ".join(str(n) for n in leaks)
    )

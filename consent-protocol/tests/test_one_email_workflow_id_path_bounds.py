"""
Regression tests for workflow_id path-parameter length enforcement.

Attach point: api/routes/one/email.py

Bug: Ten route handlers under /api/one/kyc/workflows/{workflow_id}/* accepted
an arbitrarily long ``workflow_id`` path segment with no upper-bound check.
FastAPI forwards the raw string to the service layer, which passes it to
parameterised SQL queries and log statements (CWE-400: Uncontrolled Resource
Consumption).

Real workflow IDs are UUID4 (36 characters).  A caller could craft a URL with
a kilobyte-scale workflow_id that propagates into every downstream log line and
DB query for the lifetime of that request.

Fix: introduce ``_WORKFLOW_ID_MAX_LEN = 128`` and annotate every
``workflow_id`` path parameter with ``Annotated[str, Path(max_length=...)]``.
FastAPI automatically returns HTTP 422 when the path segment exceeds the limit.

Tests cover:
- Module constant exists and is within reasonable bounds
- WorkflowId type alias is defined
- HTTP 422 for oversized workflow_id on GET /kyc/workflows/{workflow_id}
- HTTP 422 for oversized workflow_id on POST /kyc/workflows/{workflow_id}/refresh
- Valid-length workflow_id is NOT rejected with 422 by the path check
- AST guard: all workflow_id path params use WorkflowId or Path(max_length=...)
"""

from __future__ import annotations

import ast
import pathlib

import pytest

# ---------------------------------------------------------------------------
# Constant / type-alias checks (no network required)
# ---------------------------------------------------------------------------
import api.routes.one.email as _email_mod


def test_workflow_id_max_len_constant_exists():
    """_WORKFLOW_ID_MAX_LEN must be defined in the module."""
    assert hasattr(_email_mod, "_WORKFLOW_ID_MAX_LEN"), (
        "_WORKFLOW_ID_MAX_LEN constant missing from api/routes/one/email.py"
    )


def test_workflow_id_max_len_above_uuid4_length():
    """Limit must be >= 36 chars (UUID4 length) so real IDs are never rejected."""
    assert _email_mod._WORKFLOW_ID_MAX_LEN >= 36, (
        f"_WORKFLOW_ID_MAX_LEN={_email_mod._WORKFLOW_ID_MAX_LEN} would reject UUID4 workflow IDs"
    )


def test_workflow_id_max_len_not_absurdly_large():
    """Limit must be <= 1024 chars to provide meaningful DoS protection."""
    assert _email_mod._WORKFLOW_ID_MAX_LEN <= 1024, (
        f"_WORKFLOW_ID_MAX_LEN={_email_mod._WORKFLOW_ID_MAX_LEN} offers no DoS protection"
    )


def test_workflow_id_type_alias_exists():
    """WorkflowId annotated type alias must be present on the module."""
    assert hasattr(_email_mod, "WorkflowId"), (
        "WorkflowId type alias missing from api/routes/one/email.py"
    )


# ---------------------------------------------------------------------------
# AST guard: all workflow_id path params must carry a max_length constraint
# ---------------------------------------------------------------------------

_EMAIL_PY = pathlib.Path(__file__).parent.parent / "api/routes/one/email.py"


def test_ast_workflow_id_params_are_bounded():
    """
    Walk the AST to verify that every function with a ``workflow_id`` parameter
    uses the ``WorkflowId`` alias (i.e. no bare ``str`` annotation remains).
    """
    source = _EMAIL_PY.read_text()
    tree = ast.parse(source)

    bare_str_functions = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for arg in node.args.args:
            if arg.arg != "workflow_id":
                continue
            # annotation should NOT be a plain Name('str')
            if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "str":
                bare_str_functions.append(node.name)

    assert not bare_str_functions, (
        f"The following handlers still use bare 'str' for workflow_id "
        f"(missing max_length guard): {bare_str_functions}"
    )


# ---------------------------------------------------------------------------
# HTTP-layer tests (TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    """TestClient with vault-owner token auth stubbed out."""
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from api.middleware import require_vault_owner_token
    from server import app

    def _stub_token():
        return {"user_id": "user_stub_abc", "scope": "vault.owner", "token": "tok"}

    with patch.dict(app.dependency_overrides, {require_vault_owner_token: _stub_token}):
        yield TestClient(app, raise_server_exceptions=False)


_MAX = _email_mod._WORKFLOW_ID_MAX_LEN


def test_get_workflow_oversized_id_returns_422(client):
    """GET /api/one/kyc/workflows/{workflow_id} must return 422 for oversized workflow_id."""
    oversized = "w" * (_MAX + 1)
    resp = client.get(f"/api/one/kyc/workflows/{oversized}?user_id=user_stub_abc")
    assert resp.status_code == 422, (
        f"Expected 422 for oversized workflow_id on GET, got {resp.status_code}"
    )


def test_post_refresh_oversized_id_returns_422(client):
    """POST /kyc/workflows/{workflow_id}/refresh must return 422 for oversized workflow_id."""
    oversized = "w" * (_MAX + 1)
    resp = client.post(
        f"/api/one/kyc/workflows/{oversized}/refresh",
        json={"user_id": "user_stub_abc"},
    )
    assert resp.status_code == 422, (
        f"Expected 422 for oversized workflow_id on POST /refresh, got {resp.status_code}"
    )


def test_valid_workflow_id_not_rejected_by_path_check(client):
    """
    A UUID4-length workflow_id must NOT be rejected with 422 by the path check
    (the endpoint may fail for other reasons such as missing DB record).
    """
    valid_id = "a1b2c3d4-e5f6-4abc-8def-0123456789ab"  # 36 chars
    resp = client.get(f"/api/one/kyc/workflows/{valid_id}?user_id=user_stub_abc")
    assert resp.status_code != 422, (
        f"UUID4-length workflow_id was incorrectly rejected with 422: {resp.json()}"
    )

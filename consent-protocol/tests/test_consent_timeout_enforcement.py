# tests/test_consent_timeout_enforcement.py
"""
Regression tests for the poll_timeout_at enforcement gap in
ConsentDBService.get_pending_by_request_id().

Before the fix, get_pending_requests() filtered out timed-out rows via
poll_timeout_at but get_pending_by_request_id() did NOT.  This meant a
direct lookup by request_id could surface an expired consent request,
allowing the approve endpoint to issue a token for it.

All tests are hermetic: no network, no Supabase, no Firebase.
"""

from __future__ import annotations

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hushh_mcp.services.consent_db import ConsentDBService

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW_MS = int(time.time() * 1000)
_UID = "user_test_123"
_REQ_ID = "req_abc456"

# A minimal valid external audit row
_BASE_ROW: Dict[str, Any] = {
    "user_id": _UID,
    "request_id": _REQ_ID,
    "action": "REQUESTED",
    "scope": "attr.financial.*",
    "agent_id": "developer:test_app",  # external agent -> passes _is_external_audit_row
    "issued_at": _NOW_MS - 60_000,
    "expires_at": _NOW_MS + 3_600_000,  # 1 hour ahead
    "poll_timeout_at": None,
    "metadata": None,
    "scope_description": "Financial data",
}


def _row(**overrides: Any) -> Dict[str, Any]:
    return {**_BASE_ROW, **overrides}


def _supabase_returning(rows: list[Dict[str, Any]]) -> MagicMock:
    """Return a fake Supabase client whose .execute() yields the given rows."""
    execute_result = MagicMock()
    execute_result.data = rows
    chain = MagicMock()
    chain.execute.return_value = execute_result
    # .table().select().eq().eq().order().limit() all return the chain
    supabase = MagicMock()
    supabase.table.return_value.select.return_value.eq.return_value.eq.return_value.order.return_value.limit.return_value = chain  # noqa: E501
    return supabase


def _service(supabase: MagicMock) -> ConsentDBService:
    svc = ConsentDBService.__new__(ConsentDBService)
    svc._get_supabase = lambda: supabase
    return svc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGetPendingByRequestIdTimeoutEnforcement:
    """get_pending_by_request_id must return None for timed-out requests."""

    @pytest.mark.asyncio
    async def test_no_timeout_field_returns_request(self):
        """When poll_timeout_at is absent the request is still live."""
        row = _row(poll_timeout_at=None, expires_at=_NOW_MS + 3_600_000)
        svc = _service(_supabase_returning([row]))
        with patch.object(svc, "list_internal_request_events", new=AsyncMock(return_value=[])):
            result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is not None
        assert result["request_id"] == _REQ_ID

    @pytest.mark.asyncio
    async def test_future_timeout_returns_request(self):
        """A request whose poll_timeout_at is in the future is still pending."""
        row = _row(poll_timeout_at=_NOW_MS + 60_000)
        svc = _service(_supabase_returning([row]))
        with patch.object(svc, "list_internal_request_events", new=AsyncMock(return_value=[])):
            result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is not None

    @pytest.mark.asyncio
    async def test_elapsed_poll_timeout_at_returns_none(self):
        """A request whose poll_timeout_at has already passed must return None."""
        row = _row(poll_timeout_at=_NOW_MS - 1)  # 1 ms in the past
        svc = _service(_supabase_returning([row]))
        with patch.object(svc, "list_internal_request_events", new=AsyncMock(return_value=[])):
            result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is None, "Timed-out request must not be returned"

    @pytest.mark.asyncio
    async def test_far_past_timeout_returns_none(self):
        """Requests expired long ago must also be suppressed."""
        row = _row(poll_timeout_at=_NOW_MS - 3_600_000)  # 1 hour ago
        svc = _service(_supabase_returning([row]))
        with patch.object(svc, "list_internal_request_events", new=AsyncMock(return_value=[])):
            result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolved_action_returns_none(self):
        """A CONSENT_GRANTED row is not pending regardless of timeout."""
        row = _row(action="CONSENT_GRANTED", poll_timeout_at=_NOW_MS + 60_000)
        svc = _service(_supabase_returning([row]))
        result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_db_result_returns_none(self):
        """No matching row means no pending request."""
        svc = _service(_supabase_returning([]))
        result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is None

    @pytest.mark.asyncio
    async def test_expires_at_used_as_fallback_timeout(self):
        """When poll_timeout_at is absent, expires_at serves as the fallback gate."""
        # expires_at in the past with no poll_timeout_at -> treat as timed out
        row = _row(poll_timeout_at=None, expires_at=_NOW_MS - 1)
        svc = _service(_supabase_returning([row]))
        with patch.object(svc, "list_internal_request_events", new=AsyncMock(return_value=[])):
            result = await svc.get_pending_by_request_id(_UID, _REQ_ID)
        assert result is None, "Expired request (via expires_at fallback) must not be returned"

    @pytest.mark.asyncio
    async def test_consistency_with_get_pending_requests(self):
        """
        get_pending_requests and get_pending_by_request_id must agree:
        a timed-out row must be absent from both.
        """
        timed_out_row = _row(poll_timeout_at=_NOW_MS - 500)

        svc_single = _service(_supabase_returning([timed_out_row]))
        with patch.object(
            svc_single, "list_internal_request_events", new=AsyncMock(return_value=[])
        ):
            single_result = await svc_single.get_pending_by_request_id(_UID, _REQ_ID)

        # For get_pending_requests the Supabase mock must match its query chain
        list_execute = MagicMock()
        list_execute.data = [timed_out_row]
        list_supabase = MagicMock()
        list_supabase.table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value = list_execute  # noqa: E501
        svc_list = _service(list_supabase)
        with patch.object(
            svc_list, "list_internal_request_events", new=AsyncMock(return_value=[])
        ):
            list_result = await svc_list.get_pending_requests(_UID)

        assert single_result is None, "get_pending_by_request_id must filter timed-out row"
        assert list_result == [], "get_pending_requests must also filter timed-out row"

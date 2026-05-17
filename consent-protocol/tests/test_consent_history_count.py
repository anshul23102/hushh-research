"""
Tests that get_audit_log uses a DB-side count instead of fetching up to 5000
rows and counting in Python.

Canonical attach point:
    hushh_mcp.services.consent_db.ConsentDBService.get_audit_log
    -> GET /api/consent/history
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock


def _make_supabase_stub(page_rows: list[dict], db_count: int) -> MagicMock:
    """
    Build a minimal Supabase stub that tracks which select() calls were made
    and returns controlled fixtures.
    """
    stub = MagicMock()

    page_response = MagicMock()
    page_response.data = page_rows

    count_response = MagicMock()
    count_response.data = []
    count_response.count = db_count

    call_log: list[str] = []

    def _select(columns, **kwargs):
        call_log.append(columns)
        q = MagicMock()
        q.eq.return_value = q
        q.order.return_value = q
        q.limit.return_value = q
        q.offset.return_value = q
        # Distinguish page query (select="*") from count query (select="id")
        if "count" in kwargs:
            q.execute.return_value = count_response
        else:
            q.execute.return_value = page_response
        return q

    table_mock = MagicMock()
    table_mock.select.side_effect = _select
    stub.table.return_value = table_mock
    stub._call_log = call_log

    return stub


def test_count_query_does_not_fetch_rows():
    """
    get_audit_log must send count="exact" to the DB and not materialise
    5000 row IDs in Python for the total figure.
    """
    from hushh_mcp.services.consent_db import ConsentDBService

    service = ConsentDBService()
    stub = _make_supabase_stub(
        page_rows=[
            {
                "id": "row1",
                "user_id": "u1",
                "agent_id": "dev_agent",
                "scope": "attr.financial.*",
                "action": "CONSENT_GRANTED",
                "issued_at": 1_700_000_000_000,
                "expires_at": None,
                "token_id": None,
                "request_id": "req1",
                "scope_description": None,
                "metadata": None,
                "poll_timeout_at": None,
            }
        ],
        db_count=42,
    )
    service._supabase = stub

    result = asyncio.run(service.get_audit_log("u1", page=1, limit=50))

    # The DB-side count must be surfaced as the total.
    assert result["total"] == 42

    # The count query must use count="exact" not a 5000-row fetch.
    # We verify by checking that no select call requested 5000 rows.
    for call_args in stub.table.return_value.select.call_args_list:
        kwargs = call_args.kwargs if hasattr(call_args, "kwargs") else {}
        # If count kwarg is present it must be "exact"
        if "count" in kwargs:
            assert kwargs["count"] == "exact", f"unexpected count value: {kwargs['count']}"


def test_audit_log_items_returned_correctly():
    """Paginated items from the page query must be returned in the response."""
    from hushh_mcp.services.consent_db import ConsentDBService

    service = ConsentDBService()
    stub = _make_supabase_stub(
        page_rows=[
            {
                "id": "row2",
                "user_id": "u2",
                "agent_id": "ria:some_firm",
                "scope": "attr.portfolio.*",
                "action": "CONSENT_GRANTED",
                "issued_at": 1_700_000_000_000,
                "expires_at": 1_710_000_000_000,
                "token_id": "tok_abc123",
                "request_id": "req2",
                "scope_description": "Portfolio data",
                "metadata": None,
                "poll_timeout_at": None,
            }
        ],
        db_count=1,
    )
    service._supabase = stub

    result = asyncio.run(service.get_audit_log("u2", page=1, limit=50))

    assert result["page"] == 1
    assert result["limit"] == 50
    assert len(result["items"]) == 1
    assert result["items"][0]["scope"] == "attr.portfolio.*"

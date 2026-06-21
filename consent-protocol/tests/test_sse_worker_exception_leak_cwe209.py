"""
Regression tests for CWE-209 fixes in SSE worker error payloads.

CWE-209 -- Information Exposure Through Error Messages:
  Three SSE-streaming modules echoed raw str(exc) into event payloads that
  are flushed directly to connected browser clients. Internal runtime detail
  (DB errors, service timeouts, stack context) could leak through SSE frames.

Files fixed:
  api/routes/kai/run_manager.py      -- ANALYZE_RUN_WORKER_FAILED event
  api/routes/kai/import_run_manager.py -- IMPORT_RUN_WORKER_FAILED event
  api/routes/kai/losers.py           -- OPTIMIZE_STREAM_FAILED event

Each test injects a distinctive sentinel string into a mocked exception and
asserts it does NOT appear in the SSE event payload that reaches the client.

Attach points:
  GET  /api/kai/analyze/run/{run_id}/stream  (run_manager.py worker)
  POST /api/kai/portfolio/import/stream      (import_run_manager.py worker)
  POST /api/kai/analyze/losers/optimize      (losers.py generator)
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.middleware import require_vault_owner_token
from api.routes.kai import router as kai_router

_SENTINEL = "INTERNAL_SECRET_zP3mQw7nRk_LEAK_MARKER"


# ---------------------------------------------------------------------------
# Shared minimal app fixture -- same pattern as test_kai_auth_matrix.py
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def kai_app() -> FastAPI:
    app = FastAPI()
    app.include_router(kai_router)
    return app


# ---------------------------------------------------------------------------
# run_manager.py -- ANALYZE_RUN_WORKER_FAILED
# ---------------------------------------------------------------------------


class TestRunManagerWorkerExceptionLeak:
    """KaiAnalyzeRunManager._run_worker must not echo exc detail in SSE payload."""

    def test_worker_crash_does_not_echo_exception_detail(self):
        import asyncio

        from api.routes.kai.run_manager import AnalyzeRunRecord, KaiAnalyzeRunManager

        manager = KaiAnalyzeRunManager()

        run = AnalyzeRunRecord(
            run_id="test-run-001",
            user_id="user_test",
            debate_session_id="debate-sess-001",
            ticker="AAPL",
            risk_profile="balanced",
            context=None,
            consent_token="test-token",  # noqa: S106
        )

        async def _crashing_factory(ticker, user_id, consent_token, risk_profile, context, req):
            raise RuntimeError(_SENTINEL)
            yield  # pragma: no cover -- make it an async generator

        async def _run():
            await manager._run_worker(run, _crashing_factory)

        asyncio.run(_run())

        # The run should be marked failed
        assert run.status == "failed"

        # The sentinel MUST NOT appear in any buffered SSE frame
        for frame in run.events:
            data_str = frame.get("data", "")
            assert _SENTINEL not in data_str, (
                f"Internal exception detail leaked into SSE frame: {data_str!r}"
            )

        # Verify the terminal payload uses a static opaque message
        assert run.terminal_payload is not None
        assert _SENTINEL not in json.dumps(run.terminal_payload)
        assert run.terminal_payload.get("code") == "ANALYZE_RUN_WORKER_FAILED"


# ---------------------------------------------------------------------------
# import_run_manager.py -- IMPORT_RUN_WORKER_FAILED
# ---------------------------------------------------------------------------


class TestImportRunManagerWorkerExceptionLeak:
    """KaiPortfolioImportRunManager._run_worker must not echo exc detail in SSE payload."""

    def test_worker_crash_does_not_echo_exception_detail(self):
        import asyncio

        from api.routes.kai.import_run_manager import (
            KaiPortfolioImportRunManager,
            PortfolioImportRunRecord,
        )

        manager = KaiPortfolioImportRunManager()

        run = PortfolioImportRunRecord(
            run_id="import-run-001",
            user_id="user_test",
            filename="portfolio.csv",
            content=b"symbol,qty\nAAPL,1\n",
            is_csv_upload=True,
        )

        async def _crashing_factory(_run, _req):
            raise RuntimeError(_SENTINEL)
            yield  # pragma: no cover -- make it an async generator

        async def _run_it():
            await manager._run_worker(run, _crashing_factory)

        asyncio.run(_run_it())

        assert run.status == "failed"

        for frame in run.events:
            data_str = frame.get("data", "")
            assert _SENTINEL not in data_str, (
                f"Internal exception detail leaked into import SSE frame: {data_str!r}"
            )

        assert run.terminal_payload is not None
        assert _SENTINEL not in json.dumps(run.terminal_payload)
        assert run.terminal_payload.get("code") == "IMPORT_RUN_WORKER_FAILED"


# ---------------------------------------------------------------------------
# losers.py -- OPTIMIZE_STREAM_FAILED via HTTP endpoint
# ---------------------------------------------------------------------------


class TestLosersOptimizeStreamExceptionLeak:
    """POST /api/kai/analyze/losers/optimize SSE error must not echo str(e)."""

    def test_optimize_stream_error_does_not_echo_exception(self, kai_app: FastAPI):
        async def _stub_vault():
            return {"user_id": "user_test", "scope": "VAULT_OWNER"}

        payload = {
            "user_id": "user_test",
            "losers": [{"symbol": "AAPL", "gain_loss_pct": -10.0}],
            "threshold_pct": -5.0,
            "max_positions": 5,
        }

        kai_app.dependency_overrides[require_vault_owner_token] = _stub_vault
        try:
            with patch(
                "api.routes.kai.losers.get_renaissance_service",
                side_effect=RuntimeError(_SENTINEL),
            ):
                client = TestClient(kai_app, raise_server_exceptions=False)
                resp = client.post("/api/kai/analyze/losers/optimize", json=payload)
        finally:
            kai_app.dependency_overrides.pop(require_vault_owner_token, None)

        assert _SENTINEL not in resp.text, (
            "Internal exception detail leaked into SSE stream response (CWE-209): "
            "found sentinel in body"
        )

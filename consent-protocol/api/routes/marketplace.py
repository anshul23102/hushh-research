"""Marketplace discovery routes for RIA and investor ecosystems.

Attach point for CWE-400 path-param bound:
  GET /api/marketplace/ria/{ria_id}  ria_id  max_length=128
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query
from fastapi.responses import JSONResponse

from hushh_mcp.services.ria_iam_service import IAMSchemaNotReadyError, RIAIAMService

router = APIRouter(prefix="/api/marketplace", tags=["Marketplace"])

# CWE-400: public endpoint -- no auth gate -- so an oversized ria_id propagates
# directly to DB queries without any prior authentication check.
_RIA_ID_MAX_LEN: int = 128
RiaId = Annotated[str, Path(min_length=1, max_length=_RIA_ID_MAX_LEN)]


def _iam_schema_not_ready_response(message: str | None = None) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "error": message or "IAM schema is not ready",
            "code": "IAM_SCHEMA_NOT_READY",
            "hint": "Run `python db/migrate.py --iam` and `python db/verify/verify_iam_schema.py`.",
        },
    )


@router.get("/rias")
async def list_marketplace_rias(
    query: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=20, ge=1, le=50),
    firm: str | None = Query(default=None, max_length=200),
    verification_status: str | None = Query(default=None, max_length=50),
):
    service = RIAIAMService()
    try:
        items = await service.search_marketplace_rias(
            query=query,
            limit=limit,
            firm=firm,
            verification_status=verification_status,
        )
        return {"items": items}
    except IAMSchemaNotReadyError as exc:
        return _iam_schema_not_ready_response(str(exc))


@router.get("/investors")
async def list_marketplace_investors(
    query: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=20, ge=1, le=50),
):
    service = RIAIAMService()
    try:
        items = await service.search_marketplace_investors(query=query, limit=limit)
        return {"items": items}
    except IAMSchemaNotReadyError as exc:
        return _iam_schema_not_ready_response(str(exc))


@router.get("/ria/{ria_id}")
async def get_marketplace_ria(ria_id: RiaId):
    service = RIAIAMService()
    try:
        profile = await service.get_marketplace_ria_profile(ria_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="RIA profile not found")
        return profile
    except IAMSchemaNotReadyError as exc:
        return _iam_schema_not_ready_response(str(exc))

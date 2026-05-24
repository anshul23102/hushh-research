from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from api.middlewares.rate_limit import limiter
from hushh_mcp.services.crd_scrape_proxy_service import (
    CrdScrapeProviderResponse,
    CrdScrapeProxyError,
    CrdScrapeProxyService,
    normalize_crd_number,
)

router = APIRouter(prefix="/api/ria", tags=["RIA", "CRD Scraper"])


class CrdScrapeJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    crdNumber: str = Field(
        ...,
        min_length=1,
        validation_alias=AliasChoices("crdNumber", "crd_number", "crd"),
    )

    @field_validator("crdNumber")
    @classmethod
    def normalize_crd(cls, value: str) -> str:
        return str(normalize_crd_number(value))


class FinancialVerificationJobRequest(BaseModel):
    """Typed request body for POST /api/ria/financial-verification-jobs.

    Canonical attach point:
        api.routes.crd_scraper.create_financial_verification_job
        -> POST /api/ria/financial-verification-jobs
    """

    model_config = ConfigDict(extra="forbid")

    crdNumber: str = Field(
        ...,
        min_length=1,
        max_length=10,
        description="CRD registration number (digits only, max 10 characters).",
    )
    userId: Optional[str] = Field(default=None, min_length=1, max_length=128)
    requestId: Optional[str] = Field(default=None, min_length=1, max_length=128)


def get_crd_scrape_proxy_service() -> CrdScrapeProxyService:
    return CrdScrapeProxyService()


@router.post("/crd-scrape-jobs")
@limiter.limit("10/minute")
async def create_crd_scrape_job(
    payload: CrdScrapeJobRequest,
    request: Request,
    service: CrdScrapeProxyService = Depends(get_crd_scrape_proxy_service),
) -> JSONResponse:
    result = await _call_provider(
        service.create_job(
            crd_number=payload.crdNumber,
            request_id=_request_id(request),
        )
    )
    return JSONResponse(status_code=result.status_code, content=result.payload)


@router.get("/crd-scrape-jobs/{job_id}")
@limiter.limit("60/minute")
async def get_crd_scrape_job(
    job_id: str,
    request: Request,
    service: CrdScrapeProxyService = Depends(get_crd_scrape_proxy_service),
) -> JSONResponse:
    result = await _call_provider(
        service.get_job(
            job_id=job_id,
            request_id=_request_id(request),
        )
    )
    return JSONResponse(status_code=result.status_code, content=result.payload)


@router.post("/financial-verification-jobs")
@limiter.limit("10/minute")
async def create_financial_verification_job(
    payload: FinancialVerificationJobRequest,
    request: Request,
    service: CrdScrapeProxyService = Depends(get_crd_scrape_proxy_service),
) -> JSONResponse:
    result = await _call_provider(
        service.create_financial_verification_job(
            payload=payload.model_dump(exclude_none=True),
            request_id=_request_id(request),
        )
    )
    return JSONResponse(status_code=result.status_code, content=result.payload)


@router.get("/financial-verification-jobs/{job_id}")
@limiter.limit("60/minute")
async def get_financial_verification_job(
    job_id: str,
    request: Request,
    service: CrdScrapeProxyService = Depends(get_crd_scrape_proxy_service),
) -> JSONResponse:
    result = await _call_provider(
        service.get_financial_verification_job(
            job_id=job_id,
            request_id=_request_id(request),
        )
    )
    return JSONResponse(status_code=result.status_code, content=result.payload)


async def _call_provider(coro: Any) -> CrdScrapeProviderResponse:
    try:
        return await coro
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CrdScrapeProxyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


def _request_id(request: Request) -> str | None:
    value = request.headers.get("x-request-id") or request.headers.get("x-cloud-trace-context")
    return str(value).strip() or None

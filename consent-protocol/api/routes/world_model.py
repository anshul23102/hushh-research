"""
Legacy World Model compatibility routes.

These routes preserve older `/api/world-model/*` callers by delegating to the
canonical PKM implementation under `/api/pkm/*`.

DEPRECATED: Migrate to /api/pkm/* endpoints. These routes will be removed.

Attach points for CWE-400 path/query-param bounds (added in this module):
  GET /api/world-model/domains/{user_id}                user_id  max_length=128
  GET /api/world-model/metadata/{user_id}               user_id  max_length=128
  GET /api/world-model/scopes/{user_id}                 user_id  max_length=128
  POST /api/world-model/store-domain                    (body validated by StoreDomainRequest)
  GET /api/world-model/data/{user_id}                   user_id  max_length=128
  GET /api/world-model/domain-data/{user_id}/{domain}   user_id  max_length=128
                                                        domain   max_length=128
                                                        segment_ids Query max_length=50 (items max_length=256)
"""

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel

from api.middleware import require_vault_owner_token
from api.routes.pkm_routes_shared import (
    DomainDataResponse,
    PersonalKnowledgeModelMetadataResponse,
    StockContextRequest,
    StockContextResponse,
    StoreDomainRequest,
    StoreDomainResponse,
    UserScopesResponse,
)
from api.routes.pkm_routes_shared import (
    get_domain_data as _get_domain_data,
)
from api.routes.pkm_routes_shared import (
    get_encrypted_data as _get_encrypted_data,
)
from api.routes.pkm_routes_shared import (
    get_metadata as _get_metadata,
)
from api.routes.pkm_routes_shared import (
    get_stock_context as _get_stock_context,
)
from api.routes.pkm_routes_shared import (
    get_user_scopes as _get_user_scopes,
)
from api.routes.pkm_routes_shared import (
    store_domain as _store_domain,
)
from hushh_mcp.services.domain_contracts import domain_registry_payload

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE-400: Uncontrolled Resource Consumption
# Path and query params had no upper-length bound, allowing arbitrarily long
# strings that propagate to DB queries and downstream service calls.
# ---------------------------------------------------------------------------
_USER_ID_MAX_LEN: int = 128  # Firebase UIDs are 28 chars; 128 is generous
_DOMAIN_KEY_MAX_LEN: int = 128  # Domain keys are short slugs (e.g. "financial")
_SEGMENT_ID_MAX_LEN: int = 256  # Individual segment identifier ceiling
_SEGMENT_IDS_MAX_COUNT: int = 50  # Mirror of pkm_routes_shared.py PR fix

UserId = Annotated[str, Path(min_length=1, max_length=_USER_ID_MAX_LEN)]
DomainKey = Annotated[str, Path(min_length=1, max_length=_DOMAIN_KEY_MAX_LEN)]


def _inject_deprecation_headers(request: Request, response: Response):
    """Dependency that injects deprecation headers on every world-model response."""
    pkm_path = request.url.path.replace("/api/world-model", "/api/pkm")
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = "2026-06-30T00:00:00Z"
    response.headers["X-Migrate-To"] = pkm_path
    logger.info("⚠️ Deprecated world-model route: %s → %s", request.url.path, pkm_path)


router = APIRouter(
    prefix="/api/world-model",
    tags=["world-model-compat"],
    dependencies=[Depends(_inject_deprecation_headers)],
)


class WorldModelDomainsResponse(BaseModel):
    domains: list[dict[str, Any]]
    count: int


class UserWorldModelDomainsResponse(BaseModel):
    user_id: str
    domains: list[dict[str, Any]]
    total_attributes: int = 0
    last_updated: str | None = None


@router.get("/domains", response_model=WorldModelDomainsResponse)
async def get_world_model_domains(
    include_empty: bool = Query(default=False),
):
    _ = include_empty
    domains = [
        {
            "key": row["domain_key"],
            "display_name": row["display_name"],
            "icon": row["icon_name"],
            "color": row["color_hex"],
            "description": row["description"],
            "status": row["status"],
            "parent_domain": row.get("parent_domain"),
        }
        for row in domain_registry_payload()
        if not row.get("is_legacy_alias")
    ]
    return WorldModelDomainsResponse(domains=domains, count=len(domains))


@router.get("/domains/{user_id}", response_model=UserWorldModelDomainsResponse)
async def get_user_world_model_domains(
    user_id: UserId,
    token_data: dict = Depends(require_vault_owner_token),
):
    metadata = await _get_metadata(user_id, token_data)
    domains = [
        domain.model_dump() if hasattr(domain, "model_dump") else dict(domain)
        for domain in metadata.domains
    ]
    return UserWorldModelDomainsResponse(
        user_id=user_id,
        domains=domains,
        total_attributes=metadata.total_attributes,
        last_updated=metadata.last_updated,
    )


@router.get("/metadata/{user_id}", response_model=PersonalKnowledgeModelMetadataResponse)
async def get_world_model_metadata(
    user_id: UserId,
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _get_metadata(user_id, token_data)


@router.get("/scopes/{user_id}", response_model=UserScopesResponse)
async def get_world_model_scopes(
    user_id: UserId,
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _get_user_scopes(user_id, token_data)


@router.post("/store-domain", response_model=StoreDomainResponse)
async def store_world_model_domain(
    request: StoreDomainRequest,
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _store_domain(request, token_data)


@router.get("/data/{user_id}", response_model=dict)
async def get_world_model_data(
    user_id: UserId,
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _get_encrypted_data(user_id, token_data)


@router.get("/domain-data/{user_id}/{domain}", response_model=DomainDataResponse)
async def get_world_model_domain_data(
    user_id: UserId,
    domain: DomainKey,
    segment_ids: list[Annotated[str, Query(max_length=_SEGMENT_ID_MAX_LEN)]] | None = Query(
        default=None, max_length=_SEGMENT_IDS_MAX_COUNT
    ),
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _get_domain_data(user_id, domain, segment_ids, token_data)


@router.post("/get-context", response_model=StockContextResponse)
async def get_world_model_context(
    request: StockContextRequest,
    token_data: dict = Depends(require_vault_owner_token),
):
    return await _get_stock_context(request, token_data)

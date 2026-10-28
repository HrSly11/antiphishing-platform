"""Public phishing dataset governance, SHA-256 version history, sample browsing, and ETL ingestion."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.feeds.openphish import OPENPHISH_FEED_URL, OPENPHISH_LICENSE
from app.adapters.feeds.phishtank import PHISHTANK_FEED_URL, PHISHTANK_LICENSE
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.api.deps import (
    ActorPrincipal,
    allow_service_or_permission,
    get_client_ip,
    get_db,
    require_permission,
)
from app.application.commands.ingest_dataset import ingest_dataset_command
from app.application.dto.report_dto import DatasetVersionOut
from app.domain.iam.rbac import DATASET_ADMIN, DATASET_READ

router = APIRouter()


class DatasetIngestRequest(BaseModel):
    source: str = Field(
        default="openphish_sample",
        description="Feed identifier: openphish_sample | phishtank_sample | openphish_live | phishtank_live | openphish | phishtank",
    )
    prefer_live: Optional[bool] = None
    sync_blacklist: bool = True


@router.get("/info")
async def get_dataset_info(
    _: UserModel = Depends(require_permission(DATASET_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Return dataset provenance, licensing, schema metadata, and live deduplicated counts."""
    ds_repo = DatasetRepository(db)
    versions = await ds_repo.list_versions(limit=20)
    total_samples = await ds_repo.count_samples()
    active_iocs = await IocRepository(db).count_active()

    return {
        "total_samples": total_samples,
        "total_versions": len(versions),
        "active_synced_iocs": active_iocs,
        "latest_version": (
            {
                "id": versions[0].id,
                "source": versions[0].source,
                "sha256": versions[0].sha256,
                "created_at": versions[0].created_at.isoformat() if versions[0].created_at else "",
            }
            if versions
            else None
        ),
        "sources": [
            {
                "name": "OpenPhish",
                "feed_url": OPENPHISH_FEED_URL,
                "license": OPENPHISH_LICENSE,
                "schema": "backend/dataset/schemas/openphish.schema.json",
                "offline_fixture": "backend/dataset/samples/openphish_sample.txt",
            },
            {
                "name": "PhishTank",
                "feed_url": PHISHTANK_FEED_URL,
                "license": PHISHTANK_LICENSE,
                "schema": "backend/dataset/schemas/phishtank.schema.json",
                "offline_fixture": "backend/dataset/samples/phishtank_sample.csv",
            },
        ],
        "deduplication_policy": "Normalized URL SHA-256 (`ON CONFLICT (url_hash) DO NOTHING`) with raw payload SHA-256 lineage.",
    }


@router.get("/versions", response_model=List[DatasetVersionOut])
async def list_dataset_versions(
    limit: int = Query(default=25, ge=1, le=200),
    _: UserModel = Depends(require_permission(DATASET_READ)),
    db: AsyncSession = Depends(get_db),
) -> List[DatasetVersionOut]:
    """List immutable dataset ingestion runs with SHA-256 integrity hashes."""
    rows = await DatasetRepository(db).list_versions(limit=limit)
    return [
        DatasetVersionOut(
            id=v.id,
            source=v.source,
            source_url=v.source_url,
            license=v.license,
            sha256=v.sha256,
            total_records=v.total_records,
            new_records=v.new_records,
            duplicate_records=v.duplicate_records,
            invalid_records=v.invalid_records,
            status=v.status,
            triggered_by=v.triggered_by,
            created_at=v.created_at.isoformat() if v.created_at else "",
        )
        for v in rows
    ]


@router.get("/samples")
async def list_dataset_samples(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    source: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None),
    _: UserModel = Depends(require_permission(DATASET_READ)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Paginated list of deduplicated phishing URL samples."""
    rows, total = await DatasetRepository(db).list_samples(
        page=page,
        page_size=page_size,
        source=source,
        q=q,
    )
    return {
        "items": [
            {
                "id": s.id,
                "dataset_version_id": s.dataset_version_id,
                "url": s.url,
                "url_hash": s.url_hash,
                "domain": s.domain,
                "source": s.source,
                "first_seen_at": s.first_seen_at.isoformat() if s.first_seen_at else "",
            }
            for s in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/ingest")
async def ingest_dataset(
    payload: DatasetIngestRequest,
    request: Request,
    actor: ActorPrincipal = Depends(allow_service_or_permission(DATASET_ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Trigger idempotent ETL ingestion from OpenPhish or PhishTank (live HTTPS or offline sample)."""
    src_lc = (payload.source or "openphish_sample").strip().lower()
    prefer_live = payload.prefer_live if payload.prefer_live is not None else src_lc.endswith("_live")

    version = await ingest_dataset_command(
        db=db,
        source=src_lc,
        prefer_live=bool(prefer_live),
        sync_blacklist=payload.sync_blacklist,
        actor_email=actor.email,
        client_ip=get_client_ip(request),
    )
    await db.commit()
    created_iso = version.created_at.isoformat() if version.created_at else ""
    return {
        "id": version.id,
        "version_id": version.id,
        "source": version.source,
        "source_url": version.source_url,
        "license": version.license,
        "sha256": version.sha256,
        "status": version.status,
        "total_rows": version.total_records,
        "new_rows": version.new_records,
        "duplicate_rows": version.duplicate_records,
        "invalid_rows": version.invalid_records,
        "total_records": version.total_records,
        "new_records": version.new_records,
        "duplicate_records": version.duplicate_records,
        "invalid_records": version.invalid_records,
        "triggered_by": version.triggered_by,
        "created_at": created_iso,
    }

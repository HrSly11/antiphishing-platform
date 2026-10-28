"""IngestDataset command handler: OpenPhish & PhishTank ETL with SHA-256 dataset versioning."""
from __future__ import annotations

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.feeds.openphish import (
    OPENPHISH_LICENSE,
    load_openphish_feed,
    parse_openphish_bytes,
)
from app.adapters.feeds.phishtank import (
    PHISHTANK_LICENSE,
    load_phishtank_feed,
    parse_phishtank_bytes,
)
from app.adapters.persistence.models.dataset_version import DatasetVersionModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.dataset_repository import DatasetRepository


async def ingest_dataset_command(
    db: AsyncSession,
    source: str = "openphish",
    raw_bytes: Optional[bytes] = None,
    prefer_live: bool = False,
    sync_blacklist: bool = True,
    actor_email: str = "system",
    client_ip: str = "",
) -> DatasetVersionModel:
    """Ingest OpenPhish, PhishTank, or uploaded raw feed bytes into versioned PostgreSQL tables."""
    src_norm = (source or "openphish").strip().lower()

    if raw_bytes is not None:
        if "phishtank" in src_norm or raw_bytes.lstrip().startswith(b"phish_id,"):
            items = parse_phishtank_bytes(raw_bytes)
            canonical_source = "PhishTank"
            license_name = PHISHTANK_LICENSE
            source_url = "upload://phishtank.csv"
        else:
            items = parse_openphish_bytes(raw_bytes)
            canonical_source = "OpenPhish"
            license_name = OPENPHISH_LICENSE
            source_url = "upload://openphish.txt"
    elif "phishtank" in src_norm:
        raw_bytes, items, source_url = await load_phishtank_feed(prefer_live=prefer_live)
        canonical_source = "PhishTank"
        license_name = PHISHTANK_LICENSE
    else:
        raw_bytes, items, source_url = await load_openphish_feed(prefer_live=prefer_live)
        canonical_source = "OpenPhish"
        license_name = OPENPHISH_LICENSE

    ds_repo = DatasetRepository(db)
    version, new_rows, dup_rows = await ds_repo.ingest_samples(
        source=canonical_source,
        raw_bytes=raw_bytes,
        items=items,
        sync_blacklist=sync_blacklist,
        created_by_id=actor_email,
        source_url=source_url,
        license_name=license_name,
    )

    audit_repo = AuditRepository(db)
    await audit_repo.append(
        user_email=actor_email,
        action="DATASET_INGESTED",
        resource=f"dataset_version:{version.id}",
        payload={
            "source": canonical_source,
            "sha256": version.sha256,
            "total_records": version.total_records,
            "new_records": new_rows,
            "duplicate_records": dup_rows,
            "sync_blacklist": sync_blacklist,
        },
        client_ip=client_ip,
    )
    return version

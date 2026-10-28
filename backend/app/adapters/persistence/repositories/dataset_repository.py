"""PostgreSQL repository for public phishing dataset versions, deduplicated samples, and fuzzy lookups."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import desc, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.dataset_version import DatasetVersionModel
from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.phishing_sample import PhishingSampleModel
from app.adapters.persistence.models.user import UserModel
from app.core.config import settings
from app.domain.dataset.versioning import domain_of, normalize_url, sha256_bytes, url_hash

_SHARED_HOSTING_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
    "docs.google.com",
    "drive.google.com",
    "forms.gle",
    "sites.google.com",
    "github.io",
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "workers.dev",
}


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class DatasetRepository:
    """Async persistence adapter for `dataset_versions` and `phishing_samples`."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def ingest_samples(
        self,
        source: str,
        raw_bytes: bytes,
        items: List[Dict[str, Any]],
        sync_blacklist: bool = True,
        created_by_id: Optional[Union[uuid.UUID, str]] = None,
        source_url: str = "",
        license_name: str = "",
        raw_path: Optional[str] = None,
    ) -> Tuple[DatasetVersionModel, int, int]:
        """Hash raw feed bytes, normalize/deduplicate URLs, persist DatasetVersion + PhishingSample rows."""
        now = datetime.now(timezone.utc)
        digest = sha256_bytes(raw_bytes)

        triggered_by = "system"
        if created_by_id is not None:
            raw_actor = str(created_by_id).strip()
            if "@" in raw_actor:
                triggered_by = raw_actor[:255]
            elif raw_actor:
                u = await self.db.scalar(select(UserModel).where(UserModel.id == raw_actor))
                triggered_by = u.email if u else raw_actor[:255]

        default_urls = {
            "openphish": "https://openphish.com/feed.txt",
            "phishtank": "https://data.phishtank.com/data/online-valid.csv",
        }
        default_licenses = {
            "openphish": "OpenPhish Community Terms of Use (Defensive/Academic)",
            "phishtank": "PhishTank Developer License (Attribution Required)",
        }
        src_key = source.lower()
        resolved_source_url = (
            source_url
            or next((v for k, v in default_urls.items() if k in src_key), "local://dataset-fixture")
        )[:500]
        resolved_license = (
            license_name
            or next(
                (v for k, v in default_licenses.items() if k in src_key),
                "Defensive Threat Intelligence Feed",
            )
        )[:200]

        version = DatasetVersionModel(
            id=str(uuid.uuid4()),
            source=source[:100],
            source_url=resolved_source_url,
            license=resolved_license,
            sha256=digest,
            raw_path=raw_path[:500] if raw_path else None,
            total_records=len(items),
            new_records=0,
            duplicate_records=0,
            invalid_records=0,
            status="COMPLETED",
            triggered_by=triggered_by,
            created_at=now,
        )
        self.db.add(version)
        await self.db.flush()

        seen_in_batch: set[str] = set()
        prepared_rows: List[Dict[str, Any]] = []
        invalid_count = 0
        in_batch_duplicates = 0

        for item in items:
            raw_url = str(item.get("url") or "").strip() if isinstance(item, dict) else str(item).strip()
            norm = normalize_url(raw_url)
            if not norm:
                invalid_count += 1
                continue
            uhash = url_hash(norm)
            if uhash in seen_in_batch:
                in_batch_duplicates += 1
                continue
            seen_in_batch.add(uhash)
            dom = domain_of(norm)[:255]
            if not dom:
                invalid_count += 1
                continue
            prepared_rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "dataset_version_id": version.id,
                    "url": norm,
                    "url_hash": uhash,
                    "domain": dom,
                    "source": source[:100],
                    "first_seen_at": now,
                }
            )

        inserted_count = 0
        chunk_size = 500
        for idx in range(0, len(prepared_rows), chunk_size):
            chunk = prepared_rows[idx : idx + chunk_size]
            stmt = (
                pg_insert(PhishingSampleModel)
                .values(chunk)
                .on_conflict_do_nothing(index_elements=["url_hash"])
                .returning(PhishingSampleModel.id)
            )
            inserted_ids = (await self.db.scalars(stmt)).all()
            inserted_count += len(inserted_ids)

        db_duplicates = len(prepared_rows) - inserted_count
        duplicate_count = in_batch_duplicates + db_duplicates

        version.new_records = inserted_count
        version.duplicate_records = duplicate_count
        version.invalid_records = invalid_count

        if sync_blacklist and prepared_rows:
            protected = {d.lower() for d in settings.OFFICIAL_DOMAINS}
            ioc_entries: Dict[str, Dict[str, Any]] = {}
            for row in prepared_rows:
                url_val = row["url"][:500]
                dom_val = row["domain"]
                ioc_entries[f"URL:{url_val}"] = {
                    "id": str(uuid.uuid4()),
                    "ioc_type": "URL",
                    "ioc_value": url_val,
                    "list_type": "BLACKLIST",
                    "confidence_score": 95,
                    "source": source[:100],
                    "is_active": True,
                    "expires_at": None,
                    "created_by": triggered_by,
                    "created_at": now,
                }
                if (
                    dom_val
                    and dom_val not in protected
                    and dom_val not in _SHARED_HOSTING_DOMAINS
                    and not any(dom_val.endswith("." + sh) for sh in _SHARED_HOSTING_DOMAINS)
                ):
                    ioc_entries[f"DOMAIN:{dom_val}"] = {
                        "id": str(uuid.uuid4()),
                        "ioc_type": "DOMAIN",
                        "ioc_value": dom_val,
                        "list_type": "BLACKLIST",
                        "confidence_score": 90,
                        "source": source[:100],
                        "is_active": True,
                        "expires_at": None,
                        "created_by": triggered_by,
                        "created_at": now,
                    }

            ioc_list = list(ioc_entries.values())
            for idx in range(0, len(ioc_list), chunk_size):
                chunk = ioc_list[idx : idx + chunk_size]
                ioc_stmt = (
                    pg_insert(IocModel)
                    .values(chunk)
                    .on_conflict_do_nothing(constraint="uq_ioc_value_list")
                )
                await self.db.execute(ioc_stmt)

        await self.db.flush()
        return version, inserted_count, duplicate_count

    async def lookup_url_or_domain(
        self,
        url_hash_val: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Optional[PhishingSampleModel]:
        if url_hash_val:
            exact = await self.db.scalar(
                select(PhishingSampleModel).where(PhishingSampleModel.url_hash == url_hash_val)
            )
            if exact is not None:
                return exact
        if domain:
            dom = domain.strip().lower()
            if dom and dom not in _SHARED_HOSTING_DOMAINS:
                return await self.db.scalar(
                    select(PhishingSampleModel)
                    .where(PhishingSampleModel.domain == dom)
                    .order_by(desc(PhishingSampleModel.first_seen_at))
                    .limit(1)
                )
        return None

    async def list_versions(self, limit: int = 20) -> List[DatasetVersionModel]:
        limit = max(1, min(int(limit), 200))
        rows = (
            await self.db.scalars(
                select(DatasetVersionModel)
                .order_by(desc(DatasetVersionModel.created_at))
                .limit(limit)
            )
        ).all()
        return list(rows)

    async def list_samples(
        self,
        page: int = 1,
        page_size: int = 25,
        source: Optional[str] = None,
        q: Optional[str] = None,
    ) -> Tuple[List[PhishingSampleModel], int]:
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 500))
        offset = (page - 1) * page_size

        conditions = []
        if source:
            conditions.append(PhishingSampleModel.source.ilike(f"%{_like_escape(source.strip())}%", escape="\\"))
        if q and q.strip():
            escaped = f"%{_like_escape(q.strip())}%"
            conditions.append(
                or_(
                    PhishingSampleModel.url.ilike(escaped, escape="\\"),
                    PhishingSampleModel.domain.ilike(escaped, escape="\\"),
                )
            )

        rows = list(
            (
                await self.db.scalars(
                    select(PhishingSampleModel)
                    .where(*conditions)
                    .order_by(desc(PhishingSampleModel.first_seen_at))
                    .limit(page_size)
                    .offset(offset)
                )
            ).all()
        )
        total = int(
            await self.db.scalar(select(func.count(PhishingSampleModel.id)).where(*conditions)) or 0
        )
        return rows, total

    async def search_fuzzy(self, query: str, limit: int = 25) -> List[Dict[str, Any]]:
        """Trigram similarity search on phishing sample domains and URL substrings."""
        q_clean = (query or "").strip().lower()
        if not q_clean:
            return []

        limit = max(1, min(int(limit), 200))
        sim = func.similarity(PhishingSampleModel.domain, q_clean)
        escaped = f"%{_like_escape(q_clean)}%"

        stmt = (
            select(PhishingSampleModel, sim.label("sim"))
            .where(
                or_(
                    PhishingSampleModel.url.ilike(escaped, escape="\\"),
                    PhishingSampleModel.domain.ilike(escaped, escape="\\"),
                    sim > 0.25,
                )
            )
            .order_by(desc(sim), desc(PhishingSampleModel.first_seen_at))
            .limit(limit)
        )
        results = (await self.db.execute(stmt)).all()
        return [
            {
                "id": sample.id,
                "dataset_version_id": sample.dataset_version_id,
                "url": sample.url,
                "url_hash": sample.url_hash,
                "domain": sample.domain,
                "source": sample.source,
                "first_seen_at": sample.first_seen_at.isoformat() if sample.first_seen_at else "",
                "similarity": round(float(score or 0.0), 4),
            }
            for sample, score in results
        ]

    async def count_samples(self) -> int:
        return int(await self.db.scalar(select(func.count(PhishingSampleModel.id))) or 0)

"""PostgreSQL repository for detection verdicts, fuzzy search, and SOC telemetry KPIs."""
from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import desc, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _as_utc_start(value: Union[datetime, date]) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.combine(value, time.min, tzinfo=timezone.utc)


def _as_utc_end(value: Union[datetime, date]) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.combine(value + timedelta(days=1), time.min, tzinfo=timezone.utc)


class VerdictRepository:
    """Async persistence adapter for `detection_verdicts`."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save(
        self,
        verdict_obj: Optional[DetectionVerdictModel] = None,
        **kwargs: Any,
    ) -> DetectionVerdictModel:
        """Persist a DetectionVerdictModel instance or construct one from keyword arguments."""
        if verdict_obj is None:
            correlation_id = str(kwargs.get("correlation_id") or uuid.uuid4())
            subject = str(kwargs.get("subject") or "")[:500]
            summary = str(kwargs.get("summary") or "")[:1000]
            verdict_obj = DetectionVerdictModel(
                id=str(kwargs.get("id") or uuid.uuid4()),
                correlation_id=correlation_id[:64],
                sender_email=str(kwargs.get("sender_email") or "")[:255],
                recipient_email=str(kwargs.get("recipient_email") or "")[:255],
                subject=subject,
                channel=str(kwargs.get("channel") or "EMAIL").upper()[:20],
                risk_score=int(kwargs.get("risk_score") or 0),
                verdict=str(kwargs.get("verdict") or "CLEAN").upper()[:20],
                action_taken=str(kwargs.get("action_taken") or "DELIVER").upper()[:20],
                summary=summary,
                latency_ms=int(kwargs.get("latency_ms") or 0),
                analyst_label=str(kwargs.get("analyst_label") or "UNREVIEWED").upper()[:30],
                headers_meta=dict(kwargs.get("headers_meta") or {}),
                signals_meta=list(kwargs.get("signals_meta") or []),
                created_at=kwargs.get("created_at") or datetime.now(timezone.utc),
            )
        else:
            verdict_obj.subject = (verdict_obj.subject or "")[:500]
            verdict_obj.summary = (verdict_obj.summary or "")[:1000]

        self.db.add(verdict_obj)
        await self.db.flush()
        return verdict_obj

    async def get_by_id(self, verdict_id: Union[str, uuid.UUID]) -> Optional[DetectionVerdictModel]:
        vid = str(verdict_id).strip()
        row = await self.db.scalar(
            select(DetectionVerdictModel).where(DetectionVerdictModel.id == vid)
        )
        if row is None:
            row = await self.db.scalar(
                select(DetectionVerdictModel).where(DetectionVerdictModel.correlation_id == vid)
            )
        return row

    async def list_paginated(
        self,
        page: int = 1,
        page_size: int = 25,
        verdict: Optional[str] = None,
        channel: Optional[str] = None,
        analyst_label: Optional[str] = None,
        q: Optional[str] = None,
        date_from: Optional[Union[datetime, date]] = None,
        date_to: Optional[Union[datetime, date]] = None,
    ) -> Tuple[List[DetectionVerdictModel], int]:
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 500))
        offset = (page - 1) * page_size

        conditions = []
        if verdict:
            v_norm = verdict.strip().upper()
            if v_norm in {"MALICIOUS", "PHISHING"}:
                conditions.append(DetectionVerdictModel.verdict.in_(["MALICIOUS", "PHISHING"]))
            else:
                conditions.append(DetectionVerdictModel.verdict == v_norm)
        if channel:
            conditions.append(DetectionVerdictModel.channel == channel.strip().upper())
        if analyst_label:
            conditions.append(DetectionVerdictModel.analyst_label == analyst_label.strip().upper())
        if date_from is not None:
            conditions.append(DetectionVerdictModel.created_at >= _as_utc_start(date_from))
        if date_to is not None:
            if isinstance(date_to, date) and not isinstance(date_to, datetime):
                conditions.append(DetectionVerdictModel.created_at < _as_utc_end(date_to))
            else:
                conditions.append(DetectionVerdictModel.created_at <= _as_utc_end(date_to))
        if q and q.strip():
            escaped = f"%{_like_escape(q.strip())}%"
            conditions.append(
                or_(
                    DetectionVerdictModel.subject.ilike(escaped, escape="\\"),
                    DetectionVerdictModel.sender_email.ilike(escaped, escape="\\"),
                    DetectionVerdictModel.recipient_email.ilike(escaped, escape="\\"),
                    DetectionVerdictModel.correlation_id.ilike(escaped, escape="\\"),
                )
            )

        stmt = (
            select(DetectionVerdictModel)
            .where(*conditions)
            .order_by(desc(DetectionVerdictModel.created_at))
            .limit(page_size)
            .offset(offset)
        )
        count_stmt = select(func.count(DetectionVerdictModel.id)).where(*conditions)

        rows = list((await self.db.scalars(stmt)).all())
        total = int(await self.db.scalar(count_stmt) or 0)
        return rows, total

    async def set_analyst_label(
        self,
        verdict_id: Union[str, uuid.UUID],
        label: str,
        labeled_by_id: Optional[Union[uuid.UUID, str]] = None,
    ) -> Optional[DetectionVerdictModel]:
        normalized = label.strip().upper()
        if normalized not in {"TRUE_POSITIVE", "FALSE_POSITIVE", "UNREVIEWED"}:
            raise ValueError(f"Unsupported analyst_label: {label}")

        row = await self.get_by_id(verdict_id)
        if row is None:
            return None

        row.analyst_label = normalized
        meta = dict(row.headers_meta or {})
        meta["_labeled_by"] = str(labeled_by_id) if labeled_by_id else None
        meta["_labeled_at"] = datetime.now(timezone.utc).isoformat()
        row.headers_meta = meta
        await self.db.flush()
        return row

    async def search_fuzzy(self, query: str, limit: int = 25) -> List[Dict[str, Any]]:
        """Search verdicts across subject, sender_email, and sender_domain using ILIKE + pg_trgm."""
        q_clean = (query or "").strip().lower()
        if not q_clean:
            return []

        limit = max(1, min(int(limit), 200))
        like_pat = f"%{_like_escape(q_clean)}%"

        sql = text(
            """
            SELECT
                id,
                correlation_id,
                sender_email,
                split_part(lower(sender_email), '@', 2) AS sender_domain,
                recipient_email,
                subject,
                channel,
                risk_score,
                verdict,
                action_taken,
                analyst_label,
                created_at,
                GREATEST(
                    similarity(split_part(lower(sender_email), '@', 2), :q),
                    similarity(lower(sender_email), :q),
                    similarity(lower(subject), :q)
                ) AS sim
            FROM detection_verdicts
            WHERE
                subject ILIKE :like_pat ESCAPE '\\'
                OR sender_email ILIKE :like_pat ESCAPE '\\'
                OR split_part(lower(sender_email), '@', 2) ILIKE :like_pat ESCAPE '\\'
                OR similarity(split_part(lower(sender_email), '@', 2), :q) > 0.25
                OR similarity(lower(sender_email), :q) > 0.25
            ORDER BY sim DESC, created_at DESC
            LIMIT :lim
            """
        )
        result = await self.db.execute(sql, {"q": q_clean, "like_pat": like_pat, "lim": limit})
        items: List[Dict[str, Any]] = []
        for r in result.mappings().all():
            created = r["created_at"]
            items.append(
                {
                    "id": r["id"],
                    "correlation_id": r["correlation_id"],
                    "sender_email": r["sender_email"],
                    "sender_domain": r["sender_domain"] or "",
                    "recipient_email": r["recipient_email"],
                    "subject": r["subject"],
                    "channel": r["channel"],
                    "risk_score": int(r["risk_score"]),
                    "verdict": r["verdict"],
                    "action_taken": r["action_taken"],
                    "analyst_label": r["analyst_label"],
                    "similarity": round(float(r["sim"] or 0.0), 4),
                    "created_at": created.isoformat() if created else "",
                }
            )
        return items

    async def compute_kpis(self, window_days: int = 30) -> Dict[str, Any]:
        """Compute UTC analytical KPIs from PostgreSQL across `window_days`."""
        days = max(1, min(int(window_days), 365))
        now_utc = datetime.now(timezone.utc)
        today_utc = now_utc.date()
        start_day = today_utc - timedelta(days=days - 1)
        cutoff = datetime.combine(start_day, time.min, tzinfo=timezone.utc)

        # 1. Verdict & channel breakdown + latency percentiles + confusion rates in SQL
        agg_sql = text(
            """
            SELECT
                COUNT(*)::int AS total_analyzed,
                COUNT(*) FILTER (WHERE verdict = 'CLEAN')::int AS clean_count,
                COUNT(*) FILTER (WHERE verdict = 'SUSPICIOUS')::int AS suspicious_count,
                COUNT(*) FILTER (WHERE verdict IN ('MALICIOUS', 'PHISHING'))::int AS phishing_count,
                COUNT(*) FILTER (WHERE channel = 'EMAIL')::int AS ch_email,
                COUNT(*) FILTER (WHERE channel = 'SMS')::int AS ch_sms,
                COUNT(*) FILTER (WHERE channel = 'WEB')::int AS ch_web,
                COUNT(*) FILTER (WHERE channel = 'QR')::int AS ch_qr,
                AVG(latency_ms)::float AS latency_avg_ms,
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::float AS latency_p95_ms,
                COUNT(*) FILTER (WHERE analyst_label IN ('TRUE_POSITIVE', 'FALSE_POSITIVE'))::int AS labeled_count,
                COUNT(*) FILTER (
                    WHERE verdict IN ('MALICIOUS', 'PHISHING', 'SUSPICIOUS')
                      AND analyst_label = 'FALSE_POSITIVE'
                )::int AS fp_count,
                COUNT(*) FILTER (
                    WHERE verdict IN ('MALICIOUS', 'PHISHING', 'SUSPICIOUS')
                      AND analyst_label IN ('TRUE_POSITIVE', 'FALSE_POSITIVE')
                )::int AS flagged_labeled_count,
                COUNT(*) FILTER (
                    WHERE verdict = 'CLEAN' AND analyst_label = 'TRUE_POSITIVE'
                )::int AS fn_count
            FROM detection_verdicts
            WHERE created_at >= :cutoff
            """
        )
        agg_row = (await self.db.execute(agg_sql, {"cutoff": cutoff})).mappings().first() or {}

        total_analyzed = int(agg_row.get("total_analyzed") or 0)
        clean_cnt = int(agg_row.get("clean_count") or 0)
        susp_cnt = int(agg_row.get("suspicious_count") or 0)
        phish_cnt = int(agg_row.get("phishing_count") or 0)

        latency_avg = (
            round(float(agg_row["latency_avg_ms"]), 2)
            if agg_row.get("latency_avg_ms") is not None
            else 0.0
        )
        latency_p95 = (
            round(float(agg_row["latency_p95_ms"]), 2)
            if agg_row.get("latency_p95_ms") is not None
            else 0.0
        )

        labeled_count = int(agg_row.get("labeled_count") or 0)
        fp_count = int(agg_row.get("fp_count") or 0)
        flagged_labeled = int(agg_row.get("flagged_labeled_count") or 0)
        fn_count = int(agg_row.get("fn_count") or 0)

        fp_rate: Optional[float] = (
            round(fp_count / flagged_labeled, 4) if flagged_labeled > 0 else 0.0
        )
        fn_rate: Optional[float] = (
            round(fn_count / labeled_count, 4) if labeled_count > 0 else 0.0
        )

        # 2. Continuous zero-filled UTC daily series
        trend_sql = text(
            """
            SELECT
                (created_at AT TIME ZONE 'UTC')::date AS bucket_date,
                COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE verdict IN ('MALICIOUS', 'PHISHING'))::int AS phishing,
                COUNT(*) FILTER (WHERE verdict = 'SUSPICIOUS')::int AS suspicious,
                COUNT(*) FILTER (WHERE verdict = 'CLEAN')::int AS clean
            FROM detection_verdicts
            WHERE created_at >= :cutoff
            GROUP BY bucket_date
            ORDER BY bucket_date ASC
            """
        )
        trend_rows = (await self.db.execute(trend_sql, {"cutoff": cutoff})).mappings().all()
        by_day = {r["bucket_date"]: r for r in trend_rows}

        daily_trend: List[Dict[str, Any]] = []
        for idx in range(days):
            d = start_day + timedelta(days=idx)
            r = by_day.get(d)
            p_val = int(r["phishing"]) if r else 0
            s_val = int(r["suspicious"]) if r else 0
            c_val = int(r["clean"]) if r else 0
            t_val = int(r["total"]) if r else 0
            daily_trend.append(
                {
                    "date": d.isoformat(),
                    "total": t_val,
                    "phishing": p_val,
                    "malicious": p_val,
                    "suspicious": s_val,
                    "clean": c_val,
                }
            )

        # 3. Top malicious/suspicious domains & IPs from sender_email, headers_meta, and signals_meta
        threat_rows = (
            await self.db.execute(
                select(
                    DetectionVerdictModel.sender_email,
                    DetectionVerdictModel.headers_meta,
                    DetectionVerdictModel.signals_meta,
                )
                .where(
                    DetectionVerdictModel.created_at >= cutoff,
                    DetectionVerdictModel.verdict.in_(["MALICIOUS", "PHISHING", "SUSPICIOUS"]),
                )
                .order_by(desc(DetectionVerdictModel.created_at))
                .limit(2000)
            )
        ).all()

        domain_counter: Counter[str] = Counter()
        ip_counter: Counter[str] = Counter()

        for sender_email, headers_meta, signals_meta in threat_rows:
            if sender_email and "@" in sender_email:
                s_dom = sender_email.rsplit("@", 1)[-1].strip().lower()
                if s_dom:
                    domain_counter[s_dom] += 1

            h_meta = headers_meta if isinstance(headers_meta, dict) else {}
            for ip_key in ("x-originating-ip", "x-sender-ip", "originating_ip", "client_ip"):
                raw_ip = str(h_meta.get(ip_key) or "").strip(" []")
                for match in _IPV4_RE.findall(raw_ip):
                    ip_counter[match] += 1
            received_val = str(h_meta.get("received") or "")
            for match in _IPV4_RE.findall(received_val):
                if not match.startswith(("127.", "10.", "192.168.")):
                    ip_counter[match] += 1

            urls_meta = h_meta.get("_extracted_urls") or h_meta.get("urls") or []
            if isinstance(urls_meta, list):
                for u in urls_meta:
                    u_str = str(u)
                    for match in _IPV4_RE.findall(u_str):
                        ip_counter[match] += 1

            s_list = signals_meta if isinstance(signals_meta, list) else []
            for sig in s_list:
                if not isinstance(sig, dict):
                    continue
                meta = sig.get("metadata") if isinstance(sig.get("metadata"), dict) else {}
                dom_val = str(meta.get("domain") or "").strip().lower()
                if dom_val:
                    if _IPV4_RE.fullmatch(dom_val):
                        ip_counter[dom_val] += 1
                    else:
                        domain_counter[dom_val] += 1
                url_val = str(meta.get("url") or "")
                for match in _IPV4_RE.findall(url_val):
                    ip_counter[match] += 1

        top_domains = [{"domain": dom, "count": cnt} for dom, cnt in domain_counter.most_common(10)]
        top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(10)]

        return {
            "window_days": days,
            "total_analyzed": total_analyzed,
            "total_detections": total_analyzed,
            "by_verdict": {
                "CLEAN": clean_cnt,
                "SUSPICIOUS": susp_cnt,
                "PHISHING": phish_cnt,
                "MALICIOUS": phish_cnt,
            },
            "by_channel": {
                "EMAIL": int(agg_row.get("ch_email") or 0),
                "SMS": int(agg_row.get("ch_sms") or 0),
                "WEB": int(agg_row.get("ch_web") or 0),
                "QR": int(agg_row.get("ch_qr") or 0),
            },
            "latency_avg_ms": latency_avg,
            "latency_p95_ms": latency_p95,
            "labeled_count": labeled_count,
            "false_positive_rate": fp_rate,
            "false_negative_rate": fn_rate,
            "daily_trend": daily_trend,
            "trend": daily_trend,
            "top_domains": top_domains,
            "top_sender_domains": top_domains,
            "top_ips": top_ips,
            "top_attacker_ips": top_ips,
        }

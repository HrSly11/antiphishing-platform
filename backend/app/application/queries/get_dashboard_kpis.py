"""Dashboard KPIs query handler combining verdict telemetry, SLA metrics, IOCs, and dataset counts."""
from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository
from app.core.metrics import INCIDENTS_OPEN


async def get_dashboard_kpis_query(
    db: AsyncSession,
    window_days: int = 30,
) -> Dict[str, Any]:
    """Return consolidated analytical KPIs matching `DashboardKpis` and SOC dashboard contracts."""
    v_repo = VerdictRepository(db)
    i_repo = IncidentRepository(db)
    ioc_repo = IocRepository(db)
    ds_repo = DatasetRepository(db)

    v_kpis = await v_repo.compute_kpis(window_days=window_days)
    sla = await i_repo.compute_sla_metrics(window_days=window_days)
    active_iocs = await ioc_repo.count_active()
    dataset_samples = await ds_repo.count_samples()

    INCIDENTS_OPEN.set(sla["open_count"])

    fp_rate = float(v_kpis.get("false_positive_rate") or 0.0)
    fn_rate = float(v_kpis.get("false_negative_rate") or 0.0)
    accuracy_rate = round(max(0.0, (1.0 - (fp_rate + fn_rate) / 2.0) * 100.0), 2)
    by_verdict = v_kpis.get("by_verdict") or {}

    return {
        **v_kpis,
        "malicious_count": int(by_verdict.get("MALICIOUS") or 0),
        "suspicious_count": int(by_verdict.get("SUSPICIOUS") or 0),
        "clean_count": int(by_verdict.get("CLEAN") or 0),
        "avg_latency_ms": v_kpis.get("latency_avg_ms") or 0.0,
        "accuracy_rate": accuracy_rate,
        "incidents_summary": {
            "open_count": sla["open_count"],
            "overdue_count": sla["overdue_count"],
            "mttr_minutes": sla["mttr_minutes"],
            "mttt_minutes": sla["mttt_minutes"],
            "sla_compliance_rate": sla["sla_compliance_rate"],
        },
        "open_incidents": sla["open_count"],
        "overdue_incidents": sla["overdue_count"],
        "sla_compliance_rate": sla["sla_compliance_rate"],
        "mean_time_to_resolve_minutes": sla["mttr_minutes"],
        "mttr_minutes": sla["mttr_minutes"],
        "mean_time_to_triage_minutes": sla["mttt_minutes"],
        "active_iocs": active_iocs,
        "active_iocs_count": active_iocs,
        "total_active_iocs": active_iocs,
        "dataset_samples": dataset_samples,
        "dataset_samples_count": dataset_samples,
    }

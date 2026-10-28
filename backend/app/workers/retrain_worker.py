"""Analyst feedback & threshold calibration worker computing precision/recall over labeled verdicts."""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict

from app.adapters.persistence.database import async_session_factory, engine
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository
from app.core.logging import get_logger

log = get_logger("worker.calibration")


async def run_calibration_audit(window_days: int = 30) -> Dict[str, Any]:
    """Evaluate analyst feedback (`TRUE_POSITIVE` / `FALSE_POSITIVE`) to recommend scoring threshold tuning."""
    async with async_session_factory() as db:
        kpis = await VerdictRepository(db).compute_kpis(window_days=window_days)
        fp_rate = float(kpis.get("false_positive_rate") or 0.0)
        fn_rate = float(kpis.get("false_negative_rate") or 0.0)
        labeled = int(kpis.get("labeled_count") or 0)

        recommendation = "KEEP_CURRENT_THRESHOLDS (SUSPICIOUS>=35, MALICIOUS>=70)"
        if fp_rate > 0.08:
            recommendation = "CONSIDER_RAISING_SUSPICIOUS_THRESHOLD_TO_40"
        elif fn_rate > 0.05:
            recommendation = "CONSIDER_LOWERING_MALICIOUS_THRESHOLD_TO_65"

        report = {
            "window_days": window_days,
            "labeled_verdicts": labeled,
            "false_positive_rate": fp_rate,
            "false_negative_rate": fn_rate,
            "recommendation": recommendation,
        }
        await AuditRepository(db).append(
            user_email="calibration-worker@bancocentral.com",
            action="MODEL_CALIBRATION_EVALUATED",
            resource="detection:thresholds",
            payload=report,
            client_ip="127.0.0.1",
        )
        await db.commit()
        log.info("Calibration audit finished: %s", report)
        return report


async def _cli() -> None:
    try:
        res = await run_calibration_audit()
        print(json.dumps(res, indent=2))
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_cli())

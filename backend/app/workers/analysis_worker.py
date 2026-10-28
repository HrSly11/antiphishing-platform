"""Asynchronous batch analysis worker for `.eml` files or JSONL message queues."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List

from app.adapters.persistence.database import async_session_factory, engine
from app.application.commands.analyze_input import analyze_email_command, parse_eml_bytes
from app.application.dto.detection_dto import EmailAnalysisRequest
from app.core.logging import get_logger

log = get_logger("worker.analysis")


async def process_batch_file(path: Path) -> List[Dict[str, Any]]:
    """Inspect a `.eml` message or `.jsonl` batch file against PostgreSQL `antiphishing_db`."""
    results: List[Dict[str, Any]] = []
    async with async_session_factory() as db:
        if path.suffix.lower() == ".eml":
            parsed = parse_eml_bytes(path.read_bytes())
            res = await analyze_email_command(
                request=parsed,
                db=db,
                actor_email="analysis-worker@bancocentral.com",
                enable_enrichment=False,
                audit_action="WORKER_BATCH_ANALYZE",
            )
            results.append(res.model_dump())
        else:
            for line in path.read_text(encoding="utf-8").splitlines():
                raw = line.strip()
                if not raw:
                    continue
                payload = EmailAnalysisRequest(**json.loads(raw))
                res = await analyze_email_command(
                    request=payload,
                    db=db,
                    actor_email="analysis-worker@bancocentral.com",
                    enable_enrichment=False,
                    audit_action="WORKER_BATCH_ANALYZE",
                )
                results.append(res.model_dump())
        await db.commit()
    log.info("Processed %d batch items from %s", len(results), path)
    return results


async def _cli() -> None:
    parser = argparse.ArgumentParser(description="Process batch .eml or .jsonl messages.")
    parser.add_argument("input_path", type=Path, help="Path to .eml or .jsonl batch file.")
    args = parser.parse_args()
    try:
        summaries = await process_batch_file(args.input_path)
        print(json.dumps(summaries, indent=2, ensure_ascii=False))
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_cli())

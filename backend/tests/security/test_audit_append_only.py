"""PostgreSQL trigger immutability & SHA-256 hash-chain verification tests for `audit_logs`."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession


async def test_postgresql_triggers_reject_update_delete_and_truncate_on_audit_logs(
    db_session: AsyncSession,
) -> None:
    target_id = await db_session.scalar(text("SELECT id FROM audit_logs ORDER BY id ASC LIMIT 1"))
    assert target_id is not None

    # 1. Raw SQL UPDATE must be rejected by trg_audit_logs_no_update_delete
    with pytest.raises(DBAPIError, match="audit_logs is append-only"):
        await db_session.execute(
            text("UPDATE audit_logs SET action = 'TAMPERED_ACTION' WHERE id = :id"),
            {"id": target_id},
        )
    await db_session.rollback()

    # 2. Raw SQL DELETE must be rejected by trg_audit_logs_no_update_delete
    with pytest.raises(DBAPIError, match="audit_logs is append-only"):
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :id"),
            {"id": target_id},
        )
    await db_session.rollback()

    # 3. Raw SQL TRUNCATE must be rejected by trg_audit_logs_no_truncate
    with pytest.raises(DBAPIError, match="audit_logs is append-only"):
        await db_session.execute(text("TRUNCATE TABLE audit_logs"))
    await db_session.rollback()


async def test_audit_hash_chain_verification_and_compliance_posture(
    client: httpx.AsyncClient,
    auditor_headers: dict[str, str],
) -> None:
    chain_resp = await client.get("/api/v1/audit/verify-chain", headers=auditor_headers)
    assert chain_resp.status_code == 200
    chain_data = chain_resp.json()
    assert chain_data["valid"] is True
    assert chain_data["broken_at_id"] is None
    assert chain_data["checked"] >= 1
    assert chain_data["algorithm"] == "SHA-256"
    assert "trg_audit_logs_no_update_delete" in chain_data["append_only_triggers"]

    comp_resp = await client.get("/api/v1/audit/compliance", headers=auditor_headers)
    assert comp_resp.status_code == 200
    comp_data = comp_resp.json()
    assert comp_data["overall_status"] == "COMPLIANT"
    assert comp_data["live_evidence"]["audit_chain_valid"] is True
    assert comp_data["live_evidence"]["rbac_users_count"] >= 5

    frameworks = {fw["framework"]: fw["controls"] for fw in comp_data["frameworks"]}
    assert "PCI-DSS v4.0" in frameworks
    assert "ISO/IEC 27001:2022 Annex A" in frameworks
    assert "GDPR & Banking Data Confidentiality" in frameworks
    for controls in frameworks.values():
        assert all(ctrl["status"] == "COMPLIANT" for ctrl in controls)

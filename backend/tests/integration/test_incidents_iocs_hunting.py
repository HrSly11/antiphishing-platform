"""Integration tests for Incident lifecycle, SLA escalation, IOCs, pg_trgm, and Threat Hunting."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


async def test_full_incident_lifecycle_timeline_summary_and_invalid_transitions(
    client: httpx.AsyncClient,
    socl2_headers: dict[str, str],
) -> None:
    # 1. Create manual CRITICAL incident -> OPEN
    create_resp = await client.post(
        "/api/v1/incidents",
        headers=socl2_headers,
        json={
            "severity": "CRITICAL",
            "subject": "Spear-phishing SWIFT token lure against Treasury",
            "sender_email": "swift-update@banc0central.com",
            "recipient_email": "tesoreria@bancocentral.com",
            "summary": "Targeted credential harvester impersonating SWIFT portal.",
            "channel": "EMAIL",
            "risk_score": 94,
        },
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]
    assert create_resp.json()["status"] == "OPEN"

    # 2. Invalid state transitions rejected with 409 Conflict:
    #    - OPEN -> CONTAINED (skipping triage & investigation)
    #    - OPEN -> CLOSED without mandatory resolution
    skip_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers=socl2_headers,
        json={"new_status": "CONTAINED"},
    )
    assert skip_resp.status_code == 409

    missing_res_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers=socl2_headers,
        json={"new_status": "CLOSED"},
    )
    assert missing_res_resp.status_code == 409

    # 3. Assign analyst & append forensic note
    assign_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=socl2_headers,
        json={"assignee_id": "socl2@bancocentral.com"},
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["assigned_to"] == "socl2@bancocentral.com"

    note_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=socl2_headers,
        json={"note": "Verified DNS sinkhole and purged 3 recipient mailboxes."},
    )
    assert note_resp.status_code == 201
    assert note_resp.json()["event_type"] == "NOTE_ADDED"

    # 4. Walk full valid lifecycle: OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED
    for step_status in ("TRIAGED", "INVESTIGATING", "CONTAINED"):
        tr_resp = await client.post(
            f"/api/v1/incidents/{inc_id}/transition",
            headers=socl2_headers,
            json={"new_status": step_status, "note": f"Moved to {step_status}"},
        )
        assert tr_resp.status_code == 200
        assert tr_resp.json()["status"] == step_status

    close_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers=socl2_headers,
        json={
            "new_status": "CLOSED",
            "resolution": "TRUE_POSITIVE",
            "notes": "Confirmed containment; zero credentials exfiltrated.",
        },
    )
    assert close_resp.status_code == 200
    closed_data = close_resp.json()
    assert closed_data["status"] == "CLOSED"
    assert closed_data["resolution"] == "TRUE_POSITIVE"
    assert closed_data["resolved_at"] is not None

    # Terminal state cannot reopen (CLOSED -> OPEN rejected with 409)
    reopen_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers=socl2_headers,
        json={"new_status": "OPEN"},
    )
    assert reopen_resp.status_code == 409

    # Verify complete timeline events
    event_types = [e["event_type"] for e in closed_data["events"]]
    assert "CREATED" in event_types
    assert "ASSIGNED" in event_types
    assert "NOTE_ADDED" in event_types
    assert event_types.count("STATUS_CHANGED") == 4

    # 5. LangChain CISO executive summary briefing
    sum_resp = await client.post(
        f"/api/v1/incidents/{inc_id}/summarize",
        headers=socl2_headers,
    )
    assert sum_resp.status_code == 200
    briefing = sum_resp.json()
    assert briefing["incident_id"] == inc_id
    assert "Executive CISO Briefing" in briefing["summary"]
    assert len(briefing["recommended_actions"]) >= 3
    assert len(briefing["compliance_controls"]) >= 3


async def test_overdue_sla_escalation_sweep(
    client: httpx.AsyncClient,
    socl1_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    create_resp = await client.post(
        "/api/v1/incidents",
        headers=socl1_headers,
        json={
            "severity": "CRITICAL",
            "subject": "Overdue SLA Escalation Drill Incident",
            "sender_email": "urgent@bancocentral-seguridad.com",
            "summary": "Unacknowledged critical phishing alert.",
            "risk_score": 96,
        },
    )
    assert create_resp.status_code == 201
    overdue_id = create_resp.json()["id"]

    # Backdate SLA deadline into the past so the escalation sweep catches it
    past_deadline = datetime.now(timezone.utc) - timedelta(minutes=25)
    await db_session.execute(
        text("UPDATE incidents SET sla_deadline = :dl, is_escalated = false WHERE id = :id"),
        {"dl": past_deadline, "id": overdue_id},
    )
    await db_session.commit()

    esc_resp = await client.post(
        "/api/v1/incidents/escalate-overdue",
        headers={"X-Service-Key": settings.N8N_SERVICE_KEY},
    )
    assert esc_resp.status_code == 200
    esc_body = esc_resp.json()
    assert esc_body["escalated_count"] >= 1
    assert overdue_id in esc_body["incident_ids"]

    detail_resp = await client.get(f"/api/v1/incidents/{overdue_id}", headers=socl1_headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["is_escalated"] is True
    assert detail_resp.json()["sla_overdue"] is True


async def test_ioc_upsert_ttl_pg_trgm_fuzzy_search_and_threat_hunting(
    client: httpx.AsyncClient,
    socl2_headers: dict[str, str],
) -> None:
    # 1. Upsert BLACKLIST IOC with TTL days
    bl_create = await client.post(
        "/api/v1/iocs",
        headers=socl2_headers,
        json={
            "ioc_type": "DOMAIN",
            "ioc_value": "bancocentral-token-vip.net",
            "list_type": "BLACKLIST",
            "confidence_score": 97,
            "ttl_days": 30,
            "source": "SOC_THREAT_INTEL",
        },
    )
    assert bl_create.status_code == 201
    bl_ioc = bl_create.json()
    assert bl_ioc["created"] is True
    assert bl_ioc["expires_at"] is not None

    # Idempotent upsert updates existing entry rather than duplicating
    bl_upsert = await client.post(
        "/api/v1/iocs",
        headers=socl2_headers,
        json={
            "ioc_type": "DOMAIN",
            "ioc_value": "bancocentral-token-vip.net",
            "list_type": "BLACKLIST",
            "confidence_score": 99,
            "ttl_days": 45,
            "source": "SOC_THREAT_INTEL_UPDATED",
        },
    )
    assert bl_upsert.status_code == 201
    assert bl_upsert.json()["created"] is False
    assert bl_upsert.json()["confidence_score"] == 99

    # 2. Upsert WHITELIST IOC with TTL hours
    wl_create = await client.post(
        "/api/v1/iocs",
        headers=socl2_headers,
        json={
            "ioc_type": "DOMAIN",
            "ioc_value": "conciliacion.bancocentral.com",
            "list_type": "WHITELIST",
            "ttl_hours": 72,
            "source": "CORP_DNS_ALLOW",
        },
    )
    assert wl_create.status_code == 201
    assert wl_create.json()["list_type"] == "WHITELIST"
    assert wl_create.json()["expires_at"] is not None

    # 3. PostgreSQL pg_trgm fuzzy trigram search on partial/typo query 'bancocentra'
    fuzzy_resp = await client.get(
        "/api/v1/iocs/search?q=bancocentra&threshold=0.25",
        headers=socl2_headers,
    )
    assert fuzzy_resp.status_code == 200
    fuzzy_items = fuzzy_resp.json()["items"]
    assert len(fuzzy_items) >= 3
    matched_values = {item["ioc_value"] for item in fuzzy_items}
    assert "banc0central.com" in matched_values or "bancocentral-token-vip.net" in matched_values
    assert all((item["similarity"] or 0) >= 0.25 for item in fuzzy_items)

    # 4. Multi-entity unified Threat Hunting search across verdicts, IOCs, and dataset samples
    hunt_resp = await client.get(
        "/api/v1/threat-hunting/search?q=bancocentra",
        headers=socl2_headers,
    )
    assert hunt_resp.status_code == 200
    hunt_data = hunt_resp.json()
    assert hunt_data["total_matches"] >= 3
    assert len(hunt_data["iocs"]) >= 2

    # 5. Soft-deactivate temporary IOC while preserving forensic history
    del_resp = await client.delete(f"/api/v1/iocs/{bl_ioc['id']}", headers=socl2_headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["is_active"] is False

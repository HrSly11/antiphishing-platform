"""Integration tests for inline phishing detection, gateway keys, .eml/URL/QR, and analyst KPIs."""
from __future__ import annotations

import httpx

from app.core.config import settings


async def test_whitelisted_authenticated_corporate_email_delivered_clean(
    client: httpx.AsyncClient,
    socl1_headers: dict[str, str],
) -> None:
    resp = await client.post(
        "/api/v1/detection/analyze-email",
        headers=socl1_headers,
        json={
            "sender": "rrhh@bancocentral.com",
            "recipient": "analista@bancocentral.com",
            "subject": "Comunicado oficial de beneficios corporativos Q4",
            "body_text": "Consulte el detalle en https://pagos.bancocentral.com/beneficios",
            "headers": {
                "authentication-results": "spf=pass dkim=pass dmarc=pass header.from=bancocentral.com"
            },
            "channel": "EMAIL",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "CLEAN"
    assert data["action"] == "DELIVER"
    assert data["risk_score"] == 0
    assert data["incident_triggered"] is False
    assert data["incident_id"] is None


async def test_spoofed_bancocentral_email_quarantined_and_triggers_incident_iocs_audit(
    client: httpx.AsyncClient,
    socl2_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    resp = await client.post(
        "/api/v1/detection/analyze-email",
        headers=socl2_headers,
        json={
            "sender": "seguridad@bancocentral.com",
            "recipient": "tesoreria@bancocentral.com",
            "subject": "URGENTE: Su token digital corporativo ha sido suspendido",
            "body_text": (
                "Ingrese sus credenciales de inmediato en "
                "http://bancocentral-seguridad.com/login para evitar bloqueo."
            ),
            "headers": {
                "authentication-results": "spf=fail dkim=fail dmarc=fail",
                "x-originating-ip": "185.220.101.88",
            },
            "channel": "EMAIL",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "MALICIOUS"
    assert body["action"] == "QUARANTINE"
    assert body["risk_score"] >= 70
    assert body["incident_triggered"] is True
    assert body["incident_id"] is not None
    assert body["incident_code"].startswith("INC-")

    sig_names = {s["name"] for s in body["signals"]}
    assert "WHITELISTED_DOMAIN_SPOOFING" in sig_names or "OFFICIAL_DOMAIN_SPOOFING" in sig_names
    assert "IOC_BLACKLIST_MATCH" in sig_names

    # Verify auto-created Incident + linked IOCs
    inc_resp = await client.get(
        f"/api/v1/incidents/{body['incident_id']}",
        headers=socl2_headers,
    )
    assert inc_resp.status_code == 200
    inc_detail = inc_resp.json()
    assert inc_detail["status"] == "OPEN"
    linked_values = {i["ioc_value"] for i in inc_detail["iocs"]}
    assert "185.220.101.88" in linked_values
    assert any("bancocentral-seguridad.com" in v for v in linked_values)

    # Verify append-only AuditLog entry was recorded
    audit_resp = await client.get(
        "/api/v1/audit/logs?action=DETECTION_ANALYZE&page_size=20",
        headers=auditor_headers,
    )
    assert audit_resp.status_code == 200
    resources = {item["resource"] for item in audit_resp.json()["items"]}
    assert f"verdict:{body['correlation_id']}" in resources


async def test_gateway_key_authentication_on_analyze_email(client: httpx.AsyncClient) -> None:
    # Valid X-Gateway-Key without Bearer JWT -> 200
    ok_resp = await client.post(
        "/api/v1/detection/analyze-email",
        headers={"X-Gateway-Key": settings.GATEWAY_API_KEY},
        json={
            "sender": "alertas@bancocentral.com",
            "recipient": "mesa@bancocentral.com",
            "subject": "Aviso automatico conciliacion",
            "body_text": "Proceso diario finalizado sin novedades.",
            "headers": {"authentication-results": "spf=pass dkim=pass dmarc=pass"},
        },
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["verdict"] == "CLEAN"

    # Invalid X-Gateway-Key without JWT -> 401
    bad_resp = await client.post(
        "/api/v1/detection/analyze-email",
        headers={"X-Gateway-Key": "invalid-forged-gateway-key"},
        json={"sender": "test@external.org", "subject": "Ping", "body_text": "Hello"},
    )
    assert bad_resp.status_code == 401


async def test_eml_upload_url_qr_scan_and_employee_report_phishing(
    client: httpx.AsyncClient,
    socl1_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    # 1. Multipart .eml upload with Cyrillic homograph + double-extension executable
    raw_eml = (
        "From: Soporte <soporte@banc\u043ecentral.com>\r\n"
        "To: finanzas@bancocentral.com\r\n"
        "Subject: URGENTE: Desbloqueo de Token\r\n"
        "Authentication-Results: spf=fail dmarc=fail\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="EMLBOUND"\r\n\r\n'
        "--EMLBOUND\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "Ingrese sus credenciales en http://banc0central.com/unlock\r\n"
        "--EMLBOUND\r\n"
        'Content-Type: application/octet-stream; name="Certificado.pdf.exe"\r\n'
        'Content-Disposition: attachment; filename="Certificado.pdf.exe"\r\n\r\n'
        "MZ_PAYLOAD\r\n"
        "--EMLBOUND--\r\n"
    ).encode("utf-8")

    eml_resp = await client.post(
        "/api/v1/detection/analyze-eml",
        headers=socl1_headers,
        files={"file": ("suspicious_token.eml", raw_eml, "message/rfc822")},
    )
    assert eml_resp.status_code == 200
    assert eml_resp.json()["verdict"] == "MALICIOUS"
    assert eml_resp.json()["action"] == "QUARANTINE"
    assert eml_resp.json()["incident_triggered"] is True

    # 2. Standalone QR / URL scan
    qr_resp = await client.post(
        "/api/v1/detection/analyze-url",
        headers=socl1_headers,
        json={
            "url": "http://qr-login-bancocentral.top/sso/verify",
            "channel": "QR",
            "message_text": "Escanee el codigo QR para renovar su MFA corporativo",
            "enrich": False,
        },
    )
    assert qr_resp.status_code == 200
    assert qr_resp.json()["channel"] == "QR"
    assert qr_resp.json()["verdict"] == "MALICIOUS"
    assert qr_resp.json()["action"] == "QUARANTINE"

    # 3. Employee "Reportar phishing" button (accessible to any authenticated employee, e.g., VIEWER)
    report_resp = await client.post(
        "/api/v1/detection/report-phishing",
        headers=viewer_headers,
        json={
            "sender_email": "cobranzas@proveedor-externo-alerta.org",
            "subject": "URGENTE: Factura vence en 24 horas - evite el cierre",
            "body_text": "Revise el enlace acortado http://bit.ly/3k9bank urgente.",
            "headers": {"authentication-results": "spf=softfail"},
            "channel": "EMAIL",
        },
    )
    assert report_resp.status_code == 200
    rep_data = report_resp.json()
    assert rep_data["risk_score"] >= 35
    # Employee-reported suspicious emails (>= 35) automatically open a SOC triage incident
    assert rep_data["incident_triggered"] is True
    assert rep_data["incident_id"] is not None


async def test_analyst_verdict_labeling_updates_dashboard_fp_and_fn_kpis(
    client: httpx.AsyncClient,
    socl1_headers: dict[str, str],
) -> None:
    # Create a CLEAN verdict and two flagged verdicts so we can label TP, FP, and FN
    clean_r = await client.post(
        "/api/v1/detection/analyze-email",
        headers=socl1_headers,
        json={
            "sender": "alertas@alertas.bancocentral.com",
            "recipient": "ops@bancocentral.com",
            "subject": "Reporte operativo nocturno",
            "body_text": "Conciliacion completada exitosamente.",
            "headers": {"authentication-results": "spf=pass dkim=pass dmarc=pass"},
        },
    )
    clean_id = clean_r.json()["id"]

    flagged_tp_r = await client.post(
        "/api/v1/detection/analyze-email",
        headers=socl1_headers,
        json={
            "sender": "fraude@banc0central.com",
            "recipient": "ops@bancocentral.com",
            "subject": "URGENTE: clave bloqueada",
            "body_text": "Digite su clave en http://banc0central.com/login",
        },
    )
    flagged_tp_id = flagged_tp_r.json()["id"]

    flagged_fp_r = await client.post(
        "/api/v1/detection/analyze-email",
        headers=socl1_headers,
        json={
            "sender": "evento@fintech-conferencia.org",
            "recipient": "ops@bancocentral.com",
            "subject": "Urgente: vence en 24 horas su registro al webinar",
            "body_text": "Acceda mediante http://bit.ly/webinar2026",
            "headers": {"authentication-results": "spf=fail"},
        },
    )
    flagged_fp_id = flagged_fp_r.json()["id"]

    # Apply analyst labels: 1 True Positive, 1 False Positive (flagged -> FP), 1 False Negative (CLEAN -> TP)
    r1 = await client.patch(
        f"/api/v1/detection/verdicts/{flagged_tp_id}/label",
        headers=socl1_headers,
        json={"label": "TRUE_POSITIVE"},
    )
    assert r1.status_code == 200 and r1.json()["analyst_label"] == "TRUE_POSITIVE"

    r2 = await client.patch(
        f"/api/v1/detection/verdicts/{flagged_fp_id}/label",
        headers=socl1_headers,
        json={"label": "FALSE_POSITIVE"},
    )
    assert r2.status_code == 200 and r2.json()["analyst_label"] == "FALSE_POSITIVE"

    r3 = await client.patch(
        f"/api/v1/detection/verdicts/{clean_id}/label",
        headers=socl1_headers,
        json={"label": "TRUE_POSITIVE"},
    )
    assert r3.status_code == 200 and r3.json()["analyst_label"] == "TRUE_POSITIVE"

    kpi_resp = await client.get("/api/v1/dashboard/kpis?window_days=30", headers=socl1_headers)
    assert kpi_resp.status_code == 200
    kpis = kpi_resp.json()
    assert kpis["labeled_count"] >= 3
    assert kpis["false_positive_rate"] > 0.0
    assert kpis["false_negative_rate"] > 0.0

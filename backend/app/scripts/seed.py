"""Idempotent enterprise banking SOC seed script for `antiphishing_db`."""
from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.adapters.persistence.database import async_session_factory, engine
from app.adapters.persistence.models.detection_verdict import DetectionVerdictModel
from app.adapters.persistence.models.incident import IncidentModel
from app.adapters.persistence.models.incident_event import IncidentEventModel
from app.adapters.persistence.models.incident_ioc import IncidentIocModel
from app.adapters.persistence.models.ioc import IocModel
from app.adapters.persistence.models.report_schedule import ReportScheduleModel
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.simulation_repository import SimulationRepository
from app.application.commands.ingest_dataset import ingest_dataset_command
from app.core.security import hash_password

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEED_NAME = "v2_enterprise_banking_soc_2026"

DEMO_USERS: List[Tuple[str, str, str, str]] = [
    ("admin@bancocentral.com", "Admin#Banco2026!", "Valeria Mendoza — CISO & Platform Admin", "ADMIN"),
    ("socl2@bancocentral.com", "SocL2#Banco2026!", "Carlos Paredes — Lead SOC L2 Responder", "SOC_L2"),
    ("socl1@bancocentral.com", "SocL1#Banco2026!", "Lucia Rojas — SOC L1 Triage Analyst", "SOC_L1"),
    ("auditor@bancocentral.com", "Auditor#Banco2026!", "Ricardo Soto — PCI-DSS & ISO Internal Auditor", "AUDITOR"),
    ("viewer@bancocentral.com", "Viewer#Banco2026!", "Elena Vargas — Risk & Operations Executive", "VIEWER"),
]

WHITELIST_IOCS: List[Tuple[str, str, str]] = [
    ("DOMAIN", "bancocentral.com", "Official Corporate Primary Domain"),
    ("DOMAIN", "pagos.bancocentral.com", "Official Treasury & Wire Portal"),
    ("DOMAIN", "alertas.bancocentral.com", "Official Transactional Notification Subdomain"),
    ("IP", "200.48.225.10", "Corporate Outbound MTA Relay"),
]

BLACKLIST_IOCS: List[Tuple[str, str, int, str]] = [
    ("DOMAIN", "bancоcentral.com", 100, "SOC Homograph Hunter (Cyrillic U+043E)"),
    ("DOMAIN", "xn--banccentral-9ib.com", 100, "IDN Punycode Brand Spoofing"),
    ("DOMAIN", "banc0central.com", 98, "Levenshtein Typosquatting Block"),
    ("DOMAIN", "bancocentral-seguridad.com", 98, "PhishTank Verified Banking Lure"),
    ("DOMAIN", "actualizar-token-bancario.net", 95, "OpenPhish Credential Harvester"),
    ("DOMAIN", "verificacion-clave-digital.org", 94, "SMS Smishing Infrastructure"),
    ("DOMAIN", "qr-sso-bancocentral.top", 96, "QR Quishing OAuth Trap"),
    ("IP", "185.220.101.5", 95, "Hostile Bulletproof Relay #1"),
    ("IP", "45.134.20.18", 92, "Hostile Phishing Hosting #2"),
    ("IP", "91.214.124.77", 90, "Smishing C2 Redirector"),
    ("IP", "193.149.176.22", 89, "BEC Spear-Phishing Relay"),
    ("URL", "http://185.220.101.5/login-portal/token", 100, "Direct IP Credential Harvester"),
    (
        "HASH",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        97,
        "Malicious Attachment Dropper SHA-256",
    ),
]


def _build_seed_verdicts(now: datetime) -> List[Dict[str, Any]]:
    """Build 46 realistic multi-channel verdicts spanning the last 21 UTC days."""
    templates = [
        # MALICIOUS templates
        {
            "sender": "soporte@bancоcentral.com",
            "recipient": "tesoreria@bancocentral.com",
            "subject": "URGENTE: Su Token Digital Corporativo ha sido bloqueado",
            "channel": "EMAIL",
            "score": 96,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "45.134.20.18",
            "latency": 64,
            "reported": False,
            "summary": "Homógrafo cirílico detectado junto con fallo estricto SPF/DMARC y captura de coordenadas.",
            "signals": [
                {"name": "SENDER_HOMOGRAPH", "weight": 45, "score": 1.0, "reason": "Cyrillic homograph spoofing bancocentral.com", "metadata": {"domain": "bancоcentral.com"}},
                {"name": "DMARC_FAIL", "weight": 35, "score": 1.0, "reason": "DMARC p=reject alignment failure", "metadata": {"domain": "bancоcentral.com"}},
                {"name": "LLM_PHISHING_INTENT", "weight": 30, "score": 0.94, "reason": "[credential_harvesting] Urgent digital token suspension lure", "metadata": {}},
            ],
        },
        {
            "sender": "seguridad@bancocentral-seguridad.com",
            "recipient": "contabilidad@bancocentral.com",
            "subject": "Acción requerida: Validación obligatoria de firma SWIFT",
            "channel": "EMAIL",
            "score": 92,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "185.220.101.5",
            "latency": 78,
            "reported": True,
            "summary": "Combosquatting de marca protegida con enlace a cosechador de credenciales en lista negra.",
            "signals": [
                {"name": "IOC_BLACKLIST_MATCH", "weight": 85, "score": 1.0, "reason": "Domain matched PhishTank verified blacklist", "metadata": {"domain": "bancocentral-seguridad.com"}},
                {"name": "URL_TYPOSQUATTING", "weight": 40, "score": 0.92, "reason": "Brand combosquatting on bancocentral.com", "metadata": {"domain": "bancocentral-seguridad.com"}},
            ],
        },
        {
            "sender": "sms-gateway@verificacion-clave-digital.org",
            "recipient": "ejecutivo.banca@bancocentral.com",
            "subject": "[SMS] BancoCentral Alerta: Compra retenida, valide su clave OTP aqui",
            "channel": "SMS",
            "score": 88,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "91.214.124.77",
            "latency": 41,
            "reported": True,
            "summary": "Campaña de smishing solicitando código OTP mediante dominio recién registrado.",
            "signals": [
                {"name": "IOC_BLACKLIST_MATCH", "weight": 85, "score": 1.0, "reason": "Smishing domain on institutional blacklist", "metadata": {"domain": "verificacion-clave-digital.org"}},
                {"name": "NEWLY_REGISTERED_DOMAIN", "weight": 35, "score": 0.9, "reason": "Domain registered 3 days ago", "metadata": {"domain": "verificacion-clave-digital.org"}},
            ],
        },
        {
            "sender": "qr-scanner@qr-sso-bancocentral.top",
            "recipient": "operaciones.agencia@bancocentral.com",
            "subject": "[QR] Actualización de estacionamiento y SSO Microsoft 365",
            "channel": "QR",
            "score": 91,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "193.149.176.22",
            "latency": 53,
            "reported": True,
            "summary": "Código QR malicioso (quishing) redirigiendo a clon de inicio de sesión corporativo.",
            "signals": [
                {"name": "IOC_BLACKLIST_MATCH", "weight": 85, "score": 1.0, "reason": "Quishing domain blocked", "metadata": {"domain": "qr-sso-bancocentral.top"}},
                {"name": "SUSPICIOUS_TLD", "weight": 20, "score": 1.0, "reason": "High-abuse .top TLD targeting corporate SSO", "metadata": {"domain": "qr-sso-bancocentral.top"}},
            ],
        },
        {
            "sender": "alertas@banc0central.com",
            "recipient": "inversiones@bancocentral.com",
            "subject": "Desembolso pendiente - Adjunto Liquidacion_Octubre.pdf.exe",
            "channel": "EMAIL",
            "score": 98,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "185.220.101.5",
            "latency": 35,
            "reported": False,
            "summary": "Typosquatting numérico (`banc0central.com`) con ejecutable de doble extensión.",
            "signals": [
                {"name": "DOUBLE_EXTENSION_ATTACHMENT", "weight": 65, "score": 1.0, "reason": "Executable disguised as PDF (Liquidacion_Octubre.pdf.exe)", "metadata": {"domain": "banc0central.com"}},
                {"name": "SENDER_TYPOSQUATTING", "weight": 45, "score": 0.95, "reason": "Digit substitution typosquatting banc0central.com", "metadata": {"domain": "banc0central.com"}},
            ],
        },
        {
            "sender": "portal-web@actualizar-token-bancario.net",
            "recipient": "mesa.dinero@bancocentral.com",
            "subject": "[WEB] Inspección de URL reportada en navegador corporativo",
            "channel": "WEB",
            "score": 86,
            "verdict": "MALICIOUS",
            "action": "QUARANTINE",
            "label": "TRUE_POSITIVE",
            "ip": "45.134.20.18",
            "latency": 112,
            "reported": False,
            "summary": "Portal fraudulento de captura de token detectado en navegación corporativa.",
            "signals": [
                {"name": "IOC_BLACKLIST_MATCH", "weight": 85, "score": 1.0, "reason": "OpenPhish verified URL match", "metadata": {"domain": "actualizar-token-bancario.net"}},
            ],
        },
        # SUSPICIOUS templates
        {
            "sender": "facturacion@proveedor-cloud-latam.net",
            "recipient": "compras@bancocentral.com",
            "subject": "Factura electrónica vencida - Confirmar cuenta detracciones",
            "channel": "EMAIL",
            "score": 52,
            "verdict": "SUSPICIOUS",
            "action": "TAG_AND_BANNER",
            "label": "TRUE_POSITIVE",
            "ip": "103.85.24.19",
            "latency": 94,
            "reported": True,
            "summary": "Proveedor externo con SPF SoftFail y lenguaje de urgencia financiera.",
            "signals": [
                {"name": "SPF_SOFTFAIL", "weight": 25, "score": 1.0, "reason": "SPF softfail from unverified external sender", "metadata": {"domain": "proveedor-cloud-latam.net"}},
                {"name": "URGENCY_FINANCIAL_LURE", "weight": 28, "score": 0.85, "reason": "Invoice bank-account change request", "metadata": {"domain": "proveedor-cloud-latam.net"}},
            ],
        },
        {
            "sender": "eventos@conferencia-fintech-andina.org",
            "recipient": "innovacion@bancocentral.com",
            "subject": "Registro confirmado — Descargue su pase QR mediante enlace acortado",
            "channel": "EMAIL",
            "score": 44,
            "verdict": "SUSPICIOUS",
            "action": "TAG_AND_BANNER",
            "label": "FALSE_POSITIVE",
            "ip": "198.51.100.42",
            "latency": 82,
            "reported": False,
            "summary": "Uso de acortador de URL externo sin firma DKIM verificada (validado como evento legítimo por analista).",
            "signals": [
                {"name": "URL_SHORTENER", "weight": 25, "score": 1.0, "reason": "Embedded shortened link bit.ly", "metadata": {"domain": "conferencia-fintech-andina.org"}},
                {"name": "DKIM_MISSING", "weight": 20, "score": 0.9, "reason": "Unsigned external marketing message", "metadata": {"domain": "conferencia-fintech-andina.org"}},
            ],
        },
        # CLEAN templates
        {
            "sender": "rrhh@bancocentral.com",
            "recipient": "colaboradores@bancocentral.com",
            "subject": "Cronograma oficial de capacitación anual ISO 27001 y PCI-DSS",
            "channel": "EMAIL",
            "score": 0,
            "verdict": "CLEAN",
            "action": "DELIVER",
            "label": "UNREVIEWED",
            "ip": "200.48.225.10",
            "latency": 21,
            "reported": False,
            "summary": "Comunicación interna autenticada por SPF, DKIM y DMARC desde dominio oficial en lista blanca.",
            "signals": [],
        },
        {
            "sender": "alertas@alertas.bancocentral.com",
            "recipient": "auditoria@bancocentral.com",
            "subject": "Resumen diario conciliación cámara de compensación interbancaria",
            "channel": "EMAIL",
            "score": 4,
            "verdict": "CLEAN",
            "action": "DELIVER",
            "label": "UNREVIEWED",
            "ip": "200.48.225.10",
            "latency": 19,
            "reported": False,
            "summary": "Tráfico institucional legítimo verificado sin indicadores de riesgo.",
            "signals": [],
        },
    ]

    records: List[Dict[str, Any]] = []
    channels_cycle = ["EMAIL", "EMAIL", "SMS", "WEB", "QR", "EMAIL"]
    for idx in range(46):
        tpl = templates[idx % len(templates)]
        days_ago = idx % 21
        hours_ago = (idx * 3) % 23
        created_at = now - timedelta(days=days_ago, hours=hours_ago, minutes=(idx * 7) % 55)

        ch = tpl["channel"] if tpl["verdict"] != "CLEAN" else channels_cycle[idx % len(channels_cycle)]
        label = tpl["label"]
        if idx in {17, 37} and tpl["verdict"] == "SUSPICIOUS":
            label = "FALSE_POSITIVE"
        elif idx >= 36 and tpl["verdict"] != "CLEAN":
            label = "UNREVIEWED"

        records.append(
            {
                "id": str(uuid.uuid4()),
                "correlation_id": f"SEED-{created_at.strftime('%Y%m%d')}-{idx + 1:03d}",
                "sender_email": tpl["sender"],
                "recipient_email": tpl["recipient"],
                "subject": f"{tpl['subject']} (#{idx + 1})",
                "channel": ch,
                "risk_score": tpl["score"],
                "verdict": tpl["verdict"],
                "action_taken": tpl["action"],
                "summary": tpl["summary"],
                "latency_ms": tpl["latency"] + ((idx * 11) % 75),
                "analyst_label": label,
                "headers_meta": {
                    "originating_ip": tpl["ip"],
                    "authentication-results": (
                        "spf=pass dkim=pass dmarc=pass"
                        if tpl["verdict"] == "CLEAN"
                        else "spf=fail dkim=none dmarc=fail"
                    ),
                    "_reported_by_user": tpl["reported"],
                    "_llm_engine": "langchain-deterministic",
                },
                "signals_meta": tpl["signals"],
                "created_at": created_at,
            }
        )
    return records


async def run_seed(force: bool = False) -> Dict[str, Any]:
    async with async_session_factory() as db:
        already = await db.scalar(
            text("SELECT name FROM seed_runs WHERE name = :name"),
            {"name": SEED_NAME},
        )
        if already and not force:
            print(f"Seed '{SEED_NAME}' already applied — skipping (idempotent).")
            return {"status": "already_seeded", "seed_name": SEED_NAME}

        now = datetime.now(timezone.utc)
        audit = AuditRepository(db)

        # 1. Seed 5 RBAC Users
        user_by_role: Dict[str, UserModel] = {}
        for email, password, full_name, role in DEMO_USERS:
            existing = await db.scalar(select(UserModel).where(UserModel.email == email))
            if existing is None:
                user = UserModel(
                    id=str(uuid.uuid4()),
                    email=email,
                    hashed_password=hash_password(password),
                    full_name=full_name,
                    role=role,
                    is_active=True,
                    mfa_enabled=False,
                    created_at=now - timedelta(days=30),
                )
                db.add(user)
                await db.flush()
            else:
                existing.hashed_password = hash_password(password)
                existing.full_name = full_name
                existing.role = role
                existing.is_active = True
                user = existing
                await db.flush()
            user_by_role[role] = user

        await audit.append(
            user_email="admin@bancocentral.com",
            action="SEED_RBAC_USERS",
            resource="users:bootstrap",
            payload={"roles": [r for _, _, _, r in DEMO_USERS]},
            client_ip="127.0.0.1",
        )

        # 2. Seed WHITELIST and BLACKLIST IOCs
        seeded_blacklist_ids: List[str] = []
        for ioc_type, val, reason in WHITELIST_IOCS:
            stmt = (
                pg_insert(IocModel)
                .values(
                    id=str(uuid.uuid4()),
                    ioc_type=ioc_type,
                    ioc_value=val.lower(),
                    list_type="WHITELIST",
                    confidence_score=100,
                    source=reason,
                    is_active=True,
                    created_by="admin@bancocentral.com",
                    created_at=now - timedelta(days=25),
                )
                .on_conflict_do_nothing(constraint="uq_ioc_value_list")
            )
            await db.execute(stmt)

        for ioc_type, val, conf, src in BLACKLIST_IOCS:
            ioc_id = str(uuid.uuid4())
            stmt = (
                pg_insert(IocModel)
                .values(
                    id=ioc_id,
                    ioc_type=ioc_type,
                    ioc_value=val.lower(),
                    list_type="BLACKLIST",
                    confidence_score=conf,
                    source=src,
                    is_active=True,
                    created_by="socl2@bancocentral.com",
                    created_at=now - timedelta(days=20),
                )
                .on_conflict_do_nothing(constraint="uq_ioc_value_list")
            )
            await db.execute(stmt)
            row = await db.scalar(
                select(IocModel).where(IocModel.ioc_value == val.lower(), IocModel.list_type == "BLACKLIST")
            )
            if row:
                seeded_blacklist_ids.append(row.id)

        # 3. Offline ETL Ingestion for OpenPhish & PhishTank fixtures
        op_ver = await ingest_dataset_command(
            db=db,
            source="openphish_sample",
            prefer_live=False,
            sync_blacklist=True,
            actor_email="admin@bancocentral.com",
            client_ip="127.0.0.1",
        )
        pt_ver = await ingest_dataset_command(
            db=db,
            source="phishtank_sample",
            prefer_live=False,
            sync_blacklist=True,
            actor_email="admin@bancocentral.com",
            client_ip="127.0.0.1",
        )

        # 4. Seed 46 multi-channel Detection Verdicts across 21 UTC days
        verdict_dicts = _build_seed_verdicts(now)
        malicious_verdicts: List[DetectionVerdictModel] = []
        for vd in verdict_dicts:
            existing_v = await db.scalar(
                select(DetectionVerdictModel).where(
                    DetectionVerdictModel.correlation_id == vd["correlation_id"]
                )
            )
            if existing_v is None:
                v_model = DetectionVerdictModel(**vd)
                db.add(v_model)
                await db.flush()
            else:
                v_model = existing_v
            if v_model.verdict in {"MALICIOUS", "SUSPICIOUS"}:
                malicious_verdicts.append(v_model)

        # 5. Seed 7 realistic Incidents across OPEN, TRIAGED, INVESTIGATING, CONTAINED, CLOSED
        socl1_id = user_by_role["SOC_L1"].id
        socl2_id = user_by_role["SOC_L2"].id

        incident_specs = [
            # 1: OPEN CRITICAL — overdue SLA!
            {
                "code": "INC-20261027-OVR001",
                "verdict": malicious_verdicts[0],
                "severity": "CRITICAL",
                "status": "OPEN",
                "resolution": None,
                "assignee": socl1_id,
                "created_at": now - timedelta(minutes=42),
                "sla_deadline": now - timedelta(minutes=27),
                "resolved_at": None,
                "escalated": False,
                "transitions": [],
            },
            # 2: OPEN HIGH — within SLA
            {
                "code": "INC-20261027-OPN002",
                "verdict": malicious_verdicts[1],
                "severity": "HIGH",
                "status": "OPEN",
                "resolution": None,
                "assignee": socl1_id,
                "created_at": now - timedelta(minutes=18),
                "sla_deadline": now + timedelta(minutes=42),
                "resolved_at": None,
                "escalated": False,
                "transitions": [],
            },
            # 3: TRIAGED CRITICAL — within SLA
            {
                "code": "INC-20261027-TRI003",
                "verdict": malicious_verdicts[2],
                "severity": "CRITICAL",
                "status": "TRIAGED",
                "resolution": None,
                "assignee": socl1_id,
                "created_at": now - timedelta(minutes=10),
                "sla_deadline": now + timedelta(minutes=5),
                "resolved_at": None,
                "escalated": False,
                "transitions": [
                    ("OPEN", "TRIAGED", "socl1@bancocentral.com", "Verified smishing OTP lure targeting mobile banking.", 4),
                ],
            },
            # 4: INVESTIGATING HIGH — within SLA
            {
                "code": "INC-20261027-INV004",
                "verdict": malicious_verdicts[3],
                "severity": "HIGH",
                "status": "INVESTIGATING",
                "resolution": None,
                "assignee": socl2_id,
                "created_at": now - timedelta(minutes=34),
                "sla_deadline": now + timedelta(minutes=26),
                "resolved_at": None,
                "escalated": False,
                "transitions": [
                    ("OPEN", "TRIAGED", "socl1@bancocentral.com", "QR code decoded to .top credential harvester.", 6),
                    ("TRIAGED", "INVESTIGATING", "socl2@bancocentral.com", "Checking Entra ID sign-in logs for branch personnel.", 14),
                ],
            },
            # 5: CONTAINED CRITICAL — within SLA
            {
                "code": "INC-20261026-CNT005",
                "verdict": malicious_verdicts[4],
                "severity": "CRITICAL",
                "status": "CONTAINED",
                "resolution": None,
                "assignee": socl2_id,
                "created_at": now - timedelta(minutes=12),
                "sla_deadline": now + timedelta(minutes=3),
                "resolved_at": None,
                "escalated": False,
                "transitions": [
                    ("OPEN", "TRIAGED", "socl1@bancocentral.com", "Confirmed double-extension dropper (.pdf.exe).", 3),
                    ("TRIAGED", "INVESTIGATING", "socl2@bancocentral.com", "Sandbox detonation confirmed stealer behaviour.", 6),
                    ("INVESTIGATING", "CONTAINED", "socl2@bancocentral.com", "Domain banc0central.com sinkholed & mailbox purged.", 9),
                ],
            },
            # 6: CLOSED CRITICAL — resolved in 11 minutes (< 15m SLA)
            {
                "code": "INC-20261024-CLS006",
                "verdict": malicious_verdicts[5],
                "severity": "CRITICAL",
                "status": "CLOSED",
                "resolution": "TRUE_POSITIVE",
                "assignee": socl2_id,
                "created_at": now - timedelta(days=3, hours=4),
                "sla_deadline": now - timedelta(days=3, hours=4) + timedelta(minutes=15),
                "resolved_at": now - timedelta(days=3, hours=4) + timedelta(minutes=11),
                "escalated": False,
                "transitions": [
                    ("OPEN", "TRIAGED", "socl1@bancocentral.com", "Initial triage completed.", 3),
                    ("TRIAGED", "INVESTIGATING", "socl2@bancocentral.com", "Correlated OpenPhish indicator.", 6),
                    ("INVESTIGATING", "CONTAINED", "socl2@bancocentral.com", "Blocked at proxy & MTA.", 9),
                    ("CONTAINED", "CLOSED", "socl2@bancocentral.com", "Closed with TRUE_POSITIVE; zero credential compromise.", 11),
                ],
            },
            # 7: CLOSED HIGH — resolved in 27 minutes (< 60m SLA)
            {
                "code": "INC-20261021-CLS007",
                "verdict": malicious_verdicts[6],
                "severity": "HIGH",
                "status": "CLOSED",
                "resolution": "TRUE_POSITIVE",
                "assignee": socl2_id,
                "created_at": now - timedelta(days=6, hours=2),
                "sla_deadline": now - timedelta(days=6, hours=2) + timedelta(minutes=60),
                "resolved_at": now - timedelta(days=6, hours=2) + timedelta(minutes=27),
                "escalated": False,
                "transitions": [
                    ("OPEN", "TRIAGED", "socl1@bancocentral.com", "BEC invoice diversion attempt verified.", 7),
                    ("TRIAGED", "INVESTIGATING", "socl2@bancocentral.com", "Contacted procurement vendor out-of-band.", 16),
                    ("INVESTIGATING", "CONTAINED", "socl2@bancocentral.com", "Sender blocked and finance alerted.", 23),
                    ("CONTAINED", "CLOSED", "socl2@bancocentral.com", "Closed with TRUE_POSITIVE; wire prevented.", 27),
                ],
            },
        ]

        for idx, spec in enumerate(incident_specs):
            existing_inc = await db.scalar(
                select(IncidentModel).where(IncidentModel.incident_code == spec["code"])
            )
            if existing_inc is not None:
                continue

            inc = IncidentModel(
                id=str(uuid.uuid4()),
                incident_code=spec["code"],
                verdict_id=spec["verdict"].id,
                severity=spec["severity"],
                status=spec["status"],
                resolution=spec["resolution"],
                assigned_user_id=spec["assignee"],
                sla_deadline=spec["sla_deadline"],
                is_escalated=spec["escalated"],
                resolved_at=spec["resolved_at"],
                created_at=spec["created_at"],
            )
            db.add(inc)
            await db.flush()

            db.add(
                IncidentEventModel(
                    id=str(uuid.uuid4()),
                    incident_id=inc.id,
                    event_type="CREATED",
                    from_status=None,
                    to_status="OPEN",
                    actor="mta-gateway@bancocentral.com",
                    note=f"Automated SOC ticket from verdict {spec['verdict'].correlation_id}.",
                    created_at=spec["created_at"],
                )
            )
            for f_st, t_st, actor_em, note_txt, offset_min in spec["transitions"]:
                db.add(
                    IncidentEventModel(
                        id=str(uuid.uuid4()),
                        incident_id=inc.id,
                        event_type="STATUS_CHANGED",
                        from_status=f_st,
                        to_status=t_st,
                        actor=actor_em,
                        note=note_txt,
                        created_at=spec["created_at"] + timedelta(minutes=offset_min),
                    )
                )

            for ioc_id in seeded_blacklist_ids[idx : idx + 2]:
                await db.execute(
                    pg_insert(IncidentIocModel)
                    .values(incident_id=inc.id, ioc_id=ioc_id)
                    .on_conflict_do_nothing(index_elements=["incident_id", "ioc_id"])
                )

        # 6. Seed 2 Phishing Awareness Simulation Campaigns + Employee Events
        sim_repo = SimulationRepository(db)
        existing_campaigns = await sim_repo.list_campaigns(limit=5)
        if not existing_campaigns:
            camp1 = await sim_repo.create_campaign(
                name="Q4 Treasury SWIFT Token Verification Drill",
                channel="EMAIL",
                template_subject="Acción Inmediata: Renovación de Certificado SWIFT Corporativo",
                lure_type="CREDENTIAL_HARVEST",
                target_department="Finance & Treasury",
                total_targets=20,
                created_by="socl2@bancocentral.com",
            )
            for i in range(1, 21):
                emp = f"finanzas.emp{i:02d}@bancocentral.com"
                await sim_repo.record_event(camp1.id, emp, "SENT", "Finance & Treasury")
                if i <= 14:
                    await sim_repo.record_event(camp1.id, emp, "OPENED", "Finance & Treasury")
                if i <= 2:
                    await sim_repo.record_event(camp1.id, emp, "CLICKED", "Finance & Treasury")
                if 5 <= i <= 13:
                    await sim_repo.record_event(camp1.id, emp, "REPORTED", "Finance & Treasury")

            camp2 = await sim_repo.create_campaign(
                name="Branch QR SSO & Parking Permit Awareness Drill",
                channel="QR",
                template_subject="Escanee el código QR para validar su pase de acceso 2026",
                lure_type="QUISHING_OAUTH",
                target_department="Retail Branch Operations",
                total_targets=25,
                created_by="socl2@bancocentral.com",
            )
            for i in range(1, 26):
                emp = f"agencia.op{i:02d}@bancocentral.com"
                await sim_repo.record_event(camp2.id, emp, "SENT", "Retail Branch Operations")
                if i <= 18:
                    await sim_repo.record_event(camp2.id, emp, "OPENED", "Retail Branch Operations")
                if i <= 5:
                    await sim_repo.record_event(camp2.id, emp, "CLICKED", "Retail Branch Operations")
                if 8 <= i <= 15:
                    await sim_repo.record_event(camp2.id, emp, "REPORTED", "Retail Branch Operations")

        # 7. Seed 2 Automated Report Schedules
        existing_sched = await db.scalar(select(ReportScheduleModel.id).limit(1))
        if existing_sched is None:
            db.add(
                ReportScheduleModel(
                    id=str(uuid.uuid4()),
                    name="Daily CISO Executive Antiphishing Summary",
                    report_format="pdf",
                    frequency="DAILY",
                    recipients="ciso@bancocentral.com,admin@bancocentral.com",
                    filters={"template": "executive", "window_days": 1},
                    is_active=True,
                    next_run_at=now + timedelta(hours=8),
                    last_run_at=now - timedelta(hours=16),
                    last_status="DELIVERED (antiphishing_executive.pdf, 5812 bytes)",
                    created_by="admin@bancocentral.com",
                    created_at=now - timedelta(days=14),
                )
            )
            db.add(
                ReportScheduleModel(
                    id=str(uuid.uuid4()),
                    name="Weekly PCI-DSS v4.0 & ISO 27001 Telemetry Workbook",
                    report_format="xlsx",
                    frequency="WEEKLY",
                    recipients="auditor@bancocentral.com,socl2@bancocentral.com",
                    filters={"template": "compliance", "window_days": 7},
                    is_active=True,
                    next_run_at=now + timedelta(days=4),
                    last_run_at=now - timedelta(days=3),
                    last_status="DELIVERED (antiphishing_compliance.xlsx, 8420 bytes)",
                    created_by="admin@bancocentral.com",
                    created_at=now - timedelta(days=14),
                )
            )

        await audit.append(
            user_email="admin@bancocentral.com",
            action="SEED_COMPLETED",
            resource=f"seed:{SEED_NAME}",
            payload={
                "verdicts_seeded": len(verdict_dicts),
                "incidents_seeded": len(incident_specs),
                "openphish_samples": op_ver.total_records,
                "phishtank_samples": pt_ver.total_records,
            },
            client_ip="127.0.0.1",
        )

        await db.execute(
            text(
                "INSERT INTO seed_runs (name, applied_at) VALUES (:name, :ts) "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {"name": SEED_NAME, "ts": now},
        )
        await db.commit()

        chain_check = await AuditRepository(db).verify_chain()
        summary = {
            "status": "seeded",
            "seed_name": SEED_NAME,
            "users": len(DEMO_USERS),
            "verdicts": len(verdict_dicts),
            "incidents": len(incident_specs),
            "openphish_version": op_ver.id,
            "phishtank_version": pt_ver.id,
            "audit_chain": chain_check,
        }
        print("Enterprise banking SOC seed completed:", summary)
        return summary


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Seed enterprise SOC data into antiphishing_db.")
    parser.add_argument("--force", action="store_true", help="Re-apply seed even if recorded in seed_runs.")
    args = parser.parse_args()
    try:
        await run_seed(force=args.force)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())

"""AnalyzeInput command handler: RFC 822 .eml parser + full multi-layer inline phishing pipeline."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.feeds.whois_dns_tls import enrich_domain
from app.adapters.llm.langchain.email_classifier import classify_email
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.dataset_repository import DatasetRepository
from app.adapters.persistence.repositories.incident_repository import IncidentRepository
from app.adapters.persistence.repositories.ioc_repository import IocRepository
from app.adapters.persistence.repositories.verdict_repository import VerdictRepository
from app.application.dto.detection_dto import (
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    EmailAttachmentDto,
    SignalDto,
)
from app.core.config import settings
from app.core.metrics import ANALYSES_TOTAL, ANALYSIS_LATENCY
from app.domain.dataset.versioning import domain_of, normalize_url, url_hash
from app.domain.detection.engine import (
    DetectionEngine,
    EmailAnalysisInput,
    ExtractedArtifacts,
)
from app.domain.detection.scoring import DetectionSignal, RiskEvaluation, compute_risk_score
from app.domain.ioc.lists import BLACKLIST, WHITELIST, ListEntry, decide

AnalyzeEmailRequest = EmailAnalysisRequest


def parse_eml_bytes(raw_eml: bytes) -> EmailAnalysisRequest:
    """Parse raw RFC 822 `.eml` bytes into a validated `EmailAnalysisRequest` DTO."""
    if not raw_eml:
        raise ValueError("Empty .eml payload")

    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_eml)

    sender = str(msg.get("From") or "unknown@external.invalid").strip()
    recipient = str(msg.get("To") or "undisclosed@bancocentral.com").strip()
    if "," in recipient:
        recipient = recipient.split(",", 1)[0].strip()
    subject = str(msg.get("Subject") or "(no subject)").strip()[:998]

    headers: Dict[str, str] = {}
    for k, v in msg.items():
        key_lc = str(k).lower().strip()[:100]
        val_str = str(v).strip()[:2000]
        if key_lc in headers:
            headers[key_lc] = f"{headers[key_lc]}; {val_str}"[:2000]
        else:
            headers[key_lc] = val_str

    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[EmailAttachmentDto] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disp = (part.get_content_disposition() or "").lower()
            ctype = (part.get_content_type() or "application/octet-stream").lower()
            filename = part.get_filename()
            payload_bytes = part.get_payload(decode=True) or b""

            if disp == "attachment" or filename:
                attachments.append(
                    EmailAttachmentDto(
                        filename=(filename or "attachment.bin")[:255],
                        size_bytes=len(payload_bytes),
                        content_type=ctype[:150],
                    )
                )
            elif ctype == "text/plain":
                charset = part.get_content_charset() or "utf-8"
                body_text_parts.append(payload_bytes.decode(charset, errors="replace"))
            elif ctype == "text/html":
                charset = part.get_content_charset() or "utf-8"
                body_html_parts.append(payload_bytes.decode(charset, errors="replace"))
    else:
        ctype = (msg.get_content_type() or "text/plain").lower()
        payload_bytes = msg.get_payload(decode=True) or b""
        charset = msg.get_content_charset() or "utf-8"
        decoded = payload_bytes.decode(charset, errors="replace")
        if ctype == "text/html":
            body_html_parts.append(decoded)
        else:
            body_text_parts.append(decoded)

    body_text = "\n".join(body_text_parts).strip()[:200_000]
    body_html = ("\n".join(body_html_parts).strip()[:500_000]) if body_html_parts else None

    return EmailAnalysisRequest(
        sender=sender[:320] if len(sender) >= 3 else "unknown@external.invalid",
        recipient=recipient[:320] if len(recipient) >= 3 else "undisclosed@bancocentral.com",
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        attachments=attachments[:50],
        channel="EMAIL",
        reported_by_user=False,
    )


async def evaluate_email_pipeline(
    request: EmailAnalysisRequest,
    db: Optional[AsyncSession] = None,
    ioc_entries_override: Optional[Iterable[ListEntry]] = None,
    sample_domains_override: Optional[Iterable[str]] = None,
    enable_enrichment: bool = False,
) -> Tuple[RiskEvaluation, ExtractedArtifacts, Dict[str, Any]]:
    """Execute heuristics + IOC lists (whitelist vs spoofing vs blacklist) + dataset + LangChain classifier."""
    official_domains = [d.lower() for d in settings.OFFICIAL_DOMAINS]
    engine = DetectionEngine(official_domains=official_domains)

    domain_input = EmailAnalysisInput(
        sender=request.sender,
        recipient=request.recipient,
        subject=request.subject,
        body_text=request.body_text,
        body_html=request.body_html,
        headers=request.headers or {},
        attachments_meta=[att.model_dump() for att in (request.attachments or [])],
        channel=request.channel,
        reported_by_user=request.reported_by_user,
    )

    signals, artifacts = engine.collect_heuristic_signals(domain_input)
    normalized_urls = [u for u in (normalize_url(raw) for raw in artifacts.urls) if u]

    # 1. Gather IOC list entries & dataset sample hits
    by_value: Dict[str, List[ListEntry]] = {}
    if ioc_entries_override is not None:
        for entry in ioc_entries_override:
            by_value.setdefault(entry.value.strip().lower(), []).append(entry)
    elif db is not None:
        lookup_candidates: List[str] = [
            artifacts.sender_email,
            artifacts.sender_domain,
            *artifacts.url_domains,
            *normalized_urls,
        ]
        if artifacts.originating_ip:
            lookup_candidates.append(artifacts.originating_ip)
        if artifacts.reply_to_domain:
            lookup_candidates.append(artifacts.reply_to_domain)

        ioc_repo = IocRepository(db)
        rows = await ioc_repo.find_entries(lookup_candidates)
        for r in rows:
            le = ListEntry(
                value=r.ioc_value.lower(),
                list_type=r.list_type,
                source=r.source,
                expires_at=r.expires_at,
                is_active=r.is_active,
            )
            by_value.setdefault(le.value, []).append(le)

    matched_sample_source: Optional[str] = None
    if sample_domains_override is not None:
        override_set = {d.strip().lower() for d in sample_domains_override}
        if artifacts.sender_domain in override_set or any(
            d in override_set for d in artifacts.url_domains
        ):
            matched_sample_source = "DatasetFixture"
    elif db is not None and (normalized_urls or artifacts.url_domains):
        ds_repo = DatasetRepository(db)
        for n_url in normalized_urls[:10]:
            sample = await ds_repo.lookup_url_or_domain(url_hash(n_url), domain_of(n_url))
            if sample is not None:
                matched_sample_source = sample.source
                break

    # 2. LangChain semantic classification + prompt-injection defense
    llm_result = await classify_email(
        subject=request.subject,
        body=f"{request.body_text}\n{request.body_html or ''}",
        sender=request.sender,
        headers={**(request.headers or {}), "channel": request.channel},
    )
    injection_detected = bool(llm_result.get("injection_detected"))
    if injection_detected:
        signals.append(
            DetectionSignal(
                name="PROMPT_INJECTION_ATTEMPT",
                weight=75,
                score=1.0,
                reason=str(llm_result.get("explanation") or "Adversarial prompt-injection override detected."),
                metadata={"matches": llm_result.get("injection_matches", [])},
            )
        )
    elif llm_result.get("label") != "benign" and int(llm_result.get("risk_delta") or 0) > 0:
        signals.append(
            DetectionSignal(
                name="LLM_PHISHING_INTENT",
                weight=int(llm_result["risk_delta"]),
                score=float(llm_result.get("confidence") or 0.85),
                reason=f"[{llm_result['label']}] {llm_result.get('explanation', '')}",
                metadata={"label": llm_result["label"], "engine": llm_result.get("engine")},
            )
        )

    # 3. Evaluate Whitelist vs Spoofing vs Blacklist precedence
    sender_entries = by_value.get(artifacts.sender_email, []) + by_value.get(
        artifacts.sender_domain, []
    )
    sender_decision = decide(sender_entries)

    url_decisions: Dict[str, Optional[str]] = {}
    for n_url in normalized_urls:
        dom = domain_of(n_url)
        entries_for_u = by_value.get(n_url.lower(), []) + by_value.get(dom, [])
        url_decisions[dom] = decide(entries_for_u)
    for dom in artifacts.url_domains:
        if dom not in url_decisions:
            url_decisions[dom] = decide(by_value.get(dom, []))

    ip_decision = (
        decide(by_value.get(artifacts.originating_ip, [])) if artifacts.originating_ip else None
    )

    has_dangerous_attachment = any(
        s.name in {"DANGEROUS_ATTACHMENT", "DOUBLE_EXTENSION_ATTACHMENT"} for s in signals
    )
    reply_to_untrusted = bool(
        artifacts.reply_to_domain
        and artifacts.reply_to_domain != artifacts.sender_domain
        and decide(by_value.get(artifacts.reply_to_domain, [])) != WHITELIST
    )

    all_urls_whitelisted = all(
        url_decisions.get(d) == WHITELIST for d in artifacts.url_domains
    )
    any_blacklisted = (
        sender_decision == BLACKLIST
        or ip_decision == BLACKLIST
        or any(dec == BLACKLIST for dec in url_decisions.values())
        or matched_sample_source is not None
    )

    hard_whitelist = False
    hard_blacklist = False

    if (
        sender_decision == WHITELIST
        and all_urls_whitelisted
        and not artifacts.auth_failed
        and not artifacts.deceptive_anchors
        and not reply_to_untrusted
        and not has_dangerous_attachment
        and not injection_detected
        and ip_decision != BLACKLIST
    ):
        hard_whitelist = True
    else:
        # Check for spoofing or untrusted links from a whitelisted/official sender domain!
        if sender_decision == WHITELIST or artifacts.sender_domain in official_domains:
            if artifacts.auth_failed:
                signals.append(
                    DetectionSignal(
                        name="WHITELISTED_DOMAIN_SPOOFING",
                        weight=55,
                        score=1.0,
                        reason=(
                            f"Sender claims trusted domain '{artifacts.sender_domain}' "
                            "but failed SPF/DKIM/DMARC authentication (spoofed identity)."
                        ),
                        metadata={"domain": artifacts.sender_domain},
                    )
                )
            untrusted_link_domains = [
                d
                for d in artifacts.url_domains
                if url_decisions.get(d) != WHITELIST and d not in official_domains
            ]
            if untrusted_link_domains:
                signals.append(
                    DetectionSignal(
                        name="TRUSTED_SENDER_UNTRUSTED_URL",
                        weight=45,
                        score=1.0,
                        reason=(
                            f"Message from '{artifacts.sender_domain}' embeds links to untrusted "
                            f"external domain(s): {', '.join(untrusted_link_domains[:3])}."
                        ),
                        metadata={"domain": untrusted_link_domains[0], "domains": untrusted_link_domains[:5]},
                    )
                )

        if any_blacklisted:
            hard_blacklist = True
            signals.append(
                DetectionSignal(
                    name="IOC_BLACKLIST_MATCH",
                    weight=85,
                    score=1.0,
                    reason=(
                        "Indicator matched active institutional BLACKLIST or verified phishing dataset "
                        f"({matched_sample_source or 'IOC_BLACKLIST'})."
                    ),
                    metadata={"domain": artifacts.sender_domain},
                )
            )

    # 4. Optional live DNS/TLS/RDAP domain enrichment for external non-whitelisted domains
    enrichment_meta: Dict[str, Any] = {}
    if enable_enrichment and not hard_whitelist and not hard_blacklist:
        candidate_domains = [
            d
            for d in artifacts.url_domains
            if d not in official_domains and url_decisions.get(d) != WHITELIST
        ][:2]
        for dom in candidate_domains:
            enr = await enrich_domain(dom)
            enrichment_meta[dom] = enr
            age_score = float(enr.get("age_risk_score") or 0.0)
            if age_score > 0:
                signals.append(
                    DetectionSignal(
                        name="NEWLY_REGISTERED_DOMAIN",
                        weight=35,
                        score=age_score,
                        reason=str(enr.get("age_reason") or "Newly registered domain"),
                        metadata={"domain": dom},
                    )
                )

    evaluation = compute_risk_score(
        signals=signals,
        hard_blacklist=hard_blacklist,
        hard_whitelist=hard_whitelist,
    )

    pipeline_meta = {
        "llm": llm_result,
        "enrichment": enrichment_meta,
        "normalized_urls": normalized_urls,
        "originating_ip": artifacts.originating_ip,
    }
    return evaluation, artifacts, pipeline_meta


async def analyze_email_command(
    request: EmailAnalysisRequest,
    db: AsyncSession,
    actor_email: str = "mta-gateway",
    client_ip: str = "",
    enable_enrichment: bool = False,
    audit_action: str = "DETECTION_ANALYZE",
) -> EmailAnalysisResponse:
    """Full transactional command: analyze -> persist verdict -> metrics -> audit -> auto-incident & IOCs."""
    t0 = time.perf_counter()
    evaluation, artifacts, pipeline_meta = await evaluate_email_pipeline(
        request=request,
        db=db,
        enable_enrichment=enable_enrichment,
    )
    latency_ms = max(1, int(round((time.perf_counter() - t0) * 1000)))
    now_dt = datetime.now(timezone.utc)
    correlation_id = str(uuid.uuid4())

    if evaluation.risk_score >= 85:
        severity = "CRITICAL"
    elif evaluation.risk_score >= 70:
        severity = "HIGH"
    elif evaluation.risk_score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    signals_payload = [
        {
            "name": s.name,
            "weight": s.weight,
            "score": round(float(s.score), 4),
            "reason": s.reason,
            "metadata": s.metadata,
        }
        for s in evaluation.signals
    ]

    headers_meta: Dict[str, Any] = dict(request.headers or {})
    headers_meta["_extracted_urls"] = pipeline_meta["normalized_urls"][:25]
    headers_meta["_llm_engine"] = pipeline_meta["llm"].get("engine")
    headers_meta["_llm_label"] = pipeline_meta["llm"].get("label")
    if request.reported_by_user:
        headers_meta["_reported_by_user"] = True
    if artifacts.originating_ip:
        headers_meta["originating_ip"] = artifacts.originating_ip

    v_repo = VerdictRepository(db)
    verdict_row = await v_repo.save(
        correlation_id=correlation_id,
        sender_email=artifacts.sender_email or request.sender,
        recipient_email=request.recipient,
        subject=request.subject,
        channel=request.channel,
        risk_score=evaluation.risk_score,
        verdict=evaluation.verdict,
        action_taken=evaluation.action,
        summary=evaluation.summary,
        latency_ms=latency_ms,
        headers_meta=headers_meta,
        signals_meta=signals_payload,
        created_at=now_dt,
    )

    ANALYSES_TOTAL.labels(verdict=evaluation.verdict, action=evaluation.action).inc()
    ANALYSIS_LATENCY.observe(latency_ms / 1000.0)

    incident_triggered = evaluation.risk_score >= 70 or (
        request.reported_by_user and evaluation.risk_score >= 35
    )
    incident_id: Optional[str] = None
    incident_code: Optional[str] = None

    if incident_triggered:
        ioc_repo = IocRepository(db)
        official_set = {d.lower() for d in settings.OFFICIAL_DOMAINS}
        linked_ioc_ids: List[str] = []

        if artifacts.sender_domain and artifacts.sender_domain not in official_set:
            existing_sender = await ioc_repo.find_entries([artifacts.sender_domain])
            if not any(e.list_type == WHITELIST for e in existing_sender):
                ioc_row, _ = await ioc_repo.upsert(
                    ioc_type="DOMAIN",
                    value=artifacts.sender_domain,
                    list_type=BLACKLIST,
                    confidence=evaluation.risk_score,
                    source="INLINE_DETECTION",
                    ttl_days=None,
                    created_by=actor_email,
                )
                linked_ioc_ids.append(ioc_row.id)

        for n_url in pipeline_meta["normalized_urls"][:10]:
            u_dom = domain_of(n_url)
            if u_dom in official_set:
                continue
            existing_url = await ioc_repo.find_entries([n_url, u_dom])
            if any(e.list_type == WHITELIST for e in existing_url):
                continue
            url_ioc, _ = await ioc_repo.upsert(
                ioc_type="URL",
                value=n_url[:500],
                list_type=BLACKLIST,
                confidence=evaluation.risk_score,
                source="INLINE_DETECTION",
                ttl_days=None,
                created_by=actor_email,
            )
            linked_ioc_ids.append(url_ioc.id)

        if artifacts.originating_ip:
            ip_ioc, _ = await ioc_repo.upsert(
                ioc_type="IP",
                value=artifacts.originating_ip,
                list_type=BLACKLIST,
                confidence=max(70, evaluation.risk_score),
                source="INLINE_DETECTION",
                ttl_days=90,
                created_by=actor_email,
            )
            linked_ioc_ids.append(ip_ioc.id)

        inc_repo = IncidentRepository(db)
        inc_row = await inc_repo.create_from_verdict(
            verdict=verdict_row,
            actor_id=actor_email,
            ioc_ids=linked_ioc_ids,
            queue_notification=True,
        )
        incident_id = inc_row.id
        incident_code = inc_row.incident_code

    audit_repo = AuditRepository(db)
    await audit_repo.append(
        user_email=actor_email,
        action=audit_action,
        resource=f"verdict:{verdict_row.correlation_id}",
        payload={
            "verdict_id": verdict_row.id,
            "verdict": evaluation.verdict,
            "risk_score": evaluation.risk_score,
            "action": evaluation.action,
            "channel": request.channel,
            "reported_by_user": request.reported_by_user,
            "incident_id": incident_id,
            "incident_code": incident_code,
            "latency_ms": latency_ms,
        },
        client_ip=client_ip,
    )

    iso_ts = now_dt.isoformat()
    return EmailAnalysisResponse(
        id=verdict_row.id,
        correlation_id=correlation_id,
        timestamp=iso_ts,
        created_at=iso_ts,
        channel=request.channel,
        sender=request.sender,
        sender_email=artifacts.sender_email or request.sender,
        sender_domain=artifacts.sender_domain,
        recipient=request.recipient,
        subject=request.subject,
        risk_score=evaluation.risk_score,
        severity=severity,
        verdict=evaluation.verdict,
        action=evaluation.action,
        summary=evaluation.summary,
        incident_triggered=incident_triggered,
        incident_id=incident_id,
        incident_code=incident_code,
        latency_ms=latency_ms,
        urls=list(pipeline_meta["normalized_urls"]),
        attachments=list(request.attachments or []),
        llm_classification=dict(pipeline_meta["llm"]),
        enrichment=dict(pipeline_meta["enrichment"]),
        signals=[
            SignalDto(
                name=s.name,
                weight=s.weight,
                score=round(float(s.score), 4),
                reason=s.reason,
                metadata=dict(s.metadata or {}),
            )
            for s in evaluation.signals
        ],
    )

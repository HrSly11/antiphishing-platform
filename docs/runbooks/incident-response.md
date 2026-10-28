# Banking SOC Phishing Incident Response Runbook (SOP-SOC-IR-001)

## 1. Purpose and Scope
This Standard Operating Procedure (SOP) governs the 24/7 detection, triage, forensic investigation, containment, and closure of phishing, spear-phishing, business email compromise (BEC), smishing (`SMS`), and quishing (`QR`) attacks targeting **BancoCentral** employees, executives, and payment infrastructure.

All incident actions are enforced by a deterministic state machine (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`) and recorded in the append-only, SHA-256 hash-chained `audit_logs` and `incident_events` tables.

---

## 2. Severity Classification and Response SLAs

| Risk Score | Verdict | MTA Gateway Action | Incident Severity | Response SLA | Escalation Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `85 - 100` | `MALICIOUS` | `QUARANTINE` | `CRITICAL` | **15 minutes** | SOC L2 + Duty CISO |
| `70 - 84` | `MALICIOUS` | `QUARANTINE` | `HIGH` | **60 minutes** | SOC L2 |
| `35 - 69` | `SUSPICIOUS` | `TAG_AND_BANNER` | `MEDIUM` (auto if employee-reported) | **4 hours** | SOC L1 Queue |
| `0 - 34` | `CLEAN` | `DELIVER` | `LOW` | **24 hours** | Automated Telemetry |

If an incident remains non-`CLOSED` past `sla_deadline`, `sla_worker` (`POST /api/v1/incidents/escalate-overdue`) sets `is_escalated = true`, logs an `ESCALATED` timeline event, and dispatches an HMAC-SHA256 signed webhook to n8n (`sla_escalation.json`).

---

## 3. Step-by-Step Lifecycle Playbook

### Phase 1: Detection & Automated Intake (`OPEN`)
1. **Inline Inspection**: The corporate MTA or multi-channel collector invokes `POST /api/v1/detection/analyze-email`, `/analyze-eml`, or `/analyze-url`.
2. **Employee Phishing Button**: Employees submitting suspicious messages via `POST /api/v1/detection/report-phishing` set `reported_by_user = true`, lowering the automatic incident threshold to `risk_score >= 35`.
3. **Auto-Quarantine & IOC Extraction**: Messages scoring `>= 70` are quarantined before mailbox delivery; sender domains, malicious URLs, and originating IPs are linked in `incident_iocs`.

### Phase 2: Initial Triage (`OPEN -> TRIAGED`) — SOC L1
1. Inspect authentication headers (`Authentication-Results`, `Received-SPF`, `DKIM-Signature`, `DMARC`). Pay critical attention to `WHITELISTED_DOMAIN_SPOOFING` where an attacker spoofs `bancocentral.com` with failing SPF/DMARC.
2. Inspect Unicode IDN / Punycode homographs (`SENDER_HOMOGRAPH`, `URL_HOMOGRAPH` — e.g., Cyrillic `о` `U+043E` in `bancоcentral.com`), Levenshtein brand typosquatting, and deceptive HTML `<a href>` anchors.
3. Assign the ticket (`POST /api/v1/incidents/{id}/assign`) and transition status to `TRIAGED`.
4. Label false alarms immediately (`PATCH /api/v1/detection/verdicts/{verdict_id}/label` with `FALSE_POSITIVE`) and evaluate whether a vetted partner domain requires `WHITELIST` onboarding by SOC L2.

### Phase 3: Deep Forensic Investigation (`TRIAGED -> INVESTIGATING`) — SOC L2
1. Run the LangChain URL Threat Investigation Agent (`POST /api/v1/assistant/investigate-url`) to correlate `pg_trgm` brand similarity, RDAP domain registration age (`NEWLY_REGISTERED_DOMAIN < 30 days`), DNS A/MX records, and TLS X.509 certificate validity.
2. Execute unified `pg_trgm` Threat Hunting (`GET /api/v1/threat-hunting/search?q=<domain_or_ip>`) to identify all internal recipients targeted by the same campaign across `EMAIL`, `SMS`, `WEB`, and `QR`.
3. Check Identity Provider (Microsoft Entra ID / LDAPS) authentication logs to verify whether any recipient clicked the lure or submitted credentials / TOTP codes.
4. Record structured forensic findings via `POST /api/v1/incidents/{id}/notes`.

### Phase 4: Containment & Eradication (`INVESTIGATING -> CONTAINED`) — SOC L2
1. **Perimeter & IOC Block**: Upsert confirmed attacker domains, URLs, IPs, and SHA-256 payload hashes into the institutional `BLACKLIST` (`POST /api/v1/iocs` with `confidence_score >= 90`), triggering `critical_ioc_notification.json` in n8n to push firewall/DNS sinkhole blocks.
2. **Mailbox Purge**: Issue Exchange/M365 or gateway search-and-purge commands for all messages matching the sender or `url_hash`.
3. **Account Remediation (if clicked)**: Revoke active refresh/SSO tokens, force password reset under PCI-DSS 8.3 policy, re-enroll RFC 6238 TOTP MFA, and isolate endpoints if dangerous attachments (`.exe`, `.scr`, `.hta`, `.iso`, double extensions) were opened.
4. Transition incident to `CONTAINED`.

### Phase 5: Closure & Post-Incident Evidence (`CONTAINED -> CLOSED`)
1. Generate an executive CISO summary (`POST /api/v1/incidents/{id}/summarize`) mapped to PCI-DSS v4.0 and ISO/IEC 27001:2022 controls.
2. Transition to `CLOSED` supplying a mandatory `resolution` (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN_POLICY_VIOLATION`, or `DUPLICATE`). PostgreSQL check constraint `ck_incidents_closed_has_resolution` strictly rejects closure without a resolution.
3. Verify cryptographic audit integrity via `GET /api/v1/audit/verify-chain`.

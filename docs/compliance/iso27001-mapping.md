# ISO/IEC 27001:2022 Annex A Control Mapping

## 1. Purpose
This document aligns the **BancoCentral Antiphishing Platform** with the Information Security Management System (ISMS) controls of **ISO/IEC 27001:2022 Annex A**.

---

## 2. Annex A Control Mapping

### Organizational Controls (Clause 5)
- **A.5.7 Threat Intelligence**:
  - Automated ingestion of OpenPhish and PhishTank feeds (`POST /api/v1/dataset/ingest`) with immutable `SHA-256` raw-feed provenance (`dataset_versions`), license attribution, URL normalization/deduplication (`phishing_samples`), and `pg_trgm` fuzzy correlation (`GET /api/v1/threat-hunting/search`).
- **A.5.15 Access Control & A.5.17 Authentication Information**:
  - Role-based access control separating administrative duties (`ADMIN`), operational containment (`SOC_L2`), triage (`SOC_L1`), independent audit (`AUDITOR`), and executive read-only visibility (`VIEWER`).
  - Short-lived signed JWT access tokens (`30 min`), refresh token rotation (`8 hours`), Argon2id password storage, and RFC 6238 TOTP multi-factor authentication.
- **A.5.24 Information Security Incident Management Planning**:
  - Formalized operational playbooks (`docs/runbooks/incident-response.md`, `etl-failure.md`, `llm-degradation.md`) indexed directly into the SOC RAG Assistant (`POST /api/v1/assistant/chat`).
- **A.5.25 Assessment and Decision on Information Security Events**:
  - Explainable risk scoring (`0 - 100`) decomposing every verdict into weighted signals (`SPF_FAIL`, `DMARC_FAIL`, `SENDER_HOMOGRAPH`, `DECEPTIVE_HTML_ANCHOR`, `IOC_BLACKLIST_MATCH`, `LLM_PHISHING_INTENT`) with analyst feedback labeling (`TRUE_POSITIVE` / `FALSE_POSITIVE`) to track precision and recall.
- **A.5.26 Response to Information Security Incidents**:
  - Enforced lifecycle transitions (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`), SLA breach escalation, durable `notification_outbox` delivery, and signed n8n SOAR workflows.
- **A.5.28 Collection of Evidence**:
  - Tamper-evident hash-chained `audit_logs` and immutable `incident_events` timelines suitable for regulatory and forensic examination.

### People Controls (Clause 6)
- **A.6.3 Information Security Awareness, Education and Training**:
  - Departmental phishing simulation campaigns (`simulation_campaigns`, `simulation_events`) measuring real click susceptibility and reporting reflexes across corporate units.

### Technological Controls (Clause 8)
- **A.8.7 Protection Against Malware**:
  - Inline screening of dangerous executable/script attachments (`.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.hta`, `.iso`) and double-extension evasion (`factura.pdf.exe`).
- **A.8.15 Logging & A.8.16 Monitoring Activities**:
  - Structured JSON logging with `X-Correlation-ID` propagation, Prometheus metrics (`/metrics`), Grafana operational/business dashboards, and scheduled PDF/DOCX/XLSX compliance exports.
- **A.8.23 Web Filtering & A.8.28 Secure Coding**:
  - Active IOC `BLACKLIST` synchronization for malicious domains/URLs/IPs and hexagonal domain isolation free of external framework coupling.

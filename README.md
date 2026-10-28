# BancoCentral Enterprise Antiphishing Platform

Enterprise-grade banking phishing detection, SOC incident response, threat hunting, employee awareness simulation, and regulatory compliance platform built on **Hexagonal Architecture (Ports & Adapters)** and **Selective CQRS**.

---

## Architectural Highlights

- **Multi-Channel Inline Detection (`EMAIL`, `SMS`, `WEB`, `QR`)**:
  - SPF / DKIM / DMARC authentication alignment & `WHITELISTED_DOMAIN_SPOOFING` detection.
  - Unicode IDN / Punycode homograph detection (e.g., Cyrillic `о` in `bancоcentral.com`), Levenshtein brand typosquatting, Shannon domain entropy, deceptive HTML `<a href>` mismatch, raw IP links, and dangerous executable/double-extension attachment screening.
  - Explicit `WHITELIST` vs Spoofing vs `BLACKLIST` precedence + bounded DNS/TLS/RDAP domain-age enrichment (`whois_dns_tls.py`).
  - Full RFC 822 `.eml` multipart parser (`POST /api/v1/detection/analyze-eml`) and one-click employee `"Reportar phishing"` intake (`POST /api/v1/detection/report-phishing`).
- **On-Premise AI & Agentic SOC Assistance (`LangChain` + `Ollama` + `LangFlow`)**:
  - Zero cloud data exfiltration (ADR-003): local Ollama (`llama3.2`) with `0.8s` cached health check and deterministic LangChain Runnable fallback (`langchain-deterministic`).
  - XML-delimited prompt-injection sanitization & `PROMPT_INJECTION_ATTEMPT` evasion detection.
  - Grounded SOC RAG Assistant (`POST /api/v1/assistant/chat`) indexing `docs/{runbooks,compliance,architecture}` + live PostgreSQL KPIs.
  - Multi-tool URL Threat Investigation Agent (`POST /api/v1/assistant/investigate-url`) and versioned LangFlow v1 visual sandboxes (`backend/langflow/flows/`).
- **SOC Incident Lifecycle, SLA Worker & Self-Hosted `n8n` SOAR**:
  - Enforced state machine (`OPEN -> TRIAGED -> INVESTIGATING -> CONTAINED -> CLOSED`) with mandatory closure resolutions (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `BENIGN_POLICY_VIOLATION`, `DUPLICATE`).
  - Severity-driven SLAs (`15m` CRITICAL, `60m` HIGH, `4h` MEDIUM), automatic overdue escalation (`sla_worker`), durable `notification_outbox`, and 5 HMAC-SHA256 signed `n8n` SOAR workflows (`backend/n8n/workflows/`).
- **Dataset Governance & `pg_trgm` Threat Hunting**:
  - Idempotent **OpenPhish** & **PhishTank** ETL (`etl_worker`) with raw SHA-256 dataset versioning (`dataset_versions`), normalized URL deduplication (`phishing_samples`), and unified PostgreSQL `pg_trgm` fuzzy search across verdicts, IOCs, and samples.
- **Enterprise IAM, Tamper-Evident Audit & Multi-Format Reporting**:
  - 5 granular RBAC roles (`ADMIN`, `SOC_L2`, `SOC_L1`, `AUDITOR`, `VIEWER`), Argon2id hashing, 12-character PCI-DSS 8.3 password policy, 5-attempt / 15-minute lockout (`HTTP 423`), and RFC 6238 TOTP MFA.
  - Append-only `audit_logs` enforced by PostgreSQL triggers (`trg_audit_logs_no_update_delete`) and SHA-256 cryptographic hash chaining (`GET /api/v1/audit/verify-chain`).
  - Real binary **PDF** (`reportlab`), **DOCX** (`python-docx`), and **XLSX** (`openpyxl`) report exports + scheduled delivery (`report_worker`).

---

## Demo Accounts (Seeded by `app.scripts.seed`)

| Role | Email | Strong Password | Key Capabilities |
| :--- | :--- | :--- | :--- |
| **`ADMIN`** | `admin@bancocentral.com` | `Admin#Banco2026!` | Full platform access: User & RBAC admin, ETL ingestion, IOCs, Incidents, Audit, Reports |
| **`SOC_L2`** | `socl2@bancocentral.com` | `SocL2#Banco2026!` | Incident containment/closure, IOC Blacklist/Whitelist management, Threat Hunting, Audit, Schedule management |
| **`SOC_L1`** | `socl1@bancocentral.com` | `SocL1#Banco2026!` | Inline analysis, Verdict labeling (`TP`/`FP`), Incident triage & investigation, Threat Hunting |
| **`AUDITOR`** | `auditor@bancocentral.com` | `Auditor#Banco2026!` | Append-only Audit logs, SHA-256 chain verification, PCI-DSS/ISO 27001/GDPR compliance posture, Reports |
| **`VIEWER`** | `viewer@bancocentral.com` | `Viewer#Banco2026!` | Read-only Executive Dashboard KPIs, Verdicts, Incidents, Dataset info, Report downloads |

---

## Quick Start (Local Development — PostgreSQL 18 + FastAPI + React)

### 1. Backend Setup, Migrations & Seed
```powershell
cd backend
python -m alembic upgrade head
$env:PYTHONPATH = "."
python -m app.scripts.seed
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup
```powershell
cd frontend
npm install
npm run dev
```

- **Web Console**: `http://localhost:5173`
- **Swagger UI / OpenAPI**: `http://localhost:8000/docs`
- **Health / Readiness / Prometheus**: `http://localhost:8000/health`, `/ready`, `/metrics`

---

## Repository Structure

```text
antiphishing-platform/
├── backend/
│   ├── alembic/                  # Migrations 0001..0006 (schema, RBAC, pg_trgm, SLA, append-only audit, simulation & MFA)
│   ├── app/
│   │   ├── domain/               # Pure business rules (scoring, heuristics, RBAC, password policy, lifecycle, SLA)
│   │   ├── application/          # CQRS commands, queries, and Pydantic v2 DTOs
│   │   ├── adapters/             # PostgreSQL repos, OpenPhish/PhishTank feeds, LangChain/Ollama, PDF/DOCX/XLSX, n8n
│   │   ├── api/                  # FastAPI middlewares, dependencies, and 13 v1 routers
│   │   ├── workers/              # CLI & background workers (etl_worker, sla_worker, report_worker)
│   │   └── scripts/              # Idempotent seed, OpenAPI/Postman generator, MTA simulator
│   ├── dataset/                  # Offline OpenPhish & PhishTank fixtures, JSON schemas, license provenance
│   ├── langflow/flows/           # Exported LangFlow v1 visual AI sandboxes
│   └── n8n/workflows/            # 5 self-hosted n8n SOAR workflow JSONs
├── frontend/                     # React 18 + TypeScript + Tailwind CSS + Recharts SOC Console
├── docs/                         # Architecture ADRs, Mermaid diagrams, SOC Runbooks (RAG KB), Compliance & OpenAPI
└── infra/                        # Kubernetes manifests, HPA, Ingress, Prometheus, Alertmanager, Loki & Grafana
```

# Self-Hosted n8n SOAR Workflows (`backend/n8n/`)

## 1. Security & Authentication Contract
All communication between the FastAPI core (`antiphishing-backend`) and self-hosted `n8n` follows **ADR-004**:
- **Backend -> n8n (Outbound Webhooks)**: Signed with `X-Antiphish-Signature: sha256=<HMAC_HEX>`, `X-Antiphish-Timestamp: <unix_epoch>`, and `Idempotency-Key: <dedupe_key>` computed over `<timestamp>.<canonical_json_body>` using `N8N_WEBHOOK_SECRET` (implemented in `app/adapters/notifications/webhook.py` and `app/adapters/n8n/client.py`).
- **n8n -> Backend (Inbound API Calls)**: Authenticated via the `X-Service-Key: <N8N_SERVICE_KEY>` header against `/api/v1/...` service endpoints.

## 2. Included Importable Workflows (`workflows/*.json`)
1. **`etl_phishing_dataset.json`**: Runs every 6 hours -> calls `POST /api/v1/dataset/ingest` (`X-Service-Key`) to pull OpenPhish/PhishTank feeds with SHA-256 dataset versioning -> alerts SOC ChatOps if status != `COMPLETED`.
2. **`phishing_report_triage.json`**: Receives signed `/webhook/phishing-report` events -> verifies `X-Antiphish-Signature` HMAC -> calls `POST /api/v1/detection/analyze-email` (`reported_by_user=true`) -> pages SOC on `risk_score >= 70` or sends triage receipt on `< 70`.
3. **`sla_escalation.json`**: Polls every 5 minutes + listens on `/webhook/incident-escalated` -> calls `POST /api/v1/incidents/escalate-overdue` -> pages SOC L2 & CISO duty channel when overdue incidents breach SLA.
4. **`daily_report.json`**: Runs daily at `07:00 UTC` -> fetches 24h KPIs (`GET /api/v1/dashboard/kpis?window_days=1`) -> generates PDF (`POST /api/v1/reports/generate`) -> emails CISO and Audit distribution lists.
5. **`critical_ioc_notification.json`**: Receives signed `/webhook/critical-ioc` alerts -> verifies HMAC & `Idempotency-Key` -> upserts indicator into `POST /api/v1/iocs` (`BLACKLIST`) -> broadcasts perimeter firewall/MTA block confirmation.

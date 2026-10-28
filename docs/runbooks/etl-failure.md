# Public Phishing Threat Feed ETL Failure Runbook (SOP-SOC-ETL-002)

## 1. Overview
The platform ingests verified phishing intelligence every 6 hours from **OpenPhish** (`https://openphish.com/feed.txt`) and **PhishTank** (`https://data.phishtank.com/data/online-valid.csv`) via n8n (`etl_phishing_dataset.json`) or `app.workers.etl_worker`.

Every ingestion run is hashed (`SHA-256`) and versioned in `dataset_versions`, normalized and deduplicated by `url_hash` (`ON CONFLICT (url_hash) DO NOTHING`) in `phishing_samples`, and optionally synchronized into active `BLACKLIST` IOCs (`iocs`).

---

## 2. Failure Symptoms & Alerting
- **n8n Alert**: `[HIGH] Threat Feed ETL Failure` emitted by `etl_phishing_dataset.json` to the SOC ChatOps channel.
- **Stale Feed Metric**: `GET /api/v1/dataset/versions` shows no new `COMPLETED` version within the last 12 hours.
- **Common Root Causes**:
  1. Upstream HTTP `429 Too Many Requests` or `503` on PhishTank / OpenPhish public endpoints.
  2. Egress proxy or DNS resolution outage in the DMZ worker subnet.
  3. SSRF guard rejection (`app/adapters/feeds/`) if an upstream redirect points to a private/loopback RFC 1918 address.
  4. Schema drift in upstream CSV columns.

---

## 3. Diagnostic Steps
1. **Check Database Readiness & Recent Versions**:
   ```bash
   curl -s http://localhost:8000/ready
   curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/dataset/info
   ```
2. **Inspect Structured JSON Logs**:
   Filter API and worker logs by `"logger": "worker.etl"` or `"action": "DATASET_INGESTED"` using `correlation_id`.
3. **Verify Upstream Reachability & TLS**:
   Confirm outbound HTTPS (`443`) to `openphish.com` and `data.phishtank.com` from the worker container without bypassing SSRF private-IP protections.

---

## 4. Recovery & Deterministic Offline Fallback Procedure
The feed adapters (`app/adapters/feeds/openphish.py` and `phishtank.py`) are architected for zero-downtime resilience:

1. **Automatic Offline Fallback**: When `prefer_live=true` encounters an upstream timeout or HTTP error, the loader automatically falls back to the curated local snapshots (`backend/dataset/samples/openphish_sample.txt` and `phishtank_sample.csv`) so baseline coverage remains intact.
2. **Manual CLI Re-Ingestion**:
   ```bash
   PYTHONPATH=backend python -m app.workers.etl_worker --sources openphish phishtank
   ```
3. **API-Driven Ingestion (Service Key or Admin JWT)**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/dataset/ingest \
     -H "X-Service-Key: $N8N_SERVICE_KEY" \
     -H "Content-Type: application/json" \
     -d '{"source": "openphish_sample", "sync_blacklist": true}'
   ```
4. **Post-Recovery Verification**:
   - Confirm `status == "COMPLETED"` and non-empty `sha256` in `GET /api/v1/dataset/versions`.
   - Confirm shared hosting / URL shortener domains (`bit.ly`, `github.io`, `docs.google.com`) and `OFFICIAL_DOMAINS` (`bancocentral.com`) were NOT domain-blacklisted (only exact phishing URLs are blacklisted for shared hosts).

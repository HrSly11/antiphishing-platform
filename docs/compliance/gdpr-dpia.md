# Data Protection Impact Assessment (DPIA) — GDPR & Banking Secrecy

## 1. Context & Processing Purpose
The **BancoCentral Antiphishing Platform** inspects inbound electronic communications (`EMAIL`, `SMS`, `WEB`, `QR`) addressed to bank personnel to prevent credential theft, fraudulent wire transfers, malware delivery, and unauthorized disclosure of customer financial records.

- **Lawful Basis (GDPR Art. 6(1)(f) & Recital 49)**: Processing is strictly necessary for network and information security of a regulated financial institution.
- **Special Category / Banking Secrecy Alignment**: Designed under Privacy by Design and Default (**GDPR Art. 25**) and Security of Processing (**GDPR Art. 32**).

---

## 2. Data Sovereignty & Zero Cloud Exfiltration (ADR-003)
A primary privacy risk in modern AI-assisted security tools is sending raw employee/customer emails to third-party SaaS LLMs. This platform eliminates that risk architecturally:
1. **100% On-Premise Execution**: Heuristic scoring, PostgreSQL persistence, n8n SOAR workflows, and LangChain/Ollama (`llama3.2`) inference run entirely within the bank's controlled infrastructure.
2. **Bounded Network Enrichment**: External DNS, TLS, and RDAP lookups (`whois_dns_tls.py`) transmit **only** extracted untrusted external domain names—never sender/recipient identities, subject lines, or message bodies.

---

## 3. Data Minimization & Purpose Limitation (GDPR Art. 5)
- **Minimal Metadata Retention**: `detection_verdicts` persists sender/recipient addresses, subject, header authentication summaries, risk signals, and normalized indicator URLs—avoiding full raw attachment binaries in relational storage.
- **Simulation Ethics**: Awareness campaigns (`simulation_campaigns`) record interaction state (`SENT`, `OPENED`, `CLICKED`, `REPORTED`) solely for aggregate departmental training metrics (`compromise_risk`), never storing any characters typed into simulated landing pages.
- **Role-Restricted Visibility**: `VIEWER` and `AUDITOR` roles are restricted from modifying IOCs or user accounts; full user directory management requires `ADMIN` (`users:read`, `users:write`).

---

## 4. Technical & Organizational Safeguards (GDPR Art. 32 & Art. 33)
1. **Cryptographic Credentials**: Passwords hashed exclusively with Argon2id; JWT tokens signed with `HS256` institutional secrets; optional step-up RFC 6238 TOTP MFA.
2. **Tamper-Evident Accountability**: Every administrative action, login failure, report export, and incident transition is recorded in `audit_logs` with SHA-256 hash chaining (`GET /api/v1/audit/verify-chain`).
3. **Rapid Breach Triage (GDPR Art. 33 — 72h Supervisory Window)**: `CRITICAL` phishing incidents carry a **15-minute** triage SLA and automated escalation so potential personal-data exposure is contained and assessed for supervisory notification well within statutory timelines.

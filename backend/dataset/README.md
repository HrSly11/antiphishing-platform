# Public Phishing Threat Datasets & ETL Traceability

## 1. Curated Public Threat Intelligence Sources

### A. OpenPhish Community Feed
- **Endpoint**: `https://openphish.com/feed.txt`
- **Local Offline Fixture**: `backend/dataset/samples/openphish_sample.txt` (65 curated banking, SSO, IDN homograph, raw-IP, shortener, and QR/quishing URLs)
- **License**: OpenPhish Community Terms of Service (permitted for internal enterprise security operations, SOC defense, and academic evaluation).
- **Format**: UTF-8 plain text, one active phishing URL per line, refreshed every 6 hours (~2,000–8,000 active URLs in live feed).

### B. PhishTank Verified Community Feed
- **Endpoint**: `https://data.phishtank.com/data/online-valid.csv`
- **Local Offline Fixture**: `backend/dataset/samples/phishtank_sample.csv` (65 verified phishing records targeting regional and global financial institutions)
- **License**: PhishTank Developer License (free for defensive security and research with source attribution to PhishTank / Cisco Talos).
- **Schema (`phishtank_sample.csv`)**:
  - `phish_id` (`integer`): Unique PhishTank submission identifier.
  - `url` (`string`): Confirmed malicious URL.
  - `phish_detail_url` (`string`): Public verification record URL.
  - `submission_time` (`ISO-8601 UTC timestamp`): Initial submission timestamp.
  - `verified` (`yes | no`): Community verification status.
  - `verification_time` (`ISO-8601 UTC timestamp`): Verification completion timestamp.
  - `online` (`yes | no`): Reachability status at export time.
  - `target` (`string`): Impersonated bank or enterprise brand.

---

## 2. Immutable SHA-256 Versioning & ETL Pipeline

1. **Extraction (`app/adapters/feeds/{openphish,phishtank}.py`)**:
   - Enforces HTTPS transport and SSRF host/IP validation (`is_public_hostname_and_ips`) before live feed retrieval.
   - Falls back deterministically to `backend/dataset/samples/` fixtures when offline or rate-limited.
2. **Canonicalization (`app/domain/dataset/versioning.py`)**:
   - Normalizes scheme and lowercase hostname, strips URL fragments (`#...`) and tracking query parameters (`utm_*`, `fbclid`, `gclid`, `mc_*`).
   - Computes `url_hash = SHA256(normalized_url)` and extracts lowercase `domain`.
3. **Deduplicated Persistence (`app/adapters/persistence/repositories/dataset_repository.py`)**:
   - Computes `sha256_bytes(raw_bytes)` over the exact raw feed payload and creates an immutable `dataset_versions` row (`total_records`, `new_records`, `duplicate_records`, `invalid_records`, `triggered_by`, `created_at`).
   - Inserts `phishing_samples` in chunks using PostgreSQL `ON CONFLICT (url_hash) DO NOTHING`.
   - Optionally synchronizes malicious URLs and non-shared-hosting domains into `iocs` (`list_type='BLACKLIST'`, `ON CONFLICT ON CONSTRAINT uq_ioc_value_list DO NOTHING`) for real-time inline MTA blocking and `pg_trgm` fuzzy lookups.

-- Primary deterministic seeding is executed via `python -m app.scripts.seed`
-- (ensures Argon2id password hashes, SHA-256 dataset lineage, and chained `audit_logs`).
SELECT name, applied_at FROM seed_runs ORDER BY applied_at DESC;

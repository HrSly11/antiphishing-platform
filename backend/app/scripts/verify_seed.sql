-- Verification query suite for seeded PostgreSQL `antiphishing_db`
SELECT 'users' AS table_name, COUNT(*) AS row_count FROM users
UNION ALL
SELECT 'detection_verdicts', COUNT(*) FROM detection_verdicts
UNION ALL
SELECT 'incidents', COUNT(*) FROM incidents
UNION ALL
SELECT 'incident_events', COUNT(*) FROM incident_events
UNION ALL
SELECT 'iocs', COUNT(*) FROM iocs
UNION ALL
SELECT 'dataset_versions', COUNT(*) FROM dataset_versions
UNION ALL
SELECT 'phishing_samples', COUNT(*) FROM phishing_samples
UNION ALL
SELECT 'simulation_campaigns', COUNT(*) FROM simulation_campaigns
UNION ALL
SELECT 'simulation_events', COUNT(*) FROM simulation_events
UNION ALL
SELECT 'report_schedules', COUNT(*) FROM report_schedules
UNION ALL
SELECT 'audit_logs', COUNT(*) FROM audit_logs
ORDER BY table_name;

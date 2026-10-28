-- Clean operational seed data while respecting append-only `audit_logs` triggers.
DELETE FROM simulation_events;
DELETE FROM simulation_campaigns;
DELETE FROM incident_iocs;
DELETE FROM incident_events;
DELETE FROM incidents;
DELETE FROM detection_verdicts;
DELETE FROM report_schedules;
DELETE FROM seed_runs WHERE name = 'v2_enterprise_banking_soc_2026';

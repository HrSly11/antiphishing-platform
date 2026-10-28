"""Prometheus metrics exposed at /api/v1/metrics."""
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

registry = CollectorRegistry()

ANALYSES_TOTAL = Counter(
    "antiphish_analyses_total", "Emails analysed", ["verdict", "action"], registry=registry
)
ANALYSIS_LATENCY = Histogram(
    "antiphish_analysis_latency_seconds", "End-to-end analysis latency",
    buckets=(0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0), registry=registry,
)
HTTP_REQUESTS = Counter(
    "antiphish_http_requests_total", "HTTP requests", ["method", "status"], registry=registry
)
INCIDENTS_OPEN = Gauge("antiphish_incidents_open", "Open incidents", registry=registry)
INCIDENTS_ESCALATED = Counter(
    "antiphish_incidents_escalated_total", "Incidents escalated by SLA", registry=registry
)
OUTBOX_PENDING = Gauge("antiphish_outbox_pending", "Pending outbox notifications", registry=registry)
LLM_CALLS = Counter("antiphish_llm_calls_total", "LLM classifications", ["engine"], registry=registry)


def render_metrics() -> bytes:
    return generate_latest(registry)

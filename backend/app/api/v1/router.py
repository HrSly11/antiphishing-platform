"""Master API v1 router mounting all bounded-context endpoints."""
from fastapi import APIRouter

from app.api.v1 import (
    assistant,
    audit,
    auth,
    dashboard,
    dataset,
    detection,
    health,
    incidents,
    iocs,
    reports,
    simulation,
    threat_hunting,
    users,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Auth"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(detection.router, prefix="/detection", tags=["Detection"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["IOCs"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(dataset.router, prefix="/dataset", tags=["Dataset"])
api_router.include_router(simulation.router, prefix="/simulation", tags=["Simulation"])
api_router.include_router(threat_hunting.router, prefix="/threat-hunting", tags=["Threat Hunting"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_router.include_router(assistant.router, prefix="/assistant", tags=["Assistant"])

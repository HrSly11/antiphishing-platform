"""Global pytest configuration and isolated `antiphishing_test_db` fixtures.

Guarantees that running `pytest` NEVER connects to, modifies, or wipes the live
`antiphishing_db` development database served by Uvicorn.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Tuple

TEST_DB_NAME = "antiphishing_test_db"
TEST_DATABASE_URL = f"postgresql+asyncpg://postgres:12345@127.0.0.1:5432/{TEST_DB_NAME}"
POSTGRES_ADMIN_DSN = "postgresql://postgres:12345@127.0.0.1:5432/postgres"
TEST_ASYNCPG_DSN = f"postgresql://postgres:12345@127.0.0.1:5432/{TEST_DB_NAME}"

# Enforce isolated test environment BEFORE importing any application modules.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL
os.environ["LLM_PROVIDER"] = "none"
os.environ["ENRICHMENT_ENABLED"] = "false"
os.environ["WORKERS_ENABLED"] = "false"

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import asyncpg  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
from httpx import ASGITransport  # noqa: E402
from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

import app.adapters.persistence.database as database_module  # noqa: E402
from app.adapters.persistence.database import get_db as db_get_db  # noqa: E402
from app.adapters.persistence.models.ioc import IocModel  # noqa: E402
from app.adapters.persistence.models.user import UserModel  # noqa: E402
from app.adapters.persistence.repositories.audit_repository import (  # noqa: E402
    AuditRepository,
)
from app.api.deps import get_db as deps_get_db  # noqa: E402
from app.api.v1.auth import login_rate_limiter  # noqa: E402
from app.api.v1.detection import gateway_limiter  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.main import app  # noqa: E402

# Safety invariant: abort immediately if DATABASE_URL ever points outside antiphishing_test_db.
assert settings.DATABASE_URL == TEST_DATABASE_URL, (
    f"Refusing to run tests against non-isolated database: {settings.DATABASE_URL}"
)
assert not settings.DATABASE_URL.endswith("/antiphishing_db")

if not settings.GATEWAY_API_KEY:
    settings.GATEWAY_API_KEY = "test-gateway-api-key-2026"
if not settings.N8N_SERVICE_KEY:
    settings.N8N_SERVICE_KEY = "test-n8n-service-key-2026"

# NullPool prevents asyncpg connections from binding across closed function-scoped event loops on Windows.
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
    future=True,
    poolclass=NullPool,
)
TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=AsyncSession,
)

database_module.engine = test_engine
database_module.async_session_factory = TestingSessionLocal


async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


app.dependency_overrides[deps_get_db] = _override_get_db
app.dependency_overrides[db_get_db] = _override_get_db

TEST_USERS: List[Tuple[str, str, str, str]] = [
    ("admin@bancocentral.com", "Admin#Banco2026!", "Valeria Mendoza — CISO Admin", "ADMIN"),
    ("socl2@bancocentral.com", "SocL2#Banco2026!", "Carlos Paredes — SOC L2 Responder", "SOC_L2"),
    ("socl1@bancocentral.com", "SocL1#Banco2026!", "Lucia Rojas — SOC L1 Analyst", "SOC_L1"),
    ("auditor@bancocentral.com", "Auditor#Banco2026!", "Ricardo Soto — Internal Auditor", "AUDITOR"),
    ("viewer@bancocentral.com", "Viewer#Banco2026!", "Elena Vargas — Risk Viewer", "VIEWER"),
]

BASELINE_WHITELIST: List[Tuple[str, str, str]] = [
    ("DOMAIN", "bancocentral.com", "Official Corporate Primary Domain"),
    ("DOMAIN", "pagos.bancocentral.com", "Official Treasury Portal"),
    ("DOMAIN", "alertas.bancocentral.com", "Official Transactional Subdomain"),
    ("IP", "200.48.225.10", "Corporate Outbound MTA Relay"),
]

BASELINE_BLACKLIST: List[Tuple[str, str, int, str]] = [
    ("DOMAIN", "banc\u043ecentral.com", 100, "SOC Homograph Hunter (Cyrillic U+043E)"),
    ("DOMAIN", "xn--banccentral-9ib.com", 100, "IDN Punycode Brand Spoofing"),
    ("DOMAIN", "banc0central.com", 98, "Levenshtein Typosquatting Block"),
    ("DOMAIN", "bancocentral-seguridad.com", 98, "Verified Banking Phishing Lure"),
    ("DOMAIN", "actualizar-token-bancario.net", 95, "Credential Harvester Block"),
    ("DOMAIN", "qr-login-bancocentral.top", 96, "QR Quishing OAuth Trap"),
    ("IP", "185.220.101.5", 95, "Hostile Bulletproof Relay"),
]


async def _recreate_test_database() -> None:
    assert TEST_DB_NAME == "antiphishing_test_db"
    admin_conn = await asyncpg.connect(POSTGRES_ADMIN_DSN)
    try:
        await admin_conn.execute(
            """
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = $1 AND pid <> pg_backend_pid()
            """,
            TEST_DB_NAME,
        )
        await admin_conn.execute(f'DROP DATABASE IF EXISTS "{TEST_DB_NAME}"')
        await admin_conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
    finally:
        await admin_conn.close()

    ext_conn = await asyncpg.connect(TEST_ASYNCPG_DSN)
    try:
        await ext_conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    finally:
        await ext_conn.close()


async def _seed_baseline_data() -> None:
    seed_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, future=True)
    seed_session_factory = async_sessionmaker(
        bind=seed_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    now = datetime.now(timezone.utc)
    try:
        async with seed_session_factory() as db:
            for email, password, full_name, role in TEST_USERS:
                db.add(
                    UserModel(
                        id=str(uuid.uuid4()),
                        email=email,
                        hashed_password=hash_password(password),
                        full_name=full_name,
                        role=role,
                        is_active=True,
                        mfa_enabled=False,
                        created_at=now - timedelta(days=10),
                    )
                )
            await db.flush()

            for ioc_type, val, reason in BASELINE_WHITELIST:
                await db.execute(
                    pg_insert(IocModel)
                    .values(
                        id=str(uuid.uuid4()),
                        ioc_type=ioc_type,
                        ioc_value=val.lower(),
                        list_type="WHITELIST",
                        confidence_score=100,
                        source=reason,
                        is_active=True,
                        created_by="admin@bancocentral.com",
                        created_at=now - timedelta(days=7),
                    )
                    .on_conflict_do_nothing(constraint="uq_ioc_value_list")
                )

            for ioc_type, val, conf, src in BASELINE_BLACKLIST:
                await db.execute(
                    pg_insert(IocModel)
                    .values(
                        id=str(uuid.uuid4()),
                        ioc_type=ioc_type,
                        ioc_value=val.lower(),
                        list_type="BLACKLIST",
                        confidence_score=conf,
                        source=src,
                        is_active=True,
                        created_by="socl2@bancocentral.com",
                        created_at=now - timedelta(days=5),
                    )
                    .on_conflict_do_nothing(constraint="uq_ioc_value_list")
                )

            await AuditRepository(db).append(
                user_email="admin@bancocentral.com",
                action="TEST_DB_INITIALIZED",
                resource=f"db:{TEST_DB_NAME}",
                payload={"users": len(TEST_USERS), "whitelist": len(BASELINE_WHITELIST)},
                client_ip="127.0.0.1",
            )
            await db.commit()
    finally:
        await seed_engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def setup_isolated_test_database() -> None:
    """Create `antiphishing_test_db`, apply Alembic `upgrade head`, and seed baseline RBAC & IOCs."""
    asyncio.run(_recreate_test_database())

    env = {
        **os.environ,
        "DATABASE_URL": TEST_DATABASE_URL,
        "PYTHONPATH": str(BACKEND_DIR),
    }
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(BACKEND_DIR),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Alembic upgrade head failed on {TEST_DB_NAME}:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )

    asyncio.run(_seed_baseline_data())


@pytest.fixture(autouse=True)
def reset_in_memory_limiters():
    """Reset per-IP sliding window limiters before and after every test."""
    login_rate_limiter.reset()
    gateway_limiter.reset()
    yield
    login_rate_limiter.reset()
    gateway_limiter.reset()


@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a clean NullPool `AsyncSession` bound to `antiphishing_test_db`."""
    async with TestingSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Provide an ASGI `httpx.AsyncClient` against the FastAPI application."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


def make_bearer_headers(email: str, role: str) -> Dict[str, str]:
    token = create_access_token({"sub": email, "role": role})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers() -> Dict[str, str]:
    return make_bearer_headers("admin@bancocentral.com", "ADMIN")


@pytest.fixture
def socl2_headers() -> Dict[str, str]:
    return make_bearer_headers("socl2@bancocentral.com", "SOC_L2")


@pytest.fixture
def socl1_headers() -> Dict[str, str]:
    return make_bearer_headers("socl1@bancocentral.com", "SOC_L1")


@pytest.fixture
def auditor_headers() -> Dict[str, str]:
    return make_bearer_headers("auditor@bancocentral.com", "AUDITOR")


@pytest.fixture
def viewer_headers() -> Dict[str, str]:
    return make_bearer_headers("viewer@bancocentral.com", "VIEWER")

"""Integration & security tests for Auth, JWT integrity, Lockout, Rate-Limit, RBAC, and TOTP MFA."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import jwt

from app.core.security import generate_totp_code


async def test_health_readiness_metrics_and_security_headers(client: httpx.AsyncClient) -> None:
    for path in ("/health", "/api/v1/health"):
        resp = await client.get(path)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-correlation-id")

    ready = await client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["database"] == "connected"

    metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    assert "text/plain" in metrics.headers.get("content-type", "")


async def test_login_me_refresh_rotation_and_logout(client: httpx.AsyncClient) -> None:
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@bancocentral.com", "password": "Admin#Banco2026!"},
    )
    assert login_resp.status_code == 200
    bundle = login_resp.json()
    access_token = bundle["access_token"]
    refresh_token = bundle["refresh_token"]
    assert bundle["user"]["role"] == "ADMIN"
    assert len(bundle["permissions"]) == 15

    me_resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "admin@bancocentral.com"
    assert "users:write" in me_resp.json()["permissions"]

    refresh_resp = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    rotated = refresh_resp.json()
    assert rotated["access_token"] != access_token
    assert rotated["refresh_token"] != refresh_token

    logout_resp = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {rotated['access_token']}"},
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["status"] == "logged_out"


async def test_token_type_confusion_and_tampered_jwt_rejected(client: httpx.AsyncClient) -> None:
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "socl2@bancocentral.com", "password": "SocL2#Banco2026!"},
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()

    # 1. Token type confusion: passing refresh_token as Bearer access token -> 401
    confused_me = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tokens['refresh_token']}"},
    )
    assert confused_me.status_code == 401

    # 2. Reverse confusion: passing access_token to /auth/refresh -> 401
    confused_refresh = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": tokens["access_token"]},
    )
    assert confused_refresh.status_code == 401

    # 3. Tampered signature segment -> 401
    header_b64, payload_b64, _ = tokens["access_token"].split(".")
    tampered_token = f"{header_b64}.{payload_b64}.invalidsignaturesegment999"
    tampered_resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert tampered_resp.status_code == 401

    # 4. Forged JWT signed with attacker secret -> 401
    forged_jwt = jwt.encode(
        {
            "sub": "admin@bancocentral.com",
            "role": "ADMIN",
            "typ": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        },
        "attacker-forged-secret-key-0000000000",
        algorithm="HS256",
    )
    forged_resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {forged_jwt}"},
    )
    assert forged_resp.status_code == 401


async def test_account_lockout_after_five_failures_and_admin_unlock(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    create_resp = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "lockout.analyst@bancocentral.com",
            "full_name": "Lockout Test Analyst",
            "role": "SOC_L1",
            "password": "LockoutUser#2026!",
        },
    )
    assert create_resp.status_code == 201
    user_id = create_resp.json()["id"]

    # 5 consecutive bad password attempts -> 401
    for _ in range(5):
        bad_resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "lockout.analyst@bancocentral.com", "password": "WrongPassword#000!"},
        )
        assert bad_resp.status_code == 401

    # 6th attempt even with the VALID password must be blocked as locked (423 Locked)
    locked_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "lockout.analyst@bancocentral.com", "password": "LockoutUser#2026!"},
    )
    assert locked_resp.status_code in (423, 403)
    assert locked_resp.status_code == 423

    # Admin unlocks account via PATCH /api/v1/users/{id}
    unlock_resp = await client.patch(
        f"/api/v1/users/{user_id}",
        headers=admin_headers,
        json={"unlock": True},
    )
    assert unlock_resp.status_code == 200
    assert unlock_resp.json()["locked"] is False
    assert unlock_resp.json()["failed_login_attempts"] == 0

    # Subsequent login with valid password succeeds
    restored_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "lockout.analyst@bancocentral.com", "password": "LockoutUser#2026!"},
    )
    assert restored_resp.status_code == 200


async def test_login_rate_limiting_returns_429_on_burst(client: httpx.AsyncClient) -> None:
    statuses: list[int] = []
    retry_after_header: str | None = None
    for _ in range(12):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent.probe@bancocentral.com", "password": "Probe#123456!"},
        )
        statuses.append(resp.status_code)
        if resp.status_code == 429:
            retry_after_header = resp.headers.get("retry-after")
            break

    assert 429 in statuses
    assert retry_after_header is not None and int(retry_after_header) >= 1


async def test_rbac_enforcement_denies_viewer_mutations_and_audit(
    client: httpx.AsyncClient,
    viewer_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    # VIEWER is allowed read-only dashboard KPIs
    kpi_ok = await client.get("/api/v1/dashboard/kpis", headers=viewer_headers)
    assert kpi_ok.status_code == 200

    # VIEWER is denied user creation, IOC creation, incident transitions, and audit logs -> 403
    deny_users = await client.post(
        "/api/v1/users",
        headers=viewer_headers,
        json={
            "email": "rogue@bancocentral.com",
            "full_name": "Rogue User",
            "role": "ADMIN",
            "password": "RoguePassword#2026!",
        },
    )
    assert deny_users.status_code == 403

    deny_iocs = await client.post(
        "/api/v1/iocs",
        headers=viewer_headers,
        json={"ioc_type": "DOMAIN", "ioc_value": "evil-test.org", "list_type": "BLACKLIST"},
    )
    assert deny_iocs.status_code == 403

    deny_transition = await client.post(
        "/api/v1/incidents/00000000-0000-0000-0000-000000000000/transition",
        headers=viewer_headers,
        json={"new_status": "TRIAGED"},
    )
    assert deny_transition.status_code == 403

    deny_audit = await client.get("/api/v1/audit/logs", headers=viewer_headers)
    assert deny_audit.status_code == 403

    # AUDITOR can read audit logs (200) but cannot create IOCs (403)
    allow_audit = await client.get("/api/v1/audit/logs", headers=auditor_headers)
    assert allow_audit.status_code == 200
    auditor_deny_ioc = await client.post(
        "/api/v1/iocs",
        headers=auditor_headers,
        json={"ioc_type": "DOMAIN", "ioc_value": "evil-auditor.org", "list_type": "BLACKLIST"},
    )
    assert auditor_deny_ioc.status_code == 403


async def test_full_totp_mfa_lifecycle(
    client: httpx.AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    create_resp = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "mfa.responder@bancocentral.com",
            "full_name": "MFA SOC Responder",
            "role": "SOC_L2",
            "password": "MfaResponder#2026!",
        },
    )
    assert create_resp.status_code == 201

    initial_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa.responder@bancocentral.com", "password": "MfaResponder#2026!"},
    )
    assert initial_login.status_code == 200
    user_headers = {"Authorization": f"Bearer {initial_login.json()['access_token']}"}

    # 1. Setup TOTP secret
    setup_resp = await client.post("/api/v1/auth/mfa/setup", headers=user_headers)
    assert setup_resp.status_code == 200
    secret = setup_resp.json()["secret"]
    assert setup_resp.json()["otpauth_uri"].startswith("otpauth://totp/")
    assert setup_resp.json()["mfa_enabled"] is False

    # 2. Enable MFA with live RFC 6238 code
    live_code = generate_totp_code(secret)
    enable_resp = await client.post(
        "/api/v1/auth/mfa/enable",
        headers=user_headers,
        json={"totp_code": live_code},
    )
    assert enable_resp.status_code == 200
    assert enable_resp.json()["mfa_enabled"] is True

    # 3. Login without TOTP code is challenged with 401 + X-MFA-Required: true
    challenged = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa.responder@bancocentral.com", "password": "MfaResponder#2026!"},
    )
    assert challenged.status_code == 401
    assert challenged.headers.get("x-mfa-required") == "true"

    # 4. Login with valid TOTP code succeeds (200)
    mfa_login = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "mfa.responder@bancocentral.com",
            "password": "MfaResponder#2026!",
            "totp_code": generate_totp_code(secret),
        },
    )
    assert mfa_login.status_code == 200
    assert mfa_login.json()["user"]["mfa_enabled"] is True

    # 5. Disable MFA and verify password-only login works again
    disable_resp = await client.post(
        "/api/v1/auth/mfa/disable",
        headers={"Authorization": f"Bearer {mfa_login.json()['access_token']}"},
        json={"password": "MfaResponder#2026!", "totp_code": generate_totp_code(secret)},
    )
    assert disable_resp.status_code == 200
    assert disable_resp.json()["mfa_enabled"] is False

    post_disable = await client.post(
        "/api/v1/auth/login",
        json={"email": "mfa.responder@bancocentral.com", "password": "MfaResponder#2026!"},
    )
    assert post_disable.status_code == 200

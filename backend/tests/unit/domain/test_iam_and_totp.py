"""Unit tests for RBAC matrix, PCI-DSS password complexity, lockout policy, and RFC 6238 TOTP."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.core.totp import (
    build_totp_uri,
    generate_totp_code,
    generate_totp_secret,
    verify_totp,
)
from app.domain.iam.password_policy import (
    LOCK_MINUTES,
    MAX_FAILED_ATTEMPTS,
    assert_strong_password,
    is_locked,
    lock_deadline,
    validate_password,
)
from app.domain.iam.rbac import (
    ALL_PERMISSIONS,
    AUDIT_READ,
    DASHBOARD_READ,
    DATASET_ADMIN,
    DETECTION_ANALYZE,
    DETECTION_READ,
    HUNTING_READ,
    INCIDENTS_READ,
    INCIDENTS_WRITE,
    IOCS_READ,
    IOCS_WRITE,
    REPORTS_MANAGE,
    REPORTS_READ,
    USERS_READ,
    USERS_WRITE,
    has_permission,
    permissions_for,
)
from app.domain.shared.errors import WeakPassword


def test_rbac_permission_matrix_across_all_five_roles() -> None:
    # ADMIN holds every permission in the platform
    assert permissions_for("ADMIN") == ALL_PERMISSIONS
    for perm in ALL_PERMISSIONS:
        assert has_permission("ADMIN", perm) is True

    # SOC_L2 can respond to incidents, manage IOCs/reports, hunt, and read audit, but not admin users/datasets
    assert has_permission("SOC_L2", INCIDENTS_WRITE) is True
    assert has_permission("SOC_L2", IOCS_WRITE) is True
    assert has_permission("SOC_L2", REPORTS_MANAGE) is True
    assert has_permission("SOC_L2", AUDIT_READ) is True
    assert has_permission("SOC_L2", HUNTING_READ) is True
    assert has_permission("SOC_L2", USERS_WRITE) is False
    assert has_permission("SOC_L2", DATASET_ADMIN) is False

    # SOC_L1 can analyze, triage incidents, and hunt, but cannot write IOCs or manage schedules/users
    assert has_permission("SOC_L1", DETECTION_ANALYZE) is True
    assert has_permission("SOC_L1", INCIDENTS_WRITE) is True
    assert has_permission("SOC_L1", HUNTING_READ) is True
    assert has_permission("SOC_L1", IOCS_WRITE) is False
    assert has_permission("SOC_L1", REPORTS_MANAGE) is False
    assert has_permission("SOC_L1", AUDIT_READ) is False
    assert has_permission("SOC_L1", USERS_READ) is False

    # AUDITOR has read-only access + AUDIT_READ + HUNTING_READ, zero write permissions
    assert has_permission("AUDITOR", AUDIT_READ) is True
    assert has_permission("AUDITOR", HUNTING_READ) is True
    assert has_permission("AUDITOR", REPORTS_READ) is True
    assert has_permission("AUDITOR", INCIDENTS_WRITE) is False
    assert has_permission("AUDITOR", IOCS_WRITE) is False
    assert has_permission("AUDITOR", DETECTION_ANALYZE) is False

    # VIEWER has strictly read-only operational dashboards & lists
    for read_perm in (DETECTION_READ, DASHBOARD_READ, INCIDENTS_READ, IOCS_READ, REPORTS_READ):
        assert has_permission("VIEWER", read_perm) is True
    for denied in (
        DETECTION_ANALYZE,
        INCIDENTS_WRITE,
        IOCS_WRITE,
        REPORTS_MANAGE,
        DATASET_ADMIN,
        HUNTING_READ,
        AUDIT_READ,
        USERS_READ,
        USERS_WRITE,
    ):
        assert has_permission("VIEWER", denied) is False

    # Unknown role defaults to empty permission set
    assert permissions_for("UNKNOWN_ROLE") == frozenset()


@pytest.mark.parametrize(
    "weak_candidate",
    [
        "Short1!",            # < 12 characters
        "alllowercase123!",   # missing uppercase
        "ALLUPPERCASE123!",   # missing lowercase
        "NoDigitsHere!@#",    # missing digit
        "NoSpecialChar123",   # missing special symbol
        "password",           # common dictionary password
        "bancocentral",       # institutional name dictionary match
    ],
)
def test_password_policy_rejects_weak_passwords(weak_candidate: str) -> None:
    assert len(validate_password(weak_candidate)) >= 1
    with pytest.raises(WeakPassword):
        assert_strong_password(weak_candidate)


def test_password_policy_accepts_compliant_password() -> None:
    assert validate_password("Ciso#Banco2026!") == []
    assert_strong_password("Ciso#Banco2026!")


def test_account_lockout_threshold_and_expiry() -> None:
    now = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
    for attempts in range(MAX_FAILED_ATTEMPTS):
        assert lock_deadline(attempts, now=now) is None

    expiry = lock_deadline(MAX_FAILED_ATTEMPTS, now=now)
    assert expiry == now + timedelta(minutes=LOCK_MINUTES)
    assert is_locked(expiry, now=now + timedelta(minutes=14, seconds=59)) is True
    assert is_locked(expiry, now=now + timedelta(minutes=15, seconds=1)) is False
    assert is_locked(None, now=now) is False


def test_rfc6238_totp_generation_uri_and_verification() -> None:
    secret = generate_totp_secret()
    assert len(secret) >= 26

    uri = build_totp_uri(secret=secret, email="Admin@BancoCentral.com", issuer="BancoCentral SOC")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert "admin%40bancocentral.com" in uri
    assert "digits=6&period=30" in uri

    fixed_epoch = 1_730_000_000
    code_t0 = generate_totp_code(secret, for_time=fixed_epoch)
    assert len(code_t0) == 6 and code_t0.isdigit()

    # Exact timestamp and +-1 30s drift step pass verification
    assert verify_totp(secret, code_t0, for_time=fixed_epoch) is True
    assert verify_totp(secret, code_t0, for_time=fixed_epoch + 30, window=1) is True
    assert verify_totp(secret, code_t0, for_time=fixed_epoch - 30, window=1) is True

    # Outside drift window (+120s), wrong digits, and malformed secrets/codes fail
    assert verify_totp(secret, code_t0, for_time=fixed_epoch + 120, window=1) is False
    wrong_code = "999999" if code_t0 != "999999" else "000000"
    assert verify_totp(secret, wrong_code, for_time=fixed_epoch) is False
    assert verify_totp(secret, "12ab56", for_time=fixed_epoch) is False
    assert verify_totp("", code_t0, for_time=fixed_epoch) is False

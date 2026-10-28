"""Authentication, JWT rotation, RFC 6238 TOTP MFA, and enterprise SSO status endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.identity.ldap_provider import get_ldap_provider_status
from app.adapters.identity.local_provider import get_local_provider_status
from app.adapters.identity.saml_provider import get_saml_oidc_provider_status
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.user_repository import UserRepository
from app.api.deps import get_client_ip, get_current_user, get_db
from app.application.dto.iam_dto import (
    LoginRequest,
    MfaDisableRequest,
    MfaVerifyRequest,
    RefreshRequest,
    TokenOut,
    UserOut,
)
from app.core.config import settings
from app.core.rate_limit import RateLimiter, limiter_dependency
from app.core.security import (
    build_totp_uri,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret,
    verify_password,
    verify_totp,
)
from app.domain.iam.password_policy import is_locked
from app.domain.iam.rbac import permissions_for
from app.domain.shared.errors import AccountLocked

router = APIRouter()

login_rate_limiter = RateLimiter(limit=10, window_seconds=60)


def serialize_user(user: UserModel) -> UserOut:
    perms = sorted(permissions_for(user.role))
    return UserOut(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=bool(user.is_active),
        mfa_enabled=bool(user.mfa_enabled),
        locked=is_locked(user.locked_until),
        failed_login_attempts=int(user.failed_login_attempts or 0),
        locked_until=user.locked_until.isoformat() if user.locked_until else None,
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
        created_at=user.created_at.isoformat() if user.created_at else "",
        permissions=perms,
    )


def _issue_tokens(user: UserModel) -> TokenOut:
    claims = {"sub": user.email, "user_id": user.id, "role": user.role}
    user_dto = serialize_user(user)
    return TokenOut(
        access_token=create_access_token(claims),
        refresh_token=create_refresh_token(claims),
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user_dto,
        permissions=user_dto.permissions,
    )


@router.post(
    "/login",
    response_model=TokenOut,
    dependencies=[Depends(limiter_dependency(login_rate_limiter))],
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenOut:
    """Authenticate SOC user with Argon2id + account lockout + optional RFC 6238 TOTP MFA."""
    client_ip = get_client_ip(request)
    user_repo = UserRepository(db)
    audit_repo = AuditRepository(db)

    email_norm = payload.email.strip().lower()
    user = await user_repo.get_by_email(email_norm)

    if user is None:
        await audit_repo.append(
            user_email=email_norm,
            action="AUTH_LOGIN_FAILED",
            resource="auth:login",
            payload={"reason": "unknown_user"},
            client_ip=client_ip,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        await audit_repo.append(
            user_email=user.email,
            action="AUTH_LOGIN_FAILED",
            resource=f"user:{user.id}",
            payload={"reason": "inactive_account"},
            client_ip=client_ip,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    if is_locked(user.locked_until):
        await audit_repo.append(
            user_email=user.email,
            action="AUTH_LOGIN_FAILED",
            resource=f"user:{user.id}",
            payload={
                "reason": "account_locked",
                "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            },
            client_ip=client_ip,
        )
        await db.commit()
        raise AccountLocked(
            f"Account temporarily locked until {user.locked_until.isoformat() if user.locked_until else 'expiry'}"
        )

    if not verify_password(payload.password, user.hashed_password):
        await user_repo.register_failure(user)
        await audit_repo.append(
            user_email=user.email,
            action="AUTH_LOGIN_FAILED",
            resource=f"user:{user.id}",
            payload={
                "reason": "bad_password",
                "failed_login_attempts": user.failed_login_attempts,
                "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            },
            client_ip=client_ip,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if user.mfa_enabled and user.mfa_secret:
        if not payload.totp_code or not verify_totp(user.mfa_secret, payload.totp_code):
            await audit_repo.append(
                user_email=user.email,
                action="AUTH_LOGIN_FAILED",
                resource=f"user:{user.id}",
                payload={"reason": "mfa_required_or_invalid"},
                client_ip=client_ip,
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required or invalid",
                headers={"X-MFA-Required": "true"},
            )

    await user_repo.register_success(user)
    token_bundle = _issue_tokens(user)
    await audit_repo.append(
        user_email=user.email,
        action="AUTH_LOGIN_SUCCESS",
        resource=f"user:{user.id}",
        payload={"role": user.role, "mfa_verified": bool(user.mfa_enabled)},
        client_ip=client_ip,
    )
    await db.commit()
    return token_bundle


@router.post("/refresh", response_model=TokenOut)
async def refresh_tokens(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenOut:
    """Validate refresh JWT and issue rotated access & refresh tokens."""
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_repo = UserRepository(db)
    user = None
    if claims.get("user_id"):
        user = await user_repo.get_by_id(str(claims["user_id"]))
    if user is None and claims.get("sub"):
        user = await user_repo.get_by_email(str(claims["sub"]))

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is unavailable",
        )
    if is_locked(user.locked_until):
        raise AccountLocked("User account is locked")

    token_bundle = _issue_tokens(user)
    await AuditRepository(db).append(
        user_email=user.email,
        action="AUTH_TOKEN_REFRESH",
        resource=f"user:{user.id}",
        payload={"role": user.role},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return token_bundle


@router.get("/me", response_model=UserOut)
async def get_me(current_user: UserModel = Depends(get_current_user)) -> UserOut:
    """Return current authenticated user profile and RBAC permissions."""
    return serialize_user(current_user)


@router.post("/logout")
async def logout(
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Record explicit session logout in the append-only audit trail."""
    await AuditRepository(db).append(
        user_email=current_user.email,
        action="AUTH_LOGOUT",
        resource=f"user:{current_user.id}",
        payload={"role": current_user.role},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {"status": "logged_out"}


@router.post("/mfa/setup")
async def setup_mfa(
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new RFC 6238 TOTP secret and provisioning URI for authenticator enrollment."""
    secret = generate_totp_secret()
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False
    otpauth_uri = build_totp_uri(secret=secret, email=current_user.email, issuer="BancoCentral SOC")

    await AuditRepository(db).append(
        user_email=current_user.email,
        action="AUTH_MFA_SETUP",
        resource=f"user:{current_user.id}",
        payload={"issuer": "BancoCentral SOC"},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "issuer": "BancoCentral SOC",
        "mfa_enabled": False,
    }


@router.post("/mfa/enable")
async def enable_mfa(
    payload: MfaVerifyRequest,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify a live TOTP code and enforce MFA on subsequent logins."""
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Run /mfa/setup first to generate a TOTP secret",
        )
    if not verify_totp(current_user.mfa_secret, payload.totp_code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP verification code",
        )

    current_user.mfa_enabled = True
    await AuditRepository(db).append(
        user_email=current_user.email,
        action="AUTH_MFA_ENABLED",
        resource=f"user:{current_user.id}",
        payload={"mfa_enabled": True},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {"mfa_enabled": True, "status": "enabled"}


@router.post("/mfa/disable")
async def disable_mfa(
    payload: MfaDisableRequest,
    request: Request,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable TOTP MFA for the current user after optional code or password confirmation."""
    if payload.password and not verify_password(payload.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password confirmation",
        )
    if (
        payload.totp_code
        and current_user.mfa_secret
        and not verify_totp(current_user.mfa_secret, payload.totp_code)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await AuditRepository(db).append(
        user_email=current_user.email,
        action="AUTH_MFA_DISABLED",
        resource=f"user:{current_user.id}",
        payload={"mfa_enabled": False},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return {"mfa_enabled": False, "status": "disabled"}


@router.get("/sso/providers")
async def list_sso_providers():
    """Return enterprise identity federation readiness (Local Argon2id, SAML 2.0/OIDC, LDAPS)."""
    return {
        "primary_mode": "local-argon2id",
        "providers": [
            get_local_provider_status(),
            get_saml_oidc_provider_status(),
            get_ldap_provider_status(),
        ],
    }

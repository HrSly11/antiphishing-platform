"""FastAPI security & persistence dependencies: JWT auth, RBAC, MTA gateway keys, and n8n service keys."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import AsyncGenerator, Optional

from fastapi import Depends, Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.database import get_db as _session_get_db
from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.user_repository import UserRepository
from app.core.config import settings
from app.core.security import decode_token
from app.domain.iam.password_policy import is_locked
from app.domain.iam.rbac import has_permission
from app.domain.shared.errors import PermissionDenied

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ActorPrincipal:
    """Resolved caller identity (human JWT user, MTA gateway, or n8n SOAR service)."""

    email: str
    role: str
    user_id: Optional[str] = None
    auth_mode: str = "jwt"
    user: Optional[UserModel] = None


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()[:64]
    return (request.client.host if request.client else "127.0.0.1")[:64]


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in _session_get_db():
        yield session


def _constant_time_matches(provided: Optional[str], expected: str) -> bool:
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.strip().encode("utf-8"), expected.strip().encode("utf-8"))


async def _resolve_jwt_user(
    db: AsyncSession,
    credentials: Optional[HTTPAuthorizationCredentials],
    query_token: Optional[str] = None,
) -> UserModel:
    raw_token = credentials.credentials if credentials and credentials.credentials else query_token
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = decode_token(raw_token, expected_type="access")
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    repo = UserRepository(db)
    user: Optional[UserModel] = None
    if claims.get("user_id"):
        user = await repo.get_by_id(str(claims["user_id"]))
    if user is None and claims.get("sub"):
        user = await repo.get_by_email(str(claims["sub"]))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    if is_locked(user.locked_until):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is temporarily locked due to failed login attempts",
        )
    return user


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    token: Optional[str] = Query(default=None, include_in_schema=False),
) -> UserModel:
    """Validate Bearer JWT access token and return the active, unlocked `UserModel`."""
    return await _resolve_jwt_user(db=db, credentials=credentials, query_token=token)


def require_permission(perm: str):
    """Dependency factory enforcing granular RBAC permission `perm` on `current_user`."""

    async def _enforce(user: UserModel = Depends(get_current_user)) -> UserModel:
        if not has_permission(user.role, perm):
            raise PermissionDenied(f"Role '{user.role}' does not hold required permission '{perm}'")
        return user

    return _enforce


def allow_gateway_or_permission(perm: str):
    """Accept valid `X-Gateway-Key`, `X-Service-Key`, OR a Bearer JWT holding `perm`."""

    async def _enforce(
        db: AsyncSession = Depends(get_db),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
        x_gateway_key: Optional[str] = Header(default=None, alias="X-Gateway-Key"),
        x_service_key: Optional[str] = Header(default=None, alias="X-Service-Key"),
    ) -> ActorPrincipal:
        if _constant_time_matches(x_gateway_key, settings.GATEWAY_API_KEY):
            return ActorPrincipal(
                email="mta-gateway@bancocentral.com",
                role="GATEWAY",
                auth_mode="gateway_key",
            )
        if _constant_time_matches(x_service_key, settings.N8N_SERVICE_KEY):
            return ActorPrincipal(
                email="n8n-soar@bancocentral.com",
                role="SERVICE",
                auth_mode="service_key",
            )
        user = await _resolve_jwt_user(db=db, credentials=credentials)
        if not has_permission(user.role, perm):
            raise PermissionDenied(f"Role '{user.role}' does not hold required permission '{perm}'")
        return ActorPrincipal(
            email=user.email,
            role=user.role,
            user_id=user.id,
            auth_mode="jwt",
            user=user,
        )

    return _enforce


async def allow_gateway_or_authenticated(
    db: AsyncSession = Depends(get_db),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_gateway_key: Optional[str] = Header(default=None, alias="X-Gateway-Key"),
    x_service_key: Optional[str] = Header(default=None, alias="X-Service-Key"),
) -> ActorPrincipal:
    """Accept `X-Gateway-Key`, `X-Service-Key`, OR any authenticated corporate user (e.g., employee phishing button)."""
    if _constant_time_matches(x_gateway_key, settings.GATEWAY_API_KEY):
        return ActorPrincipal(
            email="mta-gateway@bancocentral.com",
            role="GATEWAY",
            auth_mode="gateway_key",
        )
    if _constant_time_matches(x_service_key, settings.N8N_SERVICE_KEY):
        return ActorPrincipal(
            email="n8n-soar@bancocentral.com",
            role="SERVICE",
            auth_mode="service_key",
        )
    user = await _resolve_jwt_user(db=db, credentials=credentials)
    return ActorPrincipal(
        email=user.email,
        role=user.role,
        user_id=user.id,
        auth_mode="jwt",
        user=user,
    )


def allow_service_or_permission(perm: str):
    """Accept valid `X-Service-Key` (n8n SOAR / cron) OR a Bearer JWT holding `perm`."""

    async def _enforce(
        db: AsyncSession = Depends(get_db),
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
        x_service_key: Optional[str] = Header(default=None, alias="X-Service-Key"),
        token: Optional[str] = Query(default=None, include_in_schema=False),
    ) -> ActorPrincipal:
        if _constant_time_matches(x_service_key, settings.N8N_SERVICE_KEY):
            return ActorPrincipal(
                email="n8n-soar@bancocentral.com",
                role="SERVICE",
                auth_mode="service_key",
            )
        user = await _resolve_jwt_user(db=db, credentials=credentials, query_token=token)
        if not has_permission(user.role, perm):
            raise PermissionDenied(f"Role '{user.role}' does not hold required permission '{perm}'")
        return ActorPrincipal(
            email=user.email,
            role=user.role,
            user_id=user.id,
            auth_mode="jwt",
            user=user,
        )

    return _enforce

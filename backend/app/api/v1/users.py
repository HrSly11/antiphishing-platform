"""User administration & granular RBAC matrix endpoints."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.persistence.models.user import UserModel
from app.adapters.persistence.repositories.audit_repository import AuditRepository
from app.adapters.persistence.repositories.user_repository import UserRepository
from app.api.deps import get_client_ip, get_current_user, get_db, require_permission
from app.api.v1.auth import serialize_user
from app.application.dto.iam_dto import UserCreate, UserOut, UserUpdate
from app.core.security import hash_password
from app.domain.iam.password_policy import assert_strong_password
from app.domain.iam.rbac import (
    ALL_PERMISSIONS,
    ROLE_PERMISSIONS,
    USERS_READ,
    USERS_WRITE,
)

router = APIRouter()


@router.get("", response_model=List[UserOut])
@router.get("/", response_model=List[UserOut], include_in_schema=False)
async def list_users(
    _: UserModel = Depends(require_permission(USERS_READ)),
    db: AsyncSession = Depends(get_db),
) -> List[UserOut]:
    """List all SOC platform users with lockout and MFA posture."""
    rows = await UserRepository(db).list_all()
    return [serialize_user(u) for u in rows]


@router.get("/roles")
async def get_rbac_matrix(_: UserModel = Depends(get_current_user)):
    """Return the role-to-permissions RBAC matrix."""
    return {
        "all_permissions": sorted(ALL_PERMISSIONS),
        "roles": [
            {"role": role_name, "permissions": sorted(perms)}
            for role_name, perms in ROLE_PERMISSIONS.items()
        ],
    }


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=UserOut, status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_user(
    payload: UserCreate,
    request: Request,
    current_admin: UserModel = Depends(require_permission(USERS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Create a new user enforcing PCI-DSS 8.3 password complexity and Argon2id hashing."""
    assert_strong_password(payload.password)

    repo = UserRepository(db)
    existing = await repo.get_by_email(payload.email)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with email '{payload.email.strip().lower()}' already exists",
        )

    user = UserModel(
        email=payload.email.strip().lower(),
        full_name=payload.full_name.strip(),
        role=payload.role,
        hashed_password=hash_password(payload.password),
        is_active=True,
        mfa_enabled=False,
    )
    await repo.add(user)
    await AuditRepository(db).append(
        user_email=current_admin.email,
        action="USER_CREATED",
        resource=f"user:{user.id}",
        payload={"email": user.email, "role": user.role},
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return serialize_user(user)


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    current_admin: UserModel = Depends(require_permission(USERS_WRITE)),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Update user role, active status, unlock account, or rotate password."""
    repo = UserRepository(db)
    target = await repo.get_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if target.id == current_admin.id:
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot deactivate their own account",
            )
        if payload.role is not None and payload.role != "ADMIN":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot demote their own role",
            )

    changes = {}
    if payload.full_name is not None:
        target.full_name = payload.full_name.strip()
        changes["full_name"] = target.full_name
    if payload.role is not None:
        target.role = payload.role
        changes["role"] = target.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
        changes["is_active"] = target.is_active
    if payload.unlock:
        target.failed_login_attempts = 0
        target.locked_until = None
        changes["unlocked"] = True
    if payload.new_password:
        assert_strong_password(payload.new_password)
        target.hashed_password = hash_password(payload.new_password)
        changes["password_rotated"] = True

    await AuditRepository(db).append(
        user_email=current_admin.email,
        action="USER_UPDATED",
        resource=f"user:{target.id}",
        payload=changes,
        client_ip=get_client_ip(request),
    )
    await db.commit()
    return serialize_user(target)

from typing import List, Optional

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=256)
    totp_code: Optional[str] = Field(default=None, max_length=12)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10, max_length=4000)


class MfaVerifyRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=12)


class MfaDisableRequest(BaseModel):
    totp_code: Optional[str] = Field(default=None, max_length=12)
    password: Optional[str] = Field(default=None, max_length=256)


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    mfa_enabled: bool = False
    locked: bool = False
    failed_login_attempts: int = 0
    locked_until: Optional[str] = None
    last_login_at: Optional[str] = None
    created_at: str
    permissions: List[str] = Field(default_factory=list)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800
    user: UserOut
    permissions: List[str]


class UserCreate(BaseModel):
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = Field(..., min_length=2, max_length=255)
    role: str = Field(..., pattern="^(ADMIN|SOC_L2|SOC_L1|AUDITOR|VIEWER)$")
    password: str = Field(..., min_length=1, max_length=256)


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    role: Optional[str] = Field(default=None, pattern="^(ADMIN|SOC_L2|SOC_L1|AUDITOR|VIEWER)$")
    is_active: Optional[bool] = None
    unlock: Optional[bool] = None
    new_password: Optional[str] = Field(default=None, max_length=256)

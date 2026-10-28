"""Authentication primitives: Argon2id password hashing, signed JWTs, and RFC 6238 TOTP."""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import settings
from app.core.totp import (
    build_totp_uri,
    generate_totp_code,
    generate_totp_secret,
    verify_totp,
)

_hasher = PasswordHasher()  # Argon2id with the library's recommended parameters


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    try:
        return _hasher.verify(stored_hash, plain_password)
    except (VerificationError, InvalidHashError):
        return False


def _encode(data: Dict[str, Any], token_type: str, expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    claims = {**data, "typ": token_type, "iat": now, "exp": now + expires, "jti": secrets.token_hex(8)}
    return jwt.encode(claims, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(data: Dict[str, Any]) -> str:
    return _encode(data, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))


def create_refresh_token(data: Dict[str, Any]) -> str:
    return _encode(data, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))


def decode_token(token: str, expected_type: str) -> Optional[Dict[str, Any]]:
    """Return the claims if the signature, expiry and token type are valid; otherwise None."""
    try:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError:
        return None
    if claims.get("typ") != expected_type:
        return None
    return claims


__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "decode_token",
    "generate_totp_secret",
    "build_totp_uri",
    "generate_totp_code",
    "verify_totp",
]

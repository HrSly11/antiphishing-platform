"""RFC 6238 Time-Based One-Time Password (TOTP) implementation using Python stdlib."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote


def _decode_base32_secret(secret: str) -> bytes:
    cleaned = (secret or "").strip().replace(" ", "").upper()
    if not cleaned:
        raise ValueError("Empty TOTP secret")
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    return base64.b32decode(cleaned + padding, casefold=True)


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generate a cryptographic 160-bit Base32 secret suitable for authenticator apps."""
    raw = secrets.token_bytes(max(16, num_bytes))
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def build_totp_uri(
    secret: str,
    email: str,
    issuer: str = "BancoCentral SOC",
    digits: int = 6,
    period: int = 30,
) -> str:
    """Build an `otpauth://totp/...` URI compatible with Google Authenticator / Microsoft Authenticator."""
    label = f"{quote(issuer)}:{quote(email.strip().lower())}"
    issuer_param = quote(issuer)
    clean_secret = secret.strip().replace(" ", "").upper().rstrip("=")
    return (
        f"otpauth://totp/{label}"
        f"?secret={clean_secret}&issuer={issuer_param}&algorithm=SHA1&digits={digits}&period={period}"
    )


def generate_totp_code(
    secret: str,
    for_time: Optional[int] = None,
    step: int = 30,
    digits: int = 6,
) -> str:
    """Generate a 6-digit RFC 6238 TOTP code for `for_time` (defaults to current UNIX epoch)."""
    key = _decode_base32_secret(secret)
    ts = int(time.time()) if for_time is None else int(for_time)
    counter = max(0, ts // step)
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = binary % (10**digits)
    return str(otp).zfill(digits)


def verify_totp(
    secret: str,
    code: str,
    window: int = 1,
    for_time: Optional[int] = None,
    step: int = 30,
    digits: int = 6,
) -> bool:
    """Constant-time verification of an RFC 6238 TOTP code within `±window` 30-second steps."""
    candidate = (code or "").strip().replace(" ", "")
    if not secret or not candidate.isdigit() or len(candidate) != digits:
        return False
    try:
        _decode_base32_secret(secret)
    except Exception:
        return False

    ref_time = int(time.time()) if for_time is None else int(for_time)
    for delta in range(-max(0, window), max(0, window) + 1):
        expected = generate_totp_code(
            secret=secret,
            for_time=ref_time + (delta * step),
            step=step,
            digits=digits,
        )
        if hmac.compare_digest(expected, candidate):
            return True
    return False

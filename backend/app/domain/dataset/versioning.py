"""Dataset versioning: content hash for immutability/traceability plus URL normalisation."""
import hashlib
import re
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_TRACKING = re.compile(r"^(utm_|fbclid|gclid|mc_)", re.IGNORECASE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_url(raw: str) -> Optional[str]:
    """Lowercase scheme/host, drop fragments and tracking parameters. Returns None if unusable."""
    raw = raw.strip()
    if not raw or " " in raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not _TRACKING.match(k)])
    host = parts.hostname.lower()
    netloc = host if parts.port is None else f"{host}:{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", query, ""))


def url_hash(normalized_url: str) -> str:
    return sha256_bytes(normalized_url.encode("utf-8"))


def domain_of(normalized_url: str) -> str:
    return (urlsplit(normalized_url).hostname or "").lower()

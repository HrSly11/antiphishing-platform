"""Unified DNS, TLS, and RDAP domain-age enrichment adapter with strict SSRF protection."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from app.core.config import settings
from app.domain.detection.heuristics.domain_age import score_domain_age

_SAFE_DOMAIN_RE = re.compile(r"^[a-z0-9._-]+$", re.IGNORECASE)
_BLOCKED_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
    ".lan",
    ".home.arpa",
    ".corp",
    ".intranet",
)
_TWO_LABEL_TLDS = {
    "com.pe",
    "org.pe",
    "gob.pe",
    "edu.pe",
    "net.pe",
    "co.uk",
    "org.uk",
    "com.br",
    "com.mx",
    "com.ar",
    "com.co",
    "com.ec",
    "com.cl",
}


def _clean_host(host: str) -> str:
    raw = (host or "").strip().lower()
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    raw = raw.split("/")[0].split(":")[0].strip().rstrip(".")
    return raw


def _is_public_ip_str(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    return bool(addr.is_global)


def is_public_hostname_and_ips(
    host: str,
    resolved_ips: Optional[Iterable[str]] = None,
) -> bool:
    """SSRF guard rejecting loopback, RFC1918 private, link-local, multicast, and internal suffixes."""
    clean = _clean_host(host)
    if not clean or len(clean) > 253:
        return False
    if clean in {"localhost", "broadcasthost", "ip6-localhost", "metadata.google.internal"}:
        return False
    if any(clean.endswith(sfx) for sfx in _BLOCKED_SUFFIXES):
        return False

    # If host itself is an IP literal, validate it directly.
    try:
        ipaddress.ip_address(clean)
        if not _is_public_ip_str(clean):
            return False
    except ValueError:
        if "." not in clean:
            return False
        try:
            ascii_host = clean.encode("idna").decode("ascii")
        except Exception:
            return False
        if not _SAFE_DOMAIN_RE.match(ascii_host):
            return False

    if resolved_ips is not None:
        ip_list = [str(ip).strip() for ip in resolved_ips if ip and str(ip).strip()]
        if not ip_list:
            return False
        for ip_val in ip_list:
            if not _is_public_ip_str(ip_val):
                return False

    return True


def registrable_domain(host: str) -> str:
    clean = _clean_host(host)
    parts = [p for p in clean.split(".") if p]
    if len(parts) <= 2:
        return clean
    tail_two = ".".join(parts[-2:])
    if tail_two in _TWO_LABEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return tail_two


async def inspect_dns(domain: str, timeout: float = 2.5) -> Dict[str, Any]:
    """Resolve A/AAAA records asynchronously and enforce SSRF validation."""
    clean = _clean_host(domain)
    if not is_public_hostname_and_ips(clean, resolved_ips=None):
        return {
            "domain": clean,
            "status": "ssrf_blocked",
            "resolved": False,
            "ips": [],
            "ssrf_blocked": True,
        }

    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(clean, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except socket.gaierror:
        return {
            "domain": clean,
            "status": "nxdomain",
            "resolved": False,
            "ips": [],
            "ssrf_blocked": False,
        }
    except Exception as exc:
        return {
            "domain": clean,
            "status": "unavailable",
            "resolved": False,
            "ips": [],
            "ssrf_blocked": False,
            "error": type(exc).__name__,
        }

    ips: List[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and sockaddr[0] not in ips:
            ips.append(sockaddr[0])

    if not is_public_hostname_and_ips(clean, ips):
        return {
            "domain": clean,
            "status": "ssrf_blocked",
            "resolved": False,
            "ips": [],
            "ssrf_blocked": True,
        }

    return {
        "domain": clean,
        "status": "ok",
        "resolved": True,
        "ips": ips[:10],
        "ssrf_blocked": False,
    }


async def inspect_tls(domain: str, timeout: float = 2.5) -> Dict[str, Any]:
    """Perform a bounded TLS 443 handshake and inspect certificate metadata."""
    clean = _clean_host(domain)
    dns_info = await inspect_dns(clean, timeout=timeout)
    if dns_info.get("ssrf_blocked"):
        return {
            "domain": clean,
            "status": "ssrf_blocked",
            "valid_tls": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
        }
    if not dns_info.get("resolved"):
        return {
            "domain": clean,
            "status": dns_info.get("status", "unavailable"),
            "valid_tls": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
        }

    ctx = ssl.create_default_context()
    writer: Optional[asyncio.StreamWriter] = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(clean, 443, ssl=ctx, server_hostname=clean),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else {}
        issuer_parts = cert.get("issuer", ())
        issuer_cn = None
        for rdn in issuer_parts:
            for k, v in rdn:
                if k in {"organizationName", "commonName"} and not issuer_cn:
                    issuer_cn = v

        not_after_raw = cert.get("notAfter")
        expires_iso = None
        days_remaining = None
        if not_after_raw:
            try:
                exp_dt = parsedate_to_datetime(not_after_raw)
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                expires_iso = exp_dt.isoformat()
                days_remaining = (exp_dt - datetime.now(timezone.utc)).days
            except Exception:
                pass

        return {
            "domain": clean,
            "status": "ok",
            "valid_tls": True,
            "issuer": issuer_cn or "Verified CA",
            "expires_at": expires_iso,
            "days_remaining": days_remaining,
        }
    except ssl.SSLCertVerificationError as exc:
        return {
            "domain": clean,
            "status": "invalid_certificate",
            "valid_tls": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
            "error": str(exc)[:200],
        }
    except Exception as exc:
        return {
            "domain": clean,
            "status": "unavailable",
            "valid_tls": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
            "error": type(exc).__name__,
        }
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def _parse_iso_dt(raw: str) -> Optional[datetime]:
    val = (raw or "").strip()
    if not val:
        return None
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(val)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def inspect_domain_age_rdap(domain: str, timeout: float = 2.5) -> Dict[str, Any]:
    """Query RDAP (`https://rdap.org/domain/{domain}`) safely with strict timeout and fallback."""
    clean = _clean_host(domain)
    reg_dom = registrable_domain(clean)
    if not is_public_hostname_and_ips(reg_dom, resolved_ips=None):
        return {
            "domain": reg_dom,
            "status": "ssrf_blocked",
            "age_days": None,
            "registrar": None,
            "created_date": None,
        }

    try:
        ascii_dom = reg_dom.encode("idna").decode("ascii")
    except Exception:
        return {
            "domain": reg_dom,
            "status": "unavailable",
            "age_days": None,
            "registrar": None,
            "created_date": None,
        }

    if not _SAFE_DOMAIN_RE.match(ascii_dom):
        return {
            "domain": reg_dom,
            "status": "unavailable",
            "age_days": None,
            "registrar": None,
            "created_date": None,
        }

    url = f"https://rdap.org/domain/{ascii_dom}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            max_redirects=3,
            headers={"Accept": "application/rdap+json, application/json"},
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return {
                    "domain": reg_dom,
                    "status": "unavailable",
                    "age_days": None,
                    "registrar": None,
                    "created_date": None,
                    "http_status": resp.status_code,
                }
            data = resp.json()
    except Exception as exc:
        return {
            "domain": reg_dom,
            "status": "unavailable",
            "age_days": None,
            "registrar": None,
            "created_date": None,
            "reason": type(exc).__name__,
        }

    created_dt: Optional[datetime] = None
    for ev in data.get("events", []) if isinstance(data, dict) else []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction") or "").lower()
        if action in {"registration", "registered", "created"}:
            created_dt = _parse_iso_dt(str(ev.get("eventDate") or ""))
            if created_dt:
                break

    registrar: Optional[str] = None
    for ent in data.get("entities", []) if isinstance(data, dict) else []:
        if not isinstance(ent, dict):
            continue
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                for entry in vcard[1]:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                        registrar = str(entry[3])
                        break
            if registrar:
                break

    age_days: Optional[int] = None
    created_iso: Optional[str] = None
    if created_dt is not None:
        age_days = max(0, (datetime.now(timezone.utc) - created_dt).days)
        created_iso = created_dt.isoformat()

    return {
        "domain": reg_dom,
        "status": "ok" if age_days is not None else "partial",
        "age_days": age_days,
        "registrar": registrar,
        "created_date": created_iso,
    }


async def enrich_domain(domain: str, timeout: Optional[float] = None) -> Dict[str, Any]:
    """Combined async DNS + TLS + RDAP enrichment with graceful offline degradation."""
    clean = _clean_host(domain)
    if not settings.ENRICHMENT_ENABLED:
        return {
            "domain": clean,
            "enabled": False,
            "dns": {"domain": clean, "status": "disabled", "resolved": False, "ips": []},
            "tls": {"domain": clean, "status": "disabled", "valid_tls": False},
            "rdap": {"domain": clean, "status": "disabled", "age_days": None, "registrar": None, "created_date": None},
            "age_risk_score": 0.0,
            "age_reason": "",
        }

    eff_timeout = float(timeout if timeout is not None else settings.ENRICHMENT_TIMEOUT_SECONDS)
    dns_res, tls_res, rdap_res = await asyncio.gather(
        inspect_dns(clean, timeout=eff_timeout),
        inspect_tls(clean, timeout=eff_timeout),
        inspect_domain_age_rdap(clean, timeout=eff_timeout),
        return_exceptions=True,
    )

    dns_dict = (
        dns_res
        if isinstance(dns_res, dict)
        else {"domain": clean, "status": "unavailable", "resolved": False, "ips": []}
    )
    tls_dict = (
        tls_res
        if isinstance(tls_res, dict)
        else {"domain": clean, "status": "unavailable", "valid_tls": False}
    )
    rdap_dict = (
        rdap_res
        if isinstance(rdap_res, dict)
        else {"domain": clean, "status": "unavailable", "age_days": None, "registrar": None, "created_date": None}
    )

    age_score, age_reason = score_domain_age(rdap_dict.get("age_days"))
    return {
        "domain": clean,
        "enabled": True,
        "dns": dns_dict,
        "tls": tls_dict,
        "rdap": rdap_dict,
        "age_risk_score": age_score,
        "age_reason": age_reason,
    }

"""PhishTank verified CSV threat feed downloader and offline fixture loader."""
from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from app.adapters.feeds.whois_dns_tls import inspect_dns, is_public_hostname_and_ips

PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
PHISHTANK_LICENSE = "PhishTank Developer License (Cisco Talos / Attribution Required)"
DEFAULT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3] / "dataset" / "samples" / "phishtank_sample.csv"
)


def parse_phishtank_bytes(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse PhishTank verified CSV bytes into normalized dictionaries."""
    text_content = raw_bytes.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text_content))
    items: List[Dict[str, Any]] = []
    for row in reader:
        if not isinstance(row, dict):
            continue
        url_val = str(row.get("url") or "").strip()
        if not url_val:
            continue
        verified_str = str(row.get("verified") or "yes").strip().lower()
        if verified_str in {"no", "false", "0"}:
            continue
        items.append(
            {
                "phish_id": row.get("phish_id"),
                "url": url_val,
                "phish_detail_url": row.get("phish_detail_url") or "",
                "submission_time": row.get("submission_time") or "",
                "verified": True,
                "verification_time": row.get("verification_time") or "",
                "online": str(row.get("online") or "yes").lower() in {"yes", "true", "1"},
                "target": row.get("target") or "Unknown",
                "source": "PhishTank",
            }
        )
    return items


def load_phishtank_fixture(
    fixture_path: Optional[Path] = None,
) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Load the bundled offline PhishTank CSV sample fixture."""
    path = fixture_path or DEFAULT_FIXTURE_PATH
    raw_bytes = path.read_bytes()
    return raw_bytes, parse_phishtank_bytes(raw_bytes)


async def fetch_phishtank_live(
    feed_url: str = PHISHTANK_FEED_URL,
    timeout: float = 10.0,
    max_items: int = 2500,
) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Download the live PhishTank HTTPS CSV feed with SSRF protection."""
    parts = urlsplit(feed_url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError("Feed URL must use HTTPS and include a valid hostname.")
    if not is_public_hostname_and_ips(parts.hostname):
        raise ValueError(f"Blocked non-public feed hostname: {parts.hostname}")

    dns_check = await inspect_dns(parts.hostname, timeout=min(timeout, 3.0))
    if dns_check.get("ssrf_blocked") or not dns_check.get("resolved"):
        raise ConnectionError(f"Unable to safely resolve feed host: {parts.hostname}")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        max_redirects=3,
        headers={"User-Agent": "AntiphishingPlatform-SOC-ETL/1.0"},
    ) as client:
        resp = await client.get(feed_url)
        resp.raise_for_status()
        raw_bytes = resp.content

    items = parse_phishtank_bytes(raw_bytes)
    if max_items > 0:
        items = items[:max_items]
    return raw_bytes, items


async def load_phishtank_feed(
    prefer_live: bool = False,
    feed_url: str = PHISHTANK_FEED_URL,
    timeout: float = 10.0,
) -> Tuple[bytes, List[Dict[str, Any]], str]:
    """Fetch live PhishTank feed when requested, falling back cleanly to local CSV fixture."""
    if prefer_live:
        try:
            raw_bytes, items = await fetch_phishtank_live(feed_url=feed_url, timeout=timeout)
            if items:
                return raw_bytes, items, feed_url
        except Exception:
            pass

    raw_bytes, items = load_phishtank_fixture()
    return raw_bytes, items, f"fixture://{DEFAULT_FIXTURE_PATH.name}"

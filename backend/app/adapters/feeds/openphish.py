"""OpenPhish threat feed downloader and offline fixture loader."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from app.adapters.feeds.whois_dns_tls import inspect_dns, is_public_hostname_and_ips

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_LICENSE = "OpenPhish Community Terms of Service (Defensive Security & Academic Use)"
DEFAULT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3] / "dataset" / "samples" / "openphish_sample.txt"
)


def parse_openphish_bytes(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Parse newline-delimited OpenPhish plain-text feed into structured item dicts."""
    text_content = raw_bytes.decode("utf-8", errors="replace")
    items: List[Dict[str, Any]] = []
    for line in text_content.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        items.append({"url": cleaned, "source": "OpenPhish", "verified": True})
    return items


def load_openphish_fixture(
    fixture_path: Optional[Path] = None,
) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Load the bundled offline OpenPhish sample fixture."""
    path = fixture_path or DEFAULT_FIXTURE_PATH
    raw_bytes = path.read_bytes()
    return raw_bytes, parse_openphish_bytes(raw_bytes)


async def fetch_openphish_live(
    feed_url: str = OPENPHISH_FEED_URL,
    timeout: float = 8.0,
    max_items: int = 2500,
) -> Tuple[bytes, List[Dict[str, Any]]]:
    """Download the live OpenPhish HTTPS feed with SSRF protection."""
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
        max_redirects=2,
        headers={"User-Agent": "AntiphishingPlatform-SOC-ETL/1.0"},
    ) as client:
        resp = await client.get(feed_url)
        resp.raise_for_status()
        raw_bytes = resp.content

    items = parse_openphish_bytes(raw_bytes)
    if max_items > 0:
        items = items[:max_items]
    return raw_bytes, items


async def load_openphish_feed(
    prefer_live: bool = False,
    feed_url: str = OPENPHISH_FEED_URL,
    timeout: float = 8.0,
) -> Tuple[bytes, List[Dict[str, Any]], str]:
    """Fetch live OpenPhish feed when requested, falling back cleanly to local fixture."""
    if prefer_live:
        try:
            raw_bytes, items = await fetch_openphish_live(feed_url=feed_url, timeout=timeout)
            if items:
                return raw_bytes, items, feed_url
        except Exception:
            pass

    raw_bytes, items = load_openphish_fixture()
    return raw_bytes, items, f"fixture://{DEFAULT_FIXTURE_PATH.name}"

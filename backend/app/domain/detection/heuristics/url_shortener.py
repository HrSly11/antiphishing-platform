"""URL shortener detection. Shorteners hide the real destination, so they raise suspicion."""
from typing import Tuple

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id",
}


def detect_url_shortener(domain: str) -> Tuple[bool, str]:
    host = domain.lower().split(":")[0]
    if host in SHORTENER_DOMAINS:
        return True, f"URL shortener '{host}' hides the final destination"
    return False, ""

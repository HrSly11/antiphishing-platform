"""Pure-Python real-time multi-channel phishing detection engine."""
from __future__ import annotations

import email.utils
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.domain.detection.heuristics.entropy import detect_high_entropy
from app.domain.detection.heuristics.homograph import detect_homograph_attack
from app.domain.detection.heuristics.typosquatting import detect_typosquatting
from app.domain.detection.heuristics.url_shortener import detect_url_shortener
from app.domain.detection.scoring import DetectionSignal, RiskEvaluation, compute_risk_score

URL_REGEX = re.compile(r'(https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+)', re.IGNORECASE)
HREF_ANCHOR_REGEX = re.compile(
    r'<a\b[^>]*?\bhref\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
HTML_TAG_STRIP_RE = re.compile(r"<[^>]+>")
IPV4_EXACT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
IPV4_FIND_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LOGIN_PATH_RE = re.compile(
    r"/(login|signin|sign-in|auth|token|banca|coordenadas|verify|verificacion|password|sso|owa|unlock)\b",
    re.IGNORECASE,
)
QR_LURE_RE = re.compile(
    r"(escanee\s+el\s+c[oó]digo\s+qr|scan\s+(?:the\s+|this\s+)?qr|qr\s+code|autenticaci[oó]n\s+qr|validar\s+con\s+qr|data:image/(?:png|jpeg|svg\+xml);base64)",
    re.IGNORECASE,
)

URGENCY_KEYWORDS = [
    "urgente",
    "bloqueo",
    "cuenta suspendida",
    "inhabilitada",
    "actualizar token",
    "clave bloqueada",
    "coordenadas",
    "evite el cierre",
    "vence en 24 horas",
    "restablecer contraseña",
    "actividad sospechosa detectada",
    "multa",
    "embargo",
    "immediate action required",
    "account suspended",
    "verify immediately",
]

CREDENTIAL_HARVESTING_KEYWORDS = [
    "ingrese sus credenciales",
    "digite su clave",
    "ingrese su tarjeta",
    "cvv",
    "codigo de seguridad",
    "token digital",
    "clave dinamica",
    "clave dinámica",
    "numero de cuenta",
    "enter your password",
    "confirm your credentials",
    "one-time passcode",
]

DANGEROUS_EXTENSIONS = (
    ".exe",
    ".scr",
    ".iso",
    ".img",
    ".vbs",
    ".hta",
    ".js",
    ".jse",
    ".wsf",
    ".bat",
    ".cmd",
    ".ps1",
    ".lnk",
    ".xlsm",
    ".docm",
    ".pptm",
)
DOUBLE_EXTENSION_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|vbs|js|bat|cmd|ps1|hta)$",
    re.IGNORECASE,
)


def parse_email_address(raw_addr: str) -> Tuple[str, str]:
    """Return `(clean_email, domain)` from a raw `From` or `Reply-To` header."""
    _, addr = email.utils.parseaddr(raw_addr or "")
    candidate = (addr or raw_addr or "").strip().strip("<>").lower()
    if "@" in candidate:
        domain = candidate.rsplit("@", 1)[-1].strip()
        return candidate, domain
    return candidate, candidate


@dataclass
class ExtractedArtifacts:
    sender_email: str
    sender_domain: str
    reply_to_email: Optional[str]
    reply_to_domain: Optional[str]
    originating_ip: Optional[str]
    spf_result: str
    dkim_result: str
    dmarc_result: str
    auth_failed: bool
    urls: List[str]
    url_domains: List[str]
    deceptive_anchors: List[Dict[str, str]]
    qr_detected: bool


@dataclass
class EmailAnalysisInput:
    sender: str
    recipient: str
    subject: str
    body_text: str
    body_html: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    attachments_meta: List[Dict[str, Any]] = field(default_factory=list)
    channel: str = "EMAIL"
    reported_by_user: bool = False


class DetectionEngine:
    """Real-time multi-layer heuristic phishing inspection engine."""

    def __init__(self, official_domains: Optional[List[str]] = None) -> None:
        self.official_domains = [
            d.lower()
            for d in (official_domains or ["bancocentral.com", "bancoseguro.com", "miempresa.com"])
        ]

    def extract_domain(self, url: str) -> str:
        candidate = (url or "").strip()
        if not candidate:
            return ""
        if "://" not in candidate:
            candidate = "http://" + candidate
        parsed = urllib.parse.urlsplit(candidate)
        return (parsed.hostname or "").lower().strip(".")

    def extract_urls(self, text: str, html: Optional[str] = None) -> List[str]:
        found: List[str] = []
        seen: set[str] = set()

        for blob in (text or "", html or ""):
            for raw in URL_REGEX.findall(blob):
                cleaned = raw.rstrip(".,;:!?'\">]")
                if cleaned and cleaned not in seen:
                    seen.add(cleaned)
                    found.append(cleaned)

        if html:
            for href, _ in HREF_ANCHOR_REGEX.findall(html):
                href_clean = href.strip()
                if href_clean.lower().startswith(("http://", "https://", "www.")):
                    if href_clean not in seen:
                        seen.add(href_clean)
                        found.append(href_clean)

        return found

    def detect_deceptive_anchors(self, html: Optional[str]) -> List[Dict[str, str]]:
        """Detect `<a href='http://evil.ru'>https://bancocentral.com</a>` anchor mismatches."""
        if not html:
            return []
        mismatches: List[Dict[str, str]] = []
        for href, inner_html in HREF_ANCHOR_REGEX.findall(html):
            href_clean = href.strip()
            if not href_clean.lower().startswith(("http://", "https://", "www.")):
                continue
            visible = HTML_TAG_STRIP_RE.sub("", inner_html or "").strip()
            if not visible:
                continue
            # Check if visible text looks like a URL or domain name
            visible_looks_like_domain = bool(
                URL_REGEX.search(visible)
                or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(?:/.*)?$", visible.lower())
            )
            if not visible_looks_like_domain:
                continue
            href_dom = self.extract_domain(href_clean)
            anchor_dom = self.extract_domain(visible)
            if href_dom and anchor_dom and href_dom != anchor_dom:
                if not href_dom.endswith("." + anchor_dom) and not anchor_dom.endswith("." + href_dom):
                    mismatches.append(
                        {
                            "anchor_text": visible[:200],
                            "anchor_domain": anchor_dom,
                            "href": href_clean[:300],
                            "href_domain": href_dom,
                        }
                    )
        return mismatches

    def extract_artifacts(self, mail: EmailAnalysisInput) -> ExtractedArtifacts:
        headers_lc = {str(k).lower(): str(v) for k, v in (mail.headers or {}).items()}
        sender_email, sender_domain = parse_email_address(mail.sender)

        reply_to_raw = headers_lc.get("reply-to") or ""
        reply_email, reply_domain = (
            parse_email_address(reply_to_raw) if reply_to_raw.strip() else (None, None)
        )

        auth_res = headers_lc.get("authentication-results", "").lower()
        spf_hdr = f"{headers_lc.get('received-spf', '').lower()} {auth_res}"
        dkim_hdr = f"{headers_lc.get('dkim-results', '').lower()} {auth_res}"
        dmarc_hdr = f"{headers_lc.get('dmarc-filter', '').lower()} {auth_res}"

        spf_result = (
            "fail"
            if ("spf=fail" in spf_hdr or "spf=softfail" in spf_hdr or spf_hdr.strip().startswith(("fail", "softfail")))
            else ("pass" if "spf=pass" in spf_hdr or spf_hdr.strip().startswith("pass") else "none")
        )
        dkim_result = (
            "fail"
            if "dkim=fail" in dkim_hdr
            else ("pass" if "dkim=pass" in dkim_hdr else "none")
        )
        dmarc_result = (
            "fail"
            if "dmarc=fail" in dmarc_hdr
            else ("pass" if "dmarc=pass" in dmarc_hdr else "none")
        )
        auth_failed = any(r == "fail" for r in (spf_result, dkim_result, dmarc_result))

        originating_ip: Optional[str] = None
        for key in ("x-originating-ip", "x-sender-ip", "client-ip"):
            if key in headers_lc:
                matches = IPV4_FIND_RE.findall(headers_lc[key])
                if matches:
                    originating_ip = matches[0]
                    break
        if originating_ip is None and "received" in headers_lc:
            for candidate_ip in IPV4_FIND_RE.findall(headers_lc["received"]):
                if not candidate_ip.startswith(("127.", "10.", "192.168.")):
                    originating_ip = candidate_ip
                    break

        urls = self.extract_urls(f"{mail.subject}\n{mail.body_text}", mail.body_html)
        url_domains = list(
            dict.fromkeys(d for d in (self.extract_domain(u) for u in urls) if d)
        )
        deceptive_anchors = self.detect_deceptive_anchors(mail.body_html)

        combined_content = f"{mail.subject}\n{mail.body_text}\n{mail.body_html or ''}"
        has_qr_attachment = any(
            "qr" in str(att.get("filename") or "").lower()
            for att in (mail.attachments_meta or [])
        )
        qr_detected = (
            mail.channel.upper() == "QR"
            or bool(QR_LURE_RE.search(combined_content))
            or has_qr_attachment
        )

        return ExtractedArtifacts(
            sender_email=sender_email,
            sender_domain=sender_domain,
            reply_to_email=reply_email,
            reply_to_domain=reply_domain,
            originating_ip=originating_ip,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            auth_failed=auth_failed,
            urls=urls,
            url_domains=url_domains,
            deceptive_anchors=deceptive_anchors,
            qr_detected=qr_detected,
        )

    def collect_heuristic_signals(
        self,
        mail: EmailAnalysisInput,
        artifacts: Optional[ExtractedArtifacts] = None,
    ) -> Tuple[List[DetectionSignal], ExtractedArtifacts]:
        art = artifacts or self.extract_artifacts(mail)
        signals: List[DetectionSignal] = []

        # 1. Authentication & Header Spoofing Signals
        if art.spf_result == "fail":
            signals.append(
                DetectionSignal(
                    name="SPF_FAILURE",
                    weight=35,
                    score=1.0,
                    reason="Sender IP is unauthorized by the domain SPF policy (spoofing indicator).",
                    metadata={"domain": art.sender_domain},
                )
            )
        if art.dkim_result == "fail":
            signals.append(
                DetectionSignal(
                    name="DKIM_FAILURE",
                    weight=30,
                    score=1.0,
                    reason="Cryptographic DKIM signature verification failed.",
                    metadata={"domain": art.sender_domain},
                )
            )
        if art.dmarc_result == "fail":
            signals.append(
                DetectionSignal(
                    name="DMARC_FAILURE",
                    weight=40,
                    score=1.0,
                    reason="Strict DMARC alignment failed against domain policy.",
                    metadata={"domain": art.sender_domain},
                )
            )

        if (
            art.sender_domain in self.official_domains
            and art.auth_failed
        ):
            signals.append(
                DetectionSignal(
                    name="OFFICIAL_DOMAIN_SPOOFING",
                    weight=50,
                    score=1.0,
                    reason=f"Protected domain '{art.sender_domain}' failed email authentication (active spoofing).",
                    metadata={"domain": art.sender_domain},
                )
            )

        if (
            art.reply_to_domain
            and art.sender_domain
            and art.reply_to_domain != art.sender_domain
        ):
            signals.append(
                DetectionSignal(
                    name="REPLY_TO_MISMATCH",
                    weight=30,
                    score=1.0,
                    reason=f"Reply-To domain '{art.reply_to_domain}' diverges from sender domain '{art.sender_domain}'.",
                    metadata={
                        "sender_domain": art.sender_domain,
                        "reply_to_domain": art.reply_to_domain,
                    },
                )
            )

        # 2. Sender Domain Homograph & Typosquatting
        is_homograph, homo_desc, homo_conf = detect_homograph_attack(art.sender_domain)
        if is_homograph:
            signals.append(
                DetectionSignal(
                    name="SENDER_HOMOGRAPH",
                    weight=75,
                    score=homo_conf,
                    reason=f"Unicode/IDN homograph sender domain: {homo_desc}",
                    metadata={"domain": art.sender_domain},
                )
            )

        is_typo, typo_desc, typo_conf = detect_typosquatting(art.sender_domain)
        if is_typo:
            signals.append(
                DetectionSignal(
                    name="SENDER_TYPOSQUATTING",
                    weight=50,
                    score=typo_conf,
                    reason=f"Sender typosquatting/combosquatting: {typo_desc}",
                    metadata={"domain": art.sender_domain},
                )
            )

        # 3. Deceptive HTML `<a href>` Anchors
        for mismatch in art.deceptive_anchors:
            signals.append(
                DetectionSignal(
                    name="DECEPTIVE_HTML_ANCHOR",
                    weight=55,
                    score=1.0,
                    reason=(
                        f"Deceptive HTML link displays '{mismatch['anchor_domain']}' "
                        f"but redirects to '{mismatch['href_domain']}'."
                    ),
                    metadata={
                        "domain": mismatch["href_domain"],
                        "url": mismatch["href"],
                        "anchor_domain": mismatch["anchor_domain"],
                    },
                )
            )

        # 4. Extracted URL Heuristics
        seen_signal_keys: set[str] = set()
        for url in art.urls:
            domain = self.extract_domain(url)
            if not domain:
                continue

            is_h, h_desc, h_conf = detect_homograph_attack(domain)
            if is_h and f"homo:{domain}" not in seen_signal_keys:
                seen_signal_keys.add(f"homo:{domain}")
                signals.append(
                    DetectionSignal(
                        name="URL_HOMOGRAPH",
                        weight=75,
                        score=h_conf,
                        reason=f"Homograph attack in URL: {h_desc} ({url})",
                        metadata={"url": url, "domain": domain},
                    )
                )

            is_t, t_desc, t_conf = detect_typosquatting(domain)
            if is_t and f"typo:{domain}" not in seen_signal_keys:
                seen_signal_keys.add(f"typo:{domain}")
                signals.append(
                    DetectionSignal(
                        name="URL_TYPOSQUATTING",
                        weight=50,
                        score=t_conf,
                        reason=f"Brand typosquatting in URL: {t_desc} ({url})",
                        metadata={"url": url, "domain": domain},
                    )
                )

            is_ent, ent_val, ent_desc = detect_high_entropy(domain)
            if is_ent and f"ent:{domain}" not in seen_signal_keys:
                seen_signal_keys.add(f"ent:{domain}")
                signals.append(
                    DetectionSignal(
                        name="URL_HIGH_ENTROPY",
                        weight=22,
                        score=0.85,
                        reason=ent_desc,
                        metadata={"url": url, "domain": domain, "entropy": round(ent_val, 3)},
                    )
                )

            is_short, short_desc = detect_url_shortener(domain)
            if is_short and f"short:{domain}" not in seen_signal_keys:
                seen_signal_keys.add(f"short:{domain}")
                signals.append(
                    DetectionSignal(
                        name="URL_SHORTENER",
                        weight=25,
                        score=1.0,
                        reason=short_desc,
                        metadata={"url": url, "domain": domain},
                    )
                )

            if IPV4_EXACT_RE.match(domain) and f"ip:{domain}" not in seen_signal_keys:
                seen_signal_keys.add(f"ip:{domain}")
                signals.append(
                    DetectionSignal(
                        name="URL_RAW_IP",
                        weight=45,
                        score=1.0,
                        reason=f"URL points directly to raw IPv4 address without DNS domain: {url}",
                        metadata={"url": url, "domain": domain},
                    )
                )

            parsed_u = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
            if (
                parsed_u.scheme.lower() == "http"
                and LOGIN_PATH_RE.search(parsed_u.path or "")
                and f"http_login:{domain}" not in seen_signal_keys
            ):
                seen_signal_keys.add(f"http_login:{domain}")
                signals.append(
                    DetectionSignal(
                        name="HTTP_INSECURE_LOGIN_PATH",
                        weight=30,
                        score=1.0,
                        reason=f"Unencrypted HTTP credential path detected: {url}",
                        metadata={"url": url, "domain": domain},
                    )
                )

        # 5. QR / Quishing Indicators
        if art.qr_detected:
            signals.append(
                DetectionSignal(
                    name="QR_QUISHING_INDICATOR",
                    weight=38,
                    score=1.0,
                    reason="QR-code authentication lure (quishing) detected across message channel or body.",
                    metadata={"channel": mail.channel},
                )
            )

        # 6. Psychological Urgency & Credential Harvesting Keywords
        full_lower = f"{mail.subject} {mail.body_text} {mail.body_html or ''}".lower()
        urgency_matches = [w for w in URGENCY_KEYWORDS if w in full_lower]
        if urgency_matches:
            signals.append(
                DetectionSignal(
                    name="URGENCY_LURE",
                    weight=25,
                    score=min(1.0, 0.5 + 0.25 * len(urgency_matches)),
                    reason=f"Psychological urgency/coercion patterns: {', '.join(urgency_matches[:3])}",
                    metadata={"matches": urgency_matches[:5]},
                )
            )

        credential_matches = [w for w in CREDENTIAL_HARVESTING_KEYWORDS if w in full_lower]
        if credential_matches:
            signals.append(
                DetectionSignal(
                    name="CREDENTIAL_HARVESTING_INTENT",
                    weight=35,
                    score=min(1.0, 0.6 + 0.25 * len(credential_matches)),
                    reason=f"Explicit request for banking credentials, OTP, or tokens: {', '.join(credential_matches[:3])}",
                    metadata={"matches": credential_matches[:5]},
                )
            )

        # 7. Dangerous & Double-Extension Attachments
        for att in mail.attachments_meta or []:
            filename = str(att.get("filename") or "").strip()
            fn_lower = filename.lower()
            if DOUBLE_EXTENSION_RE.search(fn_lower):
                signals.append(
                    DetectionSignal(
                        name="DOUBLE_EXTENSION_ATTACHMENT",
                        weight=65,
                        score=1.0,
                        reason=f"Masqueraded double-extension executable attachment: {filename}",
                        metadata={"filename": filename},
                    )
                )
            elif any(fn_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                signals.append(
                    DetectionSignal(
                        name="DANGEROUS_ATTACHMENT",
                        weight=55,
                        score=1.0,
                        reason=f"High-risk executable or macro-enabled attachment: {filename}",
                        metadata={"filename": filename},
                    )
                )

        return signals, art

    def analyze_email(self, mail: EmailAnalysisInput) -> RiskEvaluation:
        """Synchronous pure-domain evaluation (used by unit tests and inline fallback)."""
        signals, _ = self.collect_heuristic_signals(mail)
        return compute_risk_score(signals)

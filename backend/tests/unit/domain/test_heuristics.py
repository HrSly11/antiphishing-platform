"""Unit tests for lexical, Unicode homograph, entropy, domain-age, HTML anchor, and .eml heuristics."""
from __future__ import annotations

import pytest

from app.application.commands.analyze_input import parse_eml_bytes
from app.domain.detection.engine import DetectionEngine, EmailAnalysisInput
from app.domain.detection.heuristics.domain_age import score_domain_age
from app.domain.detection.heuristics.entropy import (
    calculate_shannon_entropy,
    detect_high_entropy,
)
from app.domain.detection.heuristics.homograph import (
    detect_homograph_attack,
    is_punycode,
    normalize_confusables,
)
from app.domain.detection.heuristics.typosquatting import (
    detect_typosquatting,
    levenshtein_distance,
)
from app.domain.detection.heuristics.url_shortener import detect_url_shortener


def test_homograph_cyrillic_and_punycode_detection() -> None:
    # Cyrillic 'о' (U+043E) spoofing bancocentral.com
    cyrillic_domain = "banc\u043ecentral.com"
    assert normalize_confusables(cyrillic_domain) == "bancocentral.com"

    is_homo, desc, conf = detect_homograph_attack(cyrillic_domain)
    assert is_homo is True
    assert conf >= 0.90
    assert "bancocentral.com" in desc

    # IDN Punycode representation of bancоcentral.com
    puny_domain = "xn--banccentral-unj.com"
    assert is_punycode(puny_domain) is True
    is_puny_homo, puny_desc, puny_conf = detect_homograph_attack(puny_domain)
    assert is_puny_homo is True
    assert puny_conf >= 0.95
    assert "bancocentral.com" in puny_desc

    # Malformed Punycode should still raise suspicion safely
    is_bad_puny, _, bad_conf = detect_homograph_attack("xn--invalid---punycode.com")
    assert is_bad_puny is True
    assert bad_conf >= 0.70

    # Authentic ASCII official domain is clean
    is_clean, _, clean_conf = detect_homograph_attack("bancocentral.com")
    assert is_clean is False
    assert clean_conf == 0.0


@pytest.mark.parametrize(
    ("domain", "expected_typo"),
    [
        ("bancocentra1.com", True),
        ("banc0central.com", True),
        ("bancocentral-seguridad.com", True),
        ("login-bancocentral.attacker.net", True),
        ("santandr.com", True),
        ("bancocentral.com", False),
        ("santander.com", False),
        ("intranet-corporativa.pe", False),
    ],
)
def test_levenshtein_and_combosquatting_detection(domain: str, expected_typo: bool) -> None:
    assert levenshtein_distance("bancocentra1", "bancocentral") == 1
    is_typo, desc, conf = detect_typosquatting(domain)
    assert is_typo is expected_typo
    if expected_typo:
        assert conf >= 0.85
        assert len(desc) > 5


def test_shannon_entropy_and_dga_detection() -> None:
    assert calculate_shannon_entropy("") == 0.0
    low = calculate_shannon_entropy("bancocentral")
    high = calculate_shannon_entropy("x8q9z2w1p4k7m5n0b3v6")
    assert high > low
    assert high >= 3.85

    flagged, val, reason = detect_high_entropy("x8q9z2w1p4k7m5n0b3v6.top")
    assert flagged is True
    assert val >= 3.85
    assert "x8q9z2w1p4k7m5n0b3v6" in reason

    benign_flag, _, _ = detect_high_entropy("pagos.bancocentral.com")
    assert benign_flag is False


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("bit.ly", True),
        ("tinyurl.com:443", True),
        ("t.co", True),
        ("bancocentral.com", False),
    ],
)
def test_url_shortener_detection(host: str, expected: bool) -> None:
    is_short, reason = detect_url_shortener(host)
    assert is_short is expected
    if expected:
        assert "shortener" in reason.lower()


@pytest.mark.parametrize(
    ("age_days", "expected_score"),
    [
        (None, 0.0),
        (2, 1.0),
        (14, 0.7),
        (45, 0.3),
        (365, 0.0),
    ],
)
def test_domain_age_risk_tiers(age_days: int | None, expected_score: float) -> None:
    score, reason = score_domain_age(age_days)
    assert score == expected_score
    if expected_score > 0:
        assert "registered" in reason.lower()


def test_deceptive_html_anchor_mismatch_and_engine_signals() -> None:
    engine = DetectionEngine(official_domains=["bancocentral.com"])
    deceptive_html = (
        '<html><body>Por favor valide su cuenta en '
        '<a href="http://credential-stealer.ru/login">https://bancocentral.com/personas</a> '
        'y consulte <a href="https://pagos.bancocentral.com/ayuda">https://bancocentral.com</a>'
        "</body></html>"
    )
    mismatches = engine.detect_deceptive_anchors(deceptive_html)
    assert len(mismatches) == 1
    assert mismatches[0]["anchor_domain"] == "bancocentral.com"
    assert mismatches[0]["href_domain"] == "credential-stealer.ru"

    mail = EmailAnalysisInput(
        sender="soporte@bancocentral.com",
        recipient="cliente@bancocentral.com",
        subject="URGENTE: Actualizar token digital",
        body_text="Ingrese sus credenciales para evitar el bloqueo.",
        body_html=deceptive_html,
        headers={"authentication-results": "spf=fail dkim=fail dmarc=fail"},
        attachments_meta=[{"filename": "Estado_Cuenta.pdf.exe", "size_bytes": 4096}],
    )
    evaluation = engine.analyze_email(mail)
    signal_names = {s.name for s in evaluation.signals}
    assert "DECEPTIVE_HTML_ANCHOR" in signal_names
    assert "OFFICIAL_DOMAIN_SPOOFING" in signal_names
    assert "DOUBLE_EXTENSION_ATTACHMENT" in signal_names
    assert evaluation.verdict == "MALICIOUS"
    assert evaluation.action == "QUARANTINE"


def test_parse_eml_bytes_extracts_headers_multipart_bodies_and_attachments() -> None:
    raw_eml = (
        b"From: Soporte Fraude <alerta@banc0central.com>\r\n"
        b"To: tesoreria@bancocentral.com, backup@bancocentral.com\r\n"
        b"Subject: URGENTE: Validacion de Token\r\n"
        b"Authentication-Results: spf=fail dmarc=fail\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUNDARY42"\r\n\r\n'
        b"--BOUNDARY42\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Verifique su token en http://banc0central.com/login\r\n"
        b"--BOUNDARY42\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<html><body><a href="http://evil.org/token">https://bancocentral.com</a></body></html>\r\n'
        b"--BOUNDARY42\r\n"
        b'Content-Type: application/octet-stream; name="Token_Update.pdf.exe"\r\n'
        b'Content-Disposition: attachment; filename="Token_Update.pdf.exe"\r\n\r\n'
        b"MZ_FAKE_PE_HEADER\r\n"
        b"--BOUNDARY42--\r\n"
    )
    parsed = parse_eml_bytes(raw_eml)
    assert "banc0central.com" in parsed.sender
    assert parsed.recipient == "tesoreria@bancocentral.com"
    assert parsed.subject == "URGENTE: Validacion de Token"
    assert "spf=fail" in parsed.headers["authentication-results"]
    assert "http://banc0central.com/login" in parsed.body_text
    assert parsed.body_html is not None and "evil.org" in parsed.body_html
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "Token_Update.pdf.exe"
    assert (parsed.attachments[0].size_bytes or 0) > 0

    with pytest.raises(ValueError, match="Empty .eml"):
        parse_eml_bytes(b"")

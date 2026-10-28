import unicodedata
import idna
from typing import Tuple, List

# Dominios bancarios protegidos de la entidad y socios
PROTECTED_BANK_DOMAINS = [
    "bancocentral.com",
    "bancoripley.com",
    "bancofinanciero.com",
    "bancoonline.com",
    "bancoseguro.com",
    "santander.com",
    "bbva.com",
    "bcp.com.pe",
    "interbank.pe",
]

# Mapa de caracteres confusables comunes (cirílico/griego a latino)
CONFUSABLE_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', 'ԛ': 'q', 'ԁ': 'd', 'ԍ': 'g', 'һ': 'h',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}

def normalize_confusables(text: str) -> str:
    """Reemplaza caracteres visualmente idénticos de alfabetos cirílicos/griegos."""
    normalized_chars = []
    for char in text:
        normalized_chars.append(CONFUSABLE_MAP.get(char, char))
    return ''.join(normalized_chars)

def is_punycode(domain: str) -> bool:
    """Verifica si el dominio contiene segmentos codificados en Punycode (IDN)."""
    return "xn--" in domain.lower()

def detect_homograph_attack(domain: str) -> Tuple[bool, str, float]:
    """
    Analiza si un dominio entrante constituye un ataque homógrafo.
    Retorna: (is_homograph, normalized_domain, confidence_score)
    """
    domain_lower = domain.lower().strip()
    
    # 1. Chequeo de Punycode
    if is_punycode(domain_lower):
        try:
            decoded = idna.decode(domain_lower)
            normalized = normalize_confusables(decoded)
            for protected in PROTECTED_BANK_DOMAINS:
                if protected in normalized or protected.replace(".", "") in normalized.replace(".", ""):
                    return True, f"Punycode homoglyph de '{protected}': {decoded}", 0.98
        except Exception:
            return True, "Punycode malformado sospechoso", 0.75

    # 2. Chequeo de caracteres mezclados en Unicode
    normalized = normalize_confusables(domain_lower)
    if normalized != domain_lower:
        for protected in PROTECTED_BANK_DOMAINS:
            if protected in normalized:
                return True, f"Ataque homógrafo detectado imitando a '{protected}'", 0.95

    return False, domain_lower, 0.0

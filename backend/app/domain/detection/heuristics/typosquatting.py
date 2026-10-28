from typing import Tuple

PROTECTED_BRANDS = [
    "bancocentral",
    "bancoseguro",
    "bancoonline",
    "santander",
    "bbva",
    "interbank",
    "bcp",
    "scotiabank",
    "paypal",
    "microsoft",
    "office365",
]

SUSPICIOUS_KEYWORD_AFFIXES = [
    "-login",
    "-seguridad",
    "-verificacion",
    "-verificar",
    "-banca",
    "-online",
    "-portal",
    "-cuenta",
    "-actualizar",
    "-actualizacion",
    "-token",
    "-auth",
    "-soporte",
    "-alerta",
    "-alertas",
    "-sso",
]

_LEET_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_typosquatting(domain: str) -> Tuple[bool, str, float]:
    """Detect brand combosquatting, leet-speak substitutions, and Levenshtein typosquatting."""
    clean_domain = (domain or "").lower().split(":")[0].split("/")[0].strip(".")
    if not clean_domain:
        return False, "", 0.0

    # Exact official domain is never typosquatting
    parts = clean_domain.split(".")
    sld = parts[-2] if len(parts) >= 2 else parts[0]
    if len(parts) == 3 and parts[-2] in {"com", "org", "gob", "net", "edu"} and len(parts[-1]) == 2:
        sld = parts[-3]

    if sld in PROTECTED_BRANDS:
        return False, "", 0.0

    de_leeted_domain = clean_domain.translate(_LEET_MAP)

    # 1. Combosquatting (including leet-normalized variants like banc0central-seguridad.com)
    for brand in PROTECTED_BRANDS:
        for affix in SUSPICIOUS_KEYWORD_AFFIXES:
            target_pattern1 = f"{brand}{affix}"
            target_pattern2 = f"{affix.strip('-')}-{brand}"
            if (
                target_pattern1 in clean_domain
                or target_pattern2 in clean_domain
                or target_pattern1 in de_leeted_domain
                or target_pattern2 in de_leeted_domain
            ):
                return (
                    True,
                    f"Combosquatting bancario detectado: '{brand}' combinado con '{affix}'",
                    0.92,
                )

    # 2. Brand embedded as subdomain or hyphenated lure on external domain
    hyphen_tokens = [tok for tok in sld.split("-") if len(tok) >= 3]
    for brand in PROTECTED_BRANDS:
        if brand in clean_domain and sld != brand:
            return (
                True,
                f"Combosquatting de subdominio/marca detectado imitando '{brand}' en '{clean_domain}'",
                0.90,
            )

        # 3. Direct or token-level Levenshtein distance (e.g. banc0central, santandr, interbnk)
        candidates = [sld, *hyphen_tokens]
        for cand in candidates:
            if cand == brand:
                continue
            dist = levenshtein_distance(cand, brand)
            if 1 <= dist <= 2 and len(cand) >= 4:
                return (
                    True,
                    f"Typosquatting detectado: '{cand}' imita a la marca oficial '{brand}' (dist={dist})",
                    0.88,
                )

    return False, "", 0.0

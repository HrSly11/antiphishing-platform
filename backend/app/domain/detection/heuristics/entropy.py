import math
from collections import Counter
from typing import Tuple

def calculate_shannon_entropy(text: str) -> float:
    """Calcula la entropía de Shannon de una cadena de texto."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    counts = Counter(text)
    for count in counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy

def detect_high_entropy(domain: str, threshold: float = 3.85) -> Tuple[bool, float, str]:
    """
    Detecta si el dominio o subdominio posee entropía inusualmente alta (DGA o ofuscación).
    """
    clean_domain = domain.lower().split(":")[0].split("/")[0]
    parts = clean_domain.split(".")
    
    max_entropy = 0.0
    suspicious_part = ""
    for part in parts:
        ent = calculate_shannon_entropy(part)
        if ent > max_entropy:
            max_entropy = ent
            suspicious_part = part

    if max_entropy >= threshold and len(suspicious_part) >= 8:
        return True, max_entropy, f"Entropía sospechosamente alta ({max_entropy:.2f}) en segmento '{suspicious_part}'"

    return False, max_entropy, ""

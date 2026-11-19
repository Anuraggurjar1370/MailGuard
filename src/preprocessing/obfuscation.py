"""
Obfuscation and Evasion Handler.
Detects, normalizes, and decodes obfuscations commonly used by phishing actors:
- Zero-width & invisible characters (\u200b, \u200c, \u200d, \ufeff, etc.)
- Unicode homoglyphs (Cyrillic, Greek, fullwidth lookalikes to Latin letters)
- Leetspeak and symbol substitutions ("paypa1", "v3rify", "p@ssword")
"""

import re
import unicodedata
from typing import Tuple, Dict

# Unicode homoglyphs to ASCII mapping
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    '\u0430': 'a', '\u0410': 'A', # а, А
    '\u0435': 'e', '\u0415': 'E', # е, Е
    '\u043e': 'o', '\u041e': 'O', # о, О
    '\u0440': 'p', '\u0420': 'P', # р, Р
    '\u0441': 'c', '\u0421': 'C', # с, С
    '\u0443': 'y', '\u0423': 'Y', # у, У
    '\u0445': 'x', '\u0425': 'X', # х, Х
    '\u0456': 'i', '\u0406': 'I', # і, І
    '\u0458': 'j', '\u0408': 'J', # ј, Ј
    '\u0455': 's', '\u0405': 'S', # ѕ, Ѕ
    # Greek lookalikes
    '\u03b1': 'a', '\u0391': 'A', # α, Α
    '\u03bf': 'o', '\u039f': 'O', # ο, Ο
    '\u03bd': 'v', '\u039d': 'N', # ν, Ν
    '\u03c1': 'p', '\u03a1': 'P', # ρ, Ρ
    '\u03c4': 't', '\u03a4': 'T', # τ, Τ
}

# Zero-width, formatting, and invisible characters regex
INVISIBLE_CHARS_REGEX = re.compile(
    r'[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F\u202A-\u202E\u2061-\u2064]'
)

# Leetspeak / obfuscated keyword patterns
LEET_PATTERNS = [
    (re.compile(r'\bpaypa[1l|]\b', re.IGNORECASE), 'paypal'),
    (re.compile(r'\bv[3e]r[i1l]fy\b', re.IGNORECASE), 'verify'),
    (re.compile(r'\bacc[0o]unt\b', re.IGNORECASE), 'account'),
    (re.compile(r'\bs[3e]cur[3e]\b', re.IGNORECASE), 'secure'),
    (re.compile(r'\bp[@a]ssw[0o]rd\b', re.IGNORECASE), 'password'),
    (re.compile(r'\bm[1i]cr[0o]s[0o]ft\b', re.IGNORECASE), 'microsoft'),
    (re.compile(r'\bg[0o][0o]gl[3e]\b', re.IGNORECASE), 'google'),
    (re.compile(r'\bb[@a]nk\b', re.IGNORECASE), 'bank'),
    (re.compile(r'\bupd[@a]t[3e]\b', re.IGNORECASE), 'update'),
    (re.compile(r'\bl[0o]g[1i]n\b', re.IGNORECASE), 'login'),
    (re.compile(r'\bn[3e]tfl[1i]x\b', re.IGNORECASE), 'netflix'),
    (re.compile(r'\bch[a4]s[e3]\b', re.IGNORECASE), 'chase'),
    (re.compile(r'\bcl[i1]ck\b', re.IGNORECASE), 'click'),
    (re.compile(r'\b[1i]mm[3e]d[i1][a4]t[3e]ly\b', re.IGNORECASE), 'immediately'),
]


def strip_invisible_characters(text: str) -> Tuple[str, int]:
    """
    Remove zero-width and invisible directional control characters.
    Returns (cleaned_text, count_removed).
    """
    if not text:
        return "", 0
    matches = INVISIBLE_CHARS_REGEX.findall(text)
    count = len(matches)
    cleaned = INVISIBLE_CHARS_REGEX.sub('', text)
    return cleaned, count


def normalize_homoglyphs(text: str) -> Tuple[str, int]:
    """
    Map confusing unicode homoglyphs (Cyrillic/Greek lookalikes) to standard ASCII.
    Returns (normalized_text, count_replaced).
    """
    if not text:
        return "", 0
    count = 0
    chars = []
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[ch])
            count += 1
        else:
            # NFKD normalization decomposing compatibility characters
            decomposed = unicodedata.normalize('NFKD', ch)
            if len(decomposed) == 1 and ord(decomposed) < 128:
                chars.append(decomposed)
            else:
                chars.append(ch)
    return ''.join(chars), count


def normalize_leetspeak(text: str) -> Tuple[str, int]:
    """
    Detect and normalize common phishing leetspeak patterns (e.g. paypa1 -> paypal).
    Returns (normalized_text, count_detected).
    """
    if not text:
        return "", 0
    count = 0
    normalized = text
    for pattern, replacement in LEET_PATTERNS:
        matches = pattern.findall(normalized)
        if matches:
            count += len(matches)
            normalized = pattern.sub(replacement, normalized)
    return normalized, count


def handle_all_obfuscations(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Full de-obfuscation pipeline.
    Returns cleaned text and a dictionary of detected obfuscation metrics.
    """
    cleaned, invisible_count = strip_invisible_characters(text)
    cleaned, homoglyph_count = normalize_homoglyphs(cleaned)
    cleaned, leet_count = normalize_leetspeak(cleaned)
    
    total_obfuscation_count = invisible_count + homoglyph_count + leet_count
    
    metrics = {
        "invisible_chars_count": invisible_count,
        "homoglyph_count": homoglyph_count,
        "leetspeak_count": leet_count,
        "total_obfuscation_count": total_obfuscation_count,
        "has_obfuscation": int(total_obfuscation_count > 0)
    }
    return cleaned, metrics

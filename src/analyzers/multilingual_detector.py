"""
Multilingual Phishing Detection Engine.
Detects and maps phishing lures across:
- English
- Hindi (Devanagari script)
- Hinglish (Romanized Hindi phonetic vernacular)
- Spanish

Extracts localized urgency, authority, and financial triggers, mapping them
into standardized threat signals.
"""

import re
from typing import Dict, Any, List, Tuple

# Multilingual keywords & triggers dictionary
MULTILINGUAL_LEXICON = {
    "hindi_script": {
        "urgency": ["तुरंत", "जल्दी", "तत्काल", "२४ घंटे", "समय समाप्त"],
        "threat": ["खाता बंद", "निलंबित", "अवैध", "कानूनी कार्रवाई", "सत्यापन"],
        "financial": ["रुपये", "पैसे", "लॉटरी", "बैंक खाता", "इनाम", "रिफंड"],
        "credential": ["पासवर्ड", "ओटीपी", "पिन", "पहचान पत्र", "आधार"]
    },
    "hinglish": {
        "urgency": ["turant", "jaldi", "fatafat", "abhi", "24 ghante", "aaj hi"],
        "threat": ["khata band", "block ho jayega", "suspend", "police", "legal action"],
        "financial": ["paise", "rupaye", "lottery", "inamm", "refund", "bhejo", "bank balance"],
        "credential": ["password", "otp", "aadhaar", "pan card", "pin", "verify karo"]
    },
    "spanish": {
        "urgency": ["urgente", "inmediatamente", "plazo", "24 horas", "aviso importante"],
        "threat": ["cuenta suspendida", "bloqueada", "infraccion", "penalizacion", "ilegal"],
        "financial": ["transferencia", "factura", "reembolso", "premio", "banco", "saldo"],
        "credential": ["contrasena", "credenciales", "verificar", "iniciar sesion", "clave"]
    }
}


class MultilingualDetector:
    """Detects language and extracts multilingual phishing indicators."""

    @classmethod
    def detect_language(cls, text: str) -> str:
        """Determines primary language family."""
        if not text:
            return "English"

        # Check for Devanagari script (Unicode range \u0900-\u097F)
        if re.search(r'[\u0900-\u097F]', text):
            return "Hindi"

        text_lower = text.lower()

        # Check Hinglish cues
        hinglish_hits = sum(1 for w in ["kripya", "turant", "khata", "paise", "bhejo", "karo", "apna", "aapka", "aadhaar"] if w in text_lower)
        if hinglish_hits >= 2:
            return "Hinglish"

        # Check Spanish cues
        spanish_hits = sum(1 for w in ["cuenta", "inmediatamente", "estimado", "banco", "contrasena", "por favor", "verifique"] if w in text_lower)
        if spanish_hits >= 2:
            return "Spanish"

        return "English"

    @classmethod
    def analyze_multilingual_threats(cls, text: str) -> Dict[str, Any]:
        """Detects language and extracts localized attack signals."""
        lang = cls.detect_language(text)
        text_lower = text.lower() if text else ""

        extracted_cues: List[str] = []
        is_threat_detected = False

        if lang == "Hindi":
            for cat, words in MULTILINGUAL_LEXICON["hindi_script"].items():
                for w in words:
                    if w in text:
                        extracted_cues.append(f"Hindi {cat}: '{w}'")
                        is_threat_detected = True

        elif lang == "Hinglish":
            for cat, words in MULTILINGUAL_LEXICON["hinglish"].items():
                for w in words:
                    if re.search(r'\b' + re.escape(w) + r'\b', text_lower):
                        extracted_cues.append(f"Hinglish {cat}: '{w}'")
                        is_threat_detected = True

        elif lang == "Spanish":
            for cat, words in MULTILINGUAL_LEXICON["spanish"].items():
                for w in words:
                    if re.search(r'\b' + re.escape(w) + r'\b', text_lower):
                        extracted_cues.append(f"Spanish {cat}: '{w}'")
                        is_threat_detected = True

        return {
            "detected_language": lang,
            "has_multilingual_lures": is_threat_detected,
            "matched_cues": extracted_cues,
            "localized_summary": (
                f"Detected {lang} email containing {len(extracted_cues)} localized psychological triggers."
                if is_threat_detected else f"Standard {lang} correspondence."
            )
        }

"""
Feature Extraction Pipeline.
Combines:
1. Word-level TF-IDF (1-2 grams)
2. Character-level TF-IDF (3-5 grams for sub-word & obfuscation patterns)
3. Handcrafted cybersecurity and psychological heuristic features
"""

import re
import numpy as np
from typing import List, Dict, Any, Union
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion
from src.preprocessing.text_cleaner import TextCleaner

# Cyber-threat psychological and security keyword lexicons
URGENCY_KEYWORDS = {
    'urgent', 'immediately', 'critical', 'action required', 'suspended', 'expire',
    'terminated', 'deadline', 'locked', 'freeze', '24 hours', 'avert', 'act now',
    'promptly', 'instant', 'quick', 'hurry', 'time sensitive', 'within 12 hours'
}

THREAT_FEAR_KEYWORDS = {
    'compromised', 'unauthorized', 'legal', 'forfeiture', 'prosecution', 'penalty',
    'lawsuit', 'breach', 'escalation', 'court', 'consequence', 'restricted',
    'deactivation', 'violation', 'shut down', 'fraud prevention', 'dispute'
}

FINANCIAL_BAIT_KEYWORDS = {
    'wire', 'transfer', 'refund', 'invoice', 'bitcoin', 'btc', 'gift card',
    'reward', 'payment', 'payout', 'dividend', 'lottery', 'bonus', 'overdue',
    'remit', 'treasury', 'beneficiary', 'clearing', 'balance', 'compensation'
}

CREDENTIAL_REQUEST_KEYWORDS = {
    'password', 'credentials', 'verify', 'sign in', 'login', 'sso', 'mfa',
    'token', 'authenticate', 'passcode', 'security code', 'restore access',
    're-authenticate', 'portal', 'duo'
}


class HandcraftedFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer extracting 12 dense handcrafted security features
    from raw email strings (or dictionaries containing subject and body).
    """

    def __init__(self):
        self.cleaner = TextCleaner()

    def fit(self, X, y=None):
        return self

    def _extract_single(self, text_item: Union[str, Dict[str, Any]]) -> List[float]:
        if isinstance(text_item, dict):
            subject = text_item.get("subject", "")
            body = text_item.get("body", "")
            raw = f"Subject: {subject}\n{body}"
        else:
            raw = str(text_item)
            subject = raw.split("\n")[0] if "\n" in raw else ""
            body = raw

        clean_meta = self.cleaner.clean(raw)
        cleaned_text = clean_meta["cleaned_text"]
        raw_len = max(len(raw), 1)

        # 1. URL Count
        url_count = float(clean_meta["url_count"])
        
        # 2. IP URL Presence (e.g. http://194.38.20.12)
        has_ip_url = 1.0 if ("__IP_ADDR__" in cleaned_text or re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', raw)) else 0.0

        # 3. Urgency keyword count
        urgency_count = sum(1.0 for kw in URGENCY_KEYWORDS if kw in raw.lower())

        # 4. Threat/Fear keyword count
        threat_count = sum(1.0 for kw in THREAT_FEAR_KEYWORDS if kw in raw.lower())

        # 5. Financial bait keyword count
        financial_count = sum(1.0 for kw in FINANCIAL_BAIT_KEYWORDS if kw in raw.lower())

        # 6. Credential request keyword count
        credential_count = sum(1.0 for kw in CREDENTIAL_REQUEST_KEYWORDS if kw in raw.lower())

        # 7. ALL CAPS ratio in body
        uppercase_chars = sum(1 for c in body if c.isupper())
        caps_ratio = float(uppercase_chars / raw_len)

        # 8. Exclamation mark count
        exclamation_count = float(raw.count('!'))

        # 9. HTML to text ratio
        html_ratio = float(clean_meta["html_ratio"])

        # 10. Obfuscation score (homoglyphs, invisible chars, leetspeak)
        obf = clean_meta.get("obfuscation_metrics", {})
        obfuscation_score = float(obf.get("total_obfuscation_count", 0))

        # 11. Suspicious Subject Prefix ([URGENT], CRITICAL, ACTION REQUIRED)
        suspicious_prefix = 1.0 if re.search(r'\[?(urgent|critical|action required|important notice|fwd:\s*urgent)\]?', subject, re.IGNORECASE) else 0.0

        # 12. Currency count
        currency_count = float(clean_meta["currency_count"])

        return [
            url_count,
            has_ip_url,
            urgency_count,
            threat_count,
            financial_count,
            credential_count,
            caps_ratio,
            exclamation_count,
            html_ratio,
            obfuscation_score,
            suspicious_prefix,
            currency_count
        ]

    def transform(self, X):
        features = [self._extract_single(item) for item in X]
        return np.array(features, dtype=np.float32)

    def get_feature_names_out(self, input_features=None):
        return np.array([
            "f_url_count",
            "f_has_ip_url",
            "f_urgency_count",
            "f_threat_count",
            "f_financial_count",
            "f_credential_count",
            "f_caps_ratio",
            "f_exclamation_count",
            "f_html_ratio",
            "f_obfuscation_score",
            "f_suspicious_prefix",
            "f_currency_count"
        ])


def build_feature_pipeline() -> FeatureUnion:
    """
    Constructs the hybrid feature extraction union:
    - Word TF-IDF (1-2 grams)
    - Char TF-IDF (3-5 grams)
    - Handcrafted cybersecurity features
    """
    word_vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=2500,
        sublinear_tf=True,
        token_pattern=r'(?u)\b\w+\b'
    )

    char_vectorizer = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(3, 5),
        max_features=1500,
        sublinear_tf=True
    )

    handcrafted_extractor = HandcraftedFeatureExtractor()

    pipeline = FeatureUnion([
        ("word_tfidf", word_vectorizer),
        ("char_tfidf", char_vectorizer),
        ("handcrafted", handcrafted_extractor)
    ])

    return pipeline

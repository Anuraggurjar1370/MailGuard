"""
Text Cleaning and Normalization Pipeline.
Performs HTML stripping, placeholder replacement (__URL__, __EMAIL__, __CURRENCY__, __NUM__),
obfuscation resolution, tokenization, stopword filtering, and lemmatization.
Runs completely offline with zero mandatory network downloads.
"""

import re
from typing import Dict, Any, Tuple, List
from bs4 import BeautifulSoup
from src.preprocessing.obfuscation import handle_all_obfuscations

# Built-in English stopwords list (standard set to avoid mandatory NLTK download requirements)
STOPWORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', "you're",
    "you've", "you'll", "you'd", 'your', 'yours', 'yourself', 'yourselves', 'he',
    'him', 'his', 'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', "it's",
    'its', 'itself', 'they', 'them', 'their', 'theirs', 'themselves', 'what', 'which',
    'who', 'whom', 'this', 'that', "that'll", 'these', 'those', 'am', 'is', 'are',
    'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'having', 'do',
    'does', 'did', 'doing', 'a', 'an', 'the', 'and', 'but', 'if', 'or', 'because',
    'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against',
    'between', 'into', 'through', 'during', 'before', 'after', 'above', 'below',
    'to', 'from', 'up', 'down', 'in', 'out', 'on', 'off', 'over', 'under', 'again',
    'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all',
    'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no',
    'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 's', 't',
    'can', 'will', 'just', 'don', "don't", 'should', "should've", 'now', 'd', 'll',
    'm', 'o', 're', 've', 'y', 'ain', 'aren', "aren't", 'couldn', "couldn't",
    'didn', "didn't", 'doesn', "doesn't", 'hadn', "hadn't", 'hasn', "hasn't",
    'haven', "haven't", 'isn', "isn't", 'ma', 'mightn', "mightn't", 'mustn',
    "mustn't", 'needn', "needn't", 'shan', "shan't", 'shouldn', "shouldn't",
    'wasn', "wasn't", 'weren', "weren't", 'won', "won't", 'wouldn', "wouldn't"
}

# Regex patterns for tokenization & entity placeholders
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
CURRENCY_REGEX = re.compile(r'[\$€£¥₹]\s*\d+(?:,\d{3})*(?:\.\d+)?|\b\d+(?:,\d{3})*(?:\.\d+)?\s*(?:USD|EUR|GBP|BTC|ETH|CAD|AUD)\b', re.IGNORECASE)
NUMBER_REGEX = re.compile(r'\b\d{4,}\b')


def strip_html(text: str) -> Tuple[str, float]:
    """
    Remove HTML tags and calculate HTML tag density.
    Returns (clean_text, html_tag_ratio).
    """
    if not text:
        return "", 0.0
    total_len = max(len(text), 1)
    if '<' in text and '>' in text:
        try:
            soup = BeautifulSoup(text, "html.parser")
            clean = soup.get_text(separator=" ")
            clean = re.sub(r'[ \t]+', ' ', clean).strip()
            html_tags_len = total_len - len(clean)
            ratio = max(0.0, min(1.0, html_tags_len / total_len))
            return clean, ratio
        except Exception:
            # Fallback regex
            clean = re.sub(r'<[^>]+>', ' ', text)
            clean = re.sub(r'[ \t]+', ' ', clean).strip()
            ratio = max(0.0, min(1.0, (total_len - len(clean)) / total_len))
            return clean, ratio
    return text, 0.0


def simple_lemmatize(token: str) -> str:
    """
    High-speed rule-based English suffix lemmatizer.
    Normalizes common plurals, past tenses, and gerunds to base forms.
    """
    token = token.lower()
    if len(token) <= 3:
        return token
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"
    if token.endswith("es") and len(token) > 3 and token[-3] in "sxyz":
        return token[:-2]
    if token.endswith("s") and not token.endswith("ss") and len(token) > 3:
        return token[:-1]
    if token.endswith("ing") and len(token) > 4:
        return token[:-3]
    if token.endswith("ed") and len(token) > 4:
        return token[:-2]
    return token


class TextCleaner:
    """Production text cleaning and feature-safe tokenizer."""

    def __init__(self, remove_stopwords: bool = True, lemmatize: bool = True):
        self.remove_stopwords = remove_stopwords
        self.lemmatize = lemmatize

    def clean(self, raw_text: str) -> Dict[str, Any]:
        """
        Run complete cleaning pipeline on raw text or email string.
        Returns cleaned string and extraction stats.
        """
        if not raw_text:
            return {
                "cleaned_text": "",
                "tokens": [],
                "html_ratio": 0.0,
                "url_count": 0,
                "email_count": 0,
                "currency_count": 0,
                "obfuscation_metrics": {}
            }

        # 1. HTML stripping
        text, html_ratio = strip_html(raw_text)

        # 2. Obfuscation detection & de-obfuscation
        text, obf_metrics = handle_all_obfuscations(text)

        # 3. Entity counting and placeholder substitution
        urls = URL_REGEX.findall(text)
        url_count = len(urls)
        text = URL_REGEX.sub(' __URL__ ', text)

        emails = EMAIL_REGEX.findall(text)
        email_count = len(emails)
        text = EMAIL_REGEX.sub(' __EMAIL__ ', text)

        ips = IP_REGEX.findall(text)
        text = IP_REGEX.sub(' __IP_ADDR__ ', text)

        currencies = CURRENCY_REGEX.findall(text)
        currency_count = len(currencies)
        text = CURRENCY_REGEX.sub(' __CURRENCY__ ', text)

        text = NUMBER_REGEX.sub(' __NUM__ ', text)

        # 4. Tokenization & case normalization
        words = re.findall(r'[a-zA-Z0-9_]+', text.lower())

        # 5. Stopword filtering & lemmatization
        processed_tokens: List[str] = []
        for word in words:
            if word.startswith("__") and word.endswith("__"):
                processed_tokens.append(word.upper())
                continue
            if self.remove_stopwords and word in STOPWORDS:
                continue
            if self.lemmatize:
                word = simple_lemmatize(word)
            if len(word) > 1:
                processed_tokens.append(word)

        cleaned_text = " ".join(processed_tokens)

        return {
            "cleaned_text": cleaned_text,
            "tokens": processed_tokens,
            "html_ratio": html_ratio,
            "url_count": url_count,
            "email_count": email_count,
            "currency_count": currency_count,
            "obfuscation_metrics": obf_metrics
        }


# Module level convenience function
_default_cleaner = TextCleaner()

def clean_text(text: str) -> str:
    """Quick helper returning just the cleaned string for sklearn pipelines."""
    return _default_cleaner.clean(text)["cleaned_text"]

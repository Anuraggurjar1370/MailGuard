"""
Unit tests for preprocessing and obfuscation resolution modules.
"""

import pytest
from src.preprocessing.obfuscation import (
    strip_invisible_characters,
    normalize_homoglyphs,
    normalize_leetspeak,
    handle_all_obfuscations
)
from src.preprocessing.text_cleaner import TextCleaner, strip_html


def test_strip_invisible_characters():
    # Insert zero-width spaces (\u200b) and word joiners (\u2060)
    dirty = "Pay\u200bPal\u2060 Security"
    cleaned, count = strip_invisible_characters(dirty)
    assert cleaned == "PayPal Security"
    assert count == 2


def test_normalize_homoglyphs():
    # Cyrillic 'а' (\u0430) and 'о' (\u043e) imitating Latin 'a' and 'o'
    cyrillic_spoof = "P\u0430ypal Inf\u043e"
    normalized, count = normalize_homoglyphs(cyrillic_spoof)
    assert normalized == "Paypal Info"
    assert count == 2


def test_normalize_leetspeak():
    text = "Please verify your paypa1 acc0unt immediately"
    normalized, count = normalize_leetspeak(text)
    assert "paypal" in normalized
    assert "account" in normalized
    assert count >= 2


def test_handle_all_obfuscations_metrics():
    adversarial_text = "Urgent: v3rify your P\u0430y\u200bpa1 credentials"
    cleaned, metrics = handle_all_obfuscations(adversarial_text)
    assert metrics["has_obfuscation"] == 1
    assert metrics["total_obfuscation_count"] >= 3
    assert "paypal" in cleaned.lower()


def test_strip_html():
    html_sample = "<p>Please click <a href='http://evil.com'>here</a> immediately.</p>"
    text, ratio = strip_html(html_sample)
    assert "Please click here immediately." in text
    assert ratio > 0.0


def test_text_cleaner_placeholders():
    cleaner = TextCleaner()
    raw = "Contact support@service.com or send $500 to http://192.168.1.1/login"
    result = cleaner.clean(raw)
    cleaned = result["cleaned_text"]
    assert "__EMAIL__" in cleaned
    assert "__CURRENCY__" in cleaned
    assert "__IP_ADDR__" in cleaned or "__URL__" in cleaned
    assert result["url_count"] >= 1
    assert result["currency_count"] >= 1

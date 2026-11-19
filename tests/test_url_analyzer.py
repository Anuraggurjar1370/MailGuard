"""
Unit tests for static URL analyzer, typosquatting detector, and safe defanging.
"""

import pytest
from src.analyzers.url_analyzer import (
    analyze_url,
    defang_url,
    check_typosquatting,
    levenshtein_distance,
    extract_and_analyze_all_urls
)


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("chase", "chse") == 1


def test_defang_url():
    url = "https://malicious-domain.com/login"
    defanged = defang_url(url)
    assert defanged.startswith("hxxps://")
    assert "[.]" in defanged


def test_ip_based_url():
    url = "http://192.168.1.100/verify.html"
    result = analyze_url(url)
    assert result["is_ip"] is True
    assert result["verdict"] in ["Dangerous", "Suspicious"]
    assert any("IP-based host" in flag for flag in result["threat_flags"])


def test_shortener_url():
    url = "https://bit.ly/3xY8a9"
    result = analyze_url(url)
    assert result["is_shortener"] is True
    assert any("URL shortener" in flag for flag in result["threat_flags"])


def test_typosquatting_detection():
    # Brand typosquatting lookalike
    typo_domain = "paypa1.com"
    check = check_typosquatting(typo_domain)
    assert check is not None
    assert check["targeted_brand"] == "paypal"

    full_result = analyze_url("http://paypa1-security.xyz/auth")
    assert full_result["is_typosquat"] is True
    assert full_result["is_suspicious_tld"] is True
    assert full_result["url_risk_score"] >= 60


def test_anchor_mismatch():
    raw_html = '<a href="http://evil-attacker.com/steal">https://chase.com/login</a>'
    findings = extract_and_analyze_all_urls(raw_html)
    assert len(findings) >= 1
    assert findings[0]["anchor_mismatch"] is True
    assert any("Critical Anchor Mismatch" in f for f in findings[0]["threat_flags"])

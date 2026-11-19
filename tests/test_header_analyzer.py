"""
Unit tests for RFC 822 Email Header Inspector.
"""

import pytest
from src.analyzers.email_header_analyzer import (
    EmailHeaderAnalyzer,
    extract_email_address,
    extract_domain,
    parse_auth_results
)


def test_extract_email_and_domain():
    header = "PayPal Support <support@paypal.com>"
    addr = extract_email_address(header)
    assert addr == "support@paypal.com"
    assert extract_domain(addr) == "paypal.com"


def test_parse_auth_results():
    header_val = "mx.google.com; spf=pass (google.com: domain matches); dkim=pass header.i=@paypal.com; dmarc=pass"
    auth = parse_auth_results(header_val)
    assert auth["spf"] == "pass"
    assert auth["dkim"] == "pass"
    assert auth["dmarc"] == "pass"

    fail_val = "spf=fail (sender IP 185.220.101.5 unauthorized); dkim=fail; dmarc=fail"
    auth_fail = parse_auth_results(fail_val)
    assert auth_fail["spf"] == "fail"
    assert auth_fail["dkim"] == "fail"
    assert auth_fail["dmarc"] == "fail"


def test_header_analyzer_reply_to_mismatch():
    raw_eml = """From: Security Team <security@bankofamerica.com>
Reply-To: Collector <phisher@hacker-mailbox.xyz>
Subject: Action Required: Overdue verification
Message-ID: <123456@bankofamerica.com>
Date: Mon, 19 Nov 2026 10:00:00 +0000

Please verify your credentials immediately.
"""
    result = EmailHeaderAnalyzer.analyze_raw_string(raw_eml)
    assert result["has_reply_to_mismatch"] is True
    assert any("Reply-To mismatch" in a for a in result["anomalies"])
    assert result["header_risk_score"] > 30


def test_header_analyzer_ceo_spoofing():
    raw_eml = """From: CEO Executive <executive.direct99@gmail.com>
Subject: Urgent wire transfer
Message-ID: <999@gmail.com>
Date: Mon, 19 Nov 2026 10:00:00 +0000

Are you at your desk?
"""
    result = EmailHeaderAnalyzer.analyze_raw_string(raw_eml)
    assert any("Corporate authority name spoofing" in a for a in result["anomalies"])

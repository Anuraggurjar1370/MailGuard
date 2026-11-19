"""
Unit tests for brand impersonation detector.
"""

import pytest
from src.analyzers.brand_detector import BrandDetector


def test_paypal_impersonation_detected():
    text = "Dear Customer, your PayPal account balance is restricted."
    sender = "security@paypa1-support-verify.com"
    result = BrandDetector.check_impersonation(text, sender)
    assert result["is_impersonation_detected"] is True
    assert any(b["brand"] == "PayPal" for b in result["impersonated_brands"])
    assert result["warning"] is not None


def test_genuine_paypal_sender_not_impersonated():
    text = "Your PayPal monthly transaction statement."
    sender = "service@paypal.com"
    result = BrandDetector.check_impersonation(text, sender)
    assert result["is_impersonation_detected"] is False
    assert result["warning"] is None


def test_microsoft_spoofing():
    text = "Update your Office 365 credentials."
    sender = "it-support@m1crosoft-cloud-admin.xyz"
    result = BrandDetector.check_impersonation(text, sender)
    assert result["is_impersonation_detected"] is True
    assert any(b["brand"] == "Microsoft" for b in result["impersonated_brands"])

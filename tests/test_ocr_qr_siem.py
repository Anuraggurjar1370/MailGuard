"""
Unit tests for OCR/Quishing detection and SIEM CEF/JSON exporters.
"""

import pytest
from src.analyzers.ocr_qr_detector import OcrAndQuishingDetector
from src.analyzers.siem_exporter import format_cef_event, format_json_webhook
from src.monitoring.drift_monitor import DriftMonitor


def test_quishing_detection():
    fake_qr_data = b"Some simulated QR image bytes with http://paypal-verification-center.info/qr-login"
    result = OcrAndQuishingDetector.analyze_image_bytes(fake_qr_data, filename="invoice_qr.png")
    assert result["is_quishing_detected"] is True
    assert len(result["qr_urls"]) >= 1
    assert result["verdict"] in ["Dangerous", "Suspicious"]


def test_siem_cef_export():
    scan_result = {
        "risk_score": 90,
        "verdict": "Dangerous"
    }
    cef = format_cef_event(scan_result, sender="attacker@paypa1.com", subject="Urgent Password Reset")
    assert cef.startswith("CEF:0|MailGuard|ExplainablePhishingPlatform|1.0|1001|")
    assert "cn1=90" in cef
    assert "act=BLOCKED" in cef


def test_siem_json_webhook():
    scan_result = {
        "risk_score": 20,
        "verdict": "Safe",
        "phishing_probability": 0.05
    }
    hook = format_json_webhook(scan_result, sender="team@acme.com", subject="Meeting Notes")
    assert hook["alert_type"] == "MAILGUARD_PHISHING_DETECTION"
    assert hook["verdict"] == "Safe"
    assert "recommended_action" in hook


def test_drift_monitor():
    DriftMonitor.record_prediction(0.95, "Dangerous")
    DriftMonitor.record_prediction(0.10, "Safe")
    metrics = DriftMonitor.get_drift_metrics()
    assert "total_inferences_recorded" in metrics
    assert "phishing_ratio" in metrics
    assert "drift_status" in metrics

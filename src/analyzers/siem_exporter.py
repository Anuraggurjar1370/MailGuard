"""
SIEM & Webhook Exporter.
Formats MailGuard detection alerts into:
1. CEF (Common Event Format - Splunk, ArcSight, QRadar compatible)
2. JSON Webhook Payloads for SOC alerting pipelines
"""

import time
from typing import Dict, Any


def format_cef_event(scan_result: Dict[str, Any], sender: str = "", subject: str = "") -> str:
    """
    Constructs a valid Common Event Format (CEF) string.
    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
    """
    score = scan_result.get("risk_score", 0)
    verdict = scan_result.get("verdict", "Unknown")
    severity = 10 if verdict == "Dangerous" else 5 if verdict == "Suspicious" else 1

    clean_subject = (subject or scan_result.get("subject", "No Subject")).replace("|", " ")
    clean_sender = sender or scan_result.get("from_header", "unknown@sender.com")

    cef_str = (
        f"CEF:0|MailGuard|ExplainablePhishingPlatform|1.0|1001|Email Threat Alert|{severity}|"
        f"msg={verdict} email detected by hybrid ensemble "
        f"suser={clean_sender} "
        f"cs1={clean_subject} cs1Label=Subject "
        f"cn1={score} cn1Label=RiskScore "
        f"act={'BLOCKED' if verdict == 'Dangerous' else 'QUARANTINED' if verdict == 'Suspicious' else 'PERMITTED'}"
    )
    return cef_str


def format_json_webhook(scan_result: Dict[str, Any], sender: str = "", subject: str = "") -> Dict[str, Any]:
    """Formats standardized JSON webhook notification."""
    return {
        "event_id": f"evt_{int(time.time() * 1000)}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alert_type": "MAILGUARD_PHISHING_DETECTION",
        "verdict": scan_result.get("verdict", "Unknown"),
        "risk_score": scan_result.get("risk_score", 0),
        "sender": sender or scan_result.get("from_header", ""),
        "subject": subject or scan_result.get("subject", ""),
        "key_reasons": scan_result.get("key_reasons", []),
        "phishing_probability": scan_result.get("phishing_probability", 0.0),
        "recommended_action": "Quarantine & Notify SOC" if scan_result.get("verdict") == "Dangerous" else "Allow with Warning Banner"
    }

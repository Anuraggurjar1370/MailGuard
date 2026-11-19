"""
Unit tests for threat intelligence and domain enrichment.
"""

import pytest
from src.enrichment.threat_intel import ThreatIntelEnricher


def test_threat_intel_known_malicious_domain():
    url = "http://paypal-verification-center.info/login.php"
    result = ThreatIntelEnricher.lookup_url(url)
    assert result["domain"] == "paypal-verification-center.info"
    assert result["virustotal"]["is_malicious"] is True
    assert result["overall_intel_threat"] == "High"
    assert result["whois"]["is_newly_registered"] is True


def test_threat_intel_benign_domain():
    url = "https://google.com/search"
    result = ThreatIntelEnricher.lookup_url(url)
    assert result["domain"] == "google.com"
    assert result["virustotal"]["is_malicious"] is False
    assert result["ssl_certificate"]["has_ssl"] is True

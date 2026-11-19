"""
Email Header (.EML) Analyzer.
Parses RFC 822 / MIME emails and analyzes:
1. Sender discrepancies: From vs. Reply-To vs. Return-Path
2. Authentication headers: SPF, DKIM, and DMARC verification results
3. Suspicious sender domains (typosquatting, free webmail impersonation)
4. Received header hop analysis: hop count, relay IP extraction, latency deltas
"""

import email
import re
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any, List, Optional
from src.analyzers.url_analyzer import check_typosquatting, IP_PATTERN

# Common free webmail domains often abused to spoof corporate identities
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "mail.com", "zoho.com", "yandex.com"
}


def extract_email_address(header_value: Optional[str]) -> str:
    """Extracts raw email address from header like 'John Doe <john@example.com>'."""
    if not header_value:
        return ""
    match = re.search(r'[\w\.-]+@[\w\.-]+', header_value)
    return match.group(0).lower() if match else ""


def extract_domain(email_str: str) -> str:
    """Extract domain portion of an email address."""
    if "@" in email_str:
        return email_str.split("@")[-1].lower().strip()
    return ""


def parse_auth_results(auth_header: str) -> Dict[str, str]:
    """Extracts SPF, DKIM, DMARC statuses from Authentication-Results or Received-SPF headers."""
    results = {"spf": "neutral", "dkim": "neutral", "dmarc": "neutral"}
    if not auth_header:
        return results

    header_lower = auth_header.lower()

    # SPF status
    if "spf=pass" in header_lower or "pass" in header_lower and "spf" in header_lower:
        results["spf"] = "pass"
    elif "spf=fail" in header_lower or "spf=softfail" in header_lower or "hardfail" in header_lower:
        results["spf"] = "fail"

    # DKIM status
    if "dkim=pass" in header_lower:
        results["dkim"] = "pass"
    elif "dkim=fail" in header_lower or "dkim=neutral" in header_lower:
        results["dkim"] = "fail"

    # DMARC status
    if "dmarc=pass" in header_lower:
        results["dmarc"] = "pass"
    elif "dmarc=fail" in header_lower or "dmarc=quarantine" in header_lower or "dmarc=reject" in header_lower:
        results["dmarc"] = "fail"

    return results


def parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parses 'Received' headers to trace the email routing path from origin to destination.
    Extracts originating/relay IP addresses and hostnames.
    """
    hops = []
    for i, raw_hop in enumerate(received_headers):
        # Extract IP address in square brackets [192.168.1.1] or bare IP
        ip_match = re.search(r'\[(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\]', raw_hop)
        ip = ip_match.group("ip") if ip_match else ""
        
        # Extract 'from' host
        from_match = re.search(r'from\s+([^\s\(\)]+)', raw_hop, re.IGNORECASE)
        from_host = from_match.group(1) if from_match else "unknown"

        # Extract 'by' host
        by_match = re.search(r'by\s+([^\s\(\)]+)', raw_hop, re.IGNORECASE)
        by_host = by_match.group(1) if by_match else "unknown"

        hops.append({
            "hop_number": i + 1,
            "from_host": from_host,
            "by_host": by_host,
            "relay_ip": ip,
            "raw": raw_hop.strip()[:180] + ("..." if len(raw_hop) > 180 else "")
        })

    return hops


class EmailHeaderAnalyzer:
    """Production RFC 822 Email Header Inspector."""

    @staticmethod
    def analyze_message(msg: email.message.Message) -> Dict[str, Any]:
        """Analyzes an already-parsed email.message.Message object."""
        subject = str(msg.get("subject", "") or "")
        from_raw = str(msg.get("from", "") or "")
        to_raw = str(msg.get("to", "") or "")
        date_raw = str(msg.get("date", "") or "")
        reply_to_raw = str(msg.get("reply-to", "") or "")
        return_path_raw = str(msg.get("return-path", "") or "")
        message_id = str(msg.get("message-id", "") or "")

        from_addr = extract_email_address(from_raw)
        reply_to_addr = extract_email_address(reply_to_raw)
        return_path_addr = extract_email_address(return_path_raw)

        from_domain = extract_domain(from_addr)
        reply_to_domain = extract_domain(reply_to_addr) if reply_to_addr else from_domain
        return_path_domain = extract_domain(return_path_addr) if return_path_addr else from_domain

        anomalies: List[str] = []
        header_risk_score = 0

        # 1. From vs Reply-To Mismatch
        has_reply_to_mismatch = bool(reply_to_domain and reply_to_domain != from_domain)
        if has_reply_to_mismatch:
            anomalies.append(f"Reply-To mismatch: messages route to '{reply_to_domain}' instead of sender '{from_domain}'")
            header_risk_score += 35

        # 2. From vs Return-Path Mismatch
        has_return_path_mismatch = bool(return_path_domain and return_path_domain != from_domain)
        if has_return_path_mismatch:
            anomalies.append(f"Return-Path bounce mismatch: bounces route to '{return_path_domain}'")
            header_risk_score += 20

        # 3. Free Webmail Domain Impersonation (e.g. 'CEO <ceo.company@gmail.com>')
        is_free_webmail = from_domain in FREE_WEBMAIL_DOMAINS
        display_name_lower = from_raw.lower()
        if is_free_webmail and any(title in display_name_lower for title in ["ceo", "executive", "payroll", "security", "admin", "support", "helpdesk"]):
            anomalies.append(f"Corporate authority name spoofing using free public webmail ({from_domain})")
            header_risk_score += 45

        # 4. Check sender domain for typosquatting / brand spoofing
        typo_info = check_typosquatting(from_domain)
        if typo_info:
            anomalies.append(f"Sender domain '{from_domain}' is a lookalike imitation of '{typo_info['targeted_brand']}'")
            header_risk_score += 45

        # 5. Missing critical RFC headers
        if not message_id:
            anomalies.append("Missing standard RFC Message-ID header")
            header_risk_score += 15
        if not date_raw:
            anomalies.append("Missing standard RFC Date header")
            header_risk_score += 10

        # 6. Parse SPF / DKIM / DMARC Authentication headers
        auth_results_raw = str(msg.get("authentication-results", "") or "")
        received_spf_raw = str(msg.get("received-spf", "") or "")
        combined_auth = f"{auth_results_raw} {received_spf_raw}".strip()

        auth_status = parse_auth_results(combined_auth)
        if auth_status["spf"] == "fail":
            anomalies.append("SPF validation failed (unauthorized sending IP)")
            header_risk_score += 30
        if auth_status["dkim"] == "fail":
            anomalies.append("DKIM cryptographic signature verification failed")
            header_risk_score += 30
        if auth_status["dmarc"] == "fail":
            anomalies.append("DMARC policy alignment check failed")
            header_risk_score += 35

        # 7. Hop Analysis
        received_headers = msg.get_all("received", [])
        hops = parse_received_hops(received_headers)

        header_risk_score = min(100, header_risk_score)
        verdict = "Dangerous" if header_risk_score >= 60 else "Suspicious" if header_risk_score >= 30 else "Safe"

        return {
            "subject": subject,
            "from": from_raw,
            "to": to_raw,
            "date": date_raw,
            "from_address": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_to_addr,
            "return_path": return_path_addr,
            "message_id": message_id,
            "has_reply_to_mismatch": has_reply_to_mismatch,
            "has_return_path_mismatch": has_return_path_mismatch,
            "auth_status": auth_status,
            "hops_count": len(hops),
            "hops": hops,
            "anomalies": anomalies,
            "header_risk_score": header_risk_score,
            "verdict": verdict
        }

    @classmethod
    def analyze_raw_string(cls, raw_content: str) -> Dict[str, Any]:
        """Parse raw RFC 822 string directly."""
        msg = Parser(policy=policy.default).parsestr(raw_content)
        return cls.analyze_message(msg)

    @classmethod
    def analyze_bytes(cls, raw_bytes: bytes) -> Dict[str, Any]:
        """Parse raw EML file bytes directly."""
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return cls.analyze_message(msg)

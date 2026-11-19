"""
Static URL Threat Analyzer.
Inspects URLs statically with zero external network requests:
- IP-based URLs
- URL shorteners
- Excessive subdomains
- '@' credential injection trick
- Punycode / IDN homograph attacks (xn--)
- Typosquatting via Levenshtein distance against high-value target brands
- Suspicious Top-Level Domains (TLDs)
- Anchor text vs destination HREF mismatch
- Safe URL defanging (hxxp[s]://...[.]...)
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "goo.gl", "tiny.cc", "rb.gy", "shorturl.at"
}

# Suspicious / high-abuse TLDs often favored in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "fit", "country", "gq", "cf",
    "ml", "tk", "site", "buzz", "club", "online", "link", "shop", "cc",
    "info", "biz", "su"
}

# High-value target brands monitored for typosquatting / lookalikes
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "facebook",
    "instagram", "linkedin", "twitter", "dropbox", "dhl", "fedex",
    "usps", "walmart", "target", "binance", "coinbase", "spotify"
]

IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def defang_url(url: str) -> str:
    """
    Safely defangs a URL to prevent accidental clicks.
    Example: https://evil.com/login -> hxxps://evil[.]com/login
    """
    if not url:
        return ""
    defanged = re.sub(r'^http', 'hxxp', url, flags=re.IGNORECASE)
    # Replace dots in host domain
    defanged = re.sub(r'(\w+)\.([a-zA-Z]{2,})', r'\1[.]\2', defanged)
    return defanged


def check_typosquatting(domain: str) -> Optional[Dict[str, Any]]:
    """
    Checks if the domain is a typosquatting imitation of a top protected brand.
    Returns matched brand and distance if an imitation is detected.
    """
    # Extract domain name without TLD
    clean_domain = domain.lower().split(':')[0]
    parts = clean_domain.split('.')
    main_name = parts[-2] if len(parts) >= 2 else parts[0]
    subtokens = re.split(r'[-_.]', clean_domain)

    for brand in TARGET_BRANDS:
        # Exact domain match is the real brand (e.g. paypal.com)
        if len(parts) == 2 and parts[0] == brand:
            return None

        # Check whole main_name distance
        dist = levenshtein_distance(main_name, brand)
        if 1 <= dist <= 2 and len(main_name) >= 4:
            return {
                "targeted_brand": brand,
                "distance": dist,
                "detected_token": main_name,
                "risk_message": f"Possible typosquatting imitation of '{brand}' (distance: {dist})"
            }

        # Check subtokens (e.g. "paypa1-security", "login-paypal-portal")
        for sub in subtokens:
            if sub == brand and clean_domain != f"{brand}.{parts[-1]}":
                return {
                    "targeted_brand": brand,
                    "distance": 0,
                    "detected_token": sub,
                    "risk_message": f"Deceptive use of brand '{brand}' in domain name"
                }
            sub_dist = levenshtein_distance(sub, brand)
            if 1 <= sub_dist <= 2 and len(sub) >= 4:
                return {
                    "targeted_brand": brand,
                    "distance": sub_dist,
                    "detected_token": sub,
                    "risk_message": f"Possible typosquatting imitation of '{brand}' in '{sub}' (distance: {sub_dist})"
                }

        # Check brand name embedded as deceptive substring (e.g. paypal-security-check.com)
        if brand in clean_domain and clean_domain != f"{brand}.{parts[-1]}":
            return {
                "targeted_brand": brand,
                "distance": 0,
                "detected_token": clean_domain,
                "risk_message": f"Deceptive use of brand '{brand}' in domain name"
            }

    return None


def analyze_url(url: str, anchor_text: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform deep static threat inspection of an individual URL.
    Returns structured threat flags, risk score, and defanged version.
    """
    clean_url = url.strip()
    if not clean_url.startswith(('http://', 'https://')):
        test_url = 'http://' + clean_url
    else:
        test_url = clean_url

    try:
        parsed = urlparse(test_url)
    except Exception:
        return {
            "url": clean_url,
            "defanged_url": defang_url(clean_url),
            "is_valid": False,
            "risk_score": 50,
            "threat_flags": ["Malformed URL"]
        }

    netloc = parsed.netloc.lower()
    path = parsed.path
    threat_flags: List[str] = []
    url_risk_points = 0

    # 1. IP-Based URL Check
    host_only = netloc.split(':')[0]
    is_ip = bool(IP_PATTERN.match(host_only))
    if is_ip:
        threat_flags.append("IP-based host (direct IP instead of domain name)")
        url_risk_points += 40

    # 2. URL Shortener Detection
    is_shortener = host_only in SHORTENER_DOMAINS
    if is_shortener:
        threat_flags.append(f"Known URL shortener ({host_only}) hides true destination")
        url_risk_points += 25

    # 3. Excessive Subdomains
    subdomain_parts = host_only.split('.')
    if len(subdomain_parts) > 4:
        threat_flags.append(f"Excessive subdomains ({len(subdomain_parts) - 2} levels) - common phishing cloaking")
        url_risk_points += 20

    # 4. '@' in URL (Userinfo trick)
    has_at_symbol = '@' in clean_url
    if has_at_symbol:
        threat_flags.append("URL contains '@' symbol - browser credential impersonation technique")
        url_risk_points += 35

    # 5. Punycode / IDN Homograph check (xn--)
    is_punycode = host_only.startswith('xn--') or '.xn--' in host_only
    if is_punycode:
        threat_flags.append("Punycode (IDN) homograph domain detected - deceptive internationalized script")
        url_risk_points += 40

    # 6. Suspicious TLD Check
    tld = subdomain_parts[-1] if subdomain_parts else ""
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    if is_suspicious_tld:
        threat_flags.append(f"High-abuse / suspicious TLD (.{tld})")
        url_risk_points += 20

    # 7. Typosquatting / Brand Imitation
    typo_result = check_typosquatting(host_only)
    is_typosquat = typo_result is not None
    if is_typosquat:
        threat_flags.append(typo_result["risk_message"])
        url_risk_points += 45

    # 8. Anchor Text vs Real Destination Mismatch
    mismatch_detected = False
    if anchor_text:
        anchor_clean = anchor_text.strip()
        # If anchor looks like a URL
        if re.match(r'https?://', anchor_clean, re.IGNORECASE) or any(d in anchor_clean for d in [".com", ".org", ".net", ".io"]):
            anchor_domain = anchor_clean.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
            if anchor_domain and anchor_domain not in host_only and host_only not in anchor_domain:
                mismatch_detected = True
                threat_flags.append(f"Critical Anchor Mismatch: text claims '{anchor_domain}' but leads to '{host_only}'")
                url_risk_points += 50

    # Calculate overall URL threat level
    url_risk_score = min(100, url_risk_points)
    verdict = "Dangerous" if url_risk_score >= 60 else "Suspicious" if url_risk_score >= 30 else "Safe"

    return {
        "url": clean_url,
        "defanged_url": defang_url(clean_url),
        "domain": host_only,
        "tld": tld,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "is_punycode": is_punycode,
        "is_suspicious_tld": is_suspicious_tld,
        "is_typosquat": is_typosquat,
        "typosquat_details": typo_result,
        "anchor_mismatch": mismatch_detected,
        "url_risk_score": url_risk_score,
        "verdict": verdict,
        "threat_flags": threat_flags
    }


def extract_and_analyze_all_urls(text: str) -> List[Dict[str, Any]]:
    """Finds all URLs in text or HTML and analyzes each statically."""
    if not text:
        return []

    # First look for HTML anchor tags <a href="...">text</a>
    anchor_matches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', text, re.IGNORECASE)
    results = []
    seen_urls = set()

    for href, anchor in anchor_matches:
        if href.startswith(("http://", "https://", "www.")):
            seen_urls.add(href)
            results.append(analyze_url(href, anchor_text=re.sub(r'<[^>]+>', '', anchor).strip()))

    # Then look for bare URLs
    bare_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text, re.IGNORECASE)
    for u in bare_urls:
        if u not in seen_urls:
            seen_urls.add(u)
            results.append(analyze_url(u))

    return results

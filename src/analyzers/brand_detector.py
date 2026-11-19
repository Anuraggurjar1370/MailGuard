"""
Brand Impersonation Detector.
Identifies when high-value brands are mentioned in an email while the sender
originates from an unauthorized or deceptive domain.
"""

import re
from typing import Dict, Any, Optional, List
from src.analyzers.email_header_analyzer import extract_domain, extract_email_address

# High-profile targeted brands and their authorized domain lists
KNOWN_BRANDS = {
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com", "paypal-communication.com"],
        "keywords": [r'\bpaypal\b', r'\bpaypa1\b']
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
        "keywords": [r'\bmicrosoft\b', r'\boffice ?365\b', r'\boutlook\b', r'\bm1crosoft\b']
    },
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "gmail.com", "googlemail.com"],
        "keywords": [r'\bgoogle\b', r'\bgoogle workspace\b', r'\bg00gle\b']
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com"],
        "keywords": [r'\bapple\b', r'\bicloud\b', r'\bapple id\b']
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": ["amazon.com", "amazon.co.uk", "amazon.in"],
        "keywords": [r'\bamazon\b', r'\bprime video\b', r'\bamaz0n\b']
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "keywords": [r'\bnetflix\b', r'\bnetfl1x\b']
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": ["chase.com", "jpmorganchase.com"],
        "keywords": [r'\bchase\b', r'\bjpmorgan\b']
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "official_domains": ["wellsfargo.com"],
        "keywords": [r'\bwells ?fargo\b']
    },
    "dhl": {
        "name": "DHL Express",
        "official_domains": ["dhl.com", "dhl-express.com"],
        "keywords": [r'\bdhl\b', r'\bdhl express\b']
    },
    "fedex": {
        "name": "FedEx",
        "official_domains": ["fedex.com"],
        "keywords": [r'\bfedex\b']
    }
}


class BrandDetector:
    """Checks for brand impersonation attacks."""

    @classmethod
    def check_impersonation(cls, text: str, sender_header: str = "") -> Dict[str, Any]:
        sender_email = extract_email_address(sender_header)
        sender_domain = extract_domain(sender_email)
        text_lower = text.lower() if text else ""

        impersonated_brands = []

        for key, data in KNOWN_BRANDS.items():
            # Check if brand keywords are mentioned in text or sender header
            mentioned = False
            for pattern in data["keywords"]:
                if re.search(pattern, text_lower) or re.search(pattern, sender_header.lower()):
                    mentioned = True
                    break

            if mentioned:
                # Check if sender domain is in the brand's authorized domains
                is_authorized = any(
                    sender_domain == dom or sender_domain.endswith("." + dom)
                    for dom in data["official_domains"]
                )

                if sender_domain and not is_authorized:
                    impersonated_brands.append({
                        "brand": data["name"],
                        "claimed_sender_domain": sender_domain,
                        "official_domains": data["official_domains"],
                        "risk_level": "High"
                    })

        is_spoofed = len(impersonated_brands) > 0
        return {
            "is_impersonation_detected": is_spoofed,
            "impersonated_brands": impersonated_brands,
            "warning": (
                f"Brand Impersonation Alert: Claims to represent {', '.join(b['brand'] for b in impersonated_brands)} "
                f"but sent from unauthorized domain '{sender_domain}'"
            ) if is_spoofed else None
        }

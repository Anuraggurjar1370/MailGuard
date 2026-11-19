"""
Gamified Phishing Simulator Scenarios.
Curated real-world email scenarios for interactive security training.
Includes plain-English awareness explanations and red flag checklists.
"""

import random
from typing import Dict, Any, List

SIMULATOR_SCENARIOS = [
    {
        "id": "sim_01",
        "difficulty": "Easy",
        "subject": "CRITICAL: Your Netflix Account Has Been Suspended",
        "sender": "Netflix Support <billing@netfl1x-verify-update.com>",
        "body": "Dear Customer,\n\nWe were unable to process your payment for next month's subscription. Your streaming access will terminate within 12 hours unless you update your credit card details immediately.\n\nClick here to update your card:\nhttp://netflix-billing-resolve.xyz/auth\n\nNetflix Customer Operations",
        "is_phishing": True,
        "category": "Credential Phishing",
        "explanation": "This is a classic credential harvesting scam impersonating Netflix. Look at the sender domain ('netfl1x-verify-update.com' with a '1' instead of 'l') and the deceptive '.xyz' destination link designed to steal your credit card numbers under artificial urgency.",
        "indicators": [
            "Sender domain uses leetspeak lookalike ('netfl1x')",
            "High urgency artificial deadline ('within 12 hours')",
            "Destructive threat ('access will terminate')",
            "Suspicious .xyz top-level domain"
        ]
    },
    {
        "id": "sim_02",
        "difficulty": "Easy",
        "subject": "GitHub: Alex Mercer approved Pull Request #402",
        "sender": "GitHub Notifications <notifications@github.com>",
        "body": "Hi harsh,\n\nAlex Mercer approved PR #402: 'Optimize vectorizer n-gram caching for low latency'.\n\nYou can view and merge the changes on GitHub:\nhttps://github.com/org/mailguard/pull/402\n\nGitHub, Inc., 88 Colin P Kelly Jr St, San Francisco, CA 94107",
        "is_phishing": False,
        "category": "Legitimate Notification",
        "explanation": "This is a legitimate developer notification. The sender is the official 'notifications@github.com', the link points directly to the real https://github.com domain, and there is no artificial panic or request for credentials.",
        "indicators": [
            "Official sender domain (github.com)",
            "Direct HTTPS link to legitimate platform",
            "Contextual workplace update with no credential requests",
            "Standard corporate physical address footer"
        ]
    },
    {
        "id": "sim_03",
        "difficulty": "Medium",
        "subject": "Quick task: Emergency wire transfer before 3 PM",
        "sender": "David Miller - CEO <ceo.office.direct99@gmail.com>",
        "body": "Hi,\n\nAre you available right now? I am currently trapped in an executive investor meeting and cannot take voice calls.\n\nWe need to process an emergency supplier wire transfer of $38,500 immediately to close a vendor contract today. Can you process this from our main account? I will send you the wire coordinates right away. Keep this strictly between us for now.",
        "is_phishing": True,
        "category": "Business Email Compromise (BEC)",
        "explanation": "This is a link-free CEO Wire Fraud (BEC) attack. The scammer impersonates an executive using a free Gmail address, claims an inability to talk by phone, invokes urgency ('before 3 PM'), and demands secrecy to bypass normal financial approval controls.",
        "indicators": [
            "Executive authority spoofed via free public Gmail address",
            "Urgent request to transfer funds without customary verbal confirmation",
            "Claims inability to speak by phone to prevent verification",
            "Requests confidentiality to avoid second-pair-of-eyes review"
        ]
    },
    {
        "id": "sim_04",
        "difficulty": "Medium",
        "subject": "Your monthly Chase credit card statement is available",
        "sender": "Chase Online Banking <no-reply@chase.com>",
        "body": "Dear customer,\n\nYour latest credit card statement for account ending in 4102 is now available. Log in securely to chase.com or use the Chase Mobile app to review your balance and payment due date.\n\nJPMorgan Chase Bank, N.A. Member FDIC.",
        "is_phishing": False,
        "category": "Legitimate Statement",
        "explanation": "This is a legitimate transactional notification. It does not contain shady direct links, tells you to visit the official website or mobile app directly, has genuine sender headers, and does not demand immediate panic action.",
        "indicators": [
            "Authentic sender domain (chase.com)",
            "Instructs user to navigate to official app or site directly",
            "No aggressive threats or forced deadlines",
            "Standard regulatory banking disclaimer (Member FDIC)"
        ]
    },
    {
        "id": "sim_05",
        "difficulty": "Hard",
        "subject": "IT Service Desk: Duo MFA Push Device Update Required",
        "sender": "IT Infrastructure Support <support@company-servicedesk-auth.com>",
        "body": "All Staff,\n\nOur corporate single sign-on (SSO) certificate is being renewed over the weekend. All staff must re-enroll their Duo multi-factor authentication token to avoid VPN disruption on Monday.\n\nRe-authenticate your mobile token here:\nhttp://185.220.101.5/duo/sso/auth\n\nIT Support Team",
        "is_phishing": True,
        "category": "IT / MFA Phishing",
        "explanation": "This attack mimics internal IT operations. Notice the destination link is a naked IP address (185.220.101.5) rather than your company's internal portal, and the sender uses an unauthorized external domain rather than your corporate domain.",
        "indicators": [
            "Raw IP address used as login destination (185.220.101.5)",
            "Impersonates internal IT helpdesk from an external domain",
            "Urgent call to action tied to weekend deadline",
            "Targets Multi-Factor Authentication (MFA) credentials"
        ]
    },
    {
        "id": "sim_06",
        "difficulty": "Easy",
        "subject": "DHL Express: Package #DHL-99214 on hold at sorting facility",
        "sender": "DHL Tracking <tracking@dhl-express-redelivery.top>",
        "body": "Dear customer,\n\nYour shipment could not be dispatched due to an unpaid customs fee of $1.99 USD.\n\nPlease remit the balance today to schedule immediate doorstep delivery:\nhttp://dhl-express-customs-pay.info/track?id=99214\n\nPackages held over 48 hours will be discarded.",
        "is_phishing": True,
        "category": "Delivery Scam",
        "explanation": "Very common parcel delivery scam. Threat actors use low nominal fees ($1.99) to lower the victim's guard and steal credit card data on fake lookup pages hosted on '.top' or '.info' TLDs.",
        "indicators": [
            "Suspicious low-cost fee lure ($1.99) to lower psychological resistance",
            "Suspicious TLDs (.top, .info)",
            "Threat of package destruction within 48 hours",
            "Mismatched domain (not official dhl.com)"
        ]
    }
]


def get_random_scenario() -> Dict[str, Any]:
    """Returns a random training scenario without the answer."""
    scenario = random.choice(SIMULATOR_SCENARIOS)
    return {
        "id": scenario["id"],
        "difficulty": scenario["difficulty"],
        "subject": scenario["subject"],
        "sender": scenario["sender"],
        "body": scenario["body"]
    }


def verify_scenario_answer(scenario_id: str, user_guess_is_phish: bool) -> Dict[str, Any]:
    """Checks the user's guess against ground truth and returns feedback."""
    for s in SIMULATOR_SCENARIOS:
        if s["id"] == scenario_id:
            is_correct = (user_guess_is_phish == s["is_phishing"])
            points = 100 if is_correct else 0
            return {
                "scenario_id": s["id"],
                "is_correct": is_correct,
                "points_earned": points,
                "ground_truth": "Phishing" if s["is_phishing"] else "Legitimate",
                "category": s["category"],
                "explanation": s["explanation"],
                "indicators": s["indicators"]
            }

    return {
        "scenario_id": scenario_id,
        "is_correct": False,
        "points_earned": 0,
        "ground_truth": "Unknown",
        "category": "Unknown",
        "explanation": "Scenario not found.",
        "indicators": []
    }

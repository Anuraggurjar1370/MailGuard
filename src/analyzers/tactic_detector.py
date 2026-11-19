"""
Social-Engineering Tactic Detector.
Analyzes email text across 5 primary psychological manipulation tactics:
1. Urgency (Artificial deadlines, countdown pressure)
2. Fear / Threat (Account lockout, legal penalty, breach)
3. Authority Impersonation (CEO, IT admin, security team, government)
4. Reward / Financial Bait (Overdue invoice, refunds, bitcoin, lottery)
5. Credential Requests (Password reset, verify identity, MFA token)

Outputs normalized scores (0-100) per tactic for Radar Chart visualization.
"""

import re
from typing import Dict, Any, List

# Lexicon sets for psychological tactics
TACTIC_PATTERNS = {
    "urgency": [
        r'\burgent\b', r'\bimmediately\b', r'\bcritical\b', r'\baction required\b',
        r'\bdeadline\b', r'\b24 hours?\b', r'\b12 hours?\b', r'\bexpires?\b',
        r'\bact now\b', r'\bpromptly\b', r'\binstant\b', r'\bwithout delay\b',
        r'\bh当店\b', r'\btime sensitive\b', r'\blast chance\b'
    ],
    "fear": [
        r'\bsuspended?\b', r'\blocked\b', r'\bterminated?\b', r'\bprosecution\b',
        r'\blegal action\b', r'\bpenalty\b', r'\blawsuit\b', r'\bviolation\b',
        r'\bunauthorized\b', r'\bcompromised\b', r'\bforfeiture\b', r'\bfreeze\b',
        r'\bsecurity alert\b', r'\bwarning\b', r'\bdeactivat(e|ed|ion)\b'
    ],
    "authority": [
        r'\bceo\b', r'\bexecutive\b', r'\bpresident\b', r'\bdirector\b',
        r'\bit support\b', r'\bhelpdesk\b', r'\bsecurity team\b', r'\badministrator\b',
        r'\bcompliance\b', r'\bhuman resources\b', r'\bhr department\b',
        r'\bofficial notice\b', r'\bfederal\b', r'\birs\b', r'\bgovernment\b'
    ],
    "reward": [
        r'\bwire transfer\b', r'\binvoice\b', r'\brefund\b', r'\bpayment\b',
        r'\bbonus\b', r'\bbitcoin\b', r'\bbtc\b', r'\bairdrop\b', r'\blottery\b',
        r'\bwinner\b', r'\bclaim\b', r'\bgift cards?\b', r'\bpayout\b',
        r'\bcompensation\b', r'\bdividend\b', r'\bexclusive offer\b'
    ],
    "credentials": [
        r'\bpasswords?\b', r'\bcredentials?\b', r'\blogin\b', r'\bsign ?in\b',
        r'\bverify\b', r'\bverification\b', r'\bconfirm\b', r'\bmfa\b',
        r'\b2fa\b', r'\bpasscode\b', r'\btoken\b', r'\brestore access\b',
        r'\bre-authenticate\b', r'\baccount details\b'
    ]
}


class TacticDetector:
    """Detects and scores psychological manipulation tactics in email text."""

    @classmethod
    def detect_tactics(cls, text: str) -> Dict[str, Any]:
        if not text:
            return {
                "scores": {k: 0 for k in TACTIC_PATTERNS},
                "detected_tactics": [],
                "primary_tactic": "None"
            }

        text_lower = text.lower()
        scores = {}
        detected_tactics = []

        for tactic, patterns in TACTIC_PATTERNS.items():
            matches = 0
            for pattern in patterns:
                found = re.findall(pattern, text_lower)
                matches += len(found)

            # Calculate score (each trigger gives 25 points, capped at 100)
            score = min(100, matches * 25)
            scores[tactic] = score

            if score >= 25:
                detected_tactics.append({
                    "tactic": tactic.capitalize(),
                    "score": score,
                    "triggers_count": matches
                })

        # Identify primary driver
        primary = max(scores.items(), key=lambda x: x[1])
        primary_tactic = primary[0].capitalize() if primary[1] > 0 else "None"

        return {
            "scores": scores,
            "detected_tactics": detected_tactics,
            "primary_tactic": primary_tactic
        }

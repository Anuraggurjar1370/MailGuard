"""
Active Learning Feedback Store.
Lightweight local store recording user feedback and false positive/negative reports
for continuous model auditing and review.
"""

import os
import json
import time
from typing import List, Dict, Any

FEEDBACK_FILE = os.path.join("data", "feedback.json")


def _ensure_store_exists():
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    if not os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def add_feedback(
    email_snippet: str,
    predicted_verdict: str,
    user_reported_label: str,
    comments: str = ""
) -> Dict[str, Any]:
    """Records a user feedback submission."""
    _ensure_store_exists()

    record = {
        "id": f"fb_{int(time.time() * 1000)}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "email_snippet": email_snippet[:200] + ("..." if len(email_snippet) > 200 else ""),
        "predicted_verdict": predicted_verdict,
        "user_reported_label": user_reported_label,
        "comments": comments,
        "status": "pending_review"
    }

    try:
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = []

    data.insert(0, record)

    with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return record


def get_all_feedback() -> List[Dict[str, Any]]:
    """Retrieves all feedback records."""
    _ensure_store_exists()
    try:
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

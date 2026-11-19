"""
Unit tests for adversarial robustness tester.
"""

import pytest
from src.analyzers.adversarial_tester import AdversarialTester, perturb_text_adversarially


def test_perturb_text_adversarially():
    original = "Please verify your paypal password immediately."
    perturbed, meta = perturb_text_adversarially(original)
    assert meta["mutations_applied"] >= 1
    # Check that either zero-width, homoglyph, or leetspeak occurred
    assert len(perturbed) >= len(original) or "v3rify" in perturbed or "p@ssword" in perturbed or "\u200b" in perturbed


def test_adversarial_robustness_eval():
    from src.preprocessing.text_cleaner import TextCleaner
    cleaner = TextCleaner()

    def mock_predict(text):
        # Clean text through de-obfuscation pipeline
        cleaned = cleaner.clean(text)["cleaned_text"]
        is_phish = any(w in cleaned.lower() for w in ["paypal", "paypa1", "verify", "password", "urgent"])
        return {
            "verdict": "Dangerous" if is_phish else "Safe",
            "risk_score": 85 if is_phish else 10
        }

    sample = "URGENT: Please verify your paypal account password now."
    result = AdversarialTester.test_robustness(sample, mock_predict)
    assert result["original_verdict"] == "Dangerous"
    assert result["robustness_score"] >= 70
    assert result["status"] in ["Highly Resilient", "Moderate Resilience"]

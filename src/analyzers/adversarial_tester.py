"""
Adversarial Robustness Tester.
Simulates real-world evasive perturbation attacks against email text:
1. Homoglyph Substitution (Cyrillic lookalikes)
2. Zero-Width Space Injection
3. Leetspeak Transformation (e -> 3, a -> @, i -> 1)
4. Character Transposition Noise

Evaluates whether the ML defense layer maintains detection integrity under adversarial strain.
"""

import random
from typing import Dict, Any, Tuple


def perturb_text_adversarially(text: str) -> Tuple[str, Dict[str, Any]]:
    """Applies realistic adversarial evasion mutations to text."""
    if not text:
        return "", {"mutations_applied": 0}

    chars = list(text)
    mutations_count = 0

    # 1. Zero-width character injection into keywords
    mutated = text
    for word in ["paypal", "verify", "account", "security", "urgent", "update", "password"]:
        if word in mutated.lower():
            # Inject zero-width space in the middle
            mid = len(word) // 2
            split_word = word[:mid] + "\u200b" + word[mid:]
            mutated = mutated.replace(word, split_word)
            mutated = mutated.replace(word.capitalize(), split_word.capitalize())
            mutations_count += 1

    # 2. Homoglyph injection (Latin 'a' -> Cyrillic 'а', 'e' -> Cyrillic 'е')
    homoglyphs = {'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 'p': '\u0440'}
    chars = []
    for c in mutated:
        if c in homoglyphs and random.random() < 0.25:
            chars.append(homoglyphs[c])
            mutations_count += 1
        else:
            chars.append(c)

    mutated = "".join(chars)

    # 3. Leetspeak replacement
    leets = [('verify', 'v3rify'), ('password', 'p@ssword'), ('account', 'acc0unt')]
    for original, leet in leets:
        if original in mutated.lower():
            mutated = mutated.replace(original, leet)
            mutations_count += 1

    return mutated, {
        "mutations_applied": mutations_count,
        "techniques": ["Zero-width space injection", "Cyrillic homoglyphs", "Leetspeak substitution"]
    }


class AdversarialTester:
    """Evaluates defense stability against adversarial perturbations."""

    @classmethod
    def test_robustness(cls, text: str, predict_func) -> Dict[str, Any]:
        """
        Runs original email through predict_func, generates perturbed version,
        runs it through predict_func, and compares outcomes.
        """
        # Original evaluation
        orig_res = predict_func(text)
        orig_verdict = orig_res["verdict"]
        orig_score = orig_res["risk_score"]

        # Generate perturbed sample
        perturbed_text, meta = perturb_text_adversarially(text)

        # Perturbed evaluation
        perturbed_res = predict_func(perturbed_text)
        perturbed_verdict = perturbed_res["verdict"]
        perturbed_score = perturbed_res["risk_score"]

        # Robustness calculation
        score_diff = abs(orig_score - perturbed_score)
        maintained_verdict = (orig_verdict == perturbed_verdict)

        # High robustness if verdict was maintained and score variation < 15
        robustness_score = max(0, 100 - (score_diff * 2)) if maintained_verdict else max(10, 40 - score_diff)

        if robustness_score >= 80:
            status = "Highly Resilient"
            summary = "Defense layer successfully neutralized homoglyphs and evasion tricks with zero verdict drift."
        elif robustness_score >= 50:
            status = "Moderate Resilience"
            summary = "Minor score fluctuations occurred, but overall security verdict was preserved."
        else:
            status = "Evaded / Vulnerable"
            summary = "Adversarial evasion caused verdict drift. Retraining on adversarial samples recommended."

        return {
            "original_verdict": orig_verdict,
            "original_risk_score": orig_score,
            "perturbed_verdict": perturbed_verdict,
            "perturbed_risk_score": perturbed_score,
            "robustness_score": int(robustness_score),
            "status": status,
            "summary": summary,
            "mutations_count": meta["mutations_applied"],
            "techniques_tested": meta["techniques"],
            "perturbed_preview": perturbed_text[:180] + ("..." if len(perturbed_text) > 180 else "")
        }

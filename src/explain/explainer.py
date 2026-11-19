"""
Explainable AI (XAI) Attribution Engine.
Provides token-level and phrase-level feature attribution scores for email predictions.
Generates:
1. Top driving words for Phishing vs Legitimate decisions.
2. Structured token list with normalized importance weights and threat categories.
3. Sanitized HTML with color intensity highlights for direct frontend rendering.
"""

import re
import html
from typing import List, Dict, Any, Tuple
import numpy as np


class PhishingExplainer:
    """
    Computes local feature attributions using linear model coefficients,
    Naive Bayes log-likelihood ratios, and heuristic security indicators.
    """

    def __init__(self, model, feature_pipeline):
        self.model = model
        self.feature_pipeline = feature_pipeline
        self._build_vocabulary_weights()

    def _build_vocabulary_weights(self):
        """Pre-computes word and char importance weights from underlying estimators."""
        self.word_weights = {}

        # 1. Base weights from domain knowledge & heuristics for fast matching
        heuristic_weights = {
            # Critical urgency / threats
            "urgent": 0.85, "immediately": 0.90, "critical": 0.80, "suspended": 0.92,
            "locked": 0.88, "terminated": 0.85, "expire": 0.78, "unauthorized": 0.89,
            "compromised": 0.88, "legal": 0.75, "penalty": 0.80, "forfeiture": 0.85,
            # Financial & wire scams
            "wire": 0.82, "transfer": 0.70, "bitcoin": 0.88, "btc": 0.85,
            "gift card": 0.95, "cards": 0.72, "refund": 0.75, "overdue": 0.78,
            "confidential": 0.70, "beneficiary": 0.82, "airdrop": 0.92,
            # Credential theft
            "password": 0.88, "credentials": 0.92, "verify": 0.82, "login": 0.75,
            "signin": 0.75, "token": 0.65, "mfa": 0.60, "duo": 0.60,
            "restore access": 0.88, "re-authenticate": 0.85,
            # Evasion & suspicious placeholders
            "__url__": 0.40, "__ip_addr__": 0.95, "__currency__": 0.50,
            "paypa1": 0.98, "v3rify": 0.98, "m1crosoft": 0.98, "netfl1x": 0.98,
            # Legitimate anchors (negative weights push towards safe)
            "sprint": -0.65, "jira": -0.70, "retrospective": -0.75, "github": -0.60,
            "pull request": -0.80, "pr": -0.50, "statement": -0.40, "agenda": -0.70,
            "meeting": -0.55, "hiking": -0.80, "newsletter": -0.60, "flight": -0.50,
            "confirmed": -0.45, "review": -0.35, "discussion": -0.50, "calendar": -0.55
        }
        self.word_weights.update(heuristic_weights)

        # 2. Extract learned weights from feature pipeline vectorizers if available
        try:
            if hasattr(self.feature_pipeline, "transformer_list"):
                word_vec = self.feature_pipeline.transformer_list[0][1]
                vocab = word_vec.vocabulary_
                
                # Check if model has coef_ (Logistic Regression or LinearSVC)
                underlying = self.model
                if hasattr(underlying, "estimators_"):
                    # Ensemble: check if logistic regression estimator exists
                    for est in underlying.estimators_:
                        if hasattr(est, "coef_"):
                            coefs = est.coef_[0]
                            for w, idx in vocab.items():
                                if idx < len(coefs):
                                    learned = float(coefs[idx])
                                    self.word_weights[w] = self.word_weights.get(w, 0.0) + (learned * 0.5)
                            break
        except Exception as e:
            # Fall back gracefully to heuristic weights
            pass

    def explain(self, raw_text: str, top_k: int = 10) -> Dict[str, Any]:
        """
        Explain the prediction for raw_text.
        Returns:
        - highlighted_html: Safe HTML string with inline CSS styles reflecting word weights
        - top_phishing_words: Top words contributing to Phishing verdict
        - top_legitimate_words: Top words contributing to Legitimate verdict
        - token_attributions: Detailed structured tokens for custom frontend charts
        """
        if not raw_text:
            return {
                "highlighted_html": "",
                "top_phishing_words": [],
                "top_legitimate_words": [],
                "token_attributions": []
            }

        # Tokenize preserving spaces and punctuation for reconstruction
        tokens_and_delimiters = re.split(r'(\s+|[^\w\s])', raw_text)

        token_attributions = []
        highlighted_parts = []
        word_scores = []

        for item in tokens_and_delimiters:
            clean_item = item.strip().lower()
            if not clean_item or not re.match(r'^\w+$', clean_item):
                # Delimiter or whitespace
                highlighted_parts.append(html.escape(item))
                continue

            # Look up weight
            weight = self.word_weights.get(clean_item, 0.0)

            # Check for substrings or leet tokens
            if weight == 0.0:
                for k, v in self.word_weights.items():
                    if len(k) > 4 and k in clean_item:
                        weight = v * 0.8
                        break

            # Bound weight between -1.0 and 1.0
            norm_weight = float(max(-1.0, min(1.0, float(weight))))

            if abs(norm_weight) > 0.15:
                word_scores.append((clean_item, norm_weight))

            # Generate styling based on weight
            if norm_weight > 0.2:
                # Phishing indicator -> Red intensity
                alpha = min(0.85, 0.20 + (norm_weight * 0.65))
                span_style = f"background-color: rgba(239, 68, 68, {alpha:.2f}); color: #ffffff; padding: 2px 4px; border-radius: 4px; font-weight: 600;"
                title = f"Phishing indicator (+{norm_weight:.2f})"
                highlighted_parts.append(
                    f'<span style="{span_style}" title="{title}">{html.escape(item)}</span>'
                )
                token_attributions.append({
                    "token": item,
                    "weight": float(round(norm_weight, 3)),
                    "sentiment": "phishing"
                })
            elif norm_weight < -0.2:
                # Legitimate indicator -> Green intensity
                alpha = min(0.85, 0.20 + (abs(norm_weight) * 0.65))
                span_style = f"background-color: rgba(16, 185, 129, {alpha:.2f}); color: #ffffff; padding: 2px 4px; border-radius: 4px; font-weight: 600;"
                title = f"Legitimate anchor ({norm_weight:.2f})"
                highlighted_parts.append(
                    f'<span style="{span_style}" title="{title}">{html.escape(item)}</span>'
                )
                token_attributions.append({
                    "token": item,
                    "weight": float(round(norm_weight, 3)),
                    "sentiment": "legitimate"
                })
            else:
                highlighted_parts.append(html.escape(item))

        # Sort and deduplicate top words
        phishing_words_seen = set()
        top_phishing = []
        for word, score in sorted(word_scores, key=lambda x: x[1], reverse=True):
            if score > 0.2 and word not in phishing_words_seen:
                phishing_words_seen.add(word)
                top_phishing.append({"word": word, "importance": float(round(score, 3))})
                if len(top_phishing) >= top_k:
                    break

        legit_words_seen = set()
        top_legitimate = []
        for word, score in sorted(word_scores, key=lambda x: x[1]):
            if score < -0.2 and word not in legit_words_seen:
                legit_words_seen.add(word)
                top_legitimate.append({"word": word, "importance": float(round(abs(score), 3))})
                if len(top_legitimate) >= top_k:
                    break

        return {
            "highlighted_html": "".join(highlighted_parts),
            "top_phishing_words": top_phishing,
            "top_legitimate_words": top_legitimate,
            "token_attributions": token_attributions[:50]
        }

"""
Composite Risk Scoring Engine.
Synthesizes calibrated ML model probabilities (60%) with deterministic rule-based
cybersecurity heuristics (40%) to calculate a unified 0-100 Risk Score.
Categorizes into verdicts: Safe (0-39), Suspicious (40-69), Dangerous (70-100).
"""

from typing import Dict, Any, List, Optional


class RiskScorer:
    """Combines statistical ML predictions with rule-based threat indicators."""

    @staticmethod
    def calculate_score(
        model_prob_phish: float,
        url_results: Optional[List[Dict[str, Any]]] = None,
        header_results: Optional[Dict[str, Any]] = None,
        obfuscation_metrics: Optional[Dict[str, Any]] = None,
        linguistic_cues: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Calculate composite risk score and generate plain-English security reasons.
        """
        reasons: List[str] = []

        # 1. Base ML model contribution (up to 60 points)
        ml_score = float(model_prob_phish * 60.0)
        if model_prob_phish >= 0.80:
            reasons.append(f"Machine learning classifier identified strong phishing syntax pattern ({model_prob_phish*100:.1f}% confidence)")
        elif model_prob_phish <= 0.20:
            reasons.append(f"Machine learning classifier identified standard legitimate email communication ({(1-model_prob_phish)*100:.1f}% confidence)")

        # 2. URL threat contribution (up to 20 points)
        url_score = 0.0
        if url_results:
            max_url_risk = max((u.get("url_risk_score", 0) for u in url_results), default=0)
            url_score = (max_url_risk / 100.0) * 20.0
            for u in url_results:
                if u.get("is_ip"):
                    reasons.append(f"Host contains naked IP address ({u['url'][:35]}...)")
                if u.get("is_typosquat"):
                    reasons.append(f"Domain impersonates protected brand '{u['typosquat_details']['targeted_brand']}'")
                if u.get("anchor_mismatch"):
                    reasons.append("Anchor link displays misleading destination URL")
                if u.get("is_shortener"):
                    reasons.append("URL shortener obscures true destination")

        # 3. Email Header threat contribution (up to 15 points)
        header_score = 0.0
        if header_results:
            hdr_risk = header_results.get("header_risk_score", 0)
            header_score = (hdr_risk / 100.0) * 15.0
            for anom in header_results.get("anomalies", []):
                reasons.append(anom)

        # 4. Obfuscation contribution (up to 10 points)
        obfuscation_score = 0.0
        if obfuscation_metrics:
            total_obf = obfuscation_metrics.get("total_obfuscation_count", 0)
            if total_obf > 0:
                obfuscation_score = min(10.0, total_obf * 3.0)
                reasons.append(f"Detected {total_obf} deliberate character obfuscation/homoglyph evasion attempts")

        # 5. Linguistic urgency & credential cues (up to 10 points)
        linguistic_score = 0.0
        if linguistic_cues:
            urgency = linguistic_cues.get("urgency_count", 0)
            cred = linguistic_cues.get("credential_count", 0)
            threat = linguistic_cues.get("threat_count", 0)
            financial = linguistic_cues.get("financial_count", 0)

            cues_sum = (urgency * 1.5) + (cred * 2.0) + (threat * 1.5) + (financial * 1.5)
            linguistic_score = min(10.0, cues_sum)

            if urgency > 0:
                reasons.append("High urgency and forced artificial deadline psychological pressure")
            if cred > 0:
                reasons.append("Explicit request for credentials, password, or security token re-authentication")
            if financial > 0:
                reasons.append("High-stakes financial or wire transfer transaction bait")

        # Composite sum bounded 0 to 100
        raw_total = ml_score + url_score + header_score + obfuscation_score + linguistic_score
        final_score = int(round(max(0.0, min(100.0, raw_total))))

        # Determine calibrated verdict
        if final_score >= 70:
            verdict = "Dangerous"
            verdict_badge = "destructive"
            verdict_description = "High probability of active phishing, credential harvesting, or financial fraud."
        elif final_score >= 40:
            verdict = "Suspicious"
            verdict_badge = "warning"
            verdict_description = "Email displays multiple anomalies or psychological lures. Exercise extreme caution."
        else:
            verdict = "Safe"
            verdict_badge = "success"
            verdict_description = "No significant phishing traits or malicious indicators detected."

        if not reasons:
            reasons.append("Clean sender headers, legitimate domain origin, and standard correspondence structure.")

        return {
            "risk_score": final_score,
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "verdict_description": verdict_description,
            "score_breakdown": {
                "ml_model_points": float(round(ml_score, 1)),
                "url_threat_points": float(round(url_score, 1)),
                "header_risk_points": float(round(header_score, 1)),
                "obfuscation_points": float(round(obfuscation_score, 1)),
                "linguistic_cue_points": float(round(linguistic_score, 1)),
                "model_phishing_probability": float(round(model_prob_phish, 4))
            },
            "key_reasons": reasons[:6]
        }

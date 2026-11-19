"""
Unit tests for social-engineering tactic detector.
"""

import pytest
from src.analyzers.tactic_detector import TacticDetector


def test_urgency_tactic_detection():
    text = "Action required immediately! You have 24 hours before your account is suspended."
    result = TacticDetector.detect_tactics(text)
    scores = result["scores"]
    assert scores["urgency"] >= 50
    assert scores["fear"] >= 25
    assert result["primary_tactic"] in ["Urgency", "Fear"]


def test_reward_tactic_detection():
    text = "Congratulations! You have received a dividend wire transfer of 2.5 Bitcoin."
    result = TacticDetector.detect_tactics(text)
    scores = result["scores"]
    assert scores["reward"] >= 50


def test_credential_tactic_detection():
    text = "Please verify your password and confirm your MFA login token."
    result = TacticDetector.detect_tactics(text)
    scores = result["scores"]
    assert scores["credentials"] >= 50


def test_clean_text_no_tactics():
    text = "Let's grab lunch tomorrow at 12:30 PM if you are free."
    result = TacticDetector.detect_tactics(text)
    for score in result["scores"].values():
        assert score == 0
    assert result["primary_tactic"] == "None"

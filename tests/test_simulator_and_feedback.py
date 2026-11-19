"""
Unit tests for gamified phishing simulator and active learning feedback store.
"""

import pytest
from src.data.simulator_data import get_random_scenario, verify_scenario_answer
from src.data.feedback_store import add_feedback, get_all_feedback


def test_get_simulator_scenario():
    scenario = get_random_scenario()
    assert "id" in scenario
    assert "subject" in scenario
    assert "body" in scenario
    assert "is_phishing" not in scenario  # Hidden from user


def test_verify_simulator_answer():
    # sim_01 is known phishing
    res = verify_scenario_answer("sim_01", user_guess_is_phish=True)
    assert res["is_correct"] is True
    assert res["points_earned"] == 100
    assert "Netflix" in res["explanation"]

    res_wrong = verify_scenario_answer("sim_01", user_guess_is_phish=False)
    assert res_wrong["is_correct"] is False
    assert res_wrong["points_earned"] == 0


def test_feedback_store():
    record = add_feedback(
        email_snippet="Urgent invoice transfer request",
        predicted_verdict="Dangerous",
        user_reported_label="True Positive",
        comments="Correctly detected CEO wire fraud"
    )
    assert "id" in record
    feedback_list = get_all_feedback()
    assert len(feedback_list) >= 1
    assert any(fb["id"] == record["id"] for fb in feedback_list)
